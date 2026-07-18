//go:build integration

package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/cli"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/netdetect"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

// inviteApp builds a root-run App whose every path points at temp dirs, and
// returns it with the sudoers and sshd drop-in dirs so a test can plant a stale
// artifact the way an out-of-band deletion or a failed revoke would leave one.
func inviteApp(t *testing.T) (*cli.App, *sudoers.Manager, *sshdconf.Manager, string) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	regDir := rootDir(t, 0o700)
	sudoDir := rootDir(t, 0o750)
	sshdDir := rootDir(t, 0o755)
	installPath := filepath.Join(rootDir(t, 0o755), "linux-temp-admin")
	if err := os.WriteFile(installPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) }
	auditFile := filepath.Join(rootDir(t, 0o700), "audit.log")

	sudoMgr := &sudoers.Manager{Dir: sudoDir, Validate: func(string) error { return nil }, Verify: func(string) error { return nil }}
	sshdMgr := &sshdconf.Manager{
		Dir: sshdDir, Validate: func() error { return nil }, Reload: func() error { return nil },
		Effective: func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdOK), nil },
	}
	var out, errb bytes.Buffer
	a := &cli.App{
		Out: &out, Err: &errb, In: strings.NewReader(""),
		P:       i18n.Printer{Lang: i18n.EN},
		Users:   user.New(),
		Sudoers: sudoMgr,
		Scheduler: &schedule.Scheduler{
			SystemdDir: rootDir(t, 0o755), InstallPath: installPath,
			UnitPrefix: config.AutoRevokeUnitPrefix, LegacyUnitPrefixes: []string{config.V1AutoRevokeUnitPrefix},
			Now: now, Sys: fakeSched{},
		},
		Registry:     &registry.Store{Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock")},
		SSHD:         sshdMgr,
		SSHDConfig:   func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdOK), nil },
		Detector:     netdetect.New(),
		Selfmanage:   &selfmanage.Manager{InstallPath: installPath},
		Audit:        &audit.Logger{Dir: filepath.Dir(auditFile), File: auditFile, Now: now, Actor: func() (string, int) { return "test", 0 }},
		InstallPath:  installPath,
		Now:          now,
		RandHex:      func(int) (string, error) { return "abcdef0123", nil },
		RandPassword: func(int) (string, error) { return "pw-abcdefgh", nil },
		StdoutIsTTY:  func() bool { return true },
		StdinIsTTY:   func() bool { return false },
		Geteuid:      func() int { return 0 },
	}
	return a, sudoMgr, sshdMgr, installPath
}

// TestInviteNoSudoDoesNotInheritAStaleGrant is the CRITICAL. invite unconditionally
// clears a reused name's stale auto-revoke UNIT but not its stale sudo grant or
// sshd exception, so a --no-sudo invite that reuses a name still carrying an
// orphaned /etc/sudoers.d NOPASSWD:ALL drop-in creates an account that silently
// holds passwordless root — while the registry row, status, and the audit all
// record sudo=no.
//
// The stale grant is planted the way the host actually produces one: a managed
// drop-in for a name whose account is gone (an out-of-band userdel, or a revoke
// whose removeSudoGrant failed). Then a fresh --no-sudo invite reuses the name.
func TestInviteNoSudoDoesNotInheritAStaleGrant(t *testing.T) {
	a, sudoMgr, sshdMgr, _ := inviteApp(t)
	const name = "xxvcc-reuse01"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	// A stale NOPASSWD grant and a stale sshd exception for a name with no account.
	grant := sudoMgr.FilePath(name)
	if err := os.WriteFile(grant, []byte(name+" ALL=(ALL) NOPASSWD:ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	sshEx := sshdMgr.FilePath(name)
	if err := os.WriteFile(sshEx, []byte("Match User "+name+"\n\tPubkeyAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A fresh --no-sudo, --no-fix-sshd invite reusing the name.
	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "24", "--no-sudo", "--no-fix-sshd", "--no-auto-revoke", "--yes"})
	if rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if !user.Exists(name) {
		t.Fatal("the account should have been created")
	}

	if _, err := os.Stat(grant); err == nil {
		t.Error("CRITICAL: a --no-sudo account inherited a stale NOPASSWD:ALL sudo grant")
	}
	if _, err := os.Stat(sshEx); err == nil {
		t.Error("a --no-sudo/--no-fix-sshd account inherited a stale sshd exception")
	}
}

// TestAutoRevokeDeletesEvenWhenTheRegistryRowIsLost is HIGH #1. The auto-revoke
// timer fires unattended at expiry, and by then the registry row it would need
// may be gone (hand-edit, backup restore, corruption — the whole uninstall-witness
// design assumes rows vanish). The baked command now carries --force
// --confirm-force so the firing can still delete a GECOS-managed temp account and
// strip its NOPASSWD grant, instead of refusing "unregistered" and stranding a
// root-capable account with no retry (a one-shot timer does not fire twice).
//
// The account is real and carries the managed GECOS but has NO registry row —
// exactly the lost-row state. The command run is the one the scheduler bakes.
func TestAutoRevokeDeletesEvenWhenTheRegistryRowIsLost(t *testing.T) {
	a, sudoMgr, _, installPath := inviteApp(t)
	const name = "xxvcc-lostrow1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	grant := sudoMgr.FilePath(name)
	if err := os.WriteFile(grant, []byte(name+" ALL=(ALL) NOPASSWD:ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	// The exact command the scheduler bakes into the unit / at job.
	sched := &schedule.Scheduler{InstallPath: installPath}
	cmd := sched.RevokeCommand(name) // "<path> revoke --user X --yes --force --confirm-force X"
	args := strings.Fields(cmd)[1:]  // drop the binary path

	if rc := a.Dispatch(args); rc != 0 {
		t.Fatalf("auto-revoke command rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if user.Exists(name) {
		t.Error("HIGH: a GECOS-managed account with a lost registry row survived auto-revoke")
	}
	if _, err := os.Stat(grant); err == nil {
		t.Error("HIGH: its NOPASSWD grant was stranded")
	}
}

// TestAutoRevokeForceStillProtectsARealAccount is the other half: the force
// tokens must not turn the auto-revoke into a way to delete an account this tool
// did not make. A real account (no managed GECOS, no row) must be refused even
// with --force, because IsProtectedRevokeTarget ignores --force.
func TestAutoRevokeForceStillProtectsARealAccount(t *testing.T) {
	a, _, _, installPath := inviteApp(t)
	const name = "ltarealacct1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	// A real account: an ordinary GECOS, NOT the managed marker.
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", "Real Person", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	sched := &schedule.Scheduler{InstallPath: installPath}
	args := strings.Fields(sched.RevokeCommand(name))[1:]

	if rc := a.Dispatch(args); rc == 0 {
		t.Error("the forced auto-revoke deleted a real, unmanaged account")
	}
	if !user.Exists(name) {
		t.Error("SECURITY: --force auto-revoke deleted a real account it did not create")
	}
}

// TestInviteExistingLiveAccountDoesNotStripItsGrant is the regression the
// pre-clear introduced. invite's explicit --user path has no existence guard, so
// re-inviting a name that is a currently-LIVE managed account used to be a
// harmless no-op (Create failed first, nothing touched). The unconditional
// pre-clear made it strip the live account's sudo grant and sshd exception (and
// reload sshd, locking out the invitee) BEFORE Create fails — destroying a live
// account's privilege on an operator typo. The pre-clear must only run for a name
// whose account is actually gone (the reuse case it targets).
func TestInviteExistingLiveAccountDoesNotStripItsGrant(t *testing.T) {
	a, sudoMgr, sshdMgr, _ := inviteApp(t)
	const name = "xxvcc-live01"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	// A live managed account with a real sudo grant and sshd exception on disk.
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	grant := sudoMgr.FilePath(name)
	mustWriteInvite(t, grant, name+" ALL=(ALL) NOPASSWD:ALL\n")
	sshEx := sshdMgr.FilePath(name)
	mustWriteInvite(t, sshEx, "Match User "+name+"\n\tPubkeyAuthentication yes\n")

	// Re-invite the live name. Create will fail (account exists) — the point is that
	// nothing on disk is touched on the way to that failure.
	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "24", "--no-sudo", "--no-fix-sshd", "--no-auto-revoke", "--yes"})
	if rc == 0 {
		t.Fatalf("invite of an existing account should have failed")
	}
	if _, err := os.Stat(grant); err != nil {
		t.Error("REGRESSION: re-inviting a live account stripped its NOPASSWD sudo grant")
	}
	if _, err := os.Stat(sshEx); err != nil {
		t.Error("REGRESSION: re-inviting a live account stripped its sshd exception")
	}
}

func mustWriteInvite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o440); err != nil {
		t.Fatal(err)
	}
}

// TestInvitePermanentWhenNoAutoRevoke pins the new "no auto-delete = permanent"
// semantics: no chage expiry is set (SetExpiry not called), no auto-delete task,
// and the bundle says permanent. Previously even a --no-auto-revoke account got a
// chage login-expiry; now it is genuinely permanent.
func TestInvitePermanentWhenNoAutoRevoke(t *testing.T) {
	a, _, _, _ := inviteApp(t)
	out := a.Out.(*bytes.Buffer)
	const name = "xxvcc-perm01"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--no-sudo", "--no-auto-revoke", "--yes", "--allow-non-tty-private-key-output"})
	if rc != 0 {
		t.Fatalf("invite rc=%d: %s", rc, a.Err.(*bytes.Buffer).String())
	}
	// No chage expiry: the shadow expiry field must be empty (never set).
	if line := passwdExpiryField(t, name); line != "" {
		t.Errorf("a permanent account must have no chage expiry; shadow expire field = %q", line)
	}
	if !strings.Contains(out.String(), "never") && !strings.Contains(out.String(), "永久") {
		t.Errorf("bundle should show a permanent expiry: %q", out.String())
	}
	if !strings.Contains(out.String(), "Permanent-account note") {
		t.Errorf("bundle should carry the permanent-account note: %q", out.String())
	}
}

// passwdExpiryField returns the account-expiry field (field 8) from /etc/shadow
// for name — empty when no expiry was ever set.
func passwdExpiryField(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("chage", "-l", name).CombinedOutput()
	if err != nil {
		t.Fatalf("chage -l: %v: %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(line), "account expires") {
			_, v, _ := strings.Cut(line, ":")
			v = strings.TrimSpace(v)
			if v == "never" {
				return ""
			}
			return v
		}
	}
	return ""
}

// TestInviteInteractiveDefaultsSudoOn: the interactive flow (a TTY, no --yes)
// grants sudo without asking. A --no-sudo still makes a plain account, but the
// bare interactive path is admin-by-default.
func TestInviteInteractiveDefaultsSudoOn(t *testing.T) {
	a, _, _, _ := inviteApp(t)
	out := a.Out.(*bytes.Buffer)
	a.StdinIsTTY = func() bool { return true }
	// Interactive answers: sudo is NOT asked now; auto-delete [Y/n] -> n (so no
	// hours prompt either); then the confirmation YES.
	a.In = strings.NewReader("n\nYES\n")
	const name = "xxvcc-defsudo1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--allow-non-tty-private-key-output"})
	if rc != 0 {
		t.Fatalf("invite rc=%d: %s", rc, a.Err.(*bytes.Buffer).String())
	}
	if !strings.Contains(out.String(), "Sudo: yes") {
		t.Errorf("interactive invite should default to sudo on: %q", out.String())
	}
	// It must NOT have asked the sudo question.
	if strings.Contains(a.Err.(*bytes.Buffer).String(), "Grant sudo") {
		t.Errorf("interactive invite should not ask about sudo anymore")
	}
}
