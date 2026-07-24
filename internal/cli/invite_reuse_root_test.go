//go:build integration

package cli_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	if err := os.WriteFile(installPath, []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 0.0.0-dev\n"), 0o755); err != nil {
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
		Registry:    &registry.Store{Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock")},
		SSHD:        sshdMgr,
		SSHDConfig:  func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdOK), nil },
		Detector:    netdetect.New(),
		Selfmanage:  &selfmanage.Manager{InstallPath: installPath},
		Audit:       &audit.Logger{Dir: filepath.Dir(auditFile), File: auditFile, Now: now, Actor: func() (string, int) { return "test", 0 }},
		InstallPath: installPath,
		Executable:  func() (string, error) { return installPath, nil },
		Now:         now,
		RandHex: func(n int) (string, error) {
			if n == 16 {
				return "0123456789abcdef0123456789abcdef", nil
			}
			return "abcdef0123", nil
		},
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
	if !mustExternalUserExists(t, name) {
		t.Fatal("the account should have been created")
	}

	if _, err := os.Stat(grant); err == nil {
		t.Error("CRITICAL: a --no-sudo account inherited a stale NOPASSWD:ALL sudo grant")
	}
	if _, err := os.Stat(sshEx); err == nil {
		t.Error("a --no-sudo/--no-fix-sshd account inherited a stale sshd exception")
	}
}

// A scheduled deletion has no trustworthy identity when its registry row is
// gone. It must exit successfully without touching either the account or its
// name-scoped grant; chage expiry still blocks future login.
func TestAutoRevokeSkipsWhenRegistryRowIsLost(t *testing.T) {
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

	pw, ok := mustExternalUserLookup(t, name)
	if !ok {
		t.Fatal("created account was not found")
	}

	// The exact identity-bearing command the scheduler bakes into a task, but no
	// corresponding registry row exists.
	sched := &schedule.Scheduler{InstallPath: installPath}
	cmd := sched.RevokeCommand(name, pw.UID, "11111111111111111111111111111111")
	args := strings.Fields(cmd)[1:] // drop the binary path

	if rc := a.Dispatch(args); rc != 0 {
		t.Fatalf("stale auto-revoke command rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if !mustExternalUserExists(t, name) {
		t.Error("a task with no registry identity deleted the account")
	}
	if _, err := os.Stat(grant); err != nil {
		t.Error("a task with no registry identity removed the account's grant")
	}
}

// A matching username and UID do not prove identity because Linux can reuse both
// after out-of-band deletion. The current account must still carry the managed
// marker even when the scheduled generation matches the stale registry row.
func TestAutoRevokeProtectsSameUIDUnmanagedReplacement(t *testing.T) {
	a, _, _, installPath := inviteApp(t)
	const name = "ltarealacct1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	original, ok := mustExternalUserLookup(t, name)
	if !ok {
		t.Fatal("created account was not found")
	}
	const generation = "22222222222222222222222222222222"
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	if err := a.Registry.Record(registry.Record{User: name, Port: 22, UID: original.UID, Generation: generation, AutoRevoke: true}); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("userdel", "-r", "--", name).CombinedOutput(); err != nil {
		t.Fatalf("userdel: %v: %s", err, out)
	}
	// Recreate the same name with the exact same UID, but as a real unmanaged user.
	if out, err := exec.Command("useradd", "-m", "-u", strconv.Itoa(original.UID), "-s", "/bin/bash", "-c", "Real Person", name).CombinedOutput(); err != nil {
		t.Fatalf("replacement useradd: %v: %s", err, out)
	}
	sched := &schedule.Scheduler{InstallPath: installPath}
	args := strings.Fields(sched.RevokeCommand(name, original.UID, generation))[1:]

	if rc := a.Dispatch(args); rc == 0 {
		t.Error("auto-revoke accepted an unmanaged replacement with the same UID")
	}
	if !mustExternalUserExists(t, name) {
		t.Error("auto-revoke deleted an unmanaged replacement account")
	}
	if ok, err := a.Registry.Contains(name); err != nil || !ok {
		t.Errorf("recovery registry row was not preserved: present=%v err=%v", ok, err)
	}
}

func TestAutoRevokeSkipsStaleGeneration(t *testing.T) {
	a, sudoMgr, _, installPath := inviteApp(t)
	const name = "xxvcc-stalegen1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	pw, ok := mustExternalUserLookup(t, name)
	if !ok {
		t.Fatal("created account was not found")
	}
	const currentGeneration = "33333333333333333333333333333333"
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	if err := a.Registry.Record(registry.Record{User: name, Port: 22, UID: pw.UID, Generation: currentGeneration, AutoRevoke: true}); err != nil {
		t.Fatal(err)
	}
	grant := sudoMgr.FilePath(name)
	if err := os.WriteFile(grant, []byte(name+" ALL=(ALL) NOPASSWD:ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	args := strings.Fields((&schedule.Scheduler{InstallPath: installPath}).RevokeCommand(
		name, pw.UID, "44444444444444444444444444444444"))[1:]
	if rc := a.Dispatch(args); rc != 0 {
		t.Fatalf("stale generation rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if !mustExternalUserExists(t, name) {
		t.Error("stale generation deleted the current account")
	}
	if _, err := os.Stat(grant); err != nil {
		t.Error("stale generation removed the current account's grant")
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil || !found || rec.Generation != currentGeneration {
		t.Errorf("current registry identity changed: found=%v generation=%q err=%v", found, rec.Generation, err)
	}
}

func TestInviteOutputFailureRollsBackAllState(t *testing.T) {
	a, sudoMgr, sshdMgr, _ := inviteApp(t)
	tracker := newTrackingSched()
	a.Scheduler.Sys = tracker
	a.Out = failingWriter{}
	const name = "xxvcc-outputfail1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "24", "--sudo", "--confirm-sudo", name, "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want failure when credentials cannot be written", rc)
	}
	if mustExternalUserExists(t, name) {
		t.Error("output failure left the account behind")
	}
	if present, err := a.Registry.Contains(name); err != nil || present {
		t.Errorf("output failure left a registry row: present=%v err=%v", present, err)
	}
	if _, err := os.Lstat(sudoMgr.FilePath(name)); !os.IsNotExist(err) {
		t.Errorf("output failure left a sudo grant: %v", err)
	}
	if _, err := os.Lstat(sshdMgr.FilePath(name)); !os.IsNotExist(err) {
		t.Errorf("output failure left an sshd exception: %v", err)
	}
	if len(tracker.jobs) != 0 {
		t.Errorf("output failure left scheduled jobs: %v", tracker.jobs)
	}
}

func TestRevokeSudoCleanupFailureKeepsDisabledAccountAndRecoveryState(t *testing.T) {
	a, sudoMgr, _, _ := inviteApp(t)
	tracker := newTrackingSched()
	a.Scheduler.Sys = tracker
	const name = "xxvcc-sudofail1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	if rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "24", "--sudo", "--confirm-sudo", name, "--yes"}); rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	grant := sudoMgr.FilePath(name)
	if err := os.Remove(grant); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(grant, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(grant, "still-live"), []byte("grant cannot be removed"), 0o600); err != nil {
		t.Fatal(err)
	}

	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes"}); rc != 1 {
		t.Fatalf("revoke rc=%d, want nonzero when sudo cleanup fails", rc)
	}
	if !mustExternalUserExists(t, name) {
		t.Error("revoke freed the username while a sudo artifact survived")
	}
	if present, err := a.Registry.Contains(name); err != nil || !present {
		t.Errorf("recovery registry row missing: present=%v err=%v", present, err)
	}
	if len(tracker.jobs) == 0 {
		t.Error("recovery auto-delete task was removed despite failed grant cleanup")
	}
}

func TestRevokeScheduleCleanupFailureReturnsNonzeroAndKeepsRegistry(t *testing.T) {
	a, _, _, _ := inviteApp(t)
	tracker := newTrackingSched()
	a.Scheduler.Sys = tracker
	const name = "xxvcc-schedfail1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	if rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "24", "--no-sudo", "--yes"}); rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	tracker.removeErr = errors.New("cannot enumerate at jobs")
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes"}); rc != 1 {
		t.Fatalf("revoke rc=%d, want nonzero when schedule cleanup fails", rc)
	}
	if mustExternalUserExists(t, name) {
		t.Error("account should already be deleted before schedule cleanup")
	}
	if present, err := a.Registry.Contains(name); err != nil || !present {
		t.Errorf("registry row needed for recovery was removed: present=%v err=%v", present, err)
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
