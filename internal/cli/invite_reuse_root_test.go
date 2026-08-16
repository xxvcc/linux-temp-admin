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

	sudoMgr := &sudoers.Manager{Dir: sudoDir, Validate: func([]byte) error { return nil }, Verify: func(string) error { return nil }}
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
		Registry:                 &registry.Store{Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock")},
		SSHD:                     sshdMgr,
		SSHDConfig:               func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdOK), nil },
		SSHDHasUnverifiableMatch: func(bool) bool { return false },
		Detector:                 netdetect.New(),
		Selfmanage:               &selfmanage.Manager{InstallPath: installPath},
		Audit:                    &audit.Logger{Dir: filepath.Dir(auditFile), File: auditFile, Now: now, Actor: func() (string, int) { return "test", 0 }},
		InstallPath:              installPath,
		Executable:               func() (string, error) { return installPath, nil },
		Now:                      now,
		RandHex: func(n int) (string, error) {
			if n == 16 {
				return "0123456789abcdef0123456789abcdef", nil
			}
			return "abcdef0123", nil
		},
		RandPassword:       func(int) (string, error) { return "pw-abcdefgh", nil },
		StdoutIsTTY:        func() bool { return true },
		StdinIsTTY:         func() bool { return false },
		Geteuid:            func() int { return 0 },
		ClearScheduledJobs: noDeferredJobs,
		DrainScheduledJobs: noDeferredJobDrain,
	}
	return a, sudoMgr, sshdMgr, installPath
}

func unusedHighIntegrationUID(t *testing.T) int {
	t.Helper()
	for uid := 59000; uid >= 58000; uid-- {
		err := exec.Command("getent", "passwd", strconv.Itoa(uid)).Run()
		if err == nil {
			continue
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return uid
		}
		t.Fatalf("probe integration-test UID %d: %v", uid, err)
	}
	t.Fatal("no unused high UID available for integration test")
	return 0
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

func TestPasswordNoSudoRevokeUsesTrailingWitnessAfterFullNameChange(t *testing.T) {
	for _, tc := range []struct {
		name       string
		username   string
		changeName bool
	}{
		{name: "unchanged default account", username: "xxvcc-pwdefault"},
		{name: "full-name field changed", username: "xxvcc-pwfullname", changeName: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.changeName {
				if _, err := exec.LookPath("chfn"); err != nil {
					t.Skip("chfn is unavailable")
				}
			}
			a, sudoMgr, sshdMgr, _ := inviteApp(t)
			remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", tc.username).Run() }
			remove()
			t.Cleanup(remove)

			passwordSSHD := "passwordauthentication yes\npubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
			a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(passwordSSHD), nil }
			sshdMgr.Effective = a.SSHDConfig
			if rc := a.Dispatch([]string{"invite", "--user", tc.username, "--host", "203.0.113.5",
				"--password-login", "--no-sudo", "--no-fix-sshd", "--no-auto-revoke", "--yes"}); rc != 0 {
				t.Fatalf("password invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
			}
			rec, found, err := a.Registry.Lookup(tc.username)
			if err != nil || !found {
				t.Fatalf("registry identity after invite: found=%v rec=%+v err=%v", found, rec, err)
			}
			before, exists := mustExternalUserLookup(t, tc.username)
			if !exists || !user.HasTrailingGenerationWitness(before, rec.Generation) {
				t.Fatalf("password invite lacks protected trailing witness: exists=%v pw=%+v rec=%+v", exists, before, rec)
			}
			if _, err := os.Lstat(sudoMgr.FilePath(tc.username)); !os.IsNotExist(err) {
				t.Fatalf("--no-sudo password invite created a sudo grant: %v", err)
			}

			if tc.changeName {
				if out, err := exec.Command("chfn", "-f", "x", tc.username).CombinedOutput(); err != nil {
					t.Fatalf("change full-name field: %v: %s", err, out)
				}
				after, exists := mustExternalUserLookup(t, tc.username)
				if !exists || after.GECOS == before.GECOS || !user.MatchesManagedGeneration(after, rec.Generation) ||
					!user.SameAccountIdentity(before, after) {
					t.Fatalf("full-name change damaged protected identity: exists=%v before=%+v after=%+v", exists, before, after)
				}
			}

			a.Out.(*bytes.Buffer).Reset()
			a.Err.(*bytes.Buffer).Reset()
			if rc := a.Dispatch([]string{"revoke", "--user", tc.username, "--yes"}); rc != 0 {
				t.Fatalf("revoke after full-name policy rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
			}
			if mustExternalUserExists(t, tc.username) {
				t.Fatal("password --no-sudo account survived revoke")
			}
			if found, err := a.Registry.Contains(tc.username); err != nil || found {
				t.Fatalf("revoke retained registry identity: found=%v err=%v", found, err)
			}
		})
	}
}

func TestInviteRetriesSSHDGrantCleanupBeforeAccountRollback(t *testing.T) {
	a, _, sshdMgr, _ := inviteApp(t)
	const name = "xxvcc-sshretry1"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	// The grant reload fails. Its first removal attempt also fails, but the CLI's
	// independent cleanup retry succeeds before account rollback frees the name.
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdNoPubkey), nil }
	removes := 0
	sshdMgr.RemoveFile = func(path string) error {
		removes++
		if removes == 1 {
			return errors.New("transient read-only filesystem")
		}
		return os.Remove(path)
	}
	reloads := 0
	sshdMgr.Reload = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload failed")
		}
		return nil
	}

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--no-sudo", "--no-auto-revoke", "--fix-sshd", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want the failed grant transaction to roll back", rc)
	}
	if removes < 2 {
		t.Fatalf("sshd drop-in removal attempts=%d, want Grant plus CLI retry", removes)
	}
	if _, err := os.Lstat(sshdMgr.FilePath(name)); !os.IsNotExist(err) {
		t.Fatalf("sshd drop-in survived the independent cleanup retry: %v", err)
	}
	if mustExternalUserExists(t, name) {
		t.Fatal("account survived a failed sshd grant")
	}
}

func TestInviteRetainsAccountAndRegistryWhenLaterSSHDRemovalIsUnconfirmed(t *testing.T) {
	a, _, sshdMgr, _ := inviteApp(t)
	const name = "xxvcc-sshhold1"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	// Grant succeeds and reaches the running daemon. Scheduling then fails, forcing
	// invite rollback; that rollback must not free the username when its removal
	// reload fails.
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdNoPubkey), nil }
	a.Scheduler.Sys = unavailableSched{}
	reloads := 0
	sshdMgr.Reload = func() error {
		reloads++
		if reloads == 1 {
			return nil
		}
		return errors.New("rollback reload failed")
	}

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "1", "--no-sudo", "--auto-revoke", "--fix-sshd", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want scheduling failure", rc)
	}
	if reloads != 2 {
		t.Fatalf("reload calls = %d, want grant plus failed rollback", reloads)
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("account was deleted while sshd removal was unconfirmed")
	}
	if ok, err := a.Registry.Contains(name); err != nil || !ok {
		t.Fatalf("registry witness was cleared while sshd removal was unconfirmed: ok=%v err=%v", ok, err)
	}
	if _, err := os.Lstat(sshdMgr.FilePath(name)); !os.IsNotExist(err) {
		t.Fatalf("rollback left active drop-in on disk: %v", err)
	}
	if _, err := os.Lstat(sshdMgr.FilePath(name) + ".remove-pending"); err != nil {
		t.Fatalf("rollback lost pending daemon-reload evidence: %v", err)
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), "account disabled and retained") {
		t.Fatalf("rollback did not report retained account:\n%s", a.Err.(*bytes.Buffer).String())
	}
}

func TestRevokeRetainsAccountAndRegistryWithoutReloadMechanism(t *testing.T) {
	a, _, sshdMgr, _ := inviteApp(t)
	const name = "xxvcc-sshnoreload1"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	if rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--no-sudo", "--no-auto-revoke", "--no-fix-sshd", "--yes"}); rc != 0 {
		t.Fatalf("fixture invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	dropIn := sshdMgr.FilePath(name)
	if err := os.WriteFile(dropIn, []byte("Match User "+name+"\n    PubkeyAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sshdMgr.Reload = func() error { return sshdconf.ErrNoReloadMechanism }

	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes"}); rc != 1 {
		t.Fatalf("revoke rc=%d, want unconfirmed sshd removal failure", rc)
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("revoke released the username without confirming daemon reload")
	}
	if ok, err := a.Registry.Contains(name); err != nil || !ok {
		t.Fatalf("revoke cleared registry without confirming daemon reload: ok=%v err=%v", ok, err)
	}
	if _, err := os.Lstat(dropIn); !os.IsNotExist(err) {
		t.Fatalf("revoke left the disk drop-in active: %v", err)
	}
	if _, err := os.Lstat(dropIn + ".remove-pending"); err != nil {
		t.Fatalf("revoke lost pending reload evidence: %v", err)
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

// A matching username and UID do not prove identity because Linux can reuse both.
// The dynamic GECOS marker must match the exact registry generation; copying the
// released fixed marker or another valid generation must not authorize userdel.
func TestAutoRevokeProtectsSameUIDMarkerReplacement(t *testing.T) {
	const generation = "22222222222222222222222222222222"
	for _, tc := range []struct {
		name              string
		replacementMarker string
	}{
		{name: "ltarealacct1", replacementMarker: config.ManagedGECOS},
		{name: "ltarealacct2", replacementMarker: config.ManagedGenerationGECOSPrefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _, installPath := inviteApp(t)
			testUID := unusedHighIntegrationUID(t)
			rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", tc.name).Run() }
			rm()
			t.Cleanup(rm)
			originalMarker := config.ManagedGenerationGECOSPrefix + generation
			if out, err := exec.Command("useradd", "-m", "-u", strconv.Itoa(testUID), "-s", "/bin/bash", "-c", originalMarker, tc.name).CombinedOutput(); err != nil {
				t.Fatalf("useradd: %v: %s", err, out)
			}
			original, ok := mustExternalUserLookup(t, tc.name)
			if !ok || original.UID != testUID {
				t.Fatalf("created account = %+v found=%v, want UID %d", original, ok, testUID)
			}
			if err := a.Registry.Init(); err != nil {
				t.Fatal(err)
			}
			if err := a.Registry.Record(registry.Record{
				User: tc.name, Port: 22, UID: original.UID, Generation: generation,
				IdentityBound: true, AutoRevoke: true,
			}); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("userdel", "-r", "--", tc.name).CombinedOutput(); err != nil {
				t.Fatalf("userdel: %v: %s", err, out)
			}
			if out, err := exec.Command("useradd", "-m", "-u", strconv.Itoa(original.UID), "-s", "/bin/bash", "-c", tc.replacementMarker, tc.name).CombinedOutput(); err != nil {
				t.Fatalf("replacement useradd: %v: %s", err, out)
			}
			replacement, ok := mustExternalUserLookup(t, tc.name)
			if !ok {
				t.Fatal("replacement account was not found")
			}
			sentinel := filepath.Join(replacement.Home, "replacement-data")
			if err := os.WriteFile(sentinel, []byte("keep\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			a.TerminateProcesses = func(int) error {
				t.Fatal("auto-revoke attempted to terminate replacement processes")
				return nil
			}
			args := strings.Fields((&schedule.Scheduler{InstallPath: installPath}).RevokeCommand(tc.name, original.UID, generation))[1:]
			if rc := a.Dispatch(args); rc == 0 {
				t.Error("auto-revoke accepted a same-UID marker replacement")
			}
			if !mustExternalUserExists(t, tc.name) {
				t.Error("auto-revoke deleted the replacement account")
			}
			if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep\n" {
				t.Errorf("replacement home data changed: content=%q err=%v", got, err)
			}
			if ok, err := a.Registry.Contains(tc.name); err != nil || !ok {
				t.Errorf("recovery registry row was not preserved: present=%v err=%v", ok, err)
			}
		})
	}
}

func TestLegacyIdentityRequiresDirectForceConfirmation(t *testing.T) {
	a, _, _, installPath := inviteApp(t)
	const (
		name       = "ltalegacyacct1"
		generation = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	pw, ok := mustExternalUserLookup(t, name)
	if !ok {
		t.Fatal("legacy account was not found")
	}
	legacyRow := strings.Join([]string{
		name, "2026-08-16 12:00:00 UTC", "2026-08-17 20:00 CST",
		"no", "203.0.113.5", "22", "SHA256:legacy", "yes", "",
		strconv.Itoa(pw.UID), generation,
	}, "\t")
	if err := os.WriteFile(a.Registry.File, []byte("# linux-temp-admin registry v2\n"+legacyRow+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scheduled := strings.Fields((&schedule.Scheduler{InstallPath: installPath}).RevokeCommand(name, pw.UID, generation))[1:]
	if rc := a.Dispatch(scheduled); rc == 0 {
		t.Fatal("scheduled revoke accepted a legacy fixed identity")
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("scheduled revoke deleted a legacy account")
	}
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes", "--force"}); rc == 0 {
		t.Fatal("unconfirmed legacy revoke succeeded")
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("unconfirmed legacy revoke deleted the account")
	}
	// v2.6.1 through v2.7.0 emitted exactly this unattended command. It must not
	// become deletion authority merely because the current binary sees it as an
	// externally dispatched CLI invocation.
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes", "--force", "--confirm-force", name}); rc == 0 {
		t.Fatal("historical eight-argument timer command accepted a legacy identity")
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("historical eight-argument timer command deleted the legacy account")
	}
	// App intentionally reuses one buffered reader across prompts. Feed both
	// confirmations up front so this external-package test does not reach into
	// private reader state between dispatches.
	a.In = strings.NewReader(name + "\n" + name + "\n")
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--force"}); rc == 0 {
		t.Fatal("piped full-name confirmation accepted a legacy identity")
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("piped full-name confirmation deleted the legacy account")
	}
	a.StdinIsTTY = func() bool { return true }
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--force"}); rc != 0 {
		t.Fatalf("interactive confirmed legacy revoke rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if mustExternalUserExists(t, name) {
		t.Fatal("interactive confirmed legacy revoke did not delete the account")
	}
}

func TestLegacyNineFieldRegistryInteractiveRevokeMigratesBeforeDeletion(t *testing.T) {
	a, _, _, _ := inviteApp(t)
	const name = "ltalegacyacct2"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	pw, ok := mustExternalUserLookup(t, name)
	if !ok || pw.UID < 1000 {
		t.Fatalf("legacy account identity = %+v, found=%v", pw, ok)
	}

	legacyRow := strings.Join([]string{
		name, "2026-08-16 12:00:00 UTC", "2026-08-17 20:00 CST",
		"no", "203.0.113.5", "22", "SHA256:legacy", "no", "",
	}, "\t")
	if fields := strings.Split(legacyRow, "\t"); len(fields) != 9 {
		t.Fatalf("legacy fixture has %d fields, want 9", len(fields))
	}
	if err := os.WriteFile(a.Registry.File, []byte("# linux-temp-admin registry v2\n"+legacyRow+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sequence := filepath.Join(a.Registry.Dir, "identity-sequence")
	if _, err := os.Lstat(sequence); !os.IsNotExist(err) {
		t.Fatalf("legacy fixture unexpectedly has an identity sequence: %v", err)
	}

	// The historical unattended argv must neither delete the account nor migrate
	// state; only the later TTY confirmation is allowed to cross that boundary.
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes", "--force", "--confirm-force", name}); rc == 0 {
		t.Fatal("historical non-interactive revoke accepted a nine-field legacy row")
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("historical non-interactive revoke deleted the legacy account")
	}
	if _, err := os.Lstat(sequence); !os.IsNotExist(err) {
		t.Fatalf("rejected non-interactive revoke migrated the registry: %v", err)
	}

	a.In = strings.NewReader(name + "\n")
	a.StdinIsTTY = func() bool { return true }
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--force"}); rc != 0 {
		t.Fatalf("interactive nine-field legacy revoke rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if mustExternalUserExists(t, name) {
		t.Fatal("interactive nine-field legacy revoke did not delete the account")
	}
	registryData, err := os.ReadFile(a.Registry.File)
	if err != nil {
		t.Fatal(err)
	}
	if string(registryData) != registry.Header+"\n" {
		t.Fatalf("completed registry was not migrated to an empty v5 file: %q", registryData)
	}
	sequenceData, err := os.ReadFile(sequence)
	if err != nil || len(strings.TrimSpace(string(sequenceData))) == 0 {
		t.Fatalf("identity sequence missing after legacy migration: bytes=%q err=%v", sequenceData, err)
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

func TestInviteOutputFailureRetainsAccountWhenProcessCleanupIsUncertain(t *testing.T) {
	a, _, _, _ := inviteApp(t)
	const name = "xxvcc-outputhold1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	partial := &partialFailingWriter{}
	a.Out = partial
	a.TerminateProcesses = func(int) error {
		if partial.wrote == 0 {
			return nil
		}
		return errors.New("injected rollback process uncertainty")
	}

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--no-sudo", "--no-fix-sshd", "--no-auto-revoke", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want output/rollback failure", rc)
	}
	if partial.wrote == 0 {
		t.Fatal("fixture did not expose any credential bytes before the output failure")
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("rollback freed the UID even though process cleanup was uncertain")
	}
	if expires := passwdExpiryField(t, name); expires == "" {
		t.Fatal("retained account was not disabled before rollback stopped")
	}
	if rec, found, err := a.Registry.Lookup(name); err != nil || !found || rec.Pending || rec.UID < 1 {
		t.Fatalf("completed recovery identity was not retained: found=%v rec=%+v err=%v", found, rec, err)
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), "injected rollback process uncertainty") {
		t.Fatalf("rollback uncertainty was not reported:\n%s", a.Err.(*bytes.Buffer).String())
	}
}

func TestInviteRetainsAccountWhenFailedSudoGrantCannotBeRemoved(t *testing.T) {
	a, sudoMgr, _, _ := inviteApp(t)
	const name = "xxvcc-sudograntfail1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	// The preflight removal must still see an ordinary absent file. Once Grant has
	// written the live drop-in, make both its own rollback and the CLI's independent
	// retry fail. The username and registry witness must then remain reserved.
	grantReachedVerify := false
	removeCalls := 0
	sudoMgr.Verify = func(string) error {
		grantReachedVerify = true
		return errors.New("injected effective sudo policy failure")
	}
	sudoMgr.RemoveFile = func(path string) error {
		if !grantReachedVerify {
			return os.Remove(path)
		}
		removeCalls++
		return errors.New("injected read-only sudoers filesystem")
	}

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--sudo", "--confirm-sudo", name, "--no-auto-revoke", "--no-fix-sshd", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want failed sudo grant rollback\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if removeCalls != 2 {
		t.Fatalf("sudo removal attempts=%d, want Grant rollback plus CLI retry\nstderr:\n%s", removeCalls, a.Err.(*bytes.Buffer).String())
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("invite freed the username while the sudo grant removal was unconfirmed")
	}
	if expires := passwdExpiryField(t, name); expires == "" {
		t.Error("retained account was not disabled")
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil || !found || !rec.Sudo {
		t.Fatalf("sudo recovery witness missing: found=%v record=%+v err=%v", found, rec, err)
	}
	if _, err := os.Lstat(sudoMgr.FilePath(name)); err != nil {
		t.Fatalf("test did not retain the live sudo drop-in: %v", err)
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), "sudo removal is unconfirmed; account disabled and retained") {
		t.Fatalf("rollback did not report the retained account:\n%s", a.Err.(*bytes.Buffer).String())
	}
}

func TestInviteRetainsAccountWhenLaterSudoRollbackCannotRemoveGrant(t *testing.T) {
	a, sudoMgr, _, _ := inviteApp(t)
	a.Scheduler.Sys = unavailableSched{}
	const name = "xxvcc-sudolaterfail1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	// Grant succeeds, then scheduling fails. Fail removal only after Verify proves
	// that the drop-in was live, so preflight remains unaffected.
	grantVerified := false
	sudoMgr.Verify = func(string) error {
		grantVerified = true
		return nil
	}
	sudoMgr.RemoveFile = func(path string) error {
		if !grantVerified {
			return os.Remove(path)
		}
		return errors.New("injected sudo rollback failure")
	}

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "1", "--sudo", "--confirm-sudo", name, "--auto-revoke", "--no-fix-sshd", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want scheduling failure\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if !mustExternalUserExists(t, name) {
		t.Fatalf("invite freed the username after its sudo rollback failed\nstderr:\n%s", a.Err.(*bytes.Buffer).String())
	}
	if expires := passwdExpiryField(t, name); expires == "" {
		t.Error("retained account was not disabled")
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil || !found || !rec.Sudo {
		t.Fatalf("sudo recovery witness missing: found=%v record=%+v err=%v", found, rec, err)
	}
	if _, err := os.Lstat(sudoMgr.FilePath(name)); err != nil {
		t.Fatalf("test did not retain the live sudo drop-in: %v", err)
	}
	if strings.Contains(a.Out.(*bytes.Buffer).String(), "BEGIN LINUX TEMP ADMIN INVITE") {
		t.Fatal("credentials were printed for the failed invite")
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), "sudo removal is unconfirmed; account disabled and retained") {
		t.Fatalf("rollback did not report the retained account:\n%s", a.Err.(*bytes.Buffer).String())
	}
}

func TestInviteRetainsRegistryWhenPostDeleteMailCleanupFails(t *testing.T) {
	a, _, _, _ := inviteApp(t)
	a.Scheduler.Sys = unavailableSched{}
	const name = "xxvcc-mailhold1"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	wantErr := errors.New("injected final mail cleanup failure")
	mailCalls := 0
	postDeleteCalls := 0
	a.Users.RemoveManagedMail = func(user.Passwd) error {
		mailCalls++
		exists, err := user.Exists(name)
		if err != nil {
			return err
		}
		if !exists {
			postDeleteCalls++
			return wantErr
		}
		return nil
	}

	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "1", "--no-sudo", "--auto-revoke", "--no-fix-sshd", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want scheduling/rollback failure\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if mustExternalUserExists(t, name) {
		t.Fatal("account helper did not remove the failed invite account")
	}
	if mailCalls < 2 || postDeleteCalls != 1 {
		t.Fatalf("mail cleanup calls=%d post-delete=%d, want at least one bound-identity sweep and one post-account sweep", mailCalls, postDeleteCalls)
	}
	if present, err := a.Registry.Contains(name); err != nil || !present {
		t.Fatalf("registry witness was removed after final mail cleanup failed: present=%v err=%v", present, err)
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), wantErr.Error()) ||
		!strings.Contains(a.Err.(*bytes.Buffer).String(), "account artifact cleanup is unconfirmed; keeping registry record") {
		t.Fatalf("rollback did not report retained artifact witness:\n%s", a.Err.(*bytes.Buffer).String())
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

func TestRevokeKeepsDisabledAccountWhenProcessesCannotBeCleared(t *testing.T) {
	a, _, _, _ := inviteApp(t)
	tracker := newTrackingSched()
	a.Scheduler.Sys = tracker
	const name = "xxvcc-procfail1"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)

	if rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "24", "--no-sudo", "--no-fix-sshd", "--auto-revoke", "--yes"}); rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	a.TerminateProcesses = func(int) error { return errors.New("injected survivor") }

	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes"}); rc != 1 {
		t.Fatalf("revoke rc=%d, want failure when process termination is uncertain", rc)
	}
	if !mustExternalUserExists(t, name) {
		t.Fatal("revoke freed the UID despite an unresolved process")
	}
	if expires := passwdExpiryField(t, name); expires == "" {
		t.Error("retained account was not disabled with an expiry in the past")
	}
	if present, err := a.Registry.Contains(name); err != nil || !present {
		t.Errorf("recovery registry row missing: present=%v err=%v", present, err)
	}
	if len(tracker.jobs) == 0 {
		t.Error("auto-delete retry was removed despite incomplete process termination")
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), "injected survivor") {
		t.Errorf("termination failure was not reported: %s", a.Err.(*bytes.Buffer).String())
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

// TestInvitePermanentWhenNoAutoRevoke pins the "no auto-delete = permanent"
// semantics: the safety-drain expiry is cleared, no auto-delete task is created,
// and the bundle says permanent. Previously even a --no-auto-revoke account got a
// lasting chage login-expiry; now it is genuinely permanent.
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
	// chage -E -1 represents never-expire as an empty shadow expiry field.
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
