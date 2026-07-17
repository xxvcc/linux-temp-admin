//go:build integration

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

// uninstallApp wires an App whose every destructive path points at a temp dir.
//
// This is not tidiness. The teardown removes two directories RECURSIVELY and
// deletes accounts, and CI runs this suite as root on every push: an App that
// read config.StateDir here would delete the real /var/lib/linux-temp-admin —
// on the runner, and on the machine of whoever ran `go test -tags integration`.
// Every field below that names a path is the reason the corresponding constant
// is not read directly in uninstall.go.
func uninstallApp(t *testing.T, in string, users ...string) (*App, *strings.Builder, *strings.Builder) {
	t.Helper()
	a, _, _ := newManageApp(t, in, users...)

	root := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a.StateDir = mk("state", 0o700)
	a.AuditLogDir = mk("auditlog", 0o700)
	binDir := mk("sbin", 0o755)
	a.InstallPath = filepath.Join(binDir, "linux-temp-admin")
	if err := os.WriteFile(a.InstallPath, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(a.InstallPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	a.Selfmanage = selfmanage.New(a.InstallPath, 0)
	a.SSHD = nil // no sshd is touched by these tests
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: mk("systemd", 0o755), InstallPath: a.InstallPath,
		UnitPrefix: config.AutoRevokeUnitPrefix, LegacyUnitPrefixes: []string{config.V1AutoRevokeUnitPrefix},
		Now: a.Now, Sys: fakeSys{}, UnderUnit: func(string) bool { return false },
	}
	// Re-point the registry inside the state dir, so removing the state dir is the
	// same act it is in production.
	var out, errb strings.Builder
	a.Out, a.Err = &out, &errb
	return a, &out, &errb
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTeardownNeverReadsTheRealPaths is the guard for every other test in this
// file. If uninstall.go ever reaches for config.StateDir/config.AuditLogDir
// again instead of the App's fields, this suite starts deleting the real
// directories as root, and the first thing anyone would notice is their own box.
func TestTeardownNeverReadsTheRealPaths(t *testing.T) {
	a, _, _ := uninstallApp(t, "")
	for _, real := range []string{config.StateDir, config.AuditLogDir, config.InstallPath} {
		if a.StateDir == real || a.AuditLogDir == real || a.InstallPath == real {
			t.Fatalf("a test App is pointed at the real %s", real)
		}
	}
	plan := a.teardownPlan(false)
	if plan.stateDir != a.StateDir {
		t.Errorf("plan.stateDir = %q, want the injected %q", plan.stateDir, a.StateDir)
	}
	if !strings.HasPrefix(plan.auditPath, a.AuditLogDir) {
		t.Errorf("plan.auditPath = %q, want it under the injected %q", plan.auditPath, a.AuditLogDir)
	}
	if plan.binaryPath != a.InstallPath {
		t.Errorf("plan.binaryPath = %q, want the injected %q", plan.binaryPath, a.InstallPath)
	}
}

// TestInventoryUnionsEveryWitness: the registry is a file, and every way it goes
// wrong drops accounts silently rather than announcing them. So an account named
// by ANY witness has to appear — especially one named only by its sudo grant,
// which is the witness an account cannot drop without dropping the root it is
// keeping.
func TestInventoryUnionsEveryWitness(t *testing.T) {
	a, _, _ := uninstallApp(t, "", "ltainv-registry")

	// Named only by a sudo grant: nothing else on the host knows it exists.
	mustWrite(t, a.Sudoers.FilePath("ltainv-sudoonly"), "ltainv-sudoonly ALL=(ALL) NOPASSWD:ALL\n")
	// Named only by a v2 auto-delete unit.
	mustWrite(t, filepath.Join(a.Scheduler.SystemdDir, config.AutoRevokeUnitPrefix+"ltainv-unitonly.timer"), "[Timer]\n")
	// Named only by a V1 unit — no "-v2-" infix, invisible to the v2 glob.
	mustWrite(t, filepath.Join(a.Scheduler.SystemdDir, config.V1AutoRevokeUnitPrefix+"ltainv-v1unit.timer"), "[Timer]\n")
	// Named only by v1's registry, whose format is tab-separated, username first.
	mustWrite(t, filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile)),
		"ltainv-v1row\t2020-01-01\tsomething\n\n#comment\n")

	plan := a.teardownPlan(false)
	got := map[string]bool{}
	for _, acc := range plan.accounts {
		got[acc.name] = true
	}
	for _, want := range []string{
		"ltainv-registry", "ltainv-sudoonly", "ltainv-unitonly", "ltainv-v1unit", "ltainv-v1row",
	} {
		if !got[want] {
			t.Errorf("inventory missed %q; it found %v", want, plan.names())
		}
	}
}

// TestInventoryIgnoresTheGECOSMarker pins the one signal deliberately left out.
// The marker is writable by anything with sudo — which every --sudo invitee has —
// so `usermod -c 'linux-temp-admin temporary admin' realadmin` would otherwise
// enlist a real administrator's account, and their home directory, into a
// teardown. root is the stand-in here for "an account this tool did not create";
// nothing deletes it, the inventory is a read.
func TestInventoryIgnoresTheGECOSMarker(t *testing.T) {
	a, _, _ := uninstallApp(t, "")
	plan := a.teardownPlan(false)
	for _, acc := range plan.accounts {
		if acc.name == "root" {
			t.Fatal("the inventory enlisted an account no tool-owned file names")
		}
	}
	if len(plan.accounts) != 0 {
		t.Errorf("nothing names an account here; got %v", plan.names())
	}
}

// TestUninstallRefusesWhenTheInventoryIsBlind: an inventory that under-reports is
// how a teardown removes the binary and strands the accounts it never saw, so a
// witness that could not be READ must stop the whole thing while that is still
// actionable. A missing registry is not this — no rows is the truth on a host
// that never made an account.
func TestUninstallRefusesWhenTheInventoryIsBlind(t *testing.T) {
	a, _, errb := uninstallApp(t, "")
	// A symlinked registry is what Store.readAll refuses to read.
	if err := os.Remove(a.Registry.File); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", a.Registry.File); err != nil {
		t.Fatal(err)
	}
	if rc := a.uninstall([]string{"--yes"}); rc != 1 {
		t.Errorf("rc=%d, want 1 when the inventory cannot be read", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("the binary was removed on a blind inventory")
	}
	if !strings.Contains(errb.String(), "refusing to uninstall") {
		t.Errorf("want a refusal naming the reason; got %q", errb.String())
	}
}

// TestUninstallWithAccountsRefusesNonInteractivelyWithoutTheFlag mirrors
// --fix-sshd: the irreversible thing never happens implicitly in a run nobody is
// watching, and the flag is what says it out loud.
func TestUninstallWithAccountsRefusesNonInteractivelyWithoutTheFlag(t *testing.T) {
	a, _, errb := uninstallApp(t, "", "ltaflag-a1")
	if rc := a.uninstall([]string{"--yes"}); rc != 1 {
		t.Errorf("rc=%d, want 1", rc)
	}
	if !strings.Contains(errb.String(), "--remove-users") {
		t.Errorf("the refusal must name the flag that unblocks it; got %q", errb.String())
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("the binary was removed despite the refusal")
	}
	if got := regUsers(t, a); len(got) != 1 {
		t.Errorf("nothing should have been touched; rows now %v", got)
	}
}

// TestUninstallRemovesEverythingItNamed is the happy path, end to end.
func TestUninstallRemovesEverythingItNamed(t *testing.T) {
	a, out, _ := uninstallApp(t, "", "ltafull-a1")
	mustWrite(t, a.Sudoers.FilePath("ltafull-a1"), "ltafull-a1 ALL=(ALL) NOPASSWD:ALL\n")
	unit := filepath.Join(a.Scheduler.SystemdDir, config.AutoRevokeUnitPrefix+"ltafull-a1.timer")
	mustWrite(t, unit, "[Timer]\n")

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 0 {
		t.Fatalf("rc=%d, want 0 (stdout: %s)", rc, out.String())
	}
	for _, p := range []string{a.InstallPath, a.StateDir, a.Sudoers.FilePath("ltafull-a1"), unit} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the uninstall", p)
		}
	}
}

// TestUninstallKeepsTheAuditLogUnlessAskedTwice: the log records who opened and
// closed root-capable accounts. An uninstall that erased it by default would be
// doing, on its way out, exactly what someone covering their tracks would do.
func TestUninstallKeepsTheAuditLogUnlessAskedTwice(t *testing.T) {
	logPath := func(a *App) string { return filepath.Join(a.AuditLogDir, "audit.log") }

	a, _, _ := uninstallApp(t, "")
	mustWrite(t, logPath(a), `{"action":"account.delete"}`+"\n")
	if rc := a.uninstall([]string{"--yes"}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if _, err := os.Stat(logPath(a)); err != nil {
		t.Error("the audit log was removed without --purge-audit")
	}

	b, _, _ := uninstallApp(t, "")
	mustWrite(t, logPath(b), `{"action":"account.delete"}`+"\n")
	if rc := b.uninstall([]string{"--yes", "--purge-audit"}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if _, err := os.Stat(b.AuditLogDir); !os.IsNotExist(err) {
		t.Error("--purge-audit left the audit log behind")
	}
}

// TestUninstallKeepsTheBinaryWhenAnAccountSurvives is the invariant the whole
// design rests on: never remove the binary while a managed account it could not
// remove is still there. Leaving a sudo-capable account behind while deleting the
// only thing that manages it is worse than not uninstalling — its auto-delete
// task's ExecStart IS that binary, so removing it means the account never expires.
//
// The survivor is manufactured the way the tool itself would refuse one: a real
// account whose recorded UID contradicts its current one is not provably the
// account this tool made, so revoke declines it. That is a genuine refusal
// through the real gate, not a stub.
func TestUninstallKeepsTheBinaryWhenAnAccountSurvives(t *testing.T) {
	const name = "ltasurvive1"
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	newRealAccount(t, a, name)

	// Rewrite the row so the recorded UID no longer matches: revoke will refuse.
	pw, _ := user.Lookup(name)
	if err := a.Registry.Record(registry.Record{
		User: name, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
		Host: "203.0.113.5", Port: 22, UID: pw.UID + 4242,
	}); err != nil {
		t.Fatal(err)
	}

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Errorf("rc=%d, want 1 when an account survives", rc)
	}
	if !user.Exists(name) {
		t.Fatal("the survivor was deleted; this test proves nothing")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("THE BINARY WAS REMOVED while a managed account survived — its auto-delete task can now never run")
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Error("the state directory was removed while an account survived: its row is the only record of what it was")
	}
	if !strings.Contains(errb.String(), name) {
		t.Errorf("the operator must be told which account blocked the uninstall; got %q", errb.String())
	}
}

// TestUninstallRefusesFromTheAccountItWouldDelete: a temp admin has sudo, so it
// can run this. Deleting its own account mid-teardown reaps the sudo front-end
// relaying the signals and leaves the box half dismantled with nobody able to log
// in and finish. This is an interlock for the honest operator, not a security
// boundary — `sudo su -` drops SUDO_USER and walks past it — and the code says so.
func TestUninstallRefusesFromTheAccountItWouldDelete(t *testing.T) {
	const name = "ltaself1"
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	newRealAccount(t, a, name)
	t.Setenv("SUDO_USER", name)

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Errorf("rc=%d, want 1", rc)
	}
	if !user.Exists(name) {
		t.Error("the uninstall deleted the account running it")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("the binary was removed despite the refusal")
	}
	if !strings.Contains(errb.String(), name) {
		t.Errorf("the refusal must name the account; got %q", errb.String())
	}
}
