//go:build integration

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
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
	plan := a.teardownPlan(false, false)
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

	plan := a.teardownPlan(false, false)
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
	const name = "ltagecos1"
	a, _, _ := uninstallApp(t, "")
	a.Users = user.New()

	// A REAL account carrying the managed marker and nothing else — no registry
	// row, no sudo grant, no unit. This is what `usermod -c 'linux-temp-admin
	// temporary admin' realadmin` produces, and the whole point is that the marker
	// must not be enough to enlist it. An empty inventory would pass this test
	// whether or not the marker were trusted, so the account has to exist for the
	// assertion to mean anything.
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", "linux-temp-admin temporary admin", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	if !user.IsManaged(name) {
		t.Fatalf("%s should carry the managed marker; the fixture is wrong", name)
	}

	plan := a.teardownPlan(false, false)
	for _, acc := range plan.accounts {
		if acc.name == name {
			t.Fatal("the GECOS marker enlisted an account no tool-owned FILE names — a real admin could be deleted by writing that marker to their own account")
		}
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

// TestUninstallRemovesAWitnessOnlyAccount is the case the whole "union of
// witnesses" idea exists for, and the one revoke's own guard turns away. An
// account can be real and live yet have no registry row — the row was lost, or it
// is a v1 account, or only its sudo grant still names it. teardown must delete it.
//
// Bare `revoke --user X --yes` REFUSES an unregistered account ("use --force"),
// so a teardown that reuses revoke without --force strands exactly the account
// the inventory worked hardest to find, and the uninstall can then never complete
// (the survivor blocks the binary, correctly, forever).
func TestUninstallRemovesAWitnessOnlyAccount(t *testing.T) {
	const name = "ltawitness1"
	a, _, _ := uninstallApp(t, "")
	a.Users = user.New()

	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", "linux-temp-admin temporary admin", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	// No registry row. The account exists only because a sudo grant names it — the
	// witness an account cannot drop without dropping the root it is keeping.
	mustWrite(t, a.Sudoers.FilePath(name), name+" ALL=(ALL) NOPASSWD:ALL\n")

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 0 {
		t.Fatalf("rc=%d, want 0: a witness-only account must be removable, not a permanent blocker", rc)
	}
	if user.Exists(name) {
		t.Error("the witness-only account survived the uninstall")
	}
	if _, err := os.Stat(a.Sudoers.FilePath(name)); !os.IsNotExist(err) {
		t.Error("its NOPASSWD grant survived")
	}
	if _, err := os.Stat(a.InstallPath); !os.IsNotExist(err) {
		t.Error("the binary should have been removed once every account was gone")
	}
}

// TestUninstallRefusesWhenV1RegistryIsUnreadable pins the fix for the one witness
// that had no error channel. A v1 registry that exists but cannot be read must
// refuse the uninstall, exactly as an unreadable v2 registry does — it is the
// only record of a v1 account made without a sudo grant, so collapsing "can't
// read it" into "no v1 accounts" is how such an account gets stranded.
func TestUninstallRefusesWhenV1RegistryIsUnreadable(t *testing.T) {
	a, _, errb := uninstallApp(t, "")
	// A directory where the file is expected: os.Open succeeds, the read fails.
	v1 := filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile))
	if err := os.MkdirAll(v1, 0o700); err != nil {
		t.Fatal(err)
	}
	if rc := a.uninstall([]string{"--yes"}); rc != 1 {
		t.Errorf("rc=%d, want 1 when the v1 registry cannot be read", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("the binary was removed despite an unreadable v1 registry")
	}
	if !strings.Contains(errb.String(), "refusing to uninstall") {
		t.Errorf("want a refusal; got %q", errb.String())
	}
}

// TestUninstallBlocksOnAnUnremovableGrant is HIGH #2. The survivor check used to
// key only on user.Exists, but sudoers.Remove documents that it reports failure
// precisely so the teardown won't call itself done while a NOPASSWD:ALL file it
// could not delete remains. A grant that survives (here: a non-empty directory at
// the grant path, which os.Remove cannot unlink even as root) must block the
// binary removal, because it re-arms root the instant its username is reused.
func TestUninstallBlocksOnAnUnremovableGrant(t *testing.T) {
	const name = "ltawedge1"
	a, _, _ := uninstallApp(t, "")
	a.Users = user.New()
	newRealAccount(t, a, name) // registers it with the real UID, so revoke deletes it cleanly
	// Wedge its grant path with a non-empty directory: revoke deletes the
	// account, its grant removal fails, and the account is gone — so a user.Exists
	// check sees no survivor while the grant is still on disk.
	grant := a.Sudoers.FilePath(name)
	if err := os.MkdirAll(filepath.Join(grant, "keep"), 0o700); err != nil {
		t.Fatal(err)
	}

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Errorf("rc=%d, want 1 when a grant could not be removed", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("HIGH: the binary was removed while a NOPASSWD grant survived")
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Error("the state dir was removed while a grant survived")
	}
}

// TestUninstallReInventoriesBeforeRemovingTheBinary is HIGH #3. The plan is a
// point-in-time snapshot; an account (or grant) appearing between the plan and
// the teardown must still block the binary. Here the plan is empty but a live
// managed account with a grant is present when teardown runs — a fresh
// re-inventory must catch it, or the binary would come off over a live account
// whose auto-revoke task points at it.
func TestUninstallReInventoriesBeforeRemovingTheBinary(t *testing.T) {
	const name = "ltatoctou1"
	a, _, _ := uninstallApp(t, "")
	a.Users = user.New()
	newRealAccount(t, a, name)
	mustWrite(t, a.Sudoers.FilePath(name), name+" ALL=(ALL) NOPASSWD:ALL\n")

	// An empty plan — as if the account was created after the plan was built.
	if rc := a.teardown(teardownPlan{stateDir: a.StateDir, binaryPath: a.InstallPath}, false, false); rc != 1 {
		t.Errorf("rc=%d, want 1: a re-inventory must catch an account the plan missed", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("HIGH: binary removed over an account the point-in-time plan did not list")
	}
}

// TestUninstallRefusesEarlyOnAnUnremovableBinary is HIGH #4. binaryBlocker was
// computed to be discovered "now rather than in the last step after everything
// else is already destroyed", but it was only ever printed as a warning — nothing
// refused on it. A symlinked install path (ordinary on versioned/Nix layouts)
// without --force would let the teardown delete every account and the state dir,
// then fail at the very last step with nothing left to do but --force, which is
// the footgun the redesign removes. The blocker must refuse BEFORE any teardown.
func TestUninstallRefusesEarlyOnAnUnremovableBinary(t *testing.T) {
	const name = "ltablocker1"
	a, _, _ := uninstallApp(t, "")
	a.Users = user.New()
	newRealAccount(t, a, name)
	mustWrite(t, a.Sudoers.FilePath(name), name+" ALL=(ALL) NOPASSWD:ALL\n")

	// Replace the install path with a symlink: RootSafeFile refuses it, so it is
	// unremovable without --force.
	if err := os.Remove(a.InstallPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/true", a.InstallPath); err != nil {
		t.Fatal(err)
	}

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Errorf("rc=%d, want 1 (refuse early on an unremovable binary)", rc)
	}
	if !user.Exists(name) {
		t.Error("HIGH: the account was deleted before the binary refusal — the teardown ran anyway")
	}
	if _, err := os.Lstat(a.InstallPath); err != nil {
		t.Error("the symlink was removed despite no --force")
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Error("the state dir was removed before the binary refusal")
	}
}

// TestCompactSweepsOrphanedUnits is HIGH #5. Scheduler.Orphans mirrors the
// sudoers/sshd sweeps, but until now nothing called it: doctor reported an
// orphaned auto-revoke unit as clean and cleanup-expired --compact never removed
// it, so a unit whose account is gone fired forever against the installed binary
// (and against a removed binary after an uninstall). compact must now sweep it.
func TestCompactSweepsOrphanedUnits(t *testing.T) {
	a, _, _ := uninstallApp(t, "")
	// An orphaned unit: a .timer for a name with no account and no registry row.
	unit := filepath.Join(a.Scheduler.SystemdDir, config.AutoRevokeUnitPrefix+"ltaorphanunit.timer")
	mustWrite(t, unit, "[Timer]\n")

	a.compact()

	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Error("HIGH: compact did not sweep an orphaned auto-revoke unit")
	}
	// doctor must also surface it before the sweep — build a fresh one with the
	// orphan present again.
	b, _, errb := uninstallApp(t, "")
	mustWrite(t, filepath.Join(b.Scheduler.SystemdDir, config.AutoRevokeUnitPrefix+"ltaorphanunit2.timer"), "[Timer]\n")
	if rc := b.doctor(nil); rc != 1 {
		t.Errorf("doctor rc=%d, want 1 with an orphaned unit present", rc)
	}
	if !strings.Contains(errb.String(), "orphaned auto-delete task") {
		t.Errorf("doctor did not report the orphaned unit: %q", errb.String())
	}
}

// TestCompactSweepsAGrantWhoseNameARealAccountReused is the MEDIUM name-reuse
// detection gap. The orphan sweeps used a bare user.Exists, so a managed grant
// whose temp account is gone but whose NAME a real, unmanaged account later took
// was reported by nobody: exists=true made it "not an orphan", while the
// name-keyed drop-in silently handed OUR passwordless root to that real account.
// The predicate is now "a live account WE manage", so a name taken over by an
// account that is not ours makes the grant an orphan again.
func TestCompactSweepsAGrantWhoseNameARealAccountReused(t *testing.T) {
	const name = "xxvcc-reuse09"
	a, _, _ := uninstallApp(t, "")
	a.Users = user.New()
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	// A REAL, unmanaged account that happens to carry a temp-shaped name — no
	// managed GECOS, no registry row vouching for it.
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", "Real Person", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	grant := a.Sudoers.FilePath(name)
	mustWrite(t, grant, name+" ALL=(ALL) NOPASSWD:ALL\n")

	a.compact()

	if _, err := os.Stat(grant); err == nil {
		t.Error("MEDIUM: a grant whose name a real account reused was left on disk (invisible orphan)")
	}
	if !user.Exists(name) {
		t.Error("compact must strip the grant but never delete the real account")
	}
}

// TestDoctorReportsAnAutoDeleteAccountWithNoTaskLeft covers the MEDIUM tidiness
// gap: an account that asked to auto-delete, still exists, and whose unit was
// removed out of band will never be deleted (chage still blocks its login at
// expiry, so this is tidiness, not a live-access hole). doctor now surfaces it.
func TestDoctorReportsAnAutoDeleteAccountWithNoTaskLeft(t *testing.T) {
	const name = "ltanotask1"
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	newRealAccount(t, a, name) // registers with the real UID
	// Mark the row auto-revoke, but write NO unit for it.
	rec, _, _ := a.Registry.Lookup(name)
	rec.AutoRevoke = true
	rec.AutoUnit = ""
	if err := a.Registry.Record(rec); err != nil {
		t.Fatal(err)
	}

	if rc := a.doctor(nil); rc != 1 {
		t.Errorf("doctor rc=%d, want 1", rc)
	}
	if !strings.Contains(errb.String(), "no task left") {
		t.Errorf("doctor did not surface the taskless auto-delete account: %q", errb.String())
	}
}

// TestDoctorShowsVersions covers the version lines doctor prints: the running
// process's version always, and the installed command's version (the one the
// auto-revoke timer runs) with a mismatch flagged. The installed binary is a stub
// that echoes whatever version the test wants, so all four states are exercised.
func TestDoctorShowsVersions(t *testing.T) {
	writeStub := func(t *testing.T, path, version string) {
		t.Helper()
		if version == "" { // an absent install
			_ = os.Remove(path)
			return
		}
		body := "#!/bin/sh\n[ \"$1\" = version ] && echo " + version + "\n"
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("running version is always shown", func(t *testing.T) {
		a, out, _ := uninstallApp(t, "")
		writeStub(t, a.InstallPath, "9.9.9")
		a.doctor(nil)
		if !strings.Contains(out.String(), "running version:") {
			t.Errorf("doctor did not print the running version: %q", out.String())
		}
	})

	t.Run("installed version matching is a success line", func(t *testing.T) {
		a, out, _ := uninstallApp(t, "")
		writeStub(t, a.InstallPath, buildinfoVersion())
		a.doctor(nil)
		if !strings.Contains(out.String(), "installed command version: "+buildinfoVersion()) {
			t.Errorf("doctor did not report the matching installed version: %q", out.String())
		}
	})

	t.Run("installed version mismatch is warned", func(t *testing.T) {
		a, _, errb := uninstallApp(t, "")
		writeStub(t, a.InstallPath, "0.0.1-stale")
		a.doctor(nil)
		if !strings.Contains(errb.String(), "differs from the running") {
			t.Errorf("doctor did not flag the version mismatch: %q", errb.String())
		}
	})

	t.Run("no installed command is warned", func(t *testing.T) {
		a, _, errb := uninstallApp(t, "")
		writeStub(t, a.InstallPath, "") // remove it
		a.doctor(nil)
		if !strings.Contains(errb.String(), "not installed") {
			t.Errorf("doctor did not report the missing installed command: %q", errb.String())
		}
	})
}

func buildinfoVersion() string { return buildinfo.Version }

// TestUninstallCompletesWithAStaleV1RegistryRow is the regression the re-inventory
// introduced. A v1-upgraded host has /var/lib/linux-temp-admin/users.tsv naming an
// account whose system account is long gone — a leftover row. teardownPlan lists
// it (witnessV1), and the post-revoke re-inventory listed it again and blocked on
// len(residual.accounts)>0 forever: the v1 row is never pruned by revoke, and
// removeStateDir (which would delete users.tsv) runs AFTER the gate. A bare
// registry row for a non-existent account carries no privilege — no grant, no
// exception, no unit, no process — so it must not block the binary.
func TestUninstallCompletesWithAStaleV1RegistryRow(t *testing.T) {
	a, _, _ := uninstallApp(t, "")
	// A v1 users.tsv row for an account that does not exist. Nothing else names it.
	mustWrite(t, filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile)),
		"ltav1ghost\t2020-01-01\tsomething\n")

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 0 {
		t.Fatalf("rc=%d, want 0: a stale v1 registry row must not block the uninstall", rc)
	}
	if _, err := os.Lstat(a.InstallPath); !os.IsNotExist(err) {
		t.Error("the binary should have been removed")
	}
	if _, err := os.Lstat(a.StateDir); !os.IsNotExist(err) {
		t.Error("the state dir (with the stale v1 row) should have been removed")
	}
}
