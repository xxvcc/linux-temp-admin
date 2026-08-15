//go:build integration

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/lifecycle"
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
	a.ListMarkerAccounts = user.LifecycleMarkerAccounts

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
		SystemdDir: mk("systemd", 0o755), SystemdTimerStateDir: mk("systemd-timer-state", 0o755), InstallPath: a.InstallPath,
		UnitPrefix: config.AutoRevokeUnitPrefix, LegacyUnitPrefixes: []string{config.V1AutoRevokeUnitPrefix},
		Now: a.Now, Sys: fakeUninstallSystem{},
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

type failingCancelSystem struct{ fakeSys }

func (failingCancelSystem) RemoveAtJobsFor(string) error {
	return errors.New("injected schedule cleanup failure")
}

// uninstallApp gives every systemd path a private temporary directory and every
// systemctl operation a no-op implementation. Report systemctl as available so
// Cancel can prove the fake timer stopped before deleting its files, matching the
// production safety contract without ever contacting the host's PID 1.
type fakeUninstallSystem struct{ fakeSys }

func (fakeUninstallSystem) HasSystemctl() bool { return true }

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

func TestTeardownRemovesLegacyPersistentTimerStamps(t *testing.T) {
	a, _, _ := uninstallApp(t, "")
	managed := filepath.Join(a.Scheduler.SystemdTimerStateDir,
		"stamp-"+config.AutoRevokeUnitPrefix+"oldgone.timer")
	legacy := filepath.Join(a.Scheduler.SystemdTimerStateDir,
		"stamp-"+config.V1AutoRevokeUnitPrefix+"oldergone.timer")
	unrelated := filepath.Join(a.Scheduler.SystemdTimerStateDir, "stamp-apt-daily.timer")
	for _, path := range []string{managed, legacy, unrelated} {
		mustWrite(t, path, "")
	}

	plan := a.teardownPlan(false, false)
	if rc := a.teardown(plan, uninstallOptions{}); rc != 0 {
		t.Fatal("teardown failed while removing legacy timer timestamps")
	}
	for _, path := range []string{managed, legacy} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("managed timer timestamp survived uninstall: %s", path)
		}
	}
	if _, err := os.Lstat(unrelated); err != nil {
		t.Fatalf("unrelated systemd timer timestamp was removed: %v", err)
	}
}

func TestTeardownKeepsCommandAndStateWhenTimerStampCleanupFails(t *testing.T) {
	a, _, _ := uninstallApp(t, "")
	blocked := filepath.Join(a.Scheduler.SystemdTimerStateDir,
		"stamp-"+config.AutoRevokeUnitPrefix+"blocked.timer")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}

	plan := a.teardownPlan(false, false)
	if rc := a.teardown(plan, uninstallOptions{}); rc != 1 {
		t.Fatalf("teardown rc=%d, want timer timestamp cleanup failure", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatal("binary was removed after timer timestamp cleanup failed")
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatal("state was removed after timer timestamp cleanup failed")
	}
}

func TestTeardownStopsWhenRevokeFailsWithoutDiskResidue(t *testing.T) {
	a, _, _ := uninstallApp(t, "", "ltafailedrevoke1")
	a.Scheduler.Sys = failingCancelSystem{}
	plan := a.teardownPlan(false, false)

	if rc := a.teardown(plan, uninstallOptions{}); rc != 1 {
		t.Fatalf("teardown rc=%d, want failure after revoke failed", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatal("binary was removed after a failed revoke with no disk artifact")
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatal("state was removed after a failed revoke")
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

// TestInventoryTreatsTheGECOSMarkerAsBlockOnly pins both sides of the weak
// witness contract. A current permanent invite can have no sudo grant, sshd
// exception, or auto-revoke task, so a lost registry must not make it invisible
// and let uninstall strand it. But the user-writable marker can never authorize
// deletion without a completed generation-bound registry identity.
func TestInventoryTreatsTheGECOSMarkerAsBlockOnly(t *testing.T) {
	const (
		name       = "ltagecos1"
		generation = "0123456789abcdef0123456789abcdef"
	)
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()

	// A live account carrying the current managed marker and nothing else: exactly
	// the footprint of --no-sudo --no-auto-revoke after its registry row is lost.
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGenerationGECOSPrefix+generation, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	if !mustUserManaged(t, name) {
		t.Fatalf("%s should carry the managed marker; the fixture is wrong", name)
	}

	plan := a.teardownPlan(false, true)
	found := false
	for _, acc := range plan.accounts {
		if acc.name == name {
			found = true
			if !acc.exists || len(acc.witnesses) != 1 || acc.witnesses[0] != witnessMarker {
				t.Fatalf("marker-only account inventory = %+v, want one live block-only witness", acc)
			}
		}
	}
	if !found {
		t.Fatal("the GECOS marker did not block uninstall after the registry and all privilege/task artifacts were lost")
	}

	if rc := a.uninstall([]string{"--yes", "--remove-users", "--force"}); rc != 1 {
		t.Fatalf("uninstall rc=%d, want marker-only identity refusal", rc)
	}
	if !mustUserExists(t, name) {
		t.Fatal("a block-only GECOS marker authorized account deletion")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatal("the command was removed while a marker-only permanent account remained")
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatal("state was removed while a marker-only permanent account remained")
	}
	if !strings.Contains(errb.String(), "without a current generation-bound identity record") {
		t.Fatalf("marker-only refusal did not explain the missing identity record: %q", errb.String())
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
	if strings.Contains(errb.String(), "their auto-delete tasks") || !strings.Contains(errb.String(), "any auto-delete tasks already scheduled") {
		t.Errorf("the refusal must cover permanent accounts without claiming every account has a task; got %q", errb.String())
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

	result := a.uninstallResult([]string{"--yes", "--remove-users"})
	if result.status != 0 || !result.applied {
		t.Fatalf("result=%+v, want a successful applied uninstall (stdout: %s)", result, out.String())
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

func TestPurgeAuditFailureIsNonzeroAndKeepsLogger(t *testing.T) {
	a, _, errb := uninstallApp(t, "")
	logPath := filepath.Join(a.AuditLogDir, "audit.log")
	a.Audit = &audit.Logger{
		Dir: a.AuditLogDir, File: logPath, Now: a.Now,
		Actor: func() (string, int) { return "integration", 0 },
	}
	logger := a.Audit
	wantErr := errors.New("injected audit purge failure")
	a.RemoveAll = func(path string) error {
		if path == a.AuditLogDir {
			return wantErr
		}
		return os.RemoveAll(path)
	}

	if rc := a.uninstall([]string{"--yes", "--purge-audit"}); rc != 1 {
		t.Fatalf("rc=%d, want 1 when audit purge fails", rc)
	}
	if a.Audit != logger {
		t.Fatal("audit logger was disabled after a failed purge")
	}
	if _, err := os.Lstat(a.InstallPath); !os.IsNotExist(err) {
		t.Fatalf("binary should already be removed when purge fails: %v", err)
	}
	if !strings.Contains(errb.String(), wantErr.Error()) {
		t.Fatalf("purge failure was not reported: %q", errb.String())
	}
	b, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(b), "audit purge failed") {
		t.Fatalf("live logger did not retain the purge failure: err=%v log=%q", err, b)
	}
}

func TestStateCleanupFailureIsNonzeroAndKeepsBinary(t *testing.T) {
	a, _, errb := uninstallApp(t, "")
	a.Lifecycle = lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	logPath := filepath.Join(a.AuditLogDir, "audit.log")
	a.Audit = &audit.Logger{
		Dir: a.AuditLogDir, File: logPath, Now: a.Now,
		Actor: func() (string, int) { return "integration", 0 },
	}
	wantErr := errors.New("injected state cleanup failure")
	a.RemoveAll = func(path string) error {
		if path == a.StateDir {
			return wantErr
		}
		return os.RemoveAll(path)
	}

	if rc := a.uninstall([]string{"--yes"}); rc != 1 {
		t.Fatalf("rc=%d, want 1 when state cleanup is incomplete", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatalf("binary must remain available to retry state cleanup: %v", err)
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatalf("failed state directory should remain for manual recovery: %v", err)
	}
	if stopped, err := a.Lifecycle.IsUninstalled(); err != nil || !stopped {
		t.Fatalf("state cleanup failure did not leave the fail-closed uninstall marker: stopped=%v err=%v", stopped, err)
	}
	if !strings.Contains(errb.String(), wantErr.Error()) {
		t.Fatalf("state cleanup failure was not reported: %q", errb.String())
	}
	b, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(b), `"result":"fail"`) || !strings.Contains(string(b), "state directory cleanup failed") {
		t.Fatalf("audit did not record the partial uninstall as failure: err=%v log=%q", err, b)
	}
}

func TestUninstallRefusesIfInventoryChangesAfterConfirmation(t *testing.T) {
	a, _, errb := uninstallApp(t, "")
	lock := lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	release, err := lock.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	a.Lifecycle = lock
	shown := newNotifyingBuffer("The uninstall will remove")
	a.Out = shown
	done := make(chan int, 1)
	go func() { done <- a.uninstall([]string{"--yes"}) }()
	select {
	case <-shown.seen:
	case <-time.After(2 * time.Second):
		_ = release()
		t.Fatal("uninstall did not show its pre-lock inventory")
	}

	const name = "ltaplanchange1"
	mustWrite(t, a.Sudoers.FilePath(name), name+" ALL=(ALL) NOPASSWD:ALL\n")
	if err := release(); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 1 {
			t.Fatalf("uninstall rc=%d, want changed-inventory refusal", rc)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("uninstall did not finish after the lifecycle lock was released")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatalf("binary changed after inventory mismatch: %v", err)
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatalf("state changed after inventory mismatch: %v", err)
	}
	if _, err := os.Stat(a.Sudoers.FilePath(name)); err != nil {
		t.Fatalf("new witness was touched despite inventory mismatch: %v", err)
	}
	if !strings.Contains(errb.String(), "inventory changed after confirmation") {
		t.Fatalf("inventory mismatch was not explained: %q", errb.String())
	}
}

// TestUninstallKeepsTheBinaryWhenAnAccountSurvives is the invariant the whole
// design rests on: never remove the binary while a managed account it could not
// remove is still there. Leaving a sudo-capable account behind while deleting the
// only thing that can revoke it or clean its grants is worse than not uninstalling;
// if an auto-delete task exists, its ExecStart also names that binary.
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
	pw, _ := mustUserLookup(t, name)
	if err := a.Registry.Record(registry.Record{
		User: name, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
		Host: "203.0.113.5", Port: 22, UID: pw.UID + 4242,
	}); err != nil {
		t.Fatal(err)
	}

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Errorf("rc=%d, want 1 when an account survives", rc)
	}
	if !mustUserExists(t, name) {
		t.Fatal("the survivor was deleted; this test proves nothing")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("THE BINARY WAS REMOVED while a managed account survived, so it can no longer be revoked or have its grants cleaned")
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
	if !mustUserExists(t, name) {
		t.Error("the uninstall deleted the account running it")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("the binary was removed despite the refusal")
	}
	if !strings.Contains(errb.String(), name) {
		t.Errorf("the refusal must name the account; got %q", errb.String())
	}
}

// TestUninstallRemovesAWitnessOnlyArtifact is the case the whole "union of
// witnesses" idea exists for: the registry row and account are gone, but a
// passwordless sudo grant still names them. The stale grant must be found and
// removed before the installed command can safely disappear.
//
// A live account with only a name-scoped artifact is deliberately a different
// case: the name may have been reused, so only a completed v2 UID record can
// authorize deleting that account (see TestUninstallDoesNotDeleteLiveAccountNamedOnlyByArtifact).
func TestUninstallRemovesAWitnessOnlyArtifact(t *testing.T) {
	const name = "ltawitness1"
	a, _, _ := uninstallApp(t, "")
	a.Users = user.New()

	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	// No registry row or account. Only the durable privilege artifact remains.
	mustWrite(t, a.Sudoers.FilePath(name), name+" ALL=(ALL) NOPASSWD:ALL\n")

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 0 {
		t.Fatalf("rc=%d, want 0: a witness-only artifact must be removable, not a permanent blocker", rc)
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

func TestUninstallRefusesMalformedV1Registry(t *testing.T) {
	a, _, errb := uninstallApp(t, "")
	v1 := filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile))
	if err := os.WriteFile(v1, []byte("not a valid username\t2026-07-24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := a.uninstall([]string{"--yes"}); rc != 1 {
		t.Errorf("rc=%d, want 1 for a malformed v1 registry", rc)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Error("the binary was removed despite a malformed v1 registry")
	}
	if !strings.Contains(errb.String(), "invalid username") {
		t.Errorf("malformed row was not reported: %q", errb.String())
	}
}

func TestV1RegistryRefusesSymlinkAndOversizedInput(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		a, _, _ := uninstallApp(t, "")
		target := filepath.Join(t.TempDir(), "registry")
		if err := os.WriteFile(target, []byte("xxvcc-a1\tdata\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile))
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := a.v1RegistryUsers(); err == nil {
			t.Fatal("symlinked v1 registry was accepted")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		a, _, _ := uninstallApp(t, "")
		path := filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(maxV1RegistryBytes + 1); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := a.v1RegistryUsers(); err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("oversized v1 registry error = %v, want bounded-read refusal", err)
		}
	})
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
	if rc := a.teardown(teardownPlan{stateDir: a.StateDir, binaryPath: a.InstallPath}, uninstallOptions{}); rc != 1 {
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
	if !mustUserExists(t, name) {
		t.Error("HIGH: the account was deleted before the binary refusal — the teardown ran anyway")
	}
	if _, err := os.Lstat(a.InstallPath); err != nil {
		t.Error("the symlink was removed despite no --force")
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Error("the state dir was removed before the binary refusal")
	}
}

func TestUninstallForceRefusesDirectoryBeforeTeardown(t *testing.T) {
	a, _, errb := uninstallApp(t, "")
	if err := os.Remove(a.InstallPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.InstallPath, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(a.InstallPath, "unrelated"), "keep\n")

	if rc := a.uninstall([]string{"--yes", "--force"}); rc != 1 {
		t.Fatalf("rc=%d, want early refusal for a directory at the install path", rc)
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatal("state directory was removed before the install-path directory refusal")
	}
	if !strings.Contains(errb.String(), "is a directory") {
		t.Fatalf("stderr did not explain the directory blocker: %q", errb.String())
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

func TestCompactRetainsRegistryWhenOrphanScanFails(t *testing.T) {
	const name = "ltacompactwitness"
	a, _, errb := uninstallApp(t, "", name)
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.Sudoers.Dir = blocked

	if rc := a.compact(); rc != 1 {
		t.Fatalf("compact rc=%d, want 1 when an orphan inventory is unreadable", rc)
	}
	if found, err := a.Registry.Contains(name); err != nil || !found {
		t.Fatalf("registry witness was compacted after a failed scan: found=%v err=%v", found, err)
	}
	if !strings.Contains(errb.String(), "registry was not compacted") {
		t.Fatalf("compact did not explain that it retained recovery evidence: %q", errb.String())
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
	// A real replacement can set its own GECOS full-name field. Without a current
	// registry identity, even an exact managed marker must not hide the stale grant.
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	grant := a.Sudoers.FilePath(name)
	mustWrite(t, grant, name+" ALL=(ALL) NOPASSWD:ALL\n")

	a.compact()

	if _, err := os.Stat(grant); err == nil {
		t.Error("MEDIUM: a grant whose name a real account reused was left on disk (invisible orphan)")
	}
	if !mustUserExists(t, name) {
		t.Error("compact must strip the grant but never delete the real account")
	}
}

func TestCompactPreservesArtifactsForLiveLegacyIdentity(t *testing.T) {
	const name = "ltalegacycompact1"
	a, out, errb := uninstallApp(t, "")
	a.Users = user.New()
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	pw, ok := mustUserLookup(t, name)
	if !ok {
		t.Fatal("legacy account was not found")
	}
	if err := a.Registry.Record(registry.Record{User: name, Host: "203.0.113.5", Port: 22, UID: pw.UID}); err != nil {
		t.Fatal(err)
	}
	grant := a.Sudoers.FilePath(name)
	mustWrite(t, grant, name+" ALL=(ALL) NOPASSWD:ALL\n")
	if rc := a.status([]string{"--user", name}); rc != 0 {
		t.Fatalf("status rc=%d", rc)
	}
	if !strings.Contains(out.String(), "managed=false identity=legacy-unverified") {
		t.Fatalf("status hid the weak legacy identity: %q", out.String())
	}
	_ = a.doctor(nil)
	if !strings.Contains(errb.String(), "legacy fixed identity marker") {
		t.Fatalf("doctor hid the weak legacy identity: %q", errb.String())
	}
	if rc := a.compact(); rc != 0 {
		t.Fatalf("compact rc=%d, want legacy account preserved", rc)
	}
	if _, err := os.Stat(grant); err != nil {
		t.Fatalf("compact removed a live legacy account's grant: %v", err)
	}
	if found, err := a.Registry.Contains(name); err != nil || !found {
		t.Fatalf("compact removed a live legacy registry row: found=%v err=%v", found, err)
	}
}

// TestDoctorReportsAnAutoDeleteAccountWithNoTaskLeft covers the MEDIUM tidiness
// gap: an account that asked to auto-delete, still exists, and whose unit was
// removed out of band will never be deleted. chage is only a later day-granular
// lockout backstop, so doctor must surface the missing exact-time task.
func TestDoctorReportsAutoDeleteAccountsWithNoTaskLeft(t *testing.T) {
	const systemdName = "ltanotask1"
	const atName = "ltanotask2"
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	for name, unit := range map[string]string{systemdName: "", atName: "at:42"} {
		newRealAccount(t, a, name) // registers with the real UID
		rec, _, err := a.Registry.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		rec.AutoRevoke = true
		rec.AutoUnit = unit
		if err := a.Registry.Record(rec); err != nil {
			t.Fatal(err)
		}
	}

	if rc := a.doctor(nil); rc != 1 {
		t.Errorf("doctor rc=%d, want 1", rc)
	}
	if !strings.Contains(errb.String(), "no valid task left") {
		t.Errorf("doctor did not surface the taskless auto-delete account: %q", errb.String())
	}
	for _, name := range []string{systemdName, atName} {
		if !strings.Contains(errb.String(), name) {
			t.Errorf("doctor did not report %s: %q", name, errb.String())
		}
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
		if rc := a.doctor(nil); rc != 1 {
			t.Errorf("doctor rc=%d, want 1 for a version mismatch", rc)
		}
		if !strings.Contains(errb.String(), "differs from the running") {
			t.Errorf("doctor did not flag the version mismatch: %q", errb.String())
		}
	})

	t.Run("no installed command is warned", func(t *testing.T) {
		a, _, errb := uninstallApp(t, "")
		writeStub(t, a.InstallPath, "") // remove it
		if rc := a.doctor(nil); rc != 1 {
			t.Errorf("doctor rc=%d, want 1 for a missing installed command", rc)
		}
		if !strings.Contains(errb.String(), "not installed") {
			t.Errorf("doctor did not report the missing installed command: %q", errb.String())
		}
	})
}

func TestDoctorReportsUntrustedRegistryIdentities(t *testing.T) {
	const (
		pendingName = "ltadocpending"
		markerName  = "ltadocmarker"
		legacyName  = "ltadoclegacy"
	)
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()

	newRealAccount(t, a, pendingName)
	rec, _, err := a.Registry.Lookup(pendingName)
	if err != nil {
		t.Fatal(err)
	}
	rec.Pending = true
	if err := a.Registry.Record(rec); err != nil {
		t.Fatal(err)
	}

	newRealAccount(t, a, markerName)
	if out, err := exec.Command("usermod", "-c", "Real Person", markerName).CombinedOutput(); err != nil {
		t.Fatalf("usermod: %v: %s", err, out)
	}

	newRealAccount(t, a, legacyName)
	legacy, _, err := a.Registry.Lookup(legacyName)
	if err != nil {
		t.Fatal(err)
	}
	legacy.UID = 0
	legacy.IdentityBound = false
	if err := a.Registry.Record(legacy); err != nil {
		t.Fatal(err)
	}

	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc=%d, want 1 for untrusted registry identities", rc)
	}
	got := errb.String()
	for _, want := range []string{pendingName, markerName, legacyName, "pending creation", "managed identity marker", "no safe non-root UID/GID"} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor output missing %q: %q", want, got)
		}
	}
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

func TestUninstallDoesNotDeleteLiveAccountNamedOnlyByStaleV1Row(t *testing.T) {
	const name = "ltav1reuse1"
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	mustWrite(t, filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile)),
		name+"\t2020-01-01\tstale\n")

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Fatalf("uninstall rc=%d, want refusal for an identity-unverified live v1 name", rc)
	}
	if !mustUserExists(t, name) {
		t.Fatal("live account was deleted solely because a stale v1 row reused its name")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatal("binary was removed while the identity-unverified account remained")
	}
	if !strings.Contains(errb.String(), "without a current generation-bound identity record") {
		t.Fatalf("refusal did not explain the v1 identity gap: %q", errb.String())
	}
}

func TestUninstallDoesNotBulkDeleteLegacyV2Identity(t *testing.T) {
	const (
		name       = "ltalegacyuninst1"
		generation = "cccccccccccccccccccccccccccccccc"
	)
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	pw, ok := mustUserLookup(t, name)
	if !ok {
		t.Fatal("legacy account was not found")
	}
	if err := a.Registry.Record(registry.Record{
		User: name, Host: "203.0.113.5", Port: 22, UID: pw.UID, Generation: generation,
	}); err != nil {
		t.Fatal(err)
	}
	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Fatalf("uninstall rc=%d, want legacy identity refusal", rc)
	}
	if !mustUserExists(t, name) {
		t.Fatal("bulk uninstall deleted a legacy fixed-marker account")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatal("binary was removed while a legacy account required manual recovery")
	}
	if !strings.Contains(errb.String(), "identity") {
		t.Fatalf("uninstall did not explain the legacy identity blocker: %q", errb.String())
	}
}

func TestUninstallDoesNotDeleteLiveAccountNamedOnlyByArtifact(t *testing.T) {
	const name = "ltaartifact1"
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	mustWrite(t, a.Sudoers.FilePath(name), name+" ALL=(ALL) NOPASSWD:ALL\n")

	if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
		t.Fatalf("uninstall rc=%d, want refusal for an artifact-only live name", rc)
	}
	if !mustUserExists(t, name) {
		t.Fatal("live account was deleted solely because an old artifact reused its name")
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatal("binary was removed while the identity-unverified account remained")
	}
	if !strings.Contains(errb.String(), "without a current generation-bound identity record") {
		t.Fatalf("refusal did not explain the missing identity record: %q", errb.String())
	}
}

func TestRevokeDoesNotDeleteLiveAccountNamedByPendingIntent(t *testing.T) {
	const name = "ltapending1"
	a, _, errb := uninstallApp(t, "")
	a.Users = user.New()
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	if err := a.Registry.Record(registry.Record{User: name, Port: 22, Pending: true}); err != nil {
		t.Fatal(err)
	}

	if rc := a.revoke([]string{"--user", name, "--yes"}); rc != 1 {
		t.Fatalf("revoke rc=%d, want refusal for pending identity", rc)
	}
	if !mustUserExists(t, name) {
		t.Fatal("pending creation intent authorized deletion of a live account")
	}
	if _, found, err := a.Registry.Lookup(name); err != nil || !found {
		t.Fatalf("pending recovery witness was not retained: found=%v err=%v", found, err)
	}
	if !strings.Contains(errb.String(), "pending creation intent") {
		t.Fatalf("refusal did not explain pending identity: %q", errb.String())
	}
}

func TestUninstallRequiresCompletedMatchingV2IdentityForLiveAccounts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending bool
		uid     func(actual int) int
	}{
		{name: "ltalowid1", uid: func(int) int { return 0 }},
		{name: "ltapending2", pending: true, uid: func(actual int) int { return actual }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := uninstallApp(t, "")
			a.Users = user.New()
			rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", tc.name).Run() }
			rm()
			t.Cleanup(rm)
			if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, tc.name).CombinedOutput(); err != nil {
				t.Fatalf("useradd: %v: %s", err, out)
			}
			pw, exists := mustUserLookup(t, tc.name)
			if !exists {
				t.Fatal("fixture account was not found")
			}
			if err := a.Registry.Record(registry.Record{
				User: tc.name, Port: 22, UID: tc.uid(pw.UID), Pending: tc.pending,
			}); err != nil {
				t.Fatal(err)
			}

			if rc := a.uninstall([]string{"--yes", "--remove-users"}); rc != 1 {
				t.Fatalf("uninstall rc=%d, want identity refusal", rc)
			}
			if !mustUserExists(t, tc.name) {
				t.Fatal("incomplete v2 row authorized deletion of a live account")
			}
			if _, err := os.Stat(a.InstallPath); err != nil {
				t.Fatal("binary was removed while an identity-unverified account remained")
			}
			if !strings.Contains(errb.String(), "without a current generation-bound identity record") {
				t.Fatalf("identity refusal was not explained: %q", errb.String())
			}
		})
	}
}
