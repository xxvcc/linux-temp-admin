//go:build integration

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

// fakeSys satisfies schedule.System without touching systemd or at.
type fakeSys struct{}

func (fakeSys) HasSystemctl() bool                     { return false }
func (fakeSys) Systemctl(...string) error              { return nil }
func (fakeSys) HasAt() bool                            { return false }
func (fakeSys) ScheduleAt(string, int) (string, error) { return "", nil }
func (fakeSys) RemoveAtJobsFor(string)                 {}
func (fakeSys) AtrmJob(string)                         {}

// newManageApp is newTestApp plus the collaborators a revoke reached from the
// menu actually touches, all pointed at temp dirs. It needs root: the registry
// is root-owned state by design — every write goes through a chown to 0:0 into a
// directory checked for root ownership — so seeding a row cannot be done without
// it, and faking that away would be testing something the tool does not do. The accounts named here do
// not exist on the test host, so revoke takes its "user is gone, clean up the
// registry row" path: no real account is ever involved, and what the test can
// still see is which row that clean-up named — which is the thing under test.
func newManageApp(t *testing.T, in string, users ...string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	a, out, errb := newTestApp(t, in)
	dir := t.TempDir()
	a.Sudoers = &sudoers.Manager{
		Dir:      dir,
		Validate: func(string) error { return nil },
		Verify:   func(string) error { return nil },
	}
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: dir, InstallPath: a.InstallPath, UnitPrefix: "lta-test-",
		Now: a.Now, Sys: fakeSys{}, UnderUnit: func(string) bool { return false },
	}
	// The store's dir has to be root-owned for its symlink-safety checks to pass;
	// t.TempDir() belongs to whoever runs the suite.
	if err := os.Chown(a.Registry.Dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.Registry.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		rec := registry.Record{
			User: u, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
			Sudo: true, Host: "203.0.113.5", Port: 22, AutoRevoke: true, UID: 4242,
		}
		if err := a.Registry.Record(rec); err != nil {
			t.Fatal(err)
		}
	}
	return a, out, errb
}

func regUsers(t *testing.T, a *App) []string {
	t.Helper()
	recs, err := a.Registry.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range recs {
		names = append(names, r.User)
	}
	return names
}

// TestManageUsersEnterIsLookOnly pins the default: this screen's job is to show
// the list, so leaving it must be one keystroke and must change nothing.
func TestManageUsersEnterIsLookOnly(t *testing.T) {
	a, _, _ := newManageApp(t, "\n", "ltamanage-a1")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if got := regUsers(t, a); len(got) != 1 {
		t.Errorf("Enter must not touch the registry; rows now %v", got)
	}
}

// TestManageUsersRowNumberPicksThatRow is the whole risk of numbering a table:
// the number the operator types has to name the row they are looking at. It
// deletes the second of two rows and checks the first survived.
func TestManageUsersRowNumberPicksThatRow(t *testing.T) {
	a, _, _ := newManageApp(t, "2\n", "ltamanage-a1", "ltamanage-b2")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	got := regUsers(t, a)
	if len(got) != 1 || got[0] != "ltamanage-a1" {
		t.Errorf("row 2 should have taken ltamanage-b2 and only it; rows now %v", got)
	}
}

// TestManageUsersOutOfRangeRowIsRefused covers the digits either side of the
// table. An out-of-range number must not fall through to being read as a
// username, and must not act on anything.
func TestManageUsersOutOfRangeRowIsRefused(t *testing.T) {
	for _, choice := range []string{"0", "3", "-1"} {
		a, _, errb := newManageApp(t, choice+"\n", "ltamanage-a1", "ltamanage-b2")
		if rc := a.manageUsers(); rc != 1 {
			t.Errorf("choice %q: rc=%d, want 1", choice, rc)
		}
		if !strings.Contains(errb.String(), "no such row") {
			t.Errorf("choice %q: want a no-such-row warning", choice)
		}
		if got := regUsers(t, a); len(got) != 2 {
			t.Errorf("choice %q must act on nothing; rows now %v", choice, got)
		}
	}
}

// TestManageUsersRejectsAnIllegalName: a typed answer is a username, and this
// screen must not be the thing that decides what a legal one is — it hands it to
// the same validation `revoke --user` uses.
func TestManageUsersRejectsAnIllegalName(t *testing.T) {
	a, _, _ := newManageApp(t, "../../etc/passwd\n", "ltamanage-a1")
	if rc := a.manageUsers(); rc != 1 {
		t.Errorf("rc=%d, want 1 for an illegal username", rc)
	}
	if got := regUsers(t, a); len(got) != 1 {
		t.Errorf("registry should be untouched; rows now %v", got)
	}
}

// TestManageUsersCleanupPrunesTheMissingRows is why cleanup belongs on this
// screen rather than beside it as its own menu entry: what --compact prunes is
// exactly the rows this table marks "missing" — a registry row whose account is
// gone. It was never a separate object to manage, only a separate way in.
func TestManageUsersCleanupPrunesTheMissingRows(t *testing.T) {
	a, _, _ := newManageApp(t, "c\n", "ltamanage-a1", "ltamanage-b2")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	// Neither account exists on this host, so both rows are "missing" rows.
	if got := regUsers(t, a); len(got) != 0 {
		t.Errorf("cleanup should have pruned every missing row; rows now %v", got)
	}
}

// TestManageUsersCleanupSparesTheAccountsThatExist is the other half of that
// claim: cleanup must only ever take the rows whose account is gone. root is
// here as a stand-in for "a row whose account exists" — it is the one account
// every test host is guaranteed to have. Nothing deletes it: --compact only
// rewrites registry rows, and the row is a fake this test wrote.
func TestManageUsersCleanupSparesTheAccountsThatExist(t *testing.T) {
	a, _, _ := newManageApp(t, "c\n", "ltamanage-a1", "root")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	got := regUsers(t, a)
	if len(got) != 1 || got[0] != "root" {
		t.Errorf("cleanup must spare rows whose account exists; rows now %v", got)
	}
}

// TestManageUsersCleanupRequiresRoot pins a gate that is easy to lose: the
// cleanup here calls the bare sweep, not the `cleanup-expired` subcommand that
// opens by checking for root, so this screen has to do that check itself.
func TestManageUsersCleanupRequiresRoot(t *testing.T) {
	a, _, _ := newManageApp(t, "c\n", "ltamanage-a1")
	a.Geteuid = func() int { return 1000 }
	if rc := a.manageUsers(); rc != 1 {
		t.Errorf("rc=%d, want 1 when not root", rc)
	}
	if got := regUsers(t, a); len(got) != 1 {
		t.Errorf("a non-root cleanup must change nothing; rows now %v", got)
	}
}

// parseNumberedTable reads back the rendered table: it returns the "#" cell and
// the user cell of each body row, in the order printed. It deliberately parses
// the real output rather than trusting the model that produced it — the point is
// to compare what the operator SEES against what selection DOES.
func parseNumberedTable(t *testing.T, out string) (nums []string, users []string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "│") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "│"), "│")
		if len(cells) < 2 {
			continue
		}
		n, u := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1])
		if n == "#" || n == "" { // header, or a row with no number column
			continue
		}
		nums = append(nums, n)
		users = append(users, u)
	}
	return nums, users
}

// TestManageUsersDisplayedNumberIsTheOneThatActs pins the half of the invariant
// that the mapping test cannot reach. "A row number must map to exactly the row
// displayed" is two claims: that selection resolves recs[n-1], and that the "#"
// the operator reads is that same n. A test that only inspects the registry
// afterwards pins the first and lets the second rot: invert the rendered "#"
// column alone and every other test here still passes, while the screen now tells
// the operator to type the number of a different account.
//
// So this one reads the number off the rendered table and feeds that back in.
func TestManageUsersDisplayedNumberIsTheOneThatActs(t *testing.T) {
	// Render first, with an input that changes nothing, and see what is on screen.
	view, out, _ := newManageApp(t, "\n", "ltarender-a1", "ltarender-b2", "ltarender-c3")
	if rc := view.manageUsers(); rc != 0 {
		t.Fatalf("view rc=%d", rc)
	}
	nums, users := parseNumberedTable(t, out.String())
	if len(nums) != 3 {
		t.Fatalf("want 3 numbered rows, parsed %d from:\n%s", len(nums), out.String())
	}
	// Whatever the screen labels a row, typing that label must act on that row's
	// account — checked for every row, so no single lucky alignment passes.
	for i := range nums {
		a, _, _ := newManageApp(t, nums[i]+"\n", "ltarender-a1", "ltarender-b2", "ltarender-c3")
		if rc := a.manageUsers(); rc != 0 {
			t.Fatalf("row %q: rc=%d", nums[i], rc)
		}
		got := regUsers(t, a)
		for _, g := range got {
			if g == users[i] {
				t.Errorf("screen labels %q as row %q, but typing %q left it registered (rows now %v)",
					users[i], nums[i], nums[i], got)
			}
		}
		if len(got) != 2 {
			t.Errorf("row %q should have taken exactly one account; rows now %v", nums[i], got)
		}
	}
}

// newRealAccount creates an actual local account and registers it with its REAL
// uid, returning that uid. The confirmation gate is only reachable when the
// account exists — revoke returns from its "user is gone, clean up" branch first
// otherwise — so a fake row cannot reach it, which is exactly why the gate went
// untested. The uid must be the real one or IsProtectedRevokeTarget refuses the
// account as UID-tampered before the confirmation gets to be what is under test.
func newRealAccount(t *testing.T, a *App, name string) int {
	t.Helper()
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd %s: %v: %s", name, err, out)
	}
	pw, ok := user.Lookup(name)
	if !ok {
		t.Fatalf("%s was not created", name)
	}
	if err := a.Registry.Record(registry.Record{
		User: name, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
		Host: "203.0.113.5", Port: 22, UID: pw.UID,
	}); err != nil {
		t.Fatal(err)
	}
	return pw.UID
}

// TestManageUsersRevokeRefusesWithoutTheFullName pins the merge's entire safety
// argument, which until now no test in this repo executed: picking a row does not
// delete it — revoke makes you type the account's full name, and a mistyped one
// is refused. Delete the confirmation block from revoke and every other test
// still passes; this one fails, because the account is really there to lose.
func TestManageUsersRevokeRefusesWithoutTheFullName(t *testing.T) {
	const name = "ltaconfirm1"
	a, _, errb := newManageApp(t, "1\nltaconfirm-typo\n")
	a.Users = user.New()
	newRealAccount(t, a, name)

	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("a refused confirmation is a cancel, not an error: rc=%d", rc)
	}
	if !user.Exists(name) {
		t.Fatal("THE ACCOUNT WAS DELETED without the operator typing its name")
	}
	if got := regUsers(t, a); len(got) != 1 || got[0] != name {
		t.Errorf("a cancelled revoke must leave the registry alone; rows now %v", got)
	}
	if !strings.Contains(errb.String(), "confirmation mismatch") {
		t.Errorf("want the cancel to say why; stderr: %q", errb.String())
	}
}

// TestManageUsersRevokeDeletesOnceTheFullNameIsTyped is the other half: the gate
// must open for the operator who actually names the account, or "the number is
// how you revoke" would be a lie in the safe direction.
func TestManageUsersRevokeDeletesOnceTheFullNameIsTyped(t *testing.T) {
	const name = "ltaconfirm2"
	a, _, _ := newManageApp(t, "1\n"+name+"\n")
	a.Users = user.New()
	newRealAccount(t, a, name)

	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if user.Exists(name) {
		t.Error("the account survived a confirmed revoke")
	}
	if got := regUsers(t, a); len(got) != 0 {
		t.Errorf("the registry row should be gone; rows now %v", got)
	}
}

// TestManageUsersMissingRowIsSweptWithoutAPrompt pins the deliberate asymmetry a
// review caught the docs overstating. Picking a 缺失 row does NOT ask for the
// full name: revoke's "the account is gone, clean up after it" branch runs before
// the confirmation. That is intended — there is no account to lose, and "c" on
// this same screen sweeps every missing row without asking either — but it makes
// "a number opens a confirmation" false for exactly these rows, so it is pinned
// here rather than left as folklore.
//
// The input carries a second line that would be the confirmation. Nothing must
// consume it: if a prompt ever appears here, "no-such-user" is not a legal
// username and the test fails on the changed exit code rather than passing
// quietly.
func TestManageUsersMissingRowIsSweptWithoutAPrompt(t *testing.T) {
	a, _, errb := newManageApp(t, "1\nno-such-user\n", "ltamissing-a1")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if got := regUsers(t, a); len(got) != 0 {
		t.Errorf("the missing row should have been swept; rows now %v", got)
	}
	if strings.Contains(errb.String(), "to confirm deletion") {
		t.Errorf("a missing row has no account to lose and must not demand a name: %q", errb.String())
	}
}

// TestRevokeRefusesAndReportsAUIDTamperedAccount is the CLI-level half of the
// user package's protection fix. An account whose current UID contradicts the one
// the registry pinned at creation is not the account this tool made, and revoke
// must refuse it rather than delete it — and, critically, must refuse BEFORE
// TerminateProcesses, which aims a SIGKILL sweep at the UID standing in passwd.
// A contradicting UID is by definition one the tool never issued, so that sweep
// would have been pointed at whatever the account's UID now collides with.
//
// It also pins that the refusal is not silent: UIDTampered's report only ever ran
// inside the branch something else had already refused, so on the one path where
// it was the whole story it never spoke.
func TestRevokeRefusesAndReportsAUIDTamperedAccount(t *testing.T) {
	const name = "ltatamper1"
	a, _, errb := newManageApp(t, "")
	a.Users = user.New()

	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", "linux-temp-admin temporary admin", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	pw, ok := user.Lookup(name)
	if !ok {
		t.Fatal("account not created")
	}
	// The row pins a UID this account does not have: the shape of an account that
	// rewrote its own passwd entry, and of a name whose account was recreated.
	// The GECOS marker is intact, which is exactly the case that used to pass.
	if err := a.Registry.Record(registry.Record{
		User: name, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
		Host: "203.0.113.5", Port: 22, UID: pw.UID + 4242,
	}); err != nil {
		t.Fatal(err)
	}

	if rc := a.revoke([]string{"--user", name, "--yes"}); rc != 1 {
		t.Errorf("rc=%d, want 1 (refused)", rc)
	}
	if !user.Exists(name) {
		t.Error("THE ACCOUNT WAS DELETED even though its UID proves it is not the one the tool made")
	}
	if !strings.Contains(errb.String(), "UID") {
		t.Errorf("the refusal must name the tamper, or the operator cannot act on it: %q", errb.String())
	}
}

// TestRevokeShoutsWhenTheSudoGrantSurvives pins what used to be the quietest
// failure in the tool. revoke strips the sudo drop-in FIRST, deliberately, so an
// account that survives a refused revoke cannot survive holding passwordless
// root — and the removal's error was discarded, so when it did survive, nothing
// said so.
//
// Making a real os.Remove fail AS ROOT is the trick here: a read-only directory
// does not do it (root bypasses the permission check and the test would skip,
// asserting nothing — in CI, which runs this suite as root, always). A non-empty
// directory at the grant's path fails for everyone, root included, and it fails
// inside the real os.Remove rather than a mock, so the test still bites if the
// reporting path is rewritten.
func TestRevokeShoutsWhenTheSudoGrantSurvives(t *testing.T) {
	a, _, errb := newManageApp(t, "", "ltasudogrant-a1")
	grant := a.Sudoers.FilePath("ltasudogrant-a1")
	if err := os.MkdirAll(filepath.Join(grant, "wedge"), 0o700); err != nil {
		t.Fatal(err)
	}

	a.revoke([]string{"--user", "ltasudogrant-a1", "--yes"})

	if _, err := os.Stat(grant); err != nil {
		t.Fatalf("the wedge should have survived; the test proves nothing: %v", err)
	}
	// Match the distinctive phrase, not "sudo": revoke's absent-account branch says
	// "cleaning up registry/sudoers/sshd exception/..." on this very path, so a
	// substring that loose passes with the reporting deleted (it did — this test was
	// vacuous until the mutation caught it).
	if !strings.Contains(errb.String(), "passwordless root") {
		t.Errorf("a surviving NOPASSWD grant must be reported, not discarded; stderr: %q", errb.String())
	}
}

func mustWriteManage(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o440); err != nil {
		t.Fatal(err)
	}
}

func TestManageUsersShowsOrphansWithNoRegistryRow(t *testing.T) {
	a, out, errb := newManageApp(t, "\n", "ltamanage-live")
	mustWriteManage(t, a.Sudoers.FilePath("ltaorphan-x"), "ltaorphan-x ALL=(ALL) NOPASSWD:ALL\n")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(out.String(), "ltaorphan-x") {
		t.Errorf("orphan not surfaced: %q // errb=%q", out.String(), errb.String())
	}
}

func TestManageUsersEmptyRegistryStillOffersCleanupForOrphans(t *testing.T) {
	a, out, errb := newManageApp(t, "\n")
	mustWriteManage(t, a.Sudoers.FilePath("ltaorphan-y"), "ltaorphan-y ALL=(ALL) NOPASSWD:ALL\n")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(out.String(), "ltaorphan-y") {
		t.Errorf("orphan not surfaced: %q", out.String())
	}
	if !strings.Contains(errb.String(), "Enter returns") {
		t.Errorf("no prompt: %q", errb.String())
	}
}

// TestManageUsersTrulyEmptyStillReturns: no rows AND no orphans is the one case
// that prints "(none)" and leaves without a prompt — the guard's other direction.
func TestManageUsersTrulyEmptyStillReturns(t *testing.T) {
	a, out, errb := newManageApp(t, "")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(out.String(), "(none)") {
		t.Errorf("want (none): %q", out.String())
	}
	if strings.Contains(errb.String(), "Enter returns") {
		t.Errorf("must not prompt when truly empty: %q", errb.String())
	}
}
