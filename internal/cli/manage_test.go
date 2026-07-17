package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
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
// menu actually touches, all pointed at temp dirs. The accounts named here do
// not exist on the test host, so revoke takes its "user is gone, clean up the
// registry row" path: no real account is ever involved, and what the test can
// still see is which row that clean-up named — which is the thing under test.
func newManageApp(t *testing.T, in string, users ...string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
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

// TestManageUsersEmptyRegistryDoesNotPrompt: with nothing to act on there is
// nothing to choose, so the screen must not ask. Anything queued on stdin is a
// menu choice, and consuming it here would spend it on this prompt instead.
func TestManageUsersEmptyRegistryDoesNotPrompt(t *testing.T) {
	a, out, errb := newTestApp(t, "1\n")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if !strings.Contains(out.String(), "(none)") {
		t.Errorf("want an empty list, got: %q", out.String())
	}
	// The prompt is written to stderr, so that is where its absence has to be
	// asserted; checking stdout would pass whether or not it prompted.
	if strings.Contains(errb.String(), "Enter returns") {
		t.Errorf("must not prompt with an empty list: %q", errb.String())
	}
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
