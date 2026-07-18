package schedule

import (
	"os"
	"path/filepath"
	"testing"
)

func newFinder(t *testing.T, files ...string) *Scheduler {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Scheduler{
		SystemdDir:         dir,
		UnitPrefix:         "linux-temp-admin-v2-revoke-",
		LegacyUnitPrefixes: []string{"linux-temp-admin-revoke-"},
	}
}

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestUnitUsersFindsBothVersionsAndDedupesThePair: a unit is written as a
// .service/.timer pair naming one account, and an upgraded host carries units
// from both versions of this tool.
func TestUnitUsersFindsBothVersionsAndDedupesThePair(t *testing.T) {
	s := newFinder(t,
		"linux-temp-admin-v2-revoke-xxvcc-a1.service",
		"linux-temp-admin-v2-revoke-xxvcc-a1.timer",
		"linux-temp-admin-revoke-oldv1user.service",
		"linux-temp-admin-revoke-oldv1user.timer",
	)
	users, err := s.UnitUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "oldv1user", "xxvcc-a1")
}

// TestUnitUsersFindsTheV1UnitTheV2GlobWalksPast is the regression this package
// was missing. v1's prefix has no "-v2-" infix, so globbing only the v2 prefix
// finds nothing here — and v1 installed to the same path v2 occupies, so this
// unit's ExecStart names the running binary. Missing it means an uninstall
// removes that binary and leaves this account with a timer that fires forever
// and fails forever.
func TestUnitUsersFindsTheV1UnitTheV2GlobWalksPast(t *testing.T) {
	s := newFinder(t, "linux-temp-admin-revoke-oldv1user.timer")
	users, err := s.UnitUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "oldv1user")

	// Prove the claim rather than assert it: with no legacy prefix configured, the
	// same directory reads as empty.
	s.LegacyUnitPrefixes = nil
	users, err = s.UnitUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Fatalf("the v2 prefix alone should not match a v1 unit; got %v", users)
	}
}

// TestUnitUsersIgnoresFilesItDidNotWrite: the prefix is a namespace, not a
// licence to act on anything sharing it.
func TestUnitUsersIgnoresFilesItDidNotWrite(t *testing.T) {
	s := newFinder(t,
		"linux-temp-admin-v2-revoke-.service",       // no username
		"linux-temp-admin-v2-revoke-BadName!.timer", // not a legal username
		"linux-temp-admin-v2-revoke-UPPER.timer",    // usernames are lower-case here
		"linux-temp-admin-v2-revoke-has space.timer",
		"unrelated.service",
		"linux-temp-admin-v2-revoke-good.timer",
	)
	users, err := s.UnitUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "good")
}

// TestOrphansAreUnitsWhoseAccountIsGone mirrors sudoers.Orphans/sshdconf.Orphans,
// the two sweeps this one had no counterpart to.
func TestOrphansAreUnitsWhoseAccountIsGone(t *testing.T) {
	s := newFinder(t,
		"linux-temp-admin-v2-revoke-alive.timer",
		"linux-temp-admin-v2-revoke-gone.timer",
		"linux-temp-admin-revoke-v1gone.timer",
	)
	orphans, err := s.Orphans(func(u string) bool { return u == "alive" })
	if err != nil {
		t.Fatal(err)
	}
	eq(t, orphans, "gone", "v1gone")
}
