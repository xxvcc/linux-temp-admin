package schedule

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitUsersPropagatesDirectoryReadFailure(t *testing.T) {
	old := readSystemdDir
	readSystemdDir = func(string) ([]os.DirEntry, error) {
		return nil, errors.New("injected directory I/O failure")
	}
	t.Cleanup(func() { readSystemdDir = old })

	s := newFinder(t)
	if _, err := s.UnitUsers(); err == nil || !strings.Contains(err.Error(), "injected directory I/O failure") {
		t.Fatalf("UnitUsers error = %v, want directory failure", err)
	}
}

func TestUnitUsersRejectsUnsafePrefixBeforeReadingEmptyDirectory(t *testing.T) {
	for _, prefix := range []string{"", "unsafe/prefix", "unsafe prefix", "unsafe\tprefix", "unsafe\nprefix"} {
		s := newFinder(t)
		s.UnitPrefix = prefix
		if _, err := s.UnitUsers(); err == nil || !strings.Contains(err.Error(), "unsafe managed systemd unit prefix") {
			t.Fatalf("UnitUsers(%q) error = %v, want unsafe-prefix refusal", prefix, err)
		}
	}
}

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
		InstallPath:        "/usr/local/sbin/linux-temp-admin",
		UnitPrefix:         "linux-temp-admin-v2-revoke-",
		LegacyUnitPrefixes: []string{"linux-temp-admin-revoke-"},
		Sys:                &fakeSystem{},
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

func TestUnitUsersIgnoresFilesOutsideManagedUnitShape(t *testing.T) {
	s := newFinder(t,
		"linux-temp-admin-v2-revoke-no-suffix",
		"linux-temp-admin-v2-revoke-wrong.socket",
		"unrelated.service",
		"linux-temp-admin-v2-revoke-good.timer",
	)
	users, err := s.UnitUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "good")
}

func TestUnitUsersFailsClosedOnMalformedManagedUnitName(t *testing.T) {
	for _, name := range []string{
		"linux-temp-admin-v2-revoke-.service",
		"linux-temp-admin-v2-revoke-BadName!.timer",
		"linux-temp-admin-v2-revoke-UPPER.timer",
		"linux-temp-admin-v2-revoke-has space.timer",
		"linux-temp-admin-revoke-.timer",
	} {
		t.Run(name, func(t *testing.T) {
			s := newFinder(t, name)
			if _, err := s.UnitUsers(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("UnitUsers error = %v, want malformed managed-unit refusal", err)
			}
		})
	}
}

func TestUnitUsersInventoriesManagedNamesRegardlessOfEntryType(t *testing.T) {
	s := newFinder(t)
	service := "linux-temp-admin-v2-revoke-special.service"
	timer := "linux-temp-admin-v2-revoke-special.timer"
	if err := os.Mkdir(filepath.Join(s.SystemdDir, service), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(s.SystemdDir, timer)); err != nil {
		t.Fatal(err)
	}
	users, err := s.UnitUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "special")
}

// TestOrphansAreUnitsWhoseAccountIsGone mirrors sudoers.Orphans/sshdconf.Orphans,
// the two sweeps this one had no counterpart to.
func TestOrphansAreUnitsWhoseAccountIsGone(t *testing.T) {
	s := newFinder(t,
		"linux-temp-admin-v2-revoke-alive.timer",
		"linux-temp-admin-v2-revoke-gone.timer",
		"linux-temp-admin-revoke-v1gone.timer",
	)
	orphans, err := s.Orphans(func(u string) (bool, error) { return u == "alive", nil })
	if err != nil {
		t.Fatal(err)
	}
	eq(t, orphans, "gone", "v1gone")
}

func TestScheduledUsersIncludesAtJobsWithoutRegistry(t *testing.T) {
	s := newFinder(t)
	s.Sys = &fakeSystem{hasAt: true, atJobs: []AtJob{
		{ID: "7", Body: "/usr/local/sbin/linux-temp-admin revoke --user queueduser --yes --force --confirm-force queueduser\n"},
		{ID: "8", Body: "/bin/echo unrelated\n"},
	}}
	users, err := s.ScheduledUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "queueduser")
}

func TestScheduledUsersIgnoresNonRootAtMimics(t *testing.T) {
	s := newFinder(t)
	s.Sys = &fakeSystem{hasAt: true, atJobs: []AtJob{
		{ID: "7", OwnerUID: 1001, Body: "/usr/local/sbin/linux-temp-admin revoke --user forged --yes --unknown\n"},
		{ID: "8", Body: "/usr/local/sbin/linux-temp-admin revoke --user owned --yes\n"},
	}}
	users, err := s.ScheduledUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "owned")
}

func TestScheduledUsersIncludesUnitsLoadedOnlyInSystemdManager(t *testing.T) {
	s := newFinder(t)
	s.Sys = &fakeSystem{hasSystemctl: true, loadedUnits: []string{
		"linux-temp-admin-v2-revoke-loaded.timer",
		"linux-temp-admin-revoke-legacy.service",
		"unrelated.timer",
	}}
	users, err := s.ScheduledUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "legacy", "loaded")
}

func TestScheduledUsersFailsClosedOnMalformedOrUnreadableLoadedUnitInventory(t *testing.T) {
	t.Run("malformed managed name", func(t *testing.T) {
		s := newFinder(t)
		s.Sys = &fakeSystem{hasSystemctl: true, loadedUnits: []string{"linux-temp-admin-v2-revoke-Bad!.timer"}}
		if _, err := s.ScheduledUsers(); err == nil || !strings.Contains(err.Error(), "invalid account suffix") {
			t.Fatalf("ScheduledUsers error = %v, want malformed loaded-unit refusal", err)
		}
	})
	t.Run("manager query", func(t *testing.T) {
		s := newFinder(t)
		s.Sys = &fakeSystem{hasSystemctl: true, loadedErr: errors.New("D-Bus unavailable")}
		if _, err := s.ScheduledUsers(); err == nil || !strings.Contains(err.Error(), "D-Bus unavailable") {
			t.Fatalf("ScheduledUsers error = %v, want manager inventory failure", err)
		}
	})
}

func TestScheduledUsersOnlyAcceptsKnownStandaloneRevokeCommands(t *testing.T) {
	s := newFinder(t)
	s.Sys = &fakeSystem{hasAt: true, atJobs: []AtJob{
		{ID: "1", Body: "# /usr/local/sbin/linux-temp-admin revoke --user comment --yes\n"},
		{ID: "2", Body: "echo /usr/local/sbin/linux-temp-admin revoke --user echoed --yes\n"},
		{ID: "3", Body: "/tmp/usr/local/sbin/linux-temp-admin revoke --user wrongpath --yes\n"},
		{ID: "5", Body: "/usr/local/sbin/linux-temp-admin revoke --user legacy --yes\n"},
		{ID: "6", Body: "/usr/local/sbin/linux-temp-admin revoke --user forced --yes --force --confirm-force forced\n"},
		{ID: "7", Body: "/usr/local/sbin/linux-temp-admin revoke --user current --yes --force --confirm-force current --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef\n"},
	}}

	users, err := s.ScheduledUsers()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, users, "current", "forced", "legacy")
}

func TestScheduledUsersFailsClosedOnMalformedOwnedAtCommand(t *testing.T) {
	s := newFinder(t)
	s.Sys = &fakeSystem{hasAt: true, atJobs: []AtJob{{
		ID:   "4",
		Body: "/usr/local/sbin/linux-temp-admin revoke --user future --yes --unknown\n",
	}}}
	if _, err := s.ScheduledUsers(); err == nil || !strings.Contains(err.Error(), "at job 4") {
		t.Fatalf("ScheduledUsers error = %v, want malformed owned-job refusal", err)
	}
}

func TestScheduledUsersAllowsCompletelyAbsentAtBackend(t *testing.T) {
	s := newFinder(t, "linux-temp-admin-v2-revoke-unituser.timer")
	s.Sys = &fakeSystem{atJobsErr: os.ErrNotExist}

	users, err := s.ScheduledUsers()
	if err != nil {
		t.Fatalf("systemd-only inventory failed because optional at is absent: %v", err)
	}
	eq(t, users, "unituser")
}

func TestScheduledUsersRejectsMissingBackend(t *testing.T) {
	s := newFinder(t)
	s.Sys = nil
	if _, err := s.ScheduledUsers(); err == nil || !strings.Contains(err.Error(), "no scheduler backend") {
		t.Fatalf("ScheduledUsers missing-backend error = %v", err)
	}
}
