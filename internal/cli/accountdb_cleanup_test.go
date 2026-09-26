package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

func TestAbsentAccountDatabaseFailureStillCleansNameScopedArtifacts(t *testing.T) {
	requireRootRegistryFixture(t)
	rec := registry.Record{User: "xxvcc-db-cleanup1", UID: 1001, Port: 22}
	a, _, _ := newTestApp(t, "")
	setTestRegistryRecord(t, a, rec)

	lookup := func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
	wantDBErr := errors.New("injected account database failure")
	a.LookupUser = lookup
	a.Users = &user.Manager{
		LookupUser: lookup,
		NameInUse:  func(string) (bool, error) { return false, nil },
		InspectSameNameGroupState: func(string) (bool, error) {
			return false, wantDBErr
		},
		CheckSubordinateIDsAbsent: func(string, int) error { return nil },
	}

	scheduleCalls := 0
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: filepath.Join(t.TempDir(), "linux-temp-admin"),
		UnitPrefix: config.AutoRevokeUnitPrefix,
		Sys:        revokeTestScheduleSystem{removeAtCalls: &scheduleCalls},
	}

	sudoDir := t.TempDir()
	sudoCalls := 0
	a.Sudoers = &sudoers.Manager{
		Dir: sudoDir,
		RemoveFile: func(path string) error {
			sudoCalls++
			return os.Remove(path)
		},
	}
	if err := os.WriteFile(a.Sudoers.FilePath(rec.User), []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}

	sshdDir := t.TempDir()
	sshdCalls := 0
	a.SSHD = &sshdconf.Manager{
		Dir: sshdDir, Lock: filepath.Join(t.TempDir(), "sshd.lock"),
		Validate: func() error { return nil }, Reload: func() error { return nil },
		RemoveFile: func(path string) error {
			sshdCalls++
			return os.Remove(path)
		},
	}
	if err := os.WriteFile(a.SSHD.FilePath(rec.User), []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}

	tx := revokeTransaction{app: a, username: rec.User, rec: rec, registered: true}
	if rc := tx.cleanupAbsentAccount(); rc != 1 {
		t.Fatalf("absent cleanup rc = %d, want retained database failure", rc)
	}
	if scheduleCalls != 0 || sudoCalls != 1 || sshdCalls != 1 {
		t.Fatalf("cleanup calls after database failure: schedule=%d sudo=%d sshd=%d, want schedule=0 and both grant removals=1", scheduleCalls, sudoCalls, sshdCalls)
	}
	if _, found, err := a.Registry.Lookup(rec.User); err != nil || !found {
		t.Fatalf("database failure lost registry evidence: found=%v err=%v", found, err)
	}
	for _, path := range []string{a.Sudoers.FilePath(rec.User), a.SSHD.FilePath(rec.User)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("name-scoped artifact still exists at %s: %v", path, err)
		}
	}
}

func TestAbsentRegisteredAccountWithoutManagerFailsClosed(t *testing.T) {
	requireRootRegistryFixture(t)
	rec := registry.Record{User: "xxvcc-db-cleanup2", UID: 1002, Port: 22}
	a, _, _ := newTestApp(t, "")
	setTestRegistryRecord(t, a, rec)
	a.LookupUser = func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
	a.Users = nil
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: filepath.Join(t.TempDir(), "linux-temp-admin"),
		UnitPrefix: config.AutoRevokeUnitPrefix,
		Sys:        revokeTestScheduleSystem{},
	}

	tx := revokeTransaction{app: a, username: rec.User, rec: rec, registered: true}
	if rc := tx.cleanupAbsentAccount(); rc != 1 {
		t.Fatalf("absent cleanup without account manager rc = %d, want failure", rc)
	}
	if _, found, err := a.Registry.Lookup(rec.User); err != nil || !found {
		t.Fatalf("missing account manager lost registry evidence: found=%v err=%v", found, err)
	}
}

func TestAbsentAccountKeepsRetryUntilGrantsAreRemoved(t *testing.T) {
	requireRootRegistryFixture(t)
	for _, failure := range []string{"sudo", "sshd reload"} {
		t.Run(failure, func(t *testing.T) {
			a, _, _ := newTestApp(t, "")
			rec := registry.Record{User: "xxvcc-retry1", UID: 1001, Port: 22}
			setTestRegistryRecord(t, a, rec)
			lookup := func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
			a.Users = &user.Manager{LookupUser: lookup, NameInUse: func(string) (bool, error) { return false, nil }, InspectSameNameGroupState: func(string) (bool, error) { return false, nil }, CheckSubordinateIDsAbsent: func(string, int) error { return nil }}
			sys := &recordingCanceller{}
			dir := t.TempDir()
			a.Scheduler = &schedule.Scheduler{SystemdDir: dir, SystemdTimerStateDir: t.TempDir(), InstallPath: a.InstallPath, UnitPrefix: config.AutoRevokeUnitPrefix, Sys: sys}
			unit := a.Scheduler.UnitName(rec.User)
			for _, ext := range []string{".timer", ".service"} {
				if err := os.WriteFile(filepath.Join(dir, unit+ext), []byte("test fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			repaired := false
			wantErr := errors.New("injected grant cleanup failure")
			sudoCalls, reloadCalls := 0, 0
			a.Sudoers = &sudoers.Manager{Dir: t.TempDir(), RemoveFile: func(path string) error {
				sudoCalls++
				if failure == "sudo" && !repaired {
					return wantErr
				}
				return os.Remove(path)
			}}
			a.SSHD = &sshdconf.Manager{Dir: t.TempDir(), Lock: filepath.Join(t.TempDir(), "sshd.lock"), Validate: func() error { return nil }, Reload: func() error {
				reloadCalls++
				if failure == "sshd reload" && !repaired {
					return wantErr
				}
				return nil
			}}
			for _, path := range []string{a.Sudoers.FilePath(rec.User), a.SSHD.FilePath(rec.User)} {
				if err := os.WriteFile(path, []byte("test fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			tx := revokeTransaction{app: a, username: rec.User, rec: rec, registered: true}
			if rc := tx.cleanupAbsentAccount(); rc != 1 {
				t.Fatalf("rc=%d, want failed cleanup", rc)
			}
			if len(sys.cancelled) != 0 || sudoCalls != 1 || reloadCalls != 1 {
				t.Fatalf("cancellation=%v sudo=%d reload=%d", sys.cancelled, sudoCalls, reloadCalls)
			}
			for _, ext := range []string{".timer", ".service"} {
				if _, err := os.Stat(filepath.Join(dir, unit+ext)); err != nil {
					t.Fatalf("retry task removed: %v", err)
				}
			}
			if _, found, err := a.Registry.Lookup(rec.User); err != nil || !found {
				t.Fatalf("recovery witness lost: found=%v err=%v", found, err)
			}
			repaired = true
			if rc := tx.cleanupAbsentAccount(); rc != 0 {
				t.Fatalf("repaired cleanup rc=%d", rc)
			}
			if len(sys.cancelled) == 0 {
				t.Fatal("successful cleanup did not cancel task")
			}
			for _, ext := range []string{".timer", ".service"} {
				if _, err := os.Stat(filepath.Join(dir, unit+ext)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("task retained after success: %v", err)
				}
			}
			if _, found, err := a.Registry.Lookup(rec.User); err != nil || found {
				t.Fatalf("completed witness not released: found=%v err=%v", found, err)
			}
		})
	}
}
