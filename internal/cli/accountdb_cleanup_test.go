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
		CheckSubordinateIDsAbsent: func(string) error { return nil },
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
	if scheduleCalls != 1 || sudoCalls != 1 || sshdCalls != 1 {
		t.Fatalf("cleanup calls after database failure: schedule=%d sudo=%d sshd=%d, want 1 each", scheduleCalls, sudoCalls, sshdCalls)
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
