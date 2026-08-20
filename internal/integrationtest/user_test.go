//go:build integration

package integrationtest

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type cleanupReporter struct {
	helpers int
	errors  []string
	fatals  []string
}

func (r *cleanupReporter) Helper() { r.helpers++ }

func (r *cleanupReporter) Errorf(format string, args ...any) {
	r.errors = append(r.errors, strings.TrimSpace(formatError(format, args...)))
}

func (r *cleanupReporter) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, strings.TrimSpace(formatError(format, args...)))
}

func formatError(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func isolateUserCleanup(t *testing.T) {
	t.Helper()
	oldRunUserdel, oldRunGroupdel := runUserdel, runGroupdel
	oldLookupUser, oldLookupGroup := lookupSystemUser, lookupSystemGroup
	oldInspect := inspectLocalGroupDatabase
	t.Cleanup(func() {
		runUserdel, runGroupdel = oldRunUserdel, oldRunGroupdel
		lookupSystemUser, lookupSystemGroup = oldLookupUser, oldLookupGroup
		inspectLocalGroupDatabase = oldInspect
	})
	lookupSystemGroup = func(name string) (*user.Group, error) {
		return nil, user.UnknownGroupError(name)
	}
	inspectLocalGroupDatabase = func(name string) (localGroupArtifacts, error) {
		_, err := lookupSystemGroup(name)
		if err == nil {
			return localGroupArtifacts{group: true, gshadow: true, gshadowPresent: true}, nil
		}
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return localGroupArtifacts{gshadowPresent: true}, nil
		}
		return localGroupArtifacts{}, err
	}
}

func TestCleanupUserReportsOnlyUnresolvedRemovalFailures(t *testing.T) {
	removeErr := errors.New("userdel failed")

	t.Run("missing account is tolerated", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return []byte("not found\n"), removeErr }
		lookupSystemUser = func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-missing", true)
		if len(reporter.errors) != 0 {
			t.Fatalf("missing account cleanup errors = %v", reporter.errors)
		}
		RequireUserAbsent(reporter, "lta-missing", true)
		if len(reporter.fatals) != 0 {
			t.Fatalf("missing account pre-clean failures = %v", reporter.fatals)
		}
	})

	t.Run("surviving account is reported with diagnostics", func(t *testing.T) {
		isolateUserCleanup(t)
		var gotArgs []string
		runUserdel = func(args ...string) ([]byte, error) {
			gotArgs = append([]string(nil), args...)
			return []byte("account is busy\n"), removeErr
		}
		lookupSystemUser = func(name string) (*user.User, error) { return &user.User{Username: name}, nil }
		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-busy", true)
		wantArgs := []string{"-r", "-f", "--", "lta-busy"}
		if !reflect.DeepEqual(gotArgs, wantArgs) {
			t.Fatalf("userdel args = %v, want %v", gotArgs, wantArgs)
		}
		if len(reporter.errors) != 1 || !strings.Contains(reporter.errors[0], "still exists") || !strings.Contains(reporter.errors[0], "account is busy") {
			t.Fatalf("surviving account cleanup errors = %v", reporter.errors)
		}
	})

	t.Run("strict pre-clean aborts on a surviving account", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return []byte("account is busy\n"), removeErr }
		lookupSystemUser = func(name string) (*user.User, error) { return &user.User{Username: name}, nil }
		reporter := &cleanupReporter{}
		RequireUserAbsent(reporter, "lta-stale", true)
		if len(reporter.fatals) != 1 || !strings.Contains(reporter.fatals[0], "still exists") || len(reporter.errors) != 0 {
			t.Fatalf("strict pre-clean reports: fatal=%v errors=%v", reporter.fatals, reporter.errors)
		}
	})

	t.Run("successful removal verifies user and group absence", func(t *testing.T) {
		isolateUserCleanup(t)
		groupLookups := 0
		userLookups := 0
		runUserdel = func(args ...string) ([]byte, error) {
			if reflect.DeepEqual(args, []string{"-r", "--", "lta-gone"}) {
				return nil, nil
			}
			return nil, errors.New("unexpected argv")
		}
		lookupSystemUser = func(name string) (*user.User, error) {
			userLookups++
			return nil, user.UnknownUserError(name)
		}
		lookupSystemGroup = func(name string) (*user.Group, error) {
			groupLookups++
			return nil, user.UnknownGroupError(name)
		}
		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-gone", false)
		if len(reporter.errors) != 0 {
			t.Fatalf("successful cleanup errors = %v", reporter.errors)
		}
		if groupLookups != 1 {
			t.Fatalf("group lookups = %d, want 1", groupLookups)
		}
		if userLookups != 2 {
			t.Fatalf("user lookups = %d, want pre/post group checks", userLookups)
		}
	})

	t.Run("successful userdel with surviving account is rejected", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return nil, nil }
		lookupSystemUser = func(name string) (*user.User, error) { return &user.User{Username: name}, nil }
		runGroupdel = func(...string) ([]byte, error) {
			t.Fatal("surviving account reached groupdel")
			return nil, nil
		}
		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-survivor", false)
		if len(reporter.errors) != 1 || !strings.Contains(reporter.errors[0], "reported success") || !strings.Contains(reporter.errors[0], "still exists") {
			t.Fatalf("successful userdel survivor errors = %v", reporter.errors)
		}
	})
}

func TestCleanupUserRemovesAndRechecksSameNameGroup(t *testing.T) {
	removeErr := errors.New("groupdel failed")

	t.Run("confirmed missing user still triggers group cleanup", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) {
			return []byte("user does not exist\n"), errors.New("userdel failed")
		}
		lookupSystemUser = func(name string) (*user.User, error) {
			return nil, user.UnknownUserError(name)
		}
		lookups := 0
		lookupSystemGroup = func(name string) (*user.Group, error) {
			lookups++
			if lookups == 1 {
				return &user.Group{Name: name}, nil
			}
			return nil, user.UnknownGroupError(name)
		}
		groupdelCalls := 0
		runGroupdel = func(...string) ([]byte, error) {
			groupdelCalls++
			return nil, nil
		}

		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-group", false)
		if len(reporter.errors) != 0 {
			t.Fatalf("confirmed missing user cleanup errors = %v", reporter.errors)
		}
		if groupdelCalls != 1 || lookups != 2 {
			t.Fatalf("group cleanup calls: groupdel=%d lookups=%d, want 1 and 2", groupdelCalls, lookups)
		}
	})

	t.Run("groupdel success is rechecked", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return nil, nil }
		lookups := 0
		lookupSystemGroup = func(name string) (*user.Group, error) {
			lookups++
			if lookups == 1 {
				return &user.Group{Name: name}, nil
			}
			return nil, user.UnknownGroupError(name)
		}
		var gotArgs []string
		runGroupdel = func(args ...string) ([]byte, error) {
			gotArgs = append([]string(nil), args...)
			return nil, nil
		}

		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-group", false)
		if len(reporter.errors) != 0 {
			t.Fatalf("successful group cleanup errors = %v", reporter.errors)
		}
		if !reflect.DeepEqual(gotArgs, []string{"--", "lta-group"}) {
			t.Fatalf("groupdel args = %v, want [-- lta-group]", gotArgs)
		}
		if lookups != 2 {
			t.Fatalf("group lookups = %d, want 2", lookups)
		}
	})

	t.Run("groupdel failure with surviving group is reported", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return nil, nil }
		lookupSystemGroup = func(name string) (*user.Group, error) {
			return &user.Group{Name: name}, nil
		}
		runGroupdel = func(...string) ([]byte, error) {
			return []byte("group is busy\n"), removeErr
		}

		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-group", false)
		if len(reporter.errors) != 1 || !strings.Contains(reporter.errors[0], "residue still exists") || !strings.Contains(reporter.errors[0], "group is busy") {
			t.Fatalf("failed group cleanup errors = %v", reporter.errors)
		}
	})

	t.Run("groupdel nonzero is tolerated after confirmed deletion", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return nil, nil }
		lookups := 0
		lookupSystemGroup = func(name string) (*user.Group, error) {
			lookups++
			if lookups == 1 {
				return &user.Group{Name: name}, nil
			}
			return nil, user.UnknownGroupError(name)
		}
		runGroupdel = func(...string) ([]byte, error) {
			return []byte("database warning\n"), removeErr
		}

		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-group", false)
		if len(reporter.errors) != 0 {
			t.Fatalf("confirmed group deletion errors = %v", reporter.errors)
		}
	})

	t.Run("successful groupdel with surviving group is reported", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return nil, nil }
		lookupSystemGroup = func(name string) (*user.Group, error) {
			return &user.Group{Name: name}, nil
		}
		runGroupdel = func(...string) ([]byte, error) { return nil, nil }

		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-group", false)
		if len(reporter.errors) != 1 || !strings.Contains(reporter.errors[0], "reported success") || !strings.Contains(reporter.errors[0], "residue still exists") {
			t.Fatalf("unremoved group errors = %v", reporter.errors)
		}
	})
}

func TestCleanupUserReportsUnverifiableGroupState(t *testing.T) {
	lookupErr := errors.New("group database unavailable")

	t.Run("before groupdel", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return nil, nil }
		lookupSystemGroup = func(string) (*user.Group, error) { return nil, lookupErr }
		runGroupdel = func(...string) ([]byte, error) {
			t.Fatal("groupdel ran without a confirmed group")
			return nil, nil
		}

		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-group", false)
		if len(reporter.errors) != 1 || !strings.Contains(reporter.errors[0], "cannot verify group/gshadow absence") {
			t.Fatalf("unverifiable initial group state errors = %v", reporter.errors)
		}
	})

	t.Run("after groupdel", func(t *testing.T) {
		isolateUserCleanup(t)
		runUserdel = func(...string) ([]byte, error) { return nil, nil }
		lookups := 0
		lookupSystemGroup = func(name string) (*user.Group, error) {
			lookups++
			if lookups == 1 {
				return &user.Group{Name: name}, nil
			}
			return nil, lookupErr
		}
		runGroupdel = func(...string) ([]byte, error) { return nil, nil }

		reporter := &cleanupReporter{}
		CleanupUser(reporter, "lta-group", false)
		if len(reporter.errors) != 1 || !strings.Contains(reporter.errors[0], "group/gshadow absence cannot be verified") {
			t.Fatalf("unverifiable final group state errors = %v", reporter.errors)
		}
	})
}

func TestInspectLocalGroupDatabaseFilesIncludesGShadow(t *testing.T) {
	dir := t.TempDir()
	oldGroup, oldGShadow := groupDatabasePath, gshadowDatabasePath
	groupDatabasePath = filepath.Join(dir, "group")
	gshadowDatabasePath = filepath.Join(dir, "gshadow")
	t.Cleanup(func() { groupDatabasePath, gshadowDatabasePath = oldGroup, oldGShadow })
	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(groupDatabasePath, "root:x:0:\nlta-group:x:2001:\n")
	write(gshadowDatabasePath, "root:!::\nlta-group:!::\n")
	state, err := inspectLocalGroupDatabaseFiles("lta-group")
	if err != nil || !state.group || !state.gshadow || !state.gshadowPresent {
		t.Fatalf("local group state = %+v err=%v", state, err)
	}

	write(groupDatabasePath, "root:x:0:\n")
	state, err = inspectLocalGroupDatabaseFiles("lta-group")
	if err != nil || state.group || !state.gshadow {
		t.Fatalf("orphaned gshadow state = %+v err=%v", state, err)
	}

	write(gshadowDatabasePath, "malformed\n")
	if _, err := inspectLocalGroupDatabaseFiles("lta-group"); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed gshadow error = %v", err)
	}
}
