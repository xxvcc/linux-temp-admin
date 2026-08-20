//go:build integration

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

type failedAbsentSequentialRunner struct {
	groupPresent bool
	groupdelErr  error
	calls        [][]string
}

func (*failedAbsentSequentialRunner) Look(name string) bool {
	return name == "useradd" || name == "groupdel"
}

func (r *failedAbsentSequentialRunner) Run(name string, args ...string) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	switch name {
	case "useradd":
		r.groupPresent = true
		return errors.New("injected useradd failure after partial database update")
	case "groupdel":
		if r.groupdelErr == nil {
			r.groupPresent = false
		}
		return r.groupdelErr
	default:
		return fmt.Errorf("unexpected helper %s", name)
	}
}

func (r *failedAbsentSequentialRunner) RunInput(_ string, name string, args ...string) error {
	return r.Run(name, args...)
}

func unusedAccountDBWiringName(t *testing.T, suffix string) string {
	t.Helper()
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("ltadb%s%02d", suffix, i)
		inUse, err := user.NameInUse(name)
		if err != nil {
			t.Fatal(err)
		}
		if !inUse {
			return name
		}
	}
	t.Fatal("could not find an unused account-database wiring test name")
	return ""
}

func TestInviteReconcilesPartialUseraddAccountDatabaseState(t *testing.T) {
	const reservedID = 4_000_000
	for _, tc := range []struct {
		name          string
		suffix        string
		groupdelErr   error
		wantRegistry  bool
		wantGroupLeft bool
	}{
		{name: "group cleanup succeeds", suffix: "ok"},
		{name: "group cleanup fails", suffix: "er", groupdelErr: errors.New("injected groupdel failure"), wantRegistry: true, wantGroupLeft: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := rootOwnedDir(t)
			username := unusedAccountDBWiringName(t, tc.suffix)
			runner := &failedAbsentSequentialRunner{groupdelErr: tc.groupdelErr}
			lookup := func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
			a, _, _ := newTestApp(t, "")
			a.Registry = &registry.Store{
				Dir:  filepath.Join(rootDir, "registry"),
				File: filepath.Join(rootDir, "registry", "registry.tsv"),
				Lock: filepath.Join(rootDir, "registry", "registry.lock"),
			}
			a.Users = &user.Manager{
				Runner:                    runner,
				LookupUser:                lookup,
				NameInUse:                 func(string) (bool, error) { return false, nil },
				InspectPrivateGroupState:  func(_ string, gid int, _ bool) (bool, error) { return runner.groupPresent && gid == reservedID, nil },
				InspectSameNameGroupState: func(string) (bool, error) { return runner.groupPresent, nil },
				CheckSubordinateIDsAbsent: func(string) error { return nil },
				ValidateManagedMailRoots:  func() error { return nil },
				PrepareManagedHome:        func(string) error { return nil },
				RemoveManagedMail:         func(user.Passwd) error { return nil },
			}
			a.LookupUser = lookup
			a.IdentityAllocationRange = func() (int, int, error) { return reservedID, reservedID, nil }
			a.RandHex = func(n int) (string, error) {
				if n == 16 {
					return "0123456789abcdef0123456789abcdef", nil
				}
				return "abcdef0123", nil
			}
			a.Scheduler = &schedule.Scheduler{
				SystemdDir:  filepath.Join(rootDir, "systemd"),
				InstallPath: filepath.Join(rootDir, "linux-temp-admin"),
				UnitPrefix:  config.AutoRevokeUnitPrefix, Now: a.Now, Sys: fakeSys{},
			}

			if rc := a.runInviteWithIdentityPolicy(username, "192.0.2.1", 22, 1, false, true, loginPlan{verified: true}, false); rc != 1 {
				t.Fatalf("runInvite rc = %d, want original useradd failure", rc)
			}
			wantCalls := [][]string{
				{"useradd", "-M", "-d", "/home/" + username, "-s", resolveShell(), "-c", ",,,," + config.PendingGenerationGECOSWitnessPrefix + "0123456789abcdef0123456789abcdef", "-e", "1970-01-01", "-p", "!", "-U", "-u", "4000000", "-K", "GID_MIN=4000000", "-K", "GID_MAX=4000000", username},
				{"groupdel", "--", username},
			}
			if !reflect.DeepEqual(runner.calls, wantCalls) {
				t.Fatalf("account helper calls = %v, want %v", runner.calls, wantCalls)
			}
			if runner.groupPresent != tc.wantGroupLeft {
				t.Fatalf("group residue present = %v, want %v", runner.groupPresent, tc.wantGroupLeft)
			}
			stored, found, err := a.Registry.Lookup(username)
			if err != nil {
				t.Fatal(err)
			}
			if found != tc.wantRegistry {
				t.Fatalf("registry recovery row found = %v, want %v (record %+v)", found, tc.wantRegistry, stored)
			}
			if found && (!stored.DeletionStarted || !stored.SequentialID || stored.Pending || stored.IdentityBound || stored.UID != reservedID) {
				t.Fatalf("retained deletion recovery row = %+v", stored)
			}
		})
	}
}
