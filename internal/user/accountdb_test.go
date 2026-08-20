package user

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	accountDBTestName = "xxvcc-db1"
	accountDBTestID   = 2001
)

type accountDBContents struct {
	passwd  string
	group   string
	gshadow string
	subuid  string
	subgid  string
}

func setAccountDBContents(t *testing.T, contents accountDBContents) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	oldPasswd, oldGroup := passwdPath, groupPath
	oldGShadow, oldSubUID, oldSubGID := gshadowPath, subuidPath, subgidPath
	passwdPath = write("passwd", contents.passwd)
	groupPath = write("group", contents.group)
	gshadowPath = write("gshadow", contents.gshadow)
	subuidPath = write("subuid", contents.subuid)
	subgidPath = write("subgid", contents.subgid)
	t.Cleanup(func() {
		passwdPath, groupPath = oldPasswd, oldGroup
		gshadowPath, subuidPath, subgidPath = oldGShadow, oldSubUID, oldSubGID
	})
}

func accountDBLiveContents() accountDBContents {
	return accountDBContents{
		passwd:  accountDBTestName + ":x:2001:2001::/home/" + accountDBTestName + ":/bin/sh\n",
		group:   accountDBTestName + ":x:2001:\n",
		gshadow: accountDBTestName + ":!::\n",
	}
}

func absentAccountManager(r Runner) *Manager {
	return &Manager{
		Runner:     r,
		LookupUser: Lookup,
		NameInUse:  func(string) (bool, error) { return false, nil },
	}
}

func TestPreflightSequentialAccountCreationRejectsDatabaseResidue(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contents accountDBContents
		groupdel bool
		want     string
	}{
		{name: "clean", groupdel: true},
		{name: "groupdel missing", want: "groupdel is required"},
		{name: "same-name group", groupdel: true, contents: accountDBContents{
			group: accountDBTestName + ":x:2001:\n", gshadow: accountDBTestName + ":!::\n",
		}, want: "already exists"},
		{name: "malformed group entry", groupdel: true, contents: accountDBContents{
			group: "broken\n",
		}, want: "malformed group entry"},
		{name: "malformed group gid", groupdel: true, contents: accountDBContents{
			group: "other:x:not-a-gid:\n",
		}, want: "malformed group GID"},
		{name: "duplicate group entry", groupdel: true, contents: accountDBContents{
			group: "other:x:3001:\nother:x:3002:\n",
		}, want: "duplicate group entries"},
		{name: "orphaned gshadow", groupdel: true, contents: accountDBContents{
			gshadow: accountDBTestName + ":!::\n",
		}, want: "orphaned gshadow"},
		{name: "malformed gshadow entry", groupdel: true, contents: accountDBContents{
			gshadow: "broken\n",
		}, want: "malformed gshadow entry"},
		{name: "duplicate gshadow entry", groupdel: true, contents: accountDBContents{
			gshadow: "other:!::\nother:!::\n",
		}, want: "duplicate gshadow entries"},
		{name: "stale subuid", groupdel: true, contents: accountDBContents{
			subuid: accountDBTestName + ":100000:65536\n",
		}, want: "subuid assignment remains"},
		{name: "stale subgid", groupdel: true, contents: accountDBContents{
			subgid: accountDBTestName + ":100000:65536\n",
		}, want: "subgid assignment remains"},
		{name: "malformed subuid entry", groupdel: true, contents: accountDBContents{
			subuid: "other:not-a-start:65536\n",
		}, want: "malformed subuid range"},
		{name: "malformed subgid entry", groupdel: true, contents: accountDBContents{
			subgid: "other:100000\n",
		}, want: "malformed subgid entry"},
		{name: "duplicate stale subuid assignments", groupdel: true, contents: accountDBContents{
			subuid: accountDBTestName + ":100000:65536\n" + accountDBTestName + ":200000:65536\n",
		}, want: "subuid assignment remains"},
		{name: "duplicate stale subgid assignments", groupdel: true, contents: accountDBContents{
			subgid: accountDBTestName + ":100000:65536\n" + accountDBTestName + ":200000:65536\n",
		}, want: "subgid assignment remains"},
		{name: "multiple valid ranges for another owner", groupdel: true, contents: accountDBContents{
			subuid: "other:100000:65536\nother:200000:65536\n",
			subgid: "other:100000:65536\nother:200000:65536\n",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setAccountDBContents(t, tc.contents)
			f := &fakeRunner{available: map[string]bool{"groupdel": tc.groupdel}}
			err := (&Manager{Runner: f}).preflightSequentialAccountCreation(accountDBTestName, accountDBTestID)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("preflight error = %v, want %q", err, tc.want)
			}
			if len(f.calls) != 0 {
				t.Fatalf("preflight invoked a helper: %v", f.calls)
			}
		})
	}
}

func TestPreflightPrivateGroupRemovalRequiresOriginalEmptyShape(t *testing.T) {
	base := accountDBLiveContents()
	for _, tc := range []struct {
		name     string
		mutate   func(*accountDBContents)
		groupdel bool
		want     string
	}{
		{name: "safe", groupdel: true},
		{name: "groupdel missing", want: "groupdel is required"},
		{name: "group missing", groupdel: true, mutate: func(c *accountDBContents) { c.group, c.gshadow = "", "" }, want: "missing"},
		{name: "gid changed", groupdel: true, mutate: func(c *accountDBContents) { c.group = accountDBTestName + ":x:2002:\n" }, want: "want 2001"},
		{name: "empty group password", groupdel: true, mutate: func(c *accountDBContents) { c.group = accountDBTestName + "::2001:\n" }, want: "not explicitly locked"},
		{name: "enabled group password", groupdel: true, mutate: func(c *accountDBContents) { c.group = accountDBTestName + ":$6$salt$hash:2001:\n" }, want: "not explicitly locked"},
		{name: "star group password", groupdel: true, mutate: func(c *accountDBContents) { c.group = accountDBTestName + ":*:2001:\n" }},
		{name: "locked group password", groupdel: true, mutate: func(c *accountDBContents) { c.group = accountDBTestName + ":!$6$salt$hash:2001:\n" }},
		{name: "explicit member", groupdel: true, mutate: func(c *accountDBContents) { c.group = accountDBTestName + ":x:2001:alice\n" }, want: "explicit members"},
		{name: "empty gshadow password", groupdel: true, mutate: func(c *accountDBContents) { c.gshadow = accountDBTestName + ":::\n" }},
		{name: "star gshadow password", groupdel: true, mutate: func(c *accountDBContents) { c.gshadow = accountDBTestName + ":*::\n" }},
		{name: "locked gshadow password", groupdel: true, mutate: func(c *accountDBContents) { c.gshadow = accountDBTestName + ":!$6$salt$hash::\n" }},
		{name: "enabled gshadow password", groupdel: true, mutate: func(c *accountDBContents) { c.gshadow = accountDBTestName + ":$6$salt$hash::\n" }, want: "enabled gshadow password"},
		{name: "gshadow member", groupdel: true, mutate: func(c *accountDBContents) { c.gshadow = accountDBTestName + ":!::alice\n" }, want: "gshadow administrators or members"},
		{name: "other primary user", groupdel: true, mutate: func(c *accountDBContents) { c.passwd += "alice:x:2002:2001::/home/alice:/bin/sh\n" }, want: "account alice"},
		{name: "other same gid group", groupdel: true, mutate: func(c *accountDBContents) { c.group += "other:x:2001:\n" }, want: "also uses expected private GID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := base
			if tc.mutate != nil {
				tc.mutate(&contents)
			}
			setAccountDBContents(t, contents)
			f := &fakeRunner{available: map[string]bool{"groupdel": tc.groupdel}}
			err := (&Manager{Runner: f}).preflightPrivateGroupRemoval(Passwd{
				Name: accountDBTestName, UID: accountDBTestID, GID: accountDBTestID,
			})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("private-group preflight error = %v, want %q", err, tc.want)
			}
			if len(f.calls) != 0 {
				t.Fatalf("preflight invoked a helper: %v", f.calls)
			}
		})
	}
}

func TestPrivateGroupPasswordValidationDoesNotDependOnGShadow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "placeholder", password: "x"},
		{name: "star lock", password: "*"},
		{name: "bang lock", password: "!$6$salt$hash"},
		{name: "empty", password: "", wantErr: true},
		{name: "enabled hash", password: "$6$salt$hash", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := accountDBLiveContents()
			contents.group = accountDBTestName + ":" + tc.password + ":2001:\n"
			setAccountDBContents(t, contents)
			if err := os.Remove(gshadowPath); err != nil {
				t.Fatal(err)
			}
			f := &fakeRunner{available: map[string]bool{"groupdel": true}}
			err := (&Manager{Runner: f}).preflightPrivateGroupRemoval(Passwd{
				Name: accountDBTestName, UID: accountDBTestID, GID: accountDBTestID,
			})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "not explicitly locked") {
					t.Fatalf("private-group preflight error = %v, want group-password refusal", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if len(f.calls) != 0 {
				t.Fatalf("preflight invoked a helper: %v", f.calls)
			}
		})
	}
}

func TestReconcileAccountDatabaseRemovesOnlyProvenPrivateGroup(t *testing.T) {
	t.Run("successful groupdel", func(t *testing.T) {
		contents := accountDBLiveContents()
		contents.passwd = ""
		setAccountDBContents(t, contents)
		f := &fakeRunner{available: map[string]bool{"groupdel": true}}
		f.onRun = func(name string) {
			if name == "groupdel" {
				if err := os.WriteFile(groupPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(gshadowPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := absentAccountManager(f).ReconcileAccountDatabaseAfterDeletion(accountDBTestName, accountDBTestID, true); err != nil {
			t.Fatal(err)
		}
		want := [][]string{{"groupdel", "--", accountDBTestName}}
		if !reflect.DeepEqual(f.calls, want) {
			t.Fatalf("helper calls = %v, want %v", f.calls, want)
		}
	})

	t.Run("groupdel nonzero after removal keeps recovery error", func(t *testing.T) {
		contents := accountDBLiveContents()
		contents.passwd = ""
		setAccountDBContents(t, contents)
		f := &fakeRunner{available: map[string]bool{"groupdel": true}, failOn: map[string]bool{"groupdel": true}}
		f.onRun = func(string) {
			_ = os.WriteFile(groupPath, nil, 0o600)
			_ = os.WriteFile(gshadowPath, nil, 0o600)
		}
		err := absentAccountManager(f).ReconcileAccountDatabaseAfterDeletion(accountDBTestName, accountDBTestID, true)
		if !errors.Is(err, errForced) || !strings.Contains(err.Error(), "reported incomplete cleanup") {
			t.Fatalf("reconcile error = %v, want retained helper failure", err)
		}
	})

	t.Run("groupdel success without removal keeps recovery error", func(t *testing.T) {
		contents := accountDBLiveContents()
		contents.passwd = ""
		setAccountDBContents(t, contents)
		f := &fakeRunner{available: map[string]bool{"groupdel": true}}
		err := absentAccountManager(f).ReconcileAccountDatabaseAfterDeletion(accountDBTestName, accountDBTestID, true)
		if err == nil || !strings.Contains(err.Error(), "reported success but private group") {
			t.Fatalf("reconcile error = %v, want retained private-group residue", err)
		}
		want := [][]string{{"groupdel", "--", accountDBTestName}}
		if !reflect.DeepEqual(f.calls, want) {
			t.Fatalf("helper calls = %v, want %v", f.calls, want)
		}
	})

	t.Run("group replacement after groupdel is not accepted as removal", func(t *testing.T) {
		contents := accountDBLiveContents()
		contents.passwd = ""
		setAccountDBContents(t, contents)
		f := &fakeRunner{available: map[string]bool{"groupdel": true}}
		f.onRun = func(name string) {
			if name != "groupdel" {
				return
			}
			if err := os.WriteFile(groupPath, []byte(accountDBTestName+":x:2002:\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(gshadowPath, []byte(accountDBTestName+":!::\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err := absentAccountManager(f).ReconcileAccountDatabaseAfterDeletion(accountDBTestName, accountDBTestID, true)
		if err == nil || !strings.Contains(err.Error(), "has GID 2002, want 2001") {
			t.Fatalf("reconcile error = %v, want replacement-group refusal", err)
		}
	})

	t.Run("legacy witness detects but never deletes group", func(t *testing.T) {
		contents := accountDBLiveContents()
		contents.passwd = ""
		contents.group = accountDBTestName + ":x:3456:\n"
		setAccountDBContents(t, contents)
		f := &fakeRunner{available: map[string]bool{"groupdel": true}}
		err := absentAccountManager(f).ReconcileAccountDatabaseAfterDeletion(accountDBTestName, 0, false)
		if err == nil || !strings.Contains(err.Error(), "does not prove its GID") {
			t.Fatalf("legacy reconcile error = %v, want manual group recovery", err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("legacy recovery invoked groupdel: %v", f.calls)
		}
	})

	t.Run("subordinate IDs keep recovery open", func(t *testing.T) {
		setAccountDBContents(t, accountDBContents{subuid: accountDBTestName + ":100000:65536\n"})
		f := &fakeRunner{available: map[string]bool{"groupdel": true}}
		err := absentAccountManager(f).ReconcileAccountDatabaseAfterDeletion(accountDBTestName, accountDBTestID, true)
		if err == nil || !strings.Contains(err.Error(), "subuid assignment remains") {
			t.Fatalf("subuid reconcile error = %v", err)
		}
	})
}

func TestReconcileAccountDatabaseRejectsAccountReappearanceAroundGroupdel(t *testing.T) {
	for _, tc := range []struct {
		name            string
		reappearsBefore bool
		want            string
		wantCalls       int
	}{
		{name: "before groupdel", reappearsBefore: true, want: "reappeared before groupdel"},
		{name: "after groupdel", want: "reappeared during groupdel", wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := false
			lookups := 0
			f := &fakeRunner{available: map[string]bool{"groupdel": true}}
			f.onRun = func(name string) {
				if name == "groupdel" {
					run = true
				}
			}
			m := &Manager{
				Runner: f,
				LookupUser: func(string) (Passwd, bool, error) {
					lookups++
					exists := (tc.reappearsBefore && lookups >= 2) || (!tc.reappearsBefore && run)
					return Passwd{Name: accountDBTestName}, exists, nil
				},
				NameInUse: func(string) (bool, error) { return false, nil },
				InspectPrivateGroupState: func(string, int, bool) (bool, error) {
					return !run, nil
				},
				CheckSubordinateIDsAbsent: func(string) error { return nil },
			}
			err := m.ReconcileAccountDatabaseAfterDeletion(accountDBTestName, accountDBTestID, true)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reconcile error = %v, want %q", err, tc.want)
			}
			if len(f.calls) != tc.wantCalls {
				t.Fatalf("groupdel calls = %v, want %d", f.calls, tc.wantCalls)
			}
		})
	}
}

func TestDeleteExpectedSequentialRevalidatesGroupImmediatelyBeforeUserdel(t *testing.T) {
	contents := accountDBLiveContents()
	setAccountDBContents(t, contents)
	f := &fakeRunner{available: map[string]bool{"userdel": true, "groupdel": true}}
	m := absentAccountManager(f)
	m.RemoveManagedMail = func(Passwd) error { return nil }
	m.RemoveManagedHome = func(Passwd) error { return nil }
	expected := Passwd{
		Name: accountDBTestName, UID: accountDBTestID, GID: accountDBTestID,
		Home: "/home/" + accountDBTestName, Shell: "/bin/sh",
	}
	err := m.DeleteExpectedSequential(accountDBTestName, expected, func() error {
		return os.WriteFile(groupPath, []byte(accountDBTestName+":x:2001:alice\n"), 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "revalidate managed private group") {
		t.Fatalf("DeleteExpectedSequential error = %v, want late group-shape refusal", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("late group replacement reached userdel: %v", f.calls)
	}
}

func TestDeleteExpectedSequentialExplicitlyRemovesGroupLeftByUserdel(t *testing.T) {
	setAccountDBContents(t, accountDBLiveContents())
	f := &fakeRunner{available: map[string]bool{"userdel": true, "groupdel": true}}
	f.onRun = func(name string) {
		switch name {
		case "userdel":
			if err := os.WriteFile(passwdPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		case "groupdel":
			if err := os.WriteFile(groupPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(gshadowPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	m := absentAccountManager(f)
	m.RemoveManagedMail = func(Passwd) error { return nil }
	m.RemoveManagedHome = func(Passwd) error { return nil }
	expected := Passwd{
		Name: accountDBTestName, UID: accountDBTestID, GID: accountDBTestID,
		Home: "/home/" + accountDBTestName, Shell: "/bin/sh",
	}
	if err := m.DeleteExpectedSequential(accountDBTestName, expected, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"userdel", "--", accountDBTestName}, {"groupdel", "--", accountDBTestName}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("helper calls = %v, want %v", f.calls, want)
	}
}

func TestDeleteExpectedSequentialSkipsGroupdelWhenUserdelRemovedPrivateGroup(t *testing.T) {
	setAccountDBContents(t, accountDBLiveContents())
	f := &fakeRunner{available: map[string]bool{"userdel": true, "groupdel": true}}
	f.onRun = func(name string) {
		if name != "userdel" {
			return
		}
		for _, path := range []string{passwdPath, groupPath, gshadowPath} {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	m := absentAccountManager(f)
	m.RemoveManagedMail = func(Passwd) error { return nil }
	m.RemoveManagedHome = func(Passwd) error { return nil }
	expected := Passwd{
		Name: accountDBTestName, UID: accountDBTestID, GID: accountDBTestID,
		Home: "/home/" + accountDBTestName, Shell: "/bin/sh",
	}
	if err := m.DeleteExpectedSequential(accountDBTestName, expected, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"userdel", "--", accountDBTestName}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("helper calls = %v, want %v", f.calls, want)
	}
}

func TestDeleteExpectedSequentialRejectsGIDTamperingBeforeCleanup(t *testing.T) {
	expected := Passwd{
		Name: accountDBTestName, UID: accountDBTestID, GID: accountDBTestID,
		GECOS: testManagedGenerationGECOS(t), Home: "/home/" + accountDBTestName, Shell: "/bin/sh",
	}
	current := expected
	current.GID++
	f := &fakeRunner{available: map[string]bool{"userdel": true, "groupdel": true}}
	cleanupCalls := 0
	m := &Manager{
		Runner:     f,
		LookupUser: func(string) (Passwd, bool, error) { return current, true, nil },
		RemoveManagedMail: func(Passwd) error {
			cleanupCalls++
			return nil
		},
		RemoveManagedHome: func(Passwd) error {
			cleanupCalls++
			return nil
		},
	}
	err := m.DeleteExpectedSequential(accountDBTestName, expected, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("DeleteExpectedSequential error = %v, want GID-tamper refusal", err)
	}
	if cleanupCalls != 0 || len(f.calls) != 0 {
		t.Fatalf("GID-tampered identity reached cleanup: cleanup=%d helpers=%v", cleanupCalls, f.calls)
	}
}

func TestFailedUseraddWithoutPasswdIsStillCreationStarted(t *testing.T) {
	setAccountDBContents(t, accountDBContents{})
	f := &fakeRunner{
		available: map[string]bool{"useradd": true, "groupdel": true},
		failOn:    map[string]bool{"useradd": true},
	}
	m := managerWithStubbedHomeChecks(f)
	m.InspectPrivateGroupState = nil
	m.CheckSubordinateIDsAbsent = nil
	_, err := m.CreatePendingIdentityWithID(accountDBTestName, "/bin/sh", testGeneration, accountDBTestID)
	if err == nil || errors.Is(err, ErrAccountCreationNotStarted) || !strings.Contains(err.Error(), "creation started") {
		t.Fatalf("failed useradd error = %v, want started-without-passwd classification", err)
	}
	if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
		t.Fatalf("failed useradd calls = %v", f.calls)
	}
}
