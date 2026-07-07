package user

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
)

// setPasswd points Lookup at a temporary passwd file for the test.
func setPasswd(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := passwdPath
	passwdPath = p
	t.Cleanup(func() { passwdPath = old })
}

const samplePasswd = `root:x:0:0:root:/root:/bin/bash
svc:x:200:200::/var/lib/svc:/usr/sbin/nologin
human:x:1000:1000:A Human:/home/human:/bin/bash
tmp1000:x:1001:1001:` + config.ManagedGECOS + `,,,:/home/tmp1000:/bin/bash
tmp500:x:500:500:` + config.ManagedGECOS + `:/home/tmp500:/bin/bash
`

func TestLookupAndManaged(t *testing.T) {
	setPasswd(t, samplePasswd)
	pw, ok := Lookup("tmp1000")
	if !ok || pw.UID != 1001 || pw.Home != "/home/tmp1000" {
		t.Fatalf("Lookup tmp1000 = %+v ok=%v", pw, ok)
	}
	if !IsManaged("tmp1000") {
		t.Error("tmp1000 should be managed")
	}
	if IsManaged("human") {
		t.Error("human should not be managed")
	}
	if Exists("nope") {
		t.Error("nonexistent user should not Exist")
	}
}

func TestIsProtectedRevokeTarget(t *testing.T) {
	setPasswd(t, samplePasswd)
	cases := []struct {
		name       string
		registered bool
		want       bool
	}{
		{"root", false, true},            // uid 0 / blocklist
		{"daemon", false, true},          // blocklist (not in passwd)
		{"systemd-network", false, true}, // systemd- prefix
		{"svc", false, true},             // system uid, unregistered
		{"svc", true, true},              // system uid, registered but not managed
		{"tmp500", false, true},          // managed system uid but unregistered
		{"tmp500", true, false},          // managed + registered system uid -> deletable
		{"human", false, true},           // real uid, unregistered human
		{"human", true, false},           // real uid, registered -> deletable
		{"tmp1000", false, false},        // managed real uid -> deletable even unregistered
	}
	for _, c := range cases {
		if got := IsProtectedRevokeTarget(c.name, c.registered); got != c.want {
			t.Errorf("IsProtectedRevokeTarget(%q, registered=%v) = %v, want %v", c.name, c.registered, got, c.want)
		}
	}
}

type fakeRunner struct {
	available map[string]bool
	failOn    map[string]bool
	calls     [][]string
}

func (f *fakeRunner) Run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.failOn[name] {
		return errForced
	}
	return nil
}
func (f *fakeRunner) Look(name string) bool { return f.available[name] }

var errForced = &forcedErr{}

type forcedErr struct{}

func (*forcedErr) Error() string { return "forced failure" }

func TestCreateArgvUseradd(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"useradd": true, "adduser": true}}
	m := &Manager{Runner: f}
	if err := m.Create("xxvcc-a1", "/bin/bash"); err != nil {
		t.Fatal(err)
	}
	want := []string{"useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGECOS, "xxvcc-a1"}
	if len(f.calls) != 1 || !reflect.DeepEqual(f.calls[0], want) {
		t.Errorf("useradd argv = %v, want %v", f.calls, want)
	}
}

func TestCreateArgvAdduserBusybox(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"adduser": true}} // no useradd
	m := &Manager{Runner: f}
	if err := m.Create("xxvcc-a1", "/bin/sh"); err != nil {
		t.Fatal(err)
	}
	want := []string{"adduser", "-D", "-s", "/bin/sh", "-g", config.ManagedGECOS, "xxvcc-a1"}
	if !reflect.DeepEqual(f.calls[0], want) {
		t.Errorf("adduser argv = %v, want %v", f.calls[0], want)
	}
}

func TestLockExpiryArgv(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{}}
	m := &Manager{Runner: f}
	_ = m.LockPassword("u")
	_ = m.SetExpiry("u", "2026-07-09")
	want := [][]string{{"usermod", "-L", "u"}, {"chage", "-E", "2026-07-09", "u"}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Errorf("calls = %v, want %v", f.calls, want)
	}
}

func TestDeleteFallsBackToUserdel(t *testing.T) {
	// deluser present but fails -> userdel is tried.
	f := &fakeRunner{available: map[string]bool{"deluser": true, "userdel": true}, failOn: map[string]bool{"deluser": true}}
	m := &Manager{Runner: f}
	if err := m.Delete("u"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0][0] != "deluser" || !reflect.DeepEqual(f.calls[1], []string{"userdel", "-r", "--", "u"}) {
		t.Errorf("delete calls = %v", f.calls)
	}
}
