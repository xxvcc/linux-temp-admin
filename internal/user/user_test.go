package user

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
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

func TestIsReservedName(t *testing.T) {
	reserved := []string{"root", "daemon", "nobody", "sshd", "systemd-network", "systemd-resolve", "systemd-", "systemd-x"}
	for _, n := range reserved {
		if !IsReservedName(n) {
			t.Errorf("IsReservedName(%q) = false, want true", n)
		}
	}
	// Names the create path must still allow: normal temp users, and near-misses
	// that are NOT in the reserved shape (a bare "systemd", a "systemdd-" prefix,
	// or a protected name merely used as a temp-username prefix).
	allowed := []string{"xxvcc-abcdef0123", "alice", "systemd", "systemdd-x1", "root-abcdef0123"}
	for _, n := range allowed {
		if IsReservedName(n) {
			t.Errorf("IsReservedName(%q) = true, want false", n)
		}
	}
	// Every reserved name must also be refused by the revoke path (defense in
	// depth: the two sides share this predicate and must never diverge).
	for _, n := range reserved {
		if !IsProtectedRevokeTarget(n, true) {
			t.Errorf("reserved %q is not a protected revoke target", n)
		}
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
		{"human", true, true},            // real uid, registered but NOT managed -> protected (stale entry / name reuse)
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
	stdin     []string // what each RunInput call was fed
}

func (f *fakeRunner) Run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.failOn[name] {
		return errForced
	}
	return nil
}
func (f *fakeRunner) RunInput(stdin string, name string, args ...string) error {
	f.stdin = append(f.stdin, stdin)
	return f.Run(name, args...)
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

// TestTerminateProcessesNeverSignalsRootOrAll pins the guard that keeps a
// mis-parsed or zero uid from signalling every root-owned process on the host.
// kill is stubbed, so a regression fails the test instead of killing the runner.
func TestTerminateProcessesNeverSignalsRootOrAll(t *testing.T) {
	var signalled [][2]int
	orig := kill
	kill = func(pid int, sig syscall.Signal) error {
		signalled = append(signalled, [2]int{pid, int(sig)})
		return nil
	}
	t.Cleanup(func() { kill = orig })

	for _, uid := range []int{0, -1, -1000} {
		TerminateProcesses(uid)
		if len(signalled) != 0 {
			t.Fatalf("uid %d must signal nothing, signalled %v", uid, signalled)
		}
	}
}
