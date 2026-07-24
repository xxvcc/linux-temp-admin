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
wiped:x:1002:1002:not the marker any more:/home/wiped:/bin/bash
escalated:x:0:0:` + config.ManagedGECOS + `:/home/escalated:/bin/bash
`

func TestLookupAndManaged(t *testing.T) {
	setPasswd(t, samplePasswd)
	pw, ok, err := Lookup("tmp1000")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || pw.UID != 1001 || pw.Home != "/home/tmp1000" {
		t.Fatalf("Lookup tmp1000 = %+v ok=%v", pw, ok)
	}
	if managed, err := IsManaged("tmp1000"); err != nil || !managed {
		t.Error("tmp1000 should be managed")
	}
	if managed, err := IsManaged("human"); err != nil || managed {
		t.Error("human should not be managed")
	}
	if exists, err := Exists("nope"); err != nil || exists {
		t.Error("nonexistent user should not Exist")
	}
}

func TestNameInUseConsultsNSSAfterLocalMiss(t *testing.T) {
	// Hide every local row from this package while leaving the real resolver
	// available. root must still be found through `id`, exercising the same path
	// used for LDAP/SSSD identities without requiring either service in CI.
	setPasswd(t, "")
	inUse, err := NameInUse("root")
	if err != nil {
		t.Fatal(err)
	}
	if !inUse {
		t.Fatal("NSS-visible identity was treated as an unused local username")
	}
}

func TestNameInUseFailsClosedWithoutResolver(t *testing.T) {
	setPasswd(t, "")
	t.Setenv("PATH", t.TempDir())
	if _, err := NameInUse("unused-name"); err == nil {
		t.Fatal("missing NSS resolver was treated as proof that a username is unused")
	}
}

func TestLookupErrorsAreNotAbsence(t *testing.T) {
	old := passwdPath
	passwdPath = t.TempDir() // ReadFile on a directory fails.
	t.Cleanup(func() { passwdPath = old })
	if _, _, err := Lookup("someone"); err == nil {
		t.Fatal("Lookup must report an unreadable passwd database")
	}
	if _, err := Exists("someone"); err == nil {
		t.Fatal("Exists must preserve the passwd read error")
	}
	if _, err := IsProtectedRevokeTarget("someone", true, 1001); err == nil {
		t.Fatal("revoke protection must fail closed on a passwd read error")
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
		if protected, err := IsProtectedRevokeTarget(n, true, 0); err != nil || !protected {
			t.Errorf("reserved %q is not a protected revoke target", n)
		}
	}
}

func TestIsProtectedRevokeTarget(t *testing.T) {
	setPasswd(t, samplePasswd)
	cases := []struct {
		name        string
		registered  bool
		recordedUID int // 0 = an older registry row that recorded no UID
		want        bool
	}{
		{"root", false, 0, true},            // uid 0 / blocklist
		{"daemon", false, 0, true},          // blocklist (not in passwd)
		{"systemd-network", false, 0, true}, // systemd- prefix
		{"svc", false, 0, true},             // system uid, unregistered
		{"svc", true, 0, true},              // system uid, registered but not managed
		{"tmp500", false, 0, true},          // managed system uid but unregistered
		{"tmp500", true, 0, false},          // managed + registered system uid -> deletable
		{"human", false, 0, true},           // real uid, unregistered human
		{"human", true, 0, true},            // real uid, registered but NOT managed -> protected (stale entry / name reuse)
		{"tmp1000", false, 0, false},        // managed real uid -> deletable even unregistered

		// A recorded UID detects contradictions but cannot prove identity on its own:
		// Linux can reuse the same UID after an account is deleted and recreated.
		{"wiped", true, 1002, true},  // marker erased: UID alone is reusable and cannot prove identity
		{"wiped", true, 0, true},     // same account, legacy row with no recorded uid -> old GECOS rule -> protected
		{"wiped", false, 1002, true}, // unregistered: a recorded uid we never wrote proves nothing
		{"wiped", true, 9999, true},  // recorded uid does NOT match -> not the account we made -> protected

		// A recorded UID must never make a real account deletable, even when it
		// matches exactly: the username and UID can both be reused.
		{"human", true, 1000, true}, // matching UID can belong to a recreated real account
		{"human", true, 1234, true}, // recorded uid disagrees with passwd -> real account stays protected

		// A recorded UID that disagrees is not a MISSING witness but a CONTRADICTING
		// one, and the marker must not overrule it. The two rows above only ever
		// exercised that rule on accounts whose marker was absent anyway, so the case
		// that decides it — marker intact, recorded UID contradicting — went untested
		// and returned "deletable". revoke then aimed its SIGKILL sweep at the UID in
		// passwd, i.e. at whatever UID the account had been given.
		{"tmp1000", true, 9999, true}, // marker intact BUT recorded uid contradicts -> protected

		// Escalating to uid 0 stays protected — never auto-delete a root account —
		// even though it is registered, managed, and its name is ours.
		{"escalated", true, 1003, true},
		{"escalated", true, 0, true},
	}
	for _, c := range cases {
		got, err := IsProtectedRevokeTarget(c.name, c.registered, c.recordedUID)
		if err != nil {
			t.Fatalf("IsProtectedRevokeTarget(%q): %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("IsProtectedRevokeTarget(%q, registered=%v, recordedUID=%d) = %v, want %v",
				c.name, c.registered, c.recordedUID, got, c.want)
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
	//
	// The -f is load-bearing, not decoration: without it shadow's userdel exits 8
	// whenever a session exists, so an invitee reconnecting in a loop could make
	// every revoke fail and keep the account alive.
	f := &fakeRunner{available: map[string]bool{"deluser": true, "userdel": true}, failOn: map[string]bool{"deluser": true}}
	m := &Manager{Runner: f}
	if err := m.Delete("u"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0][0] != "deluser" || !reflect.DeepEqual(f.calls[1], []string{"userdel", "-r", "-f", "--", "u"}) {
		t.Errorf("delete calls = %v", f.calls)
	}
}

// TestDisableLoginExpiresBeforeLocking pins the H2 fix: revoke must shut the
// account's door before it starts taking it apart. Expiry is what actually stops
// a KEY login (locking the password alone would not), so it must be issued.
func TestDisableLoginExpiresBeforeLocking(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"chage": true, "usermod": true}}
	m := &Manager{Runner: f}
	if err := m.DisableLogin("u"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("DisableLogin calls = %v, want chage then usermod", f.calls)
	}
	if !reflect.DeepEqual(f.calls[0], []string{"chage", "-E", "1970-01-01", "u"}) {
		t.Errorf("first call = %v, want the account expired to a past date", f.calls[0])
	}
	if !reflect.DeepEqual(f.calls[1], []string{"usermod", "-L", "u"}) {
		t.Errorf("second call = %v, want the password locked", f.calls[1])
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
