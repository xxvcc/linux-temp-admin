package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"golang.org/x/sys/unix"
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

func writeUserCommand(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

const testGeneration = "0123456789abcdef0123456789abcdef"

const samplePasswd = `root:x:0:0:root:/root:/bin/bash
svc:x:200:200::/var/lib/svc:/usr/sbin/nologin
human:x:1000:1000:A Human:/home/human:/bin/bash
tmp1000:x:1001:1001:` + config.ManagedGenerationGECOSPrefix + testGeneration + `,,,:/home/tmp1000:/bin/bash
tmp500:x:500:500:` + config.ManagedGenerationGECOSPrefix + testGeneration + `:/home/tmp500:/bin/bash
legacy:x:1004:1004:` + config.ManagedGECOS + `:/home/legacy:/bin/bash
wiped:x:1002:1002:not the marker any more:/home/wiped:/bin/bash
escalated:x:0:0:` + config.ManagedGenerationGECOSPrefix + testGeneration + `:/home/escalated:/bin/bash
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

func TestGenerationBoundManagedMarkers(t *testing.T) {
	const otherGeneration = "fedcba9876543210fedcba9876543210"
	tests := []struct {
		name       string
		gecos      string
		managed    bool
		legacy     bool
		matchesGen bool
	}{
		{name: "legacy", gecos: config.ManagedGECOS + ",,,", managed: true, legacy: true},
		{name: "bound", gecos: config.ManagedGenerationGECOSPrefix + testGeneration + ",,,", managed: true, matchesGen: true},
		{name: "other generation", gecos: config.ManagedGenerationGECOSPrefix + otherGeneration, managed: true},
		{name: "malformed generation", gecos: config.ManagedGenerationGECOSPrefix + "short"},
		{name: "substring", gecos: "prefix " + config.ManagedGECOS},
		{name: "pending", gecos: config.PendingGenerationGECOSPrefix + testGeneration},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pw := Passwd{GECOS: tc.gecos}
			if got := IsManagedEntry(pw); got != tc.managed {
				t.Errorf("IsManagedEntry = %v, want %v", got, tc.managed)
			}
			if got := IsLegacyManagedEntry(pw); got != tc.legacy {
				t.Errorf("IsLegacyManagedEntry = %v, want %v", got, tc.legacy)
			}
			if got := MatchesManagedGeneration(pw, testGeneration); got != tc.matchesGen {
				t.Errorf("MatchesManagedGeneration = %v, want %v", got, tc.matchesGen)
			}
		})
	}
	if _, err := ManagedGECOSForGeneration("short"); err == nil {
		t.Fatal("ManagedGECOSForGeneration accepted an invalid generation")
	}
}

func TestLookupRejectsReservedKernelIDs(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot represent the reserved uint32 uid/gid sentinel")
	}
	reserved := uint64(^uint32(0))
	for _, entry := range []string{
		fmt.Sprintf("baduid:x:%d:1000::/home/baduid:/bin/sh\n", reserved),
		fmt.Sprintf("badgid:x:1000:%d::/home/badgid:/bin/sh\n", reserved),
	} {
		setPasswd(t, entry)
		name := strings.SplitN(entry, ":", 2)[0]
		if _, _, err := Lookup(name); err == nil || !strings.Contains(err.Error(), "malformed passwd entry") {
			t.Fatalf("Lookup(%s) error = %v, want invalid uid/gid refusal", name, err)
		}
	}
}

func TestReadPasswdDatabaseIsBoundedAndRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswdDatabase(path, 4); err == nil || !strings.Contains(err.Error(), "4-byte limit") {
		t.Fatalf("oversized passwd error = %v, want bounded-read refusal", err)
	}
	fifo := filepath.Join(dir, "passwd.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswdDatabase(fifo, 4); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO passwd error = %v, want regular-file refusal", err)
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

func TestNameInUseDistinguishesConfirmedMissFromResolverFailure(t *testing.T) {
	tests := []struct {
		name       string
		diagnostic string
		wantErr    bool
	}{
		{"gnu missing user", `printf "id: '%s': no such user\n" "$3" >&2; exit 1`, false},
		{"gnu musl missing user", `printf "id: '%s': no such user: Invalid argument\n" "$3" >&2; exit 1`, false},
		{"busybox missing user", `printf "id: unknown user %s\n" "$3" >&2; exit 1`, false},
		{"different GNU errno", `printf "id: '%s': no such user: Resource temporarily unavailable\n" "$3" >&2; exit 1`, true},
		{"NSS backend failure", `printf "id: NSS backend unavailable\n" >&2; exit 1`, true},
		{"unclassified empty failure", `exit 2`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setPasswd(t, "")
			dir := t.TempDir()
			writeUserCommand(t, dir, "id", `[ "$1:$2" = "-u:--" ] || exit 9
`+tt.diagnostic)
			t.Setenv("PATH", dir)

			inUse, err := NameInUse("ldap-user")
			if inUse {
				t.Fatal("failed identity query reported the username as in use")
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("NameInUse error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestNSSCommandsAreBoundedAndUseCLocale(t *testing.T) {
	old := nssCommandOptions
	t.Cleanup(func() { nssCommandOptions = old })

	t.Run("name probe locale", func(t *testing.T) {
		setPasswd(t, "")
		dir := t.TempDir()
		writeUserCommand(t, dir, "id", `[ "$LC_ALL:$LANG:$1:$2:$3" = "C:C:-u:--:ldap-user" ]`)
		t.Setenv("PATH", dir)
		inUse, err := NameInUse("ldap-user")
		if err != nil || !inUse {
			t.Fatalf("NameInUse = %v, %v; helper did not receive C locale/expected argv", inUse, err)
		}
	})

	t.Run("groups locale", func(t *testing.T) {
		dir := t.TempDir()
		writeUserCommand(t, dir, "id", `[ "$LC_ALL:$LANG:$1:$2" = "C:C:-Gn:alice" ] || exit 9
printf 'primary extra\n'`)
		t.Setenv("PATH", dir)
		groups, err := Groups(Passwd{Name: "alice"})
		if err != nil || !reflect.DeepEqual(groups, []string{"primary", "extra"}) {
			t.Fatalf("Groups = %v, %v; helper did not receive C locale/expected argv", groups, err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		setPasswd(t, "")
		dir := t.TempDir()
		writeUserCommand(t, dir, "id", `/bin/sleep 30 & wait`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = 50 * time.Millisecond
		nssCommandOptions = opts
		_, err := NameInUse("slow-user")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("NameInUse error = %v, want bounded timeout", err)
		}
	})

	t.Run("output limit", func(t *testing.T) {
		setPasswd(t, "")
		dir := t.TempDir()
		writeUserCommand(t, dir, "id", `while :; do printf 0123456789abcdef; done`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = time.Second
		opts.MaxOutput = 64
		nssCommandOptions = opts
		_, err := NameInUse("noisy-user")
		if !errors.Is(err, executil.ErrOutputLimit) {
			t.Fatalf("NameInUse error = %v, want output limit", err)
		}
	})
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
	if _, err := IsProtectedRevokeTarget("someone", true, 1001, testGeneration, false); err == nil {
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
		if protected, err := IsProtectedRevokeTarget(n, true, 0, testGeneration, false); err != nil || !protected {
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
		generation  string
		allowLegacy bool
		want        bool
	}{
		{"root", false, 0, "", false, true},                 // uid 0 / blocklist
		{"daemon", false, 0, "", false, true},               // blocklist (not in passwd)
		{"systemd-network", false, 0, "", false, true},      // systemd- prefix
		{"svc", false, 0, "", false, true},                  // system uid, unregistered
		{"svc", true, 0, testGeneration, false, true},       // system uid, registered but not managed
		{"tmp500", false, 0, "", false, true},               // managed system uid but unregistered
		{"tmp500", true, 500, testGeneration, false, false}, // generation-bound + registered system uid -> deletable
		{"human", false, 0, "", false, true},                // real uid, unregistered human
		{"human", true, 0, testGeneration, false, true},     // real uid, registered but NOT managed -> protected
		{"tmp1000", false, 0, "", false, false},             // managed real uid -> explicit unregistered recovery may delete
		{"legacy", true, 1004, "", false, true},             // fixed legacy marker is not identity proof
		{"legacy", true, 1004, "", true, false},             // direct force recovery may accept it

		// A recorded UID detects contradictions but cannot prove identity on its own:
		// Linux can reuse the same UID after an account is deleted and recreated.
		{"wiped", true, 1002, testGeneration, false, true}, // marker erased
		{"wiped", true, 0, testGeneration, false, true},    // no recorded uid
		{"wiped", false, 1002, "", false, true},            // unregistered
		{"wiped", true, 9999, testGeneration, false, true}, // recorded uid mismatch

		// A recorded UID must never make a real account deletable, even when it
		// matches exactly: the username and UID can both be reused.
		{"human", true, 1000, testGeneration, false, true}, // matching UID can belong to a recreated real account
		{"human", true, 1234, testGeneration, false, true}, // recorded uid disagrees

		// A recorded UID that disagrees is not a MISSING witness but a CONTRADICTING
		// one, and the marker must not overrule it. The two rows above only ever
		// exercised that rule on accounts whose marker was absent anyway, so the case
		// that decides it — marker intact, recorded UID contradicting — went untested
		// and returned "deletable". revoke then aimed its SIGKILL sweep at the UID in
		// passwd, i.e. at whatever UID the account had been given.
		{"tmp1000", true, 9999, testGeneration, false, true},                     // marker intact BUT recorded uid contradicts
		{"tmp1000", true, 1001, "fedcba9876543210fedcba9876543210", false, true}, // wrong generation

		// Escalating to uid 0 stays protected — never auto-delete a root account —
		// even though it is registered, managed, and its name is ours.
		{"escalated", true, 1003, testGeneration, false, true},
		{"escalated", true, 0, testGeneration, false, true},
	}
	for _, c := range cases {
		got, err := IsProtectedRevokeTarget(c.name, c.registered, c.recordedUID, c.generation, c.allowLegacy)
		if err != nil {
			t.Fatalf("IsProtectedRevokeTarget(%q): %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("IsProtectedRevokeTarget(%q, registered=%v, recordedUID=%d, generation=%q, allowLegacy=%v) = %v, want %v",
				c.name, c.registered, c.recordedUID, c.generation, c.allowLegacy, got, c.want)
		}
	}
}

func TestIsProtectedRevokeEntryUsesSuppliedSnapshot(t *testing.T) {
	setPasswd(t, "same:x:4321:4321:"+config.ManagedGECOS+":/home/same:/bin/bash\n")
	snapshot := Passwd{Name: "same", UID: 1234, GID: 1234, GECOS: "Real Person", Home: "/srv/same", Shell: "/bin/sh"}
	if !IsProtectedRevokeEntry("same", snapshot, true, true, 1234, testGeneration, false) {
		t.Fatal("supplied untrusted snapshot was ignored in favor of a second passwd lookup")
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

func TestAccountMutationsRejectInvalidUsernameBeforeRunningHelpers(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Manager) error
	}{
		{name: "create", run: func(m *Manager) error { return m.Create("bad:user", "/bin/sh", testGeneration) }},
		{name: "create pending", run: func(m *Manager) error { return m.CreatePending("bad:user", "/bin/sh", testGeneration) }},
		{name: "mark managed", run: func(m *Manager) error { return m.MarkManaged("bad:user", testGeneration) }},
		{name: "disable key password", run: func(m *Manager) error { return m.DisablePasswordForKeyLogin("bad:user") }},
		{name: "lock password", run: func(m *Manager) error { return m.LockPassword("bad:user") }},
		{name: "set password", run: func(m *Manager) error { return m.SetPassword("bad:user", "secret") }},
		{name: "set expiry", run: func(m *Manager) error { return m.SetExpiry("bad:user", "2026-07-09") }},
		{name: "delete", run: func(m *Manager) error { return m.Delete("bad:user") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{available: map[string]bool{
				"useradd": true, "adduser": true, "usermod": true,
				"chpasswd": true, "chage": true, "deluser": true, "userdel": true,
			}}
			if err := tc.run(&Manager{Runner: f}); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Fatalf("mutation error = %v, want username refusal", err)
			}
			if len(f.calls) != 0 || len(f.stdin) != 0 {
				t.Fatalf("invalid username reached helper: calls=%v stdin=%v", f.calls, f.stdin)
			}
		})
	}
}

var errForced = &forcedErr{}

type forcedErr struct{}

func (*forcedErr) Error() string { return "forced failure" }

func TestExecRunnerBoundsCommandsAndNeverEchoesSecretInput(t *testing.T) {
	old := accountCommandOptions
	t.Cleanup(func() { accountCommandOptions = old })
	runner := execRunner{}

	t.Run("locale", func(t *testing.T) {
		accountCommandOptions = old
		cmd := writeUserCommand(t, t.TempDir(), "account-helper", `[ "$LC_ALL:$LANG" = "C:C" ]`)
		if err := runner.Run(cmd); err != nil {
			t.Fatalf("Run did not force the C locale: %v", err)
		}
	})

	t.Run("output limit", func(t *testing.T) {
		opts := old
		opts.Timeout = time.Second
		opts.MaxOutput = 64
		accountCommandOptions = opts
		cmd := writeUserCommand(t, t.TempDir(), "account-helper", `while :; do printf 0123456789abcdef; done`)
		if err := runner.Run(cmd); !errors.Is(err, executil.ErrOutputLimit) {
			t.Fatalf("Run error = %v, want output limit", err)
		}
	})

	t.Run("secret output discarded", func(t *testing.T) {
		accountCommandOptions = old
		cmd := writeUserCommand(t, t.TempDir(), "account-helper", `IFS= read -r value
printf 'child echoed %s\n' "$value" >&2
exit 1`)
		const secret = "alice:correct-horse-battery-staple"
		err := runner.RunInput(secret+"\n", cmd)
		if err == nil {
			t.Fatal("RunInput accepted a failing helper")
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "child echoed") {
			t.Fatalf("RunInput leaked child output containing stdin: %v", err)
		}
	})
}

func TestCreateArgvUseradd(t *testing.T) {
	marker := config.ManagedGenerationGECOSPrefix + testGeneration
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+marker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "adduser": true}}
	m := &Manager{Runner: f}
	if err := m.Create("xxvcc-a1", "/bin/bash", testGeneration); err != nil {
		t.Fatal(err)
	}
	want := []string{"useradd", "-m", "-s", "/bin/bash", "-c", marker, "xxvcc-a1"}
	if len(f.calls) != 1 || !reflect.DeepEqual(f.calls[0], want) {
		t.Errorf("useradd argv = %v, want %v", f.calls, want)
	}
}

func TestCreatePendingAndMarkManagedArgv(t *testing.T) {
	pendingMarker := config.PendingGenerationGECOSPrefix + testGeneration
	managedMarker := config.ManagedGenerationGECOSPrefix + testGeneration
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "usermod": true}}
	m := &Manager{Runner: f}
	if err := m.CreatePending("xxvcc-a1", "/bin/bash", testGeneration); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkManaged("xxvcc-a1", testGeneration); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"useradd", "-m", "-s", "/bin/bash", "-c", pendingMarker, "xxvcc-a1"},
		{"usermod", "-c", managedMarker, "xxvcc-a1"},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("pending identity argv = %v, want %v", f.calls, want)
	}
}

func TestMarkManagedRequiresUsermod(t *testing.T) {
	if err := (&Manager{Runner: &fakeRunner{}}).MarkManaged("xxvcc-a1", testGeneration); err == nil {
		t.Fatal("MarkManaged accepted a host without usermod")
	}
}

func TestCreateArgvAdduserBusybox(t *testing.T) {
	marker := config.ManagedGenerationGECOSPrefix + testGeneration
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+marker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"adduser": true}} // no useradd
	m := &Manager{Runner: f}
	if err := m.Create("xxvcc-a1", "/bin/sh", testGeneration); err != nil {
		t.Fatal(err)
	}
	want := []string{"adduser", "-D", "-s", "/bin/sh", "-g", marker, "xxvcc-a1"}
	if !reflect.DeepEqual(f.calls[0], want) {
		t.Errorf("adduser argv = %v, want %v", f.calls[0], want)
	}
}

func setProcRoot(t *testing.T, statuses map[int]string) {
	t.Helper()
	dir := t.TempDir()
	for pid, status := range statuses {
		pidDir := filepath.Join(dir, fmt.Sprint(pid))
		if err := os.Mkdir(pidDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := procRoot
	procRoot = dir
	t.Cleanup(func() { procRoot = old })
}

func TestCreateRejectsUIDWithResidualProcess(t *testing.T) {
	marker := config.ManagedGenerationGECOSPrefix + testGeneration
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+marker+":/home/xxvcc-a1:/bin/sh\n")
	// The target UID appears only in the saved-set UID column. Checking only real
	// and effective UIDs would miss this process, which can switch back to 2345.
	setProcRoot(t, map[int]string{77: "Name:\tleftover\nUid:\t1000\t1000\t2345\t1000\n"})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "userdel": true}}
	err := (&Manager{Runner: f}).Create("xxvcc-a1", "/bin/sh", testGeneration)
	if err == nil || !strings.Contains(err.Error(), "UID 2345") || !strings.Contains(err.Error(), "77") {
		t.Fatalf("Create error = %v, want residual-UID process refusal", err)
	}
	want := [][]string{
		{"useradd", "-m", "-s", "/bin/sh", "-c", marker, "xxvcc-a1"},
		{"userdel", "-r", "-f", "--", "xxvcc-a1"},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("Create calls = %v, want create followed by rollback %v", f.calls, want)
	}
}

func TestCreateFailsClosedWhenProcCannotBeScanned(t *testing.T) {
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+config.ManagedGenerationGECOSPrefix+testGeneration+":/home/xxvcc-a1:/bin/sh\n")
	old := procRoot
	procRoot = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { procRoot = old })
	f := &fakeRunner{available: map[string]bool{"useradd": true, "userdel": true}}
	if err := (&Manager{Runner: f}).Create("xxvcc-a1", "/bin/sh", testGeneration); err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("Create error = %v, want proc scan failure", err)
	}
	if len(f.calls) != 2 || f.calls[1][0] != "userdel" {
		t.Fatalf("failed safety check did not roll back account: calls=%v", f.calls)
	}
}

func TestProcessesForUIDChecksAllFourUIDColumns(t *testing.T) {
	setProcRoot(t, map[int]string{
		11: "Uid:\t1111\t2000\t2000\t2000\n",
		12: "Uid:\t2000\t1111\t2000\t2000\n",
		13: "Uid:\t2000\t2000\t1111\t2000\n",
		14: "Uid:\t2000\t2000\t2000\t1111\n",
	})
	pids, err := processesForUID(1111)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{11, 12, 13, 14}; !reflect.DeepEqual(pids, want) {
		t.Fatalf("processesForUID = %v, want %v", pids, want)
	}
}

func TestProcessesForUIDIgnoresZombieAndDeadTasks(t *testing.T) {
	setProcRoot(t, map[int]string{
		11: "State:\tZ (zombie)\nUid:\t1111\t1111\t1111\t1111\n",
		12: "State:\tX (dead)\nUid:\t1111\t1111\t1111\t1111\n",
		13: "State:\tS (sleeping)\nUid:\t1111\t1111\t1111\t1111\n",
	})
	pids, err := processesForUID(1111)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{13}; !reflect.DeepEqual(pids, want) {
		t.Fatalf("processesForUID = %v, want only live tasks %v", pids, want)
	}
}

func withFakePidfds(t *testing.T, send func(int, unix.Signal, *unix.Siginfo, int) error) {
	t.Helper()
	oldOpen, oldSend, oldClose, oldSleep := pidfdOpen, pidfdSendSignal, closeFD, terminateSleep
	pidfdOpen = func(pid, flags int) (int, error) { return pid + 10000, nil }
	pidfdSendSignal = send
	closeFD = func(int) error { return nil }
	terminateSleep = func(time.Duration) {}
	t.Cleanup(func() {
		pidfdOpen, pidfdSendSignal, closeFD, terminateSleep = oldOpen, oldSend, oldClose, oldSleep
	})
}

func TestCheckPidfdReportsKernelOrSandboxFailure(t *testing.T) {
	oldOpen, oldSend, oldClose := pidfdOpen, pidfdSendSignal, closeFD
	pidfdOpen = func(pid, flags int) (int, error) {
		if pid != os.Getpid() || flags != 0 {
			t.Fatalf("PidfdOpen(%d, %d), want self", pid, flags)
		}
		return -1, syscall.ENOSYS
	}
	pidfdSendSignal = func(int, unix.Signal, *unix.Siginfo, int) error {
		t.Fatal("signal called after failed pidfd open")
		return nil
	}
	closeFD = func(int) error { t.Fatal("close called after failed pidfd probe"); return nil }
	t.Cleanup(func() { pidfdOpen, pidfdSendSignal, closeFD = oldOpen, oldSend, oldClose })
	if err := CheckPidfd(); err == nil || !errors.Is(err, syscall.ENOSYS) {
		t.Fatalf("CheckPidfd error=%v, want ENOSYS", err)
	}
}

func TestCheckPidfdReportsSignalFailureAndClosesDescriptor(t *testing.T) {
	oldOpen, oldSend, oldClose := pidfdOpen, pidfdSendSignal, closeFD
	pidfdOpen = func(int, int) (int, error) { return 42, nil }
	pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
		if fd != 42 || sig != 0 || info != nil || flags != 0 {
			t.Fatalf("PidfdSendSignal(%d, %d, %v, %d), want harmless self probe", fd, sig, info, flags)
		}
		return syscall.EPERM
	}
	closed := false
	closeFD = func(fd int) error {
		if fd != 42 {
			t.Fatalf("close(%d), want 42", fd)
		}
		closed = true
		return nil
	}
	t.Cleanup(func() { pidfdOpen, pidfdSendSignal, closeFD = oldOpen, oldSend, oldClose })
	if err := CheckPidfd(); err == nil || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("CheckPidfd signal error=%v, want EPERM", err)
	}
	if !closed {
		t.Fatal("pidfd was not closed after the signalling probe failed")
	}
}

func TestTerminateProcessesDoesNotOpenPidfdsForUnrelatedUIDs(t *testing.T) {
	setProcRoot(t, map[int]string{77: "State:\tS (sleeping)\nUid:\t9999\t9999\t9999\t9999\n"})
	oldOpen := pidfdOpen
	opened := 0
	pidfdOpen = func(int, int) (int, error) {
		opened++
		return -1, syscall.ENOSYS
	}
	t.Cleanup(func() { pidfdOpen = oldOpen })
	if err := TerminateProcesses(2345); err != nil {
		t.Fatalf("no target processes should need no pidfd: %v", err)
	}
	if opened != 0 {
		t.Fatalf("opened %d pidfds for unrelated processes, want 0", opened)
	}
}

func TestTerminateProcessesFailsClosedWhenTargetNeedsUnavailablePidfd(t *testing.T) {
	setProcRoot(t, map[int]string{77: "State:\tS (sleeping)\nUid:\t2345\t2345\t2345\t2345\n"})
	oldOpen := pidfdOpen
	pidfdOpen = func(int, int) (int, error) { return -1, syscall.ENOSYS }
	t.Cleanup(func() { pidfdOpen = oldOpen })
	if err := TerminateProcesses(2345); err == nil || !errors.Is(err, syscall.ENOSYS) {
		t.Fatalf("target process without pidfd support error=%v, want ENOSYS", err)
	}
}

func TestTerminateProcessesReportsScanAndSignalFailures(t *testing.T) {
	t.Run("scan", func(t *testing.T) {
		old := procRoot
		procRoot = filepath.Join(t.TempDir(), "missing")
		t.Cleanup(func() { procRoot = old })
		if err := TerminateProcesses(2345); err == nil || !strings.Contains(err.Error(), "scan") {
			t.Fatalf("TerminateProcesses error = %v, want scan error", err)
		}
	})

	t.Run("signal", func(t *testing.T) {
		setProcRoot(t, map[int]string{77: "Uid:\t2345\t2345\t2345\t2345\n"})
		withFakePidfds(t, func(int, unix.Signal, *unix.Siginfo, int) error { return syscall.EPERM })
		if err := TerminateProcesses(2345); err == nil || !errors.Is(err, syscall.EPERM) {
			t.Fatalf("TerminateProcesses error = %v, want EPERM", err)
		}
	})
}

func TestTerminateProcessesUsesPidfdAndReportsSurvivors(t *testing.T) {
	setProcRoot(t, map[int]string{77: "Uid:\t2345\t2345\t2345\t2345\n"})
	var signals []unix.Signal
	withFakePidfds(t, func(fd int, sig unix.Signal, _ *unix.Siginfo, flags int) error {
		if fd != 10077 || flags != 0 {
			t.Fatalf("pidfd signal args fd=%d flags=%d", fd, flags)
		}
		signals = append(signals, sig)
		return nil
	})
	err := TerminateProcesses(2345)
	if err == nil || !strings.Contains(err.Error(), "surviving processes") || !strings.Contains(err.Error(), "77") {
		t.Fatalf("TerminateProcesses error = %v, want survivor list", err)
	}
	if len(signals) != 1+terminateSweeps || signals[0] != unix.SIGTERM {
		t.Fatalf("signals = %v, want TERM then %d KILL sweeps", signals, terminateSweeps)
	}
	for _, sig := range signals[1:] {
		if sig != unix.SIGKILL {
			t.Fatalf("signals = %v, want only SIGKILL after SIGTERM", signals)
		}
	}
}

func TestLockExpiryArgv(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{}}
	m := &Manager{Runner: f}
	_ = m.LockPassword("xxvcc-u")
	_ = m.SetExpiry("xxvcc-u", "2026-07-09")
	want := [][]string{{"usermod", "-L", "xxvcc-u"}, {"chage", "-E", "2026-07-09", "xxvcc-u"}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Errorf("calls = %v, want %v", f.calls, want)
	}
}

func TestDisablePasswordForKeyLoginUsesUnmatchableUnlockedShadowValue(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{}}
	m := &Manager{Runner: f}
	if err := m.DisablePasswordForKeyLogin("xxvcc-u"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"usermod", "-p", keyOnlyPasswordHash, "xxvcc-u"}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	if strings.HasPrefix(keyOnlyPasswordHash, "!") || strings.HasPrefix(keyOnlyPasswordHash, "*") {
		t.Fatal("key-only shadow value would make OpenSSH classify the account as locked")
	}
	if len(keyOnlyPasswordHash) == 13 || strings.HasPrefix(keyOnlyPasswordHash, "$") || strings.HasPrefix(keyOnlyPasswordHash, "_") {
		t.Fatal("key-only shadow value resembles a supported crypt(3) result")
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
	if err := m.Delete("xxvcc-u"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0][0] != "deluser" || !reflect.DeepEqual(f.calls[1], []string{"userdel", "-r", "-f", "--", "xxvcc-u"}) {
		t.Errorf("delete calls = %v", f.calls)
	}
}

func TestDeleteRequiresConfirmedAccountRemoval(t *testing.T) {
	setPasswd(t, "xxvcc-u:x:1001:1001::/home/xxvcc-u:/bin/sh\n")
	f := &fakeRunner{available: map[string]bool{"deluser": true, "userdel": true}}
	m := &Manager{Runner: f}
	if err := m.Delete("xxvcc-u"); err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("Delete error = %v, want post-delete existence failure", err)
	}
	if len(f.calls) != 2 || f.calls[0][0] != "deluser" || f.calls[1][0] != "userdel" {
		t.Fatalf("Delete calls = %v, want both helpers after the first false success", f.calls)
	}
}

func TestDeleteFailsClosedWhenRemovalCannotBeVerified(t *testing.T) {
	old := passwdPath
	passwdPath = t.TempDir()
	t.Cleanup(func() { passwdPath = old })
	f := &fakeRunner{available: map[string]bool{"deluser": true}}
	if err := (&Manager{Runner: f}).Delete("xxvcc-u"); err == nil || !strings.Contains(err.Error(), "verify deluser") {
		t.Fatalf("Delete error = %v, want passwd verification failure", err)
	}
}

// TestDisableLoginExpiresBeforeLocking pins the H2 fix: revoke must shut the
// account's door before it starts taking it apart. Expiry is what actually stops
// a KEY login (locking the password alone would not), so it must be issued.
func TestDisableLoginExpiresBeforeLocking(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"chage": true, "usermod": true}}
	m := &Manager{Runner: f}
	if err := m.DisableLogin("xxvcc-u"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("DisableLogin calls = %v, want chage then usermod", f.calls)
	}
	if !reflect.DeepEqual(f.calls[0], []string{"chage", "-E", "1970-01-01", "xxvcc-u"}) {
		t.Errorf("first call = %v, want the account expired to a past date", f.calls[0])
	}
	if !reflect.DeepEqual(f.calls[1], []string{"usermod", "-L", "xxvcc-u"}) {
		t.Errorf("second call = %v, want the password locked", f.calls[1])
	}
}

// TestTerminateProcessesNeverSignalsRootOrAll pins the guard that keeps a
// mis-parsed or zero uid from signalling every root-owned process on the host.
// kill is stubbed, so a regression fails the test instead of killing the runner.
func TestTerminateProcessesNeverSignalsRootOrAll(t *testing.T) {
	var opened []int
	orig := pidfdOpen
	pidfdOpen = func(pid, _ int) (int, error) {
		opened = append(opened, pid)
		return -1, errors.New("must not be called")
	}
	t.Cleanup(func() { pidfdOpen = orig })

	for _, uid := range []int{0, -1, -1000} {
		if err := TerminateProcesses(uid); err != nil {
			t.Fatalf("TerminateProcesses(%d): %v", uid, err)
		}
		if len(opened) != 0 {
			t.Fatalf("uid %d must open no pidfds, opened %v", uid, opened)
		}
	}
	if strconv.IntSize >= 64 {
		reserved := int(uint64(^uint32(0)))
		if err := TerminateProcesses(reserved); err == nil || !strings.Contains(err.Error(), "invalid Linux UID") {
			t.Fatalf("TerminateProcesses(%d) error = %v, want range refusal", reserved, err)
		}
		if len(opened) != 0 {
			t.Fatalf("reserved uid must open no pidfds, opened %v", opened)
		}
	}
}
