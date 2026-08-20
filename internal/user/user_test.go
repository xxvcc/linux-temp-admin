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
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
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

func setIdentityDatabases(t *testing.T, passwd, group, loginDefs string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	oldPasswd, oldGroup, oldLoginDefs := passwdPath, groupPath, loginDefsPath
	passwdPath = write("passwd", passwd)
	groupPath = write("group", group)
	loginDefsPath = write("login.defs", loginDefs)
	t.Cleanup(func() {
		passwdPath, groupPath, loginDefsPath = oldPasswd, oldGroup, oldLoginDefs
	})
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

func testManagedGenerationGECOS(t *testing.T) string {
	t.Helper()
	value, err := ManagedGECOSForGeneration(testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testPendingGenerationGECOS(t *testing.T) string {
	t.Helper()
	value, err := pendingGECOSForGeneration(testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

var noOpBeforeDelete = func() error { return nil }

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
	managedMarker := config.ManagedGenerationGECOSPrefix + testGeneration
	pendingMarker := config.PendingGenerationGECOSPrefix + testGeneration
	managedWitness := config.ManagedGenerationGECOSWitnessPrefix + testGeneration
	pendingWitness := config.PendingGenerationGECOSWitnessPrefix + testGeneration
	tests := []struct {
		name           string
		gecos          string
		managed        bool
		lifecycle      bool
		legacy         bool
		matchesGen     bool
		matchesPending bool
		trailing       bool
	}{
		{name: "legacy", gecos: config.ManagedGECOS + ",,,", managed: true, lifecycle: true, legacy: true},
		{name: "deployed first-field marker", gecos: managedMarker + ",,,", managed: true, lifecycle: true, matchesGen: true},
		{name: "new trailing marker", gecos: ",,,," + managedWitness, managed: true, lifecycle: true, matchesGen: true, trailing: true},
		{name: "self-service full-name change", gecos: "Changed Name,,,," + managedWitness, managed: true, lifecycle: true, matchesGen: true, trailing: true},
		{name: "self-service office changes", gecos: "Changed Name,room,work,home," + managedWitness, managed: true, lifecycle: true, matchesGen: true, trailing: true},
		{name: "trailing witness only", gecos: ",,,," + managedWitness, managed: true, lifecycle: true, matchesGen: true, trailing: true},
		{name: "contradictory trailing marker", gecos: managedMarker + ",,,," + config.ManagedGenerationGECOSWitnessPrefix + otherGeneration, managed: true, lifecycle: true},
		{name: "other generation", gecos: config.ManagedGenerationGECOSPrefix + otherGeneration, managed: true, lifecycle: true},
		{name: "malformed generation", gecos: config.ManagedGenerationGECOSPrefix + "short"},
		{name: "substring", gecos: "prefix " + config.ManagedGECOS},
		{name: "deployed pending", gecos: pendingMarker, lifecycle: true, matchesPending: true},
		{name: "new pending after full-name change", gecos: "changed,,,," + pendingWitness, lifecycle: true, matchesPending: true},
		{name: "malformed pending", gecos: config.PendingGenerationGECOSPrefix + "short"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pw := Passwd{GECOS: tc.gecos}
			if got := IsManagedEntry(pw); got != tc.managed {
				t.Errorf("IsManagedEntry = %v, want %v", got, tc.managed)
			}
			if got := HasLifecycleMarker(pw); got != tc.lifecycle {
				t.Errorf("HasLifecycleMarker = %v, want %v", got, tc.lifecycle)
			}
			if got := IsLegacyManagedEntry(pw); got != tc.legacy {
				t.Errorf("IsLegacyManagedEntry = %v, want %v", got, tc.legacy)
			}
			if got := MatchesManagedGeneration(pw, testGeneration); got != tc.matchesGen {
				t.Errorf("MatchesManagedGeneration = %v, want %v", got, tc.matchesGen)
			}
			if got := MatchesPendingGeneration(pw, testGeneration); got != tc.matchesPending {
				t.Errorf("MatchesPendingGeneration = %v, want %v", got, tc.matchesPending)
			}
			if got := HasTrailingGenerationWitness(pw, testGeneration); got != tc.trailing {
				t.Errorf("HasTrailingGenerationWitness = %v, want %v", got, tc.trailing)
			}
		})
	}
	if got, err := ManagedGECOSForGeneration(testGeneration); err != nil || got != ",,,,"+managedWitness {
		t.Fatalf("ManagedGECOSForGeneration = %q, %v; want trailing marker", got, err)
	}
	if _, err := ManagedGECOSForGeneration("short"); err == nil {
		t.Fatal("ManagedGECOSForGeneration accepted an invalid generation")
	}
}

func TestSameAccountIdentityUsesOnlyProtectedWitnessForMutableFields(t *testing.T) {
	managed := testManagedGenerationGECOS(t)
	base := Passwd{
		Name: "xxvcc-a1", UID: 1001, GID: 1001, GECOS: managed,
		Home: "/home/xxvcc-a1", Shell: "/bin/bash",
	}
	mutable := base
	mutable.GECOS = "Changed Name,room,work,home," + config.ManagedGenerationGECOSWitnessPrefix + testGeneration
	mutable.Shell = "/bin/sh"
	if !SameAccountIdentity(base, mutable) {
		t.Fatal("protected trailing witness did not tolerate user-changeable GECOS/shell fields")
	}

	old := base
	old.GECOS = config.ManagedGenerationGECOSPrefix + testGeneration
	oldChanged := old
	oldChanged.GECOS = "Changed Name"
	oldChanged.Shell = "/bin/sh"
	if SameAccountIdentity(old, oldChanged) {
		t.Fatal("deployed first-field-only identity accepted a changed passwd snapshot")
	}

	otherGeneration := config.ManagedGenerationGECOSWitnessPrefix + "fedcba9876543210fedcba9876543210"
	tests := []struct {
		name   string
		mutate func(*Passwd)
	}{
		{name: "name", mutate: func(p *Passwd) { p.Name = "xxvcc-replacement" }},
		{name: "uid", mutate: func(p *Passwd) { p.UID++ }},
		{name: "gid", mutate: func(p *Passwd) { p.GID++ }},
		{name: "home", mutate: func(p *Passwd) { p.Home = "/srv/replacement" }},
		{name: "empty shell", mutate: func(p *Passwd) { p.Shell = "" }},
		{name: "missing trailing witness", mutate: func(p *Passwd) { p.GECOS = config.ManagedGenerationGECOSPrefix + testGeneration }},
		{name: "changed trailing witness", mutate: func(p *Passwd) { p.GECOS = "Changed,,,," + otherGeneration }},
		{name: "extra trailing field", mutate: func(p *Passwd) { p.GECOS += ",extra" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			current := base
			tc.mutate(&current)
			if SameAccountIdentity(base, current) {
				t.Fatalf("identity accepted protected-field change: current=%+v", current)
			}
		})
	}
}

func TestLifecycleMarkerAccountsFindsOnlyExactMarkers(t *testing.T) {
	setPasswd(t, strings.Join([]string{
		"human:x:1000:1000:A Human:/home/human:/bin/bash",
		"managed:x:1001:1001:" + config.ManagedGenerationGECOSPrefix + testGeneration + ",,,:/home/managed:/bin/sh",
		"legacy:x:1002:1002:" + config.ManagedGECOS + ":/home/legacy:/bin/sh",
		"pending:x:1003:1003:" + config.PendingGenerationGECOSPrefix + testGeneration + ":/home/pending:/bin/sh",
		"substring:x:1004:1004:prefix " + config.ManagedGECOS + ":/home/substring:/bin/sh",
		"malformed:x:1005:1005:" + config.ManagedGenerationGECOSPrefix + "short:/home/malformed:/bin/sh",
	}, "\n")+"\n")

	got, err := LifecycleMarkerAccounts()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"legacy", "managed", "pending"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LifecycleMarkerAccounts = %v, want %v", got, want)
	}
}

func TestLifecycleMarkerAccountsSkipsNamesThisToolCannotHaveCreated(t *testing.T) {
	// invite runs validateMutationName before useradd, so every account this tool
	// has ever made carries a validate.Username name. A marker on any other name is
	// not evidence about this tool — and treating it as an inventory error let any
	// local user with a non-conforming name refuse every uninstall, permanently and
	// with no operator override, just by running chfn on their own account.
	setPasswd(t, strings.Join([]string{
		"Uppercase:x:1000:1000:" + config.ManagedGECOS + ":/home/Uppercase:/bin/sh",
		"way-too-long-a-name-for-a-temporary-account:x:1001:1001:" + config.ManagedGECOS + ":/home/x:/bin/sh",
		"managed:x:1002:1002:" + config.ManagedGenerationGECOSPrefix + testGeneration + ":/home/managed:/bin/sh",
	}, "\n")+"\n")

	got, err := LifecycleMarkerAccounts()
	if err != nil {
		t.Fatalf("marker scan failed on names this tool could never have created: %v", err)
	}
	if want := []string{"managed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("LifecycleMarkerAccounts = %v, want %v", got, want)
	}
}

func TestLifecycleMarkerAccountsFailsClosedOnMalformedPasswd(t *testing.T) {
	setPasswd(t, "broken:x:not-a-uid\nmanaged:x:1001:1001:"+config.ManagedGenerationGECOSPrefix+testGeneration+":/home/managed:/bin/sh\n")
	if _, err := LifecycleMarkerAccounts(); err == nil || !strings.Contains(err.Error(), "passwd line 1") {
		t.Fatalf("LifecycleMarkerAccounts error = %v, want malformed passwd refusal", err)
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

func TestLookupRejectsMalformedOrDuplicateTargetRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "truncated", content: "alice:x:1000\n", want: "malformed passwd entry"},
		{name: "extra field", content: "alice:x:1000:1000::/home/alice:/bin/sh:extra\n", want: "malformed passwd entry"},
		{name: "duplicate", content: "alice:x:1000:1000::/home/alice:/bin/sh\nalice:x:1001:1001::/home/alice:/bin/bash\n", want: "duplicate passwd entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setPasswd(t, tc.content)
			if _, ok, err := Lookup("alice"); err == nil || ok || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Lookup malformed target = ok %v, err %v; want %q", ok, err, tc.want)
			}
		})
	}

	setPasswd(t, "broken:x:uid\nalice:x:1000:1000::/home/alice:/bin/sh\n")
	if pw, ok, err := Lookup("alice"); err != nil || !ok || pw.UID != 1000 {
		t.Fatalf("unrelated malformed row affected Lookup: pw=%+v ok=%v err=%v", pw, ok, err)
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
		writeUserCommand(t, dir, "id", `[ "$LC_ALL:$LANG:$1:$2:$3" = "C:C:-Gn:--:alice" ] || exit 9
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
	if _, err := IsProtectedRevokeTarget("someone", RevokeIdentity{
		Registered: true, RecordedUID: 1001, RecordedGeneration: testGeneration, IdentityBound: true,
	}, false); err == nil {
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
		if protected, err := IsProtectedRevokeTarget(n, RevokeIdentity{Registered: true}, false); err != nil || !protected {
			t.Errorf("reserved %q is not a protected revoke target", n)
		}
	}
}

func TestIsProtectedRevokeTarget(t *testing.T) {
	setPasswd(t, samplePasswd)
	cases := []struct {
		name          string
		registered    bool
		recordedUID   int // 0 = an older registry row that recorded no UID
		generation    string
		identityBound bool
		allowLegacy   bool
		want          bool
	}{
		{"root", false, 0, "", false, false, true},                 // uid 0 / blocklist
		{"daemon", false, 0, "", false, false, true},               // blocklist (not in passwd)
		{"systemd-network", false, 0, "", false, false, true},      // systemd- prefix
		{"svc", false, 0, "", false, false, true},                  // system uid, unregistered
		{"svc", true, 0, testGeneration, false, false, true},       // system uid, registered but not managed
		{"tmp500", false, 0, "", false, false, true},               // managed system uid but unregistered
		{"tmp500", true, 500, testGeneration, true, false, false},  // generation-bound + registered system uid -> deletable
		{"tmp500", true, 500, testGeneration, false, true, true},   // unbound system uid is protected even with recovery authority
		{"human", false, 0, "", false, false, true},                // real uid, unregistered human
		{"human", true, 0, testGeneration, true, false, true},      // real uid, registered but NOT managed -> protected
		{"tmp1000", false, 0, "", false, false, false},             // managed real uid -> explicit unregistered recovery may delete
		{"tmp1000", true, 1001, testGeneration, false, true, true}, // an unbound generation column is never identity proof
		{"legacy", false, 0, "", false, false, true},               // a fixed marker alone is not unattended deletion authority
		{"legacy", false, 0, "", false, true, false},               // live explicit recovery may accept a marker-only legacy account
		{"legacy", true, 0, "", false, false, true},                // a nine-field row has no unattended deletion authority
		{"legacy", true, 0, "", false, true, false},                // direct recovery may supply its missing UID authority
		{"legacy", true, 1004, "", false, false, true},             // fixed legacy marker is not identity proof
		{"legacy", true, 1004, "", false, true, false},             // direct force recovery may accept it

		// A recorded UID detects contradictions but cannot prove identity on its own:
		// Linux can reuse the same UID after an account is deleted and recreated.
		{"wiped", true, 1002, testGeneration, true, false, true}, // marker erased
		{"wiped", true, 0, testGeneration, true, false, true},    // no recorded uid
		{"wiped", false, 1002, "", false, false, true},           // unregistered
		{"wiped", true, 9999, testGeneration, true, false, true}, // recorded uid mismatch

		// A recorded UID must never make a real account deletable, even when it
		// matches exactly: the username and UID can both be reused.
		{"human", true, 1000, testGeneration, true, false, true}, // matching UID can belong to a recreated real account
		{"human", true, 1234, testGeneration, true, false, true}, // recorded uid disagrees

		// A recorded UID that disagrees is not a MISSING witness but a CONTRADICTING
		// one, and the marker must not overrule it. The two rows above only ever
		// exercised that rule on accounts whose marker was absent anyway, so the case
		// that decides it — marker intact, recorded UID contradicting — went untested
		// and returned "deletable". revoke then aimed its SIGKILL sweep at the UID in
		// passwd, i.e. at whatever UID the account had been given.
		{"tmp1000", true, 9999, testGeneration, true, false, true},                     // marker intact BUT recorded uid contradicts
		{"tmp1000", true, 1001, "fedcba9876543210fedcba9876543210", true, false, true}, // wrong generation

		// Escalating to uid 0 stays protected — never auto-delete a root account —
		// even though it is registered, managed, and its name is ours.
		{"escalated", true, 1003, testGeneration, true, false, true},
		{"escalated", true, 0, testGeneration, true, false, true},
	}
	for _, c := range cases {
		got, err := IsProtectedRevokeTarget(c.name, RevokeIdentity{
			Registered:         c.registered,
			RecordedUID:        c.recordedUID,
			RecordedGeneration: c.generation,
			IdentityBound:      c.identityBound,
		}, c.allowLegacy)
		if err != nil {
			t.Fatalf("IsProtectedRevokeTarget(%q): %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("IsProtectedRevokeTarget(%q, registered=%v, recordedUID=%d, generation=%q, identityBound=%v, allowLegacy=%v) = %v, want %v",
				c.name, c.registered, c.recordedUID, c.generation, c.identityBound, c.allowLegacy, got, c.want)
		}
	}
}

func TestRegisteredLegacyMissingUIDRecoveryRequiresHighUIDAndExactMarker(t *testing.T) {
	base := Passwd{
		Name: "xxvcc-legacy1", UID: 1000, GID: 1000, GECOS: config.ManagedGECOS,
		Home: "/home/xxvcc-legacy1", Shell: "/bin/bash",
	}
	for _, tc := range []struct {
		name          string
		mutate        func(*Passwd)
		allowLegacy   bool
		wantProtected bool
	}{
		{name: "interactive recovery", allowLegacy: true},
		{name: "no recovery authority", wantProtected: true},
		{name: "low UID", allowLegacy: true, mutate: func(p *Passwd) { p.UID, p.GID = 999, 999 }, wantProtected: true},
		{name: "UID zero", allowLegacy: true, mutate: func(p *Passwd) { p.UID, p.GID = 0, 0 }, wantProtected: true},
		{name: "marker mismatch", allowLegacy: true, mutate: func(p *Passwd) { p.GECOS = "ordinary account" }, wantProtected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pw := base
			if tc.mutate != nil {
				tc.mutate(&pw)
			}
			if got := IsProtectedRevokeEntry(pw.Name, pw, true, RevokeIdentity{Registered: true}, tc.allowLegacy); got != tc.wantProtected {
				t.Fatalf("IsProtectedRevokeEntry = %v, want %v", got, tc.wantProtected)
			}
		})
	}
}

func TestLegacyRevokePolicyKeepsNineTenAndElevenColumnRowsUnbound(t *testing.T) {
	const otherGeneration = "fedcba9876543210fedcba9876543210"
	for _, tc := range []struct {
		name          string
		uid           int
		recordedUID   int
		generation    string
		gecos         string
		wantProtected bool
	}{
		{name: "nine fields high UID", uid: 1001, gecos: config.ManagedGECOS},
		{name: "ten fields high UID", uid: 1001, recordedUID: 1001, gecos: config.ManagedGECOS},
		{name: "eleven fields high UID", uid: 1001, recordedUID: 1001, generation: otherGeneration, gecos: config.ManagedGECOS},
		{name: "nine fields low UID", uid: 999, gecos: config.ManagedGECOS, wantProtected: true},
		{name: "ten fields low UID", uid: 999, recordedUID: 999, gecos: config.ManagedGECOS, wantProtected: true},
		{
			name: "eleven fields cannot impersonate a bound generation", uid: 1001,
			recordedUID: 1001, generation: testGeneration,
			gecos: config.ManagedGenerationGECOSPrefix + testGeneration, wantProtected: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pw := Passwd{
				Name: "xxvcc-legacy1", UID: tc.uid, GID: tc.uid, GECOS: tc.gecos,
				Home: "/home/xxvcc-legacy1", Shell: "/bin/sh",
			}
			identity := RevokeIdentity{
				Registered: true, RecordedUID: tc.recordedUID,
				RecordedGeneration: tc.generation, IdentityBound: false,
			}
			if got := IsProtectedRevokeEntry(pw.Name, pw, true, identity, true); got != tc.wantProtected {
				t.Fatalf("interactive legacy protection = %v, want %v", got, tc.wantProtected)
			}
			if !IsProtectedRevokeEntry(pw.Name, pw, true, identity, false) {
				t.Fatal("unattended invocation gained legacy deletion authority")
			}
		})
	}
}

func TestIsProtectedRevokeEntryUsesSuppliedSnapshot(t *testing.T) {
	setPasswd(t, "same:x:4321:4321:"+config.ManagedGECOS+":/home/same:/bin/bash\n")
	snapshot := Passwd{Name: "same", UID: 1234, GID: 1234, GECOS: "Real Person", Home: "/srv/same", Shell: "/bin/sh"}
	if !IsProtectedRevokeEntry("same", snapshot, true, RevokeIdentity{
		Registered: true, RecordedUID: 1234, RecordedGeneration: testGeneration, IdentityBound: true,
	}, false) {
		t.Fatal("supplied untrusted snapshot was ignored in favor of a second passwd lookup")
	}
}

// TestUnregisteredDeletionRequiresAuthoritativeMarker pins the split between the
// two questions a GECOS marker answers. HasLifecycleMarker only ever BLOCKS work,
// so it stays permissive about which field the marker sits in. IsProtectedRevoke*
// turns a marker into permission to DELETE an unregistered account, so once the
// root-only trailing field carries a value it decides — a user-changeable
// full-name copy must not be able to re-establish evidence it contradicts.
func TestUnregisteredDeletionRequiresAuthoritativeMarker(t *testing.T) {
	firstField := config.ManagedGenerationGECOSPrefix + testGeneration
	witness := config.ManagedGenerationGECOSWitnessPrefix + testGeneration
	for _, tc := range []struct {
		name          string
		gecos         string
		wantProtected bool
	}{
		{name: "trailing witness", gecos: ",,,," + witness, wantProtected: false},
		{name: "v2.9.3 first field only", gecos: firstField, wantProtected: false},
		{name: "first field with four empty office fields", gecos: firstField + ",,,", wantProtected: false},
		{name: "contradicted by a non-witness trailing field", gecos: firstField + ",,,,other info", wantProtected: true},
		{name: "contradicted by an empty-looking trailing field", gecos: firstField + ",room,work,home,x", wantProtected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pw := Passwd{
				Name: "xxvcc-a1", UID: 1500, GID: 1500, GECOS: tc.gecos,
				Home: "/home/xxvcc-a1", Shell: "/bin/sh",
			}
			got := IsProtectedRevokeEntry("xxvcc-a1", pw, true, RevokeIdentity{}, false)
			if got != tc.wantProtected {
				t.Fatalf("IsProtectedRevokeEntry = %v, want %v", got, tc.wantProtected)
			}
			// The blocking predicate must stay permissive in every one of these cases,
			// including the ones deletion now refuses.
			if !HasLifecycleMarker(pw) {
				t.Fatal("block-only marker recognition regressed to the deletion-authority rule")
			}
		})
	}
}

type fakeRunner struct {
	available map[string]bool
	failOn    map[string]bool
	calls     [][]string
	stdin     []string // what each RunInput call was fed
	onRun     func(name string)
}

func (f *fakeRunner) Run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.onRun != nil {
		f.onRun(name)
	}
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

// stubAbsentAccountDatabaseChecks keeps tests that exercise other Manager
// behavior independent of the host's privileged account databases. Tests for
// the real parsers and private-group state machine live in accountdb_test.go.
func stubAbsentAccountDatabaseChecks(m *Manager) *Manager {
	m.InspectPrivateGroupState = func(string, int, bool) (bool, error) { return false, nil }
	m.InspectSameNameGroupState = func(string) (bool, error) { return false, nil }
	m.CheckSubordinateIDsAbsent = func(string) error { return nil }
	return m
}

func managerWithStubbedHomeChecks(r Runner) *Manager {
	return stubAbsentAccountDatabaseChecks(&Manager{
		Runner:                   r,
		NameInUse:                func(string) (bool, error) { return false, nil },
		ValidateManagedMailRoots: func() error { return nil },
		PrepareManagedHome:       func(string) error { return nil },
		CreateManagedHome:        func(Passwd) error { return nil },
		ValidateManagedHome:      func(Passwd) error { return nil },
		RemoveManagedMail:        func(Passwd) error { return nil },
		RemoveManagedHome:        func(Passwd) error { return nil },
	})
}

func managerWithStubbedHomeRemoval(r Runner) *Manager {
	return stubAbsentAccountDatabaseChecks(&Manager{
		Runner:            r,
		NameInUse:         func(string) (bool, error) { return false, nil },
		RemoveManagedMail: func(Passwd) error { return nil },
		RemoveManagedHome: func(Passwd) error { return nil },
	})
}

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
		{name: "clear expiry", run: func(m *Manager) error { return m.ClearExpiry("bad:user") }},
		{name: "delete", run: func(m *Manager) error { return m.DeleteExpected("bad:user", Passwd{}, noOpBeforeDelete) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{available: map[string]bool{
				"useradd": true, "busybox": true, "usermod": true,
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

func TestAccountMutationsRejectReservedUsernameBeforeRunningHelpers(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Manager) error
	}{
		{name: "create", run: func(m *Manager) error { return m.Create("nobody", "/bin/sh", testGeneration) }},
		{name: "create pending", run: func(m *Manager) error { return m.CreatePending("systemd-test", "/bin/sh", testGeneration) }},
		{name: "mark managed", run: func(m *Manager) error { return m.MarkManaged("nobody", testGeneration) }},
		{name: "disable key password", run: func(m *Manager) error { return m.DisablePasswordForKeyLogin("nobody") }},
		{name: "lock password", run: func(m *Manager) error { return m.LockPassword("nobody") }},
		{name: "set password", run: func(m *Manager) error { return m.SetPassword("nobody", "secret") }},
		{name: "set expiry", run: func(m *Manager) error { return m.SetExpiry("nobody", "2026-07-09") }},
		{name: "clear expiry", run: func(m *Manager) error { return m.ClearExpiry("nobody") }},
		{name: "disable login", run: func(m *Manager) error { return m.DisableLogin("nobody") }},
		{name: "delete", run: func(m *Manager) error {
			return m.DeleteExpected("nobody", Passwd{Name: "nobody", UID: 65534, GID: 65534, Home: "/home/nobody", Shell: "/bin/sh"}, noOpBeforeDelete)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{available: map[string]bool{
				"useradd": true, "usermod": true, "chpasswd": true,
				"chage": true, "userdel": true,
			}}
			m := managerWithStubbedHomeChecks(f)
			m.LookupUser = func(string) (Passwd, bool, error) {
				t.Fatal("reserved username reached an account lookup")
				return Passwd{}, false, nil
			}
			if err := tc.run(m); err == nil || !strings.Contains(err.Error(), "reserved username") {
				t.Fatalf("mutation error = %v, want reserved-username refusal", err)
			}
			if len(f.calls) != 0 {
				t.Fatalf("reserved username reached helper commands: %v", f.calls)
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
	marker := testManagedGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+marker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "adduser": true}}
	m := managerWithStubbedHomeChecks(f)
	if err := m.Create("xxvcc-a1", "/bin/bash", testGeneration); err != nil {
		t.Fatal(err)
	}
	want := []string{"useradd", "-M", "-d", "/home/xxvcc-a1", "-s", "/bin/bash", "-c", marker,
		"-e", expiredDate, "-p", initialLockedPasswordHash, "xxvcc-a1"}
	if len(f.calls) != 1 || !reflect.DeepEqual(f.calls[0], want) {
		t.Errorf("useradd argv = %v, want %v", f.calls, want)
	}
}

func TestCreatePendingAndMarkManagedArgv(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	managedMarker := testManagedGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "usermod": true}}
	f.onRun = func(name string) {
		if name == "usermod" {
			if err := os.WriteFile(passwdPath, []byte("xxvcc-a1:x:2345:2345:"+managedMarker+":/home/xxvcc-a1:/bin/bash\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	m := managerWithStubbedHomeChecks(f)
	pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/bash", testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := m.MarkManagedExpected("xxvcc-a1", testGeneration, pending)
	if err != nil {
		t.Fatal(err)
	}
	if managed.GECOS != managedMarker || managed.UID != pending.UID || managed.Home != pending.Home {
		t.Fatalf("managed identity = %+v, pending = %+v", managed, pending)
	}
	want := [][]string{
		{"useradd", "-M", "-d", "/home/xxvcc-a1", "-s", "/bin/bash", "-c", pendingMarker,
			"-e", expiredDate, "-p", initialLockedPasswordHash, "xxvcc-a1"},
		{"usermod", "-c", managedMarker, "xxvcc-a1"},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("pending identity argv = %v, want %v", f.calls, want)
	}
}

func TestCreatePendingIdentityPinsReservedUIDAndGID(t *testing.T) {
	const reserved = 2345
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "groupdel": true}}
	m := managerWithStubbedHomeChecks(f)
	pw, err := m.CreatePendingIdentityWithID("xxvcc-a1", "/bin/bash", testGeneration, reserved)
	if err != nil || pw.UID != reserved || pw.GID != reserved {
		t.Fatalf("reserved identity = %+v err=%v", pw, err)
	}
	want := []string{"useradd", "-M", "-d", "/home/xxvcc-a1", "-s", "/bin/bash", "-c", pendingMarker,
		"-e", expiredDate, "-p", initialLockedPasswordHash,
		"-U", "-u", "2345", "-K", "GID_MIN=2345", "-K", "GID_MAX=2345", "xxvcc-a1"}
	if len(f.calls) != 1 || !reflect.DeepEqual(f.calls[0], want) {
		t.Fatalf("reserved useradd argv = %v, want %v", f.calls, want)
	}
}

func TestCreatePendingIdentityRejectsReservedIDMismatch(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2346:"+pendingMarker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "groupdel": true}}
	m := managerWithStubbedHomeChecks(f)
	pw, err := m.CreatePendingIdentityWithID("xxvcc-a1", "/bin/bash", testGeneration, 2345)
	if err == nil || pw.GID != 2346 || !strings.Contains(err.Error(), "want reserved 2345:2345") {
		t.Fatalf("reserved mismatch = %+v err=%v", pw, err)
	}
}

func TestIdentityAllocationRangeScansLocalUIDsAndGIDs(t *testing.T) {
	setIdentityDatabases(t,
		"root:x:0:0:root:/root:/bin/sh\nalice:x:1500:1700::/home/alice:/bin/sh\noutside:x:2100:2100::/home/outside:/bin/sh\n",
		"root:x:0:\nalice:x:1500:\nservice:x:1600:\noutside:x:2100:\n",
		"UID_MIN 1000\nUID_MAX 2000\nGID_MIN 1200\nGID_MAX 1900\n")
	snapshot, err := InspectIdentityAllocation()
	if err != nil || snapshot != (IdentityAllocationSnapshot{Lower: 1200, Upper: 1900, CurrentHighest: 1700}) {
		t.Fatalf("InspectIdentityAllocation = %+v err=%v, want lower=1200 upper=1900 currentHighest=1700", snapshot, err)
	}
	minimum, maximum, err := IdentityAllocationRange()
	if err != nil || minimum != 1701 || maximum != 1900 {
		t.Fatalf("IdentityAllocationRange = %d..%d err=%v, want 1701..1900", minimum, maximum, err)
	}
}

func TestInspectIdentityAllocationReturnsExhaustedSnapshot(t *testing.T) {
	setIdentityDatabases(t,
		"root:x:0:0:root:/root:/bin/sh\nlast:x:1900:1500::/home/last:/bin/sh\n",
		"root:x:0:\nlast:x:1900:\n",
		"UID_MIN 1000\nUID_MAX 2000\nGID_MIN 1200\nGID_MAX 1900\n")
	snapshot, err := InspectIdentityAllocation()
	if err != nil || snapshot != (IdentityAllocationSnapshot{Lower: 1200, Upper: 1900, CurrentHighest: 1900}) {
		t.Fatalf("InspectIdentityAllocation = %+v err=%v, want an exhausted 1200..1900 snapshot", snapshot, err)
	}
	if _, _, err := IdentityAllocationRange(); err == nil || err.Error() != "UID/GID allocation range 1200..1900 is exhausted" {
		t.Fatalf("IdentityAllocationRange exhaustion error = %v", err)
	}
}

func TestInspectIdentityAllocationReportsNoObservedIDAsZero(t *testing.T) {
	setIdentityDatabases(t,
		"root:x:0:0:root:/root:/bin/sh\nservice:x:999:999::/nonexistent:/usr/sbin/nologin\n",
		"root:x:0:\nservice:x:999:\n",
		"UID_MIN 1000\nUID_MAX 2000\nGID_MIN 1200\nGID_MAX 1900\n")
	snapshot, err := InspectIdentityAllocation()
	if err != nil || snapshot != (IdentityAllocationSnapshot{Lower: 1200, Upper: 1900}) {
		t.Fatalf("InspectIdentityAllocation = %+v err=%v, want no ID observed in 1200..1900", snapshot, err)
	}
	minimum, maximum, err := IdentityAllocationRange()
	if err != nil || minimum != 1200 || maximum != 1900 {
		t.Fatalf("IdentityAllocationRange = %d..%d err=%v, want 1200..1900", minimum, maximum, err)
	}
}

func TestIdentityAllocationRangeFailsClosedOnInvalidPolicyOrDatabase(t *testing.T) {
	for _, tc := range []struct {
		name, passwd, group, defs, want string
	}{
		{name: "disjoint ranges", passwd: "root:x:0:0::/root:/bin/sh\n", group: "root:x:0:\n", defs: "UID_MIN 1000\nUID_MAX 1100\nGID_MIN 1200\nGID_MAX 1300\n", want: "do not overlap"},
		{name: "duplicate policy", passwd: "root:x:0:0::/root:/bin/sh\n", group: "root:x:0:\n", defs: "UID_MIN 1000\nUID_MIN 1001\n", want: "duplicate UID_MIN"},
		{name: "malformed group", passwd: "root:x:0:0::/root:/bin/sh\n", group: "broken:x:not-a-gid:\n", defs: "UID_MIN 1000\n", want: "malformed group GID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setIdentityDatabases(t, tc.passwd, tc.group, tc.defs)
			if _, _, err := IdentityAllocationRange(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("IdentityAllocationRange error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestIdentityAllocationRangeFallsBackWhenLoginDefsIsAbsent(t *testing.T) {
	// shadow's own useradd uses its compiled-in range when /etc/login.defs is
	// missing, and minimal images ship it that way. Failing closed here made every
	// invite fail on a host whose account tooling works perfectly.
	setIdentityDatabases(t,
		"root:x:0:0:root:/root:/bin/sh\nalice:x:1500:1500::/home/alice:/bin/sh\n",
		"root:x:0:\nalice:x:1500:\n",
		"UID_MIN 1000\n")
	if err := os.Remove(loginDefsPath); err != nil {
		t.Fatal(err)
	}
	minimum, maximum, err := IdentityAllocationRange()
	if err != nil || minimum != 1501 || maximum != 60000 {
		t.Fatalf("IdentityAllocationRange = %d..%d err=%v, want the built-in 1501..60000", minimum, maximum, err)
	}
}

func TestIdentityAllocationRangeStillFailsClosedOnUnreadableLoginDefs(t *testing.T) {
	// Only a confirmed absence uses the built-in range. Anything that could be
	// hiding a narrower configured range must still stop account creation.
	setIdentityDatabases(t,
		"root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\n", "UID_MIN 1000\n")
	if err := os.Remove(loginDefsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(loginDefsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := IdentityAllocationRange(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("IdentityAllocationRange error = %v, want a fail-closed non-regular login.defs refusal", err)
	}
}

func TestCreateReturnsTheIdentityItReadOnFieldMismatch(t *testing.T) {
	// The snapshot is the last complete identity this call proved. Returning a
	// zero Passwd instead left invite's rollback with nothing to verify, so one
	// unexpected field turned into an account only a human could ever clean up.
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "groupdel": true}}
	m := managerWithStubbedHomeChecks(f)
	pw, err := m.CreatePendingIdentityWithID("xxvcc-a1", "/bin/bash", testGeneration, 2345)
	if err == nil || !strings.Contains(err.Error(), "rollback or manual recovery") {
		t.Fatalf("shell mismatch error = %v, want a retained-account report", err)
	}
	want := Passwd{
		Name: "xxvcc-a1", UID: 2345, GID: 2345, GECOS: pendingMarker,
		Home: "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	if pw != want {
		t.Fatalf("returned identity = %+v, want the snapshot that was read %+v", pw, want)
	}
}

func TestCreatePendingDefersHomeUntilExpectedIdentityCall(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true}}
	var order []string
	m := &Manager{
		Runner:             f,
		PrepareManagedHome: func(string) error { return nil },
		RemoveManagedMail: func(got Passwd) error {
			order = append(order, "mail")
			if got.Name != "xxvcc-a1" || got.UID != 2345 {
				t.Fatalf("mail cleanup identity = %+v", got)
			}
			return nil
		},
		CreateManagedHome: func(Passwd) error {
			order = append(order, "home")
			return nil
		},
		ValidateManagedHome: func(Passwd) error {
			order = append(order, "validate")
			return nil
		},
	}
	pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/bash", testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"mail"}) {
		t.Fatalf("pending account artifact order = %v, want mail cleanup with no Home creation", order)
	}
	if err := m.CreateManagedHomeExpected("xxvcc-a1", pending); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"mail", "home", "validate"}) {
		t.Fatalf("completed account artifact order = %v, want deferred Home creation and validation", order)
	}
}

func TestCreateStillClearsMatchingMailBeforeCreatingHome(t *testing.T) {
	marker := testManagedGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+marker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	var order []string
	m := &Manager{
		Runner:             &fakeRunner{available: map[string]bool{"useradd": true}},
		PrepareManagedHome: func(string) error { return nil },
		RemoveManagedMail: func(Passwd) error {
			order = append(order, "mail")
			return nil
		},
		CreateManagedHome: func(Passwd) error {
			order = append(order, "home")
			return nil
		},
		ValidateManagedHome: func(Passwd) error {
			order = append(order, "validate")
			return nil
		},
	}
	if err := m.Create("xxvcc-a1", "/bin/bash", testGeneration); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"mail", "home", "validate"}) {
		t.Fatalf("account artifact order = %v, want mail cleanup before Home creation", order)
	}
}

func TestCreatePendingCompatibilityStillCreatesHome(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/bash\n")
	setProcRoot(t, map[int]string{})
	var order []string
	m := &Manager{
		Runner:             &fakeRunner{available: map[string]bool{"useradd": true}},
		PrepareManagedHome: func(string) error { return nil },
		RemoveManagedMail: func(Passwd) error {
			order = append(order, "mail")
			return nil
		},
		CreateManagedHome: func(Passwd) error {
			order = append(order, "home")
			return nil
		},
		ValidateManagedHome: func(Passwd) error {
			order = append(order, "validate")
			return nil
		},
	}
	if err := m.CreatePending("xxvcc-a1", "/bin/bash", testGeneration); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"mail", "home", "validate"}) {
		t.Fatalf("compatibility CreatePending artifact order = %v, want complete Home creation", order)
	}
}

func TestCreateManagedHomeExpectedRefusesReplacementBeforeCreation(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	homeCalls := 0
	m := &Manager{
		Runner:             &fakeRunner{available: map[string]bool{"useradd": true}},
		PrepareManagedHome: func(string) error { return nil },
		RemoveManagedMail:  func(Passwd) error { return nil },
		CreateManagedHome: func(Passwd) error {
			homeCalls++
			return nil
		},
		ValidateManagedHome: func(Passwd) error {
			t.Fatal("replacement identity reached Home validation")
			return nil
		},
	}
	pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/sh", testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwdPath, []byte("xxvcc-a1:x:3456:3456:replacement:/home/xxvcc-a1:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = m.CreateManagedHomeExpected("xxvcc-a1", pending)
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement Home creation error = %v, want identity-change refusal", err)
	}
	if homeCalls != 0 {
		t.Fatalf("replacement identity reached Home creation %d time(s)", homeCalls)
	}
}

func TestCreateManagedHomeExpectedRefusesIdentityChangeAfterCreation(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	changedMarker := "Changed Name,,,," + config.PendingGenerationGECOSWitnessPrefix + testGeneration
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	var order []string
	m := &Manager{
		Runner:             &fakeRunner{available: map[string]bool{"useradd": true}},
		PrepareManagedHome: func(string) error { return nil },
		RemoveManagedMail:  func(Passwd) error { return nil },
		CreateManagedHome: func(Passwd) error {
			order = append(order, "home")
			return os.WriteFile(passwdPath, []byte("xxvcc-a1:x:2345:2345:"+changedMarker+":/home/xxvcc-a1:/bin/sh\n"), 0o644)
		},
		ValidateManagedHome: func(Passwd) error {
			t.Fatal("replacement identity reached Home validation")
			return nil
		},
	}
	pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/sh", testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	err = m.CreateManagedHomeExpected("xxvcc-a1", pending)
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("post-create replacement error = %v, want identity-change refusal", err)
	}
	if !reflect.DeepEqual(order, []string{"home"}) {
		t.Fatalf("Home hook order = %v, want identity check immediately after creation", order)
	}
}

func TestClearManagedMailExpectedRejectsUserWritableFieldChange(t *testing.T) {
	expected := Passwd{
		Name: "xxvcc-a1", UID: 2345, GID: 2345, GECOS: testPendingGenerationGECOS(t),
		Home: "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	current := expected
	m := &Manager{
		LookupUser: func(string) (Passwd, bool, error) { return current, true, nil },
		RemoveManagedMail: func(Passwd) error {
			current.GECOS = "Changed Name,,,," + config.PendingGenerationGECOSWitnessPrefix + testGeneration
			return nil
		},
	}
	if err := m.ClearManagedMailExpected(expected.Name, expected); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("ClearManagedMailExpected error = %v, want strict identity refusal", err)
	}
}

func TestCreateManagedHomeExpectedRefusesIdentityChangeDuringValidation(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	var order []string
	m := &Manager{
		Runner:             &fakeRunner{available: map[string]bool{"useradd": true}},
		PrepareManagedHome: func(string) error { return nil },
		RemoveManagedMail:  func(Passwd) error { return nil },
		CreateManagedHome: func(Passwd) error {
			order = append(order, "home")
			return nil
		},
		ValidateManagedHome: func(Passwd) error {
			order = append(order, "validate")
			return os.WriteFile(passwdPath, []byte("xxvcc-a1:x:3456:3456:replacement:/home/xxvcc-a1:/bin/sh\n"), 0o644)
		},
	}
	pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/sh", testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	err = m.CreateManagedHomeExpected("xxvcc-a1", pending)
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("validation replacement error = %v, want identity-change refusal", err)
	}
	if !reflect.DeepEqual(order, []string{"home", "validate"}) {
		t.Fatalf("Home hook order = %v, want creation then validation", order)
	}
}

func TestCreateManagedHomeExpectedChecksIdentityAfterHookErrors(t *testing.T) {
	for _, stage := range []string{"create", "validate"} {
		t.Run(stage, func(t *testing.T) {
			pendingMarker := testPendingGenerationGECOS(t)
			setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
			setProcRoot(t, map[int]string{})
			wantErr := errors.New(stage + " failed")
			m := &Manager{
				Runner:             &fakeRunner{available: map[string]bool{"useradd": true}},
				PrepareManagedHome: func(string) error { return nil },
				RemoveManagedMail:  func(Passwd) error { return nil },
				CreateManagedHome: func(Passwd) error {
					if stage == "create" {
						return wantErr
					}
					return nil
				},
				ValidateManagedHome: func(Passwd) error {
					if stage == "validate" {
						return wantErr
					}
					t.Fatal("validation ran after failed Home creation")
					return nil
				},
			}
			pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/sh", testGeneration)
			if err != nil {
				t.Fatal(err)
			}
			lookups := 0
			m.LookupUser = func(name string) (Passwd, bool, error) {
				lookups++
				return Lookup(name)
			}
			err = m.CreateManagedHomeExpected("xxvcc-a1", pending)
			if !errors.Is(err, wantErr) {
				t.Fatalf("Home %s error = %v, want injected error", stage, err)
			}
			wantLookups := 2
			if stage == "validate" {
				wantLookups = 3
			}
			if lookups != wantLookups {
				t.Fatalf("identity lookups after %s error = %d, want %d", stage, lookups, wantLookups)
			}
		})
	}
}

func TestCreateManagedHomeExpectedRejectsLegacyMarker(t *testing.T) {
	expected := Passwd{
		Name: "xxvcc-a1", UID: 2345, GID: 2345, GECOS: config.ManagedGECOS,
		Home: "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	m := &Manager{
		LookupUser: func(string) (Passwd, bool, error) {
			t.Fatal("legacy marker reached identity lookup")
			return Passwd{}, false, nil
		},
		CreateManagedHome: func(Passwd) error {
			t.Fatal("legacy marker reached Home creation")
			return nil
		},
	}
	err := m.CreateManagedHomeExpected(expected.Name, expected)
	if err == nil || !strings.Contains(err.Error(), "invalid expected account identity") {
		t.Fatalf("legacy marker error = %v, want input refusal", err)
	}
}

func TestReconcileManagedMailAfterDeletionRequiresContinuousAbsence(t *testing.T) {
	const name = "xxvcc-mail-recovery"
	replacement := Passwd{Name: name, UID: 2002, GID: 2002, Home: "/home/" + name, Shell: "/bin/sh"}

	t.Run("absent mail-only cleanup", func(t *testing.T) {
		mailCalls := 0
		m := &Manager{
			LookupUser: func(string) (Passwd, bool, error) { return Passwd{}, false, nil },
			NameInUse:  func(string) (bool, error) { return false, nil },
			RemoveManagedMail: func(got Passwd) error {
				mailCalls++
				if got.Name != name || got.UID != 1001 || got.GID != 0 || got.Home != "" {
					t.Fatalf("post-deletion mail identity = %+v", got)
				}
				return nil
			},
			RemoveManagedHome: func(Passwd) error {
				t.Fatal("post-deletion reconciliation touched Home")
				return nil
			},
		}
		if err := m.ReconcileManagedMailAfterDeletion(name, 1001); err != nil {
			t.Fatal(err)
		}
		if mailCalls != 1 {
			t.Fatalf("mail cleanup calls = %d, want 1", mailCalls)
		}
	})

	t.Run("replacement appears", func(t *testing.T) {
		lookups := 0
		m := &Manager{
			LookupUser: func(string) (Passwd, bool, error) {
				lookups++
				if lookups == 1 {
					return Passwd{}, false, nil
				}
				return replacement, true, nil
			},
			NameInUse:         func(string) (bool, error) { return false, nil },
			RemoveManagedMail: func(Passwd) error { return nil },
		}
		err := m.ReconcileManagedMailAfterDeletion(name, 1001)
		if err == nil || !strings.Contains(err.Error(), "reappeared") {
			t.Fatalf("reconciliation error = %v, want replacement refusal", err)
		}
	})

	t.Run("NSS identity blocks local-absence cleanup", func(t *testing.T) {
		mailCalls := 0
		m := &Manager{
			LookupUser:        func(string) (Passwd, bool, error) { return Passwd{}, false, nil },
			NameInUse:         func(string) (bool, error) { return true, nil },
			RemoveManagedMail: func(Passwd) error { mailCalls++; return nil },
		}
		err := m.ReconcileManagedMailAfterDeletion(name, 1001)
		if err == nil || !strings.Contains(err.Error(), "remains present through NSS") {
			t.Fatalf("NSS replacement error = %v, want fail-closed refusal", err)
		}
		if mailCalls != 0 {
			t.Fatalf("NSS identity reached mail cleanup %d time(s)", mailCalls)
		}
	})

	t.Run("NSS lookup failure is not absence", func(t *testing.T) {
		wantErr := errors.New("NSS unavailable")
		m := &Manager{
			LookupUser: func(string) (Passwd, bool, error) { return Passwd{}, false, nil },
			NameInUse:  func(string) (bool, error) { return false, wantErr },
			RemoveManagedMail: func(Passwd) error {
				t.Fatal("failed NSS lookup reached mail cleanup")
				return nil
			},
		}
		err := m.ReconcileManagedMailAfterDeletion(name, 1001)
		if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "confirm account absence through NSS") {
			t.Fatalf("NSS lookup error = %v, want %v", err, wantErr)
		}
	})
}

func TestMarkManagedExpectedRefusesReplacementBeforeUsermod(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "usermod": true}}
	m := managerWithStubbedHomeChecks(f)
	pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/sh", testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwdPath, []byte("xxvcc-a1:x:3456:3456:replacement:/home/xxvcc-a1:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.MarkManagedExpected("xxvcc-a1", testGeneration, pending); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement MarkManagedExpected error = %v", err)
	}
	if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
		t.Fatalf("replacement reached usermod: calls=%v", f.calls)
	}
}

func TestMarkManagedExpectedRejectsUserWritableFieldChangeAfterUsermod(t *testing.T) {
	pendingMarker := testPendingGenerationGECOS(t)
	managedMarker := testManagedGenerationGECOS(t)
	changedMarker := "Changed Name,,,," + config.ManagedGenerationGECOSWitnessPrefix + testGeneration
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "usermod": true}}
	f.onRun = func(name string) {
		if name == "usermod" {
			if err := os.WriteFile(passwdPath, []byte("xxvcc-a1:x:2345:2345:"+changedMarker+":/home/xxvcc-a1:/bin/sh\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	m := managerWithStubbedHomeChecks(f)
	pending, err := m.CreatePendingIdentity("xxvcc-a1", "/bin/sh", testGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.MarkManagedExpected("xxvcc-a1", testGeneration, pending); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("MarkManagedExpected error = %v, want strict post-usermod identity refusal (exact marker %q)", err, managedMarker)
	}
}

func TestMarkManagedRequiresUsermod(t *testing.T) {
	if err := (&Manager{Runner: &fakeRunner{}}).MarkManaged("xxvcc-a1", testGeneration); err == nil {
		t.Fatal("MarkManaged accepted a host without usermod")
	}
}

func TestCreateRequiresUseradd(t *testing.T) {
	for _, helper := range []string{"adduser", "busybox"} {
		t.Run(helper, func(t *testing.T) {
			f := &fakeRunner{available: map[string]bool{helper: true}}
			err := managerWithStubbedHomeChecks(f).Create("xxvcc-a1", "/bin/sh", testGeneration)
			if err == nil || !strings.Contains(err.Error(), "useradd not available") {
				t.Fatalf("Create error = %v, want useradd refusal", err)
			}
			if len(f.calls) != 0 {
				t.Fatalf("unapproved account helper was invoked: %v", f.calls)
			}
		})
	}
}

func TestCreateValidatesManagedMailRootsBeforeUseradd(t *testing.T) {
	wantErr := errors.New("unsafe mail root")
	f := &fakeRunner{available: map[string]bool{"useradd": true}}
	m := managerWithStubbedHomeChecks(f)
	m.ValidateManagedMailRoots = func() error { return wantErr }
	m.PrepareManagedHome = func(string) error {
		t.Fatal("managed Home preflight ran after mail-root preflight failed")
		return nil
	}

	err := m.Create("xxvcc-a1", "/bin/sh", testGeneration)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "before account creation") {
		t.Fatalf("Create error = %v, want pre-useradd mail-root refusal", err)
	}
	if !errors.Is(err, ErrAccountCreationNotStarted) {
		t.Fatalf("Create error = %v, want creation-not-started classification", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("unsafe mail root reached useradd: %v", f.calls)
	}
}

func TestCreateRevalidatesMailRootAfterUseraddAndReturnsCapturedIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mail-root ownership and mode transition requires root")
	}
	pendingMarker := testPendingGenerationGECOS(t)
	expected := Passwd{
		Name: "xxvcc-a1", UID: 2345, GID: 2345, GECOS: pendingMarker,
		Home: "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+pendingMarker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})
	root := t.TempDir()
	if err := os.Chown(root, 0, 2346); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o775|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	oldRoots := managedMailRoots
	managedMailRoots = []string{root}
	t.Cleanup(func() { managedMailRoots = oldRoots })

	f := &fakeRunner{available: map[string]bool{"useradd": true}}
	f.onRun = func(name string) {
		if name == "useradd" {
			if err := os.Chmod(root, 0o777|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
		}
	}
	preflightCalls := 0
	mailCleanupCalls := 0
	m := &Manager{
		Runner:     f,
		LookupUser: Lookup,
		NameInUse:  func(string) (bool, error) { return false, nil },
		ValidateManagedMailRoots: func() error {
			preflightCalls++
			return validateManagedMailRoots()
		},
		PrepareManagedHome: func(string) error { return nil },
		RemoveManagedMail: func(got Passwd) error {
			mailCleanupCalls++
			if got != expected {
				t.Fatalf("post-useradd mail identity = %+v, want %+v", got, expected)
			}
			return removeManagedMail(got)
		},
	}
	got, err := m.CreatePendingIdentity(expected.Name, expected.Shell, testGeneration)
	if err == nil || !strings.Contains(err.Error(), "world-writable roots require sticky") {
		t.Fatalf("CreatePendingIdentity error = %v, want post-useradd mode refusal", err)
	}
	if got != expected {
		t.Fatalf("captured rollback identity = %+v, want %+v", got, expected)
	}
	if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
		t.Fatalf("post-preflight mode change helper calls = %v", f.calls)
	}
	if preflightCalls != 1 || mailCleanupCalls != 1 {
		t.Fatalf("mail-root preflight/UID cleanup calls = %d/%d, want 1/1", preflightCalls, mailCleanupCalls)
	}
}

func TestCreateEnforcesManagedHomeChecks(t *testing.T) {
	marker := testManagedGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+marker+":/home/xxvcc-a1:/bin/sh\n")
	setProcRoot(t, map[int]string{})

	t.Run("preflight before helper", func(t *testing.T) {
		f := &fakeRunner{available: map[string]bool{"useradd": true}}
		wantErr := errors.New("pre-existing home")
		m := &Manager{
			Runner:              f,
			PrepareManagedHome:  func(string) error { return wantErr },
			ValidateManagedHome: func(Passwd) error { t.Fatal("post-create check ran"); return nil },
		}
		if err := m.Create("xxvcc-a1", "/bin/sh", testGeneration); !errors.Is(err, wantErr) {
			t.Fatalf("Create error = %v, want %v", err, wantErr)
		}
		if len(f.calls) != 0 {
			t.Fatalf("unsafe home reached useradd: %v", f.calls)
		}
	})

	t.Run("post-create identity", func(t *testing.T) {
		f := &fakeRunner{available: map[string]bool{"useradd": true}}
		wantErr := errors.New("wrong home owner")
		m := &Manager{
			Runner:              f,
			PrepareManagedHome:  func(string) error { return nil },
			CreateManagedHome:   func(Passwd) error { return nil },
			ValidateManagedHome: func(Passwd) error { return wantErr },
		}
		if err := m.Create("xxvcc-a1", "/bin/sh", testGeneration); !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "retained") {
			t.Fatalf("Create error = %v, want retained-account home failure", err)
		}
		if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
			t.Fatalf("post-create check call order = %v", f.calls)
		}
	})

	t.Run("create empty home before validation", func(t *testing.T) {
		f := &fakeRunner{available: map[string]bool{"useradd": true}}
		wantErr := errors.New("home creation failed")
		m := &Manager{
			Runner:             f,
			PrepareManagedHome: func(string) error { return nil },
			CreateManagedHome:  func(Passwd) error { return wantErr },
			ValidateManagedHome: func(Passwd) error {
				t.Fatal("validation ran after failed Home creation")
				return nil
			},
		}
		if err := m.Create("xxvcc-a1", "/bin/sh", testGeneration); !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "retained") {
			t.Fatalf("Create error = %v, want retained-account Home creation failure", err)
		}
		if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
			t.Fatalf("Home creation failure call order = %v", f.calls)
		}
	})
}

func useTemporaryManagedHomeRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("managed-home safety checks require root ownership")
	}
	root := t.TempDir()
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	old := managedHomeRoot
	managedHomeRoot = root
	t.Cleanup(func() { managedHomeRoot = old })
	return root
}

func managedHomeFixture(t *testing.T, name string) (Passwd, string) {
	t.Helper()
	root := useTemporaryManagedHomeRoot(t)
	home := filepath.Join(root, name)
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	const uid, gid = 2345, 2346
	if err := os.Chown(home, uid, gid); err != nil {
		t.Fatal(err)
	}
	return Passwd{Name: name, UID: uid, GID: gid, Home: home, Shell: "/bin/sh"}, home
}

func TestPrepareManagedHomeRejectsExistingTargetAndUnsafeParent(t *testing.T) {
	root := useTemporaryManagedHomeRoot(t)
	if err := prepareManagedHome("xxvcc-u"); err != nil {
		t.Fatalf("absent home rejected: %v", err)
	}
	home := filepath.Join(root, "xxvcc-u")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := prepareManagedHome("xxvcc-u"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("pre-existing home error = %v", err)
	}
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := prepareManagedHome("xxvcc-u"); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("writable home parent error = %v", err)
	}
}

func TestCreateManagedHomeCreatesAnEmptyPinnedDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("managed Home ownership requires root")
	}
	root := useTemporaryManagedHomeRoot(t)
	expected := Passwd{
		Name: "xxvcc-emptyhome", UID: 2345, GID: 2346,
		Home: filepath.Join(root, "xxvcc-emptyhome"), Shell: "/bin/sh",
	}
	if err := createManagedHome(expected); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(expected.Home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("new managed Home inherited unexpected entries: %v", entries)
	}
	fi, err := os.Lstat(expected.Home)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(expected.UID) || st.Gid != uint32(expected.GID) || fi.Mode().Perm() != 0o700 {
		t.Fatalf("managed Home metadata = owner %v:%v mode %o, want %d:%d 700", st.Uid, st.Gid, fi.Mode().Perm(), expected.UID, expected.GID)
	}
	if err := createManagedHome(expected); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Home creation error = %v, want existing-target refusal", err)
	}
}

func TestCreateManagedHomeFailsClosedWhenParentIsReplaced(t *testing.T) {
	root := useTemporaryManagedHomeRoot(t)
	expected := Passwd{
		Name: "xxvcc-parent-swap", UID: 2345, GID: 2346,
		Home: filepath.Join(root, "xxvcc-parent-swap"), Shell: "/bin/sh",
	}
	oldSync := syncCreatedHomeMetadata
	syncCreatedHomeMetadata = func(home *os.File) error {
		oldRoot := root + ".replaced"
		if err := os.Rename(root, oldRoot); err != nil {
			return err
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return err
		}
		if err := os.Chown(root, 0, 0); err != nil {
			return err
		}
		return home.Sync()
	}
	t.Cleanup(func() { syncCreatedHomeMetadata = oldSync })

	if err := createManagedHome(expected); err == nil || !strings.Contains(err.Error(), "parent was replaced") {
		t.Fatalf("parent replacement error = %v", err)
	}
}

func TestCreateManagedHomeReportsDurabilityFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation string
		inject    func(error)
	}{
		{
			name:      "home metadata",
			operation: "managed home metadata update",
			inject: func(want error) {
				syncCreatedHomeMetadata = func(*os.File) error { return want }
			},
		},
		{
			name:      "parent entry",
			operation: "managed home creation",
			inject: func(want error) {
				syncCreatedHomeParent = func(*os.File) error { return want }
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := useTemporaryManagedHomeRoot(t)
			oldHomeSync, oldParentSync := syncCreatedHomeMetadata, syncCreatedHomeParent
			t.Cleanup(func() {
				syncCreatedHomeMetadata, syncCreatedHomeParent = oldHomeSync, oldParentSync
			})
			wantErr := errors.New("injected fsync failure")
			tc.inject(wantErr)
			expected := Passwd{
				Name: "xxvcc-sync-fail", UID: 2345, GID: 2346,
				Home: filepath.Join(root, "xxvcc-sync-fail"), Shell: "/bin/sh",
			}
			err := createManagedHome(expected)
			var durability *fsutil.DurabilityError
			if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != tc.operation {
				t.Fatalf("createManagedHome error = %v, want %q durability failure", err, tc.operation)
			}
		})
	}
}

func TestValidateCreatedHomeRequiresNonRootOwnedRealDirectory(t *testing.T) {
	expected, home := managedHomeFixture(t, "xxvcc-u")
	if err := validateCreatedHome(expected); err != nil {
		t.Fatalf("valid created home rejected: %v", err)
	}
	expected.GID = 0
	if err := validateCreatedHome(expected); err == nil || !strings.Contains(err.Error(), "invalid account owner") {
		t.Fatalf("root primary group error = %v", err)
	}
	expected.GID = 2346
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := validateCreatedHome(expected); err == nil || !strings.Contains(err.Error(), "was not created") {
		t.Fatalf("missing created home error = %v", err)
	}
}

func setProcRoot(t *testing.T, statuses map[int]string) {
	t.Helper()
	dir := t.TempDir()
	old := procRoot
	procRoot = dir
	t.Cleanup(func() { procRoot = old })
	for pid, status := range statuses {
		writeProcProcess(t, pid, status)
	}
}

func writeProcProcess(t *testing.T, tgid int, status string) {
	t.Helper()
	writeProcTask(t, tgid, tgid, status)
}

func writeProcTask(t *testing.T, tgid, tid int, status string) {
	t.Helper()
	pidDir := filepath.Join(procRoot, fmt.Sprint(tgid))
	taskDir := filepath.Join(pidDir, "task", fmt.Sprint(tid))
	if err := os.MkdirAll(taskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taskDir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	if tid == tgid {
		if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCreateRejectsUIDWithResidualProcess(t *testing.T) {
	marker := testManagedGenerationGECOS(t)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+marker+":/home/xxvcc-a1:/bin/sh\n")
	// The target UID appears only in the saved-set UID column. Checking only real
	// and effective UIDs would miss this process, which can switch back to 2345.
	setProcRoot(t, map[int]string{77: "Name:\tleftover\nUid:\t1000\t1000\t2345\t1000\n"})
	f := &fakeRunner{available: map[string]bool{"useradd": true, "userdel": true}}
	err := managerWithStubbedHomeChecks(f).Create("xxvcc-a1", "/bin/sh", testGeneration)
	if err == nil || !strings.Contains(err.Error(), "UID 2345") || !strings.Contains(err.Error(), "77") {
		t.Fatalf("Create error = %v, want residual-UID process refusal", err)
	}
	want := [][]string{{"useradd", "-M", "-d", "/home/xxvcc-a1", "-s", "/bin/sh", "-c", marker,
		"-e", expiredDate, "-p", initialLockedPasswordHash, "xxvcc-a1"}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("Create calls = %v, want the pending account retained to occupy the reused UID: %v", f.calls, want)
	}
}

func TestCreateFailsClosedWhenProcCannotBeScanned(t *testing.T) {
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+testManagedGenerationGECOS(t)+":/home/xxvcc-a1:/bin/sh\n")
	old := procRoot
	procRoot = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { procRoot = old })
	f := &fakeRunner{available: map[string]bool{"useradd": true, "userdel": true}}
	if err := managerWithStubbedHomeChecks(f).Create("xxvcc-a1", "/bin/sh", testGeneration); err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("Create error = %v, want proc scan failure", err)
	}
	if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
		t.Fatalf("inconclusive UID scan freed the pending UID: calls=%v", f.calls)
	}
}

func TestCreateRollbackRefusesReplacementIdentity(t *testing.T) {
	const original = "xxvcc-a1:x:2345:2345:original:/home/xxvcc-a1:/bin/sh\n"
	setPasswd(t, original)
	old := procRoot
	procRoot = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { procRoot = old })
	replacement := Passwd{Name: "xxvcc-a1", UID: 3456, GID: 3456, GECOS: "replacement", Home: "/srv/xxvcc-a1", Shell: "/bin/bash"}
	f := &fakeRunner{available: map[string]bool{"useradd": true, "userdel": true}}
	m := &Manager{
		Runner: f,
		LookupUser: func(string) (Passwd, bool, error) {
			return replacement, true, nil
		},
		PrepareManagedHome:  func(string) error { return nil },
		ValidateManagedHome: func(Passwd) error { return nil },
	}
	err := m.Create("xxvcc-a1", "/bin/sh", testGeneration)
	if err == nil || !strings.Contains(err.Error(), "identity does not match") {
		t.Fatalf("Create error = %v, want replacement refusal", err)
	}
	if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
		t.Fatalf("replacement identity reached name-scoped delete: calls=%v", f.calls)
	}
}

func TestCreateDoesNotRollBackAnUnsafeOrUnreadableIdentityByName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		passwd string
	}{
		{name: "uid zero", passwd: "xxvcc-a1:x:0:0:unsafe:/root:/bin/sh\n"},
		{name: "missing", passwd: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setPasswd(t, tc.passwd)
			f := &fakeRunner{available: map[string]bool{"useradd": true, "userdel": true}}
			err := managerWithStubbedHomeChecks(f).Create("xxvcc-a1", "/bin/sh", testGeneration)
			if err == nil {
				t.Fatal("Create accepted an unsafe or missing post-create identity")
			}
			if len(f.calls) != 1 || f.calls[0][0] != "useradd" {
				t.Fatalf("unverified identity reached name-scoped delete: calls=%v", f.calls)
			}
		})
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

func TestProcessScanAndSignalFindLiveWorkerBehindZombieLeader(t *testing.T) {
	const uid = 1111
	setProcRoot(t, map[int]string{
		77: "State:\tZ (zombie)\nUid:\t1111\t1111\t1111\t1111\n",
	})
	writeProcTask(t, 77, 78, "State:\tS (sleeping)\nUid:\t1111\t1111\t1111\t1111\n")

	pids, err := processesForUID(uid)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{77}; !reflect.DeepEqual(pids, want) {
		t.Fatalf("processesForUID = %v, want thread group with live worker %v", pids, want)
	}

	var signalled []int
	withFakePidfds(t, func(fd int, sig unix.Signal, _ *unix.Siginfo, flags int) error {
		if sig != unix.SIGKILL || flags != 0 {
			t.Fatalf("pidfd signal = (%d, %d), want SIGKILL with flags 0", sig, flags)
		}
		signalled = append(signalled, fd-10000)
		return nil
	})
	got, err := signalUID(unix.SIGKILL, uid)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{77}; !reflect.DeepEqual(got, want) || !reflect.DeepEqual(signalled, want) {
		t.Fatalf("signalUID = %v, pidfds=%v; want zombie-leader group %v", got, signalled, want)
	}
}

func TestProcessesForUIDRetriesWhenSnapshotTaskForksThenExits(t *testing.T) {
	const uid = 1111
	setProcRoot(t, map[int]string{
		77: "State:\tS (sleeping)\nUid:\t1111\t1111\t1111\t1111\n",
	})
	oldReadDir := readProcDirectory
	readCalls := 0
	readProcDirectory = func(path string) ([]os.DirEntry, error) {
		entries, err := oldReadDir(path)
		if err != nil {
			return nil, err
		}
		if path != procRoot {
			return entries, nil
		}
		readCalls++
		if readCalls == 1 {
			// The old snapshot contains only the parent. It forks a child and exits
			// before its status is read, so the child exists only in the next snapshot.
			if err := os.RemoveAll(filepath.Join(procRoot, "77")); err != nil {
				t.Fatal(err)
			}
			status := "State:\tS (sleeping)\nUid:\t1111\t1111\t1111\t1111\n"
			writeProcProcess(t, 78, status)
		}
		return entries, nil
	}
	t.Cleanup(func() { readProcDirectory = oldReadDir })

	pids, err := processesForUID(uid)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{78}; !reflect.DeepEqual(pids, want) {
		t.Fatalf("processesForUID = %v, want forked child %v", pids, want)
	}
	if readCalls != 2 {
		t.Fatalf("process directory reads = %d, want unstable snapshot plus retry", readCalls)
	}
}

func TestProcessesForUIDDoesNotLetPIDReuseMaskForkedChild(t *testing.T) {
	const uid = 1111
	setProcRoot(t, map[int]string{
		77: "State:\tS (sleeping)\nUid:\t1111\t1111\t1111\t1111\n",
	})
	oldReadDir := readProcDirectory
	rootReads := 0
	readProcDirectory = func(path string) ([]os.DirEntry, error) {
		entries, err := oldReadDir(path)
		if err != nil {
			return nil, err
		}
		if path != procRoot {
			return entries, nil
		}
		rootReads++
		if rootReads == 1 {
			// The old target parent exits after forking 78, but PID 77 is reused
			// before its status is read. Reading the unrelated replacement produces
			// no ENOENT, so only a second stable empty scan can discover the child.
			if err := os.RemoveAll(filepath.Join(procRoot, "77")); err != nil {
				t.Fatal(err)
			}
			writeProcProcess(t, 77, "State:\tS (sleeping)\nUid:\t9999\t9999\t9999\t9999\n")
			writeProcProcess(t, 78, "State:\tS (sleeping)\nUid:\t1111\t1111\t1111\t1111\n")
		}
		return entries, nil
	}
	t.Cleanup(func() { readProcDirectory = oldReadDir })

	pids, err := processesForUID(uid)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{78}; !reflect.DeepEqual(pids, want) {
		t.Fatalf("processesForUID = %v, want child hidden by PID reuse %v", pids, want)
	}
	if rootReads != 2 {
		t.Fatalf("top-level process scans = %d, want two-scan empty confirmation", rootReads)
	}
}

func TestProcessesForUIDFailsClosedWhenSnapshotsNeverStabilize(t *testing.T) {
	setProcRoot(t, map[int]string{
		77: "State:\tS (sleeping)\nUid:\t9999\t9999\t9999\t9999\n",
	})
	oldReadDir := readProcDirectory
	readCalls := 0
	readProcDirectory = func(path string) ([]os.DirEntry, error) {
		entries, err := oldReadDir(path)
		if err != nil {
			return nil, err
		}
		if path != procRoot {
			return entries, nil
		}
		readCalls++
		oldPID := 76 + readCalls
		newPID := oldPID + 1
		if err := os.RemoveAll(filepath.Join(procRoot, strconv.Itoa(oldPID))); err != nil {
			t.Fatal(err)
		}
		status := "State:\tS (sleeping)\nUid:\t9999\t9999\t9999\t9999\n"
		writeProcProcess(t, newPID, status)
		return entries, nil
	}
	t.Cleanup(func() { readProcDirectory = oldReadDir })

	if pids, err := processesForUID(1111); err == nil || !strings.Contains(err.Error(), "no consecutive stable empty process snapshots") {
		t.Fatalf("processesForUID = %v, %v; want unstable-snapshot refusal", pids, err)
	}
	if readCalls != processScanAttempts {
		t.Fatalf("process directory reads = %d, want bounded %d attempts", readCalls, processScanAttempts)
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

func TestTerminateProcessesRescansAfterSnapshotTaskForksThenExits(t *testing.T) {
	const uid = 2345
	setProcRoot(t, map[int]string{77: "State:\tS (sleeping)\nUid:\t2345\t2345\t2345\t2345\n"})
	oldOpen, oldSend, oldClose, oldSleep := pidfdOpen, pidfdSendSignal, closeFD, terminateSleep
	openCalls := 0
	pidfdOpen = func(pid, flags int) (int, error) {
		if flags != 0 {
			t.Fatalf("PidfdOpen flags = %d, want 0", flags)
		}
		openCalls++
		if openCalls == 2 {
			// The first SIGKILL snapshot contained only pid 77. Before its pidfd
			// opens, it forks pid 78 and exits. pid 78 was never in that snapshot.
			if err := os.RemoveAll(filepath.Join(procRoot, "77")); err != nil {
				t.Fatal(err)
			}
			status := "State:\tS (sleeping)\nUid:\t2345\t2345\t2345\t2345\n"
			writeProcProcess(t, 78, status)
			return -1, unix.ESRCH
		}
		return pid + 10000, nil
	}
	kills := 0
	pidfdSendSignal = func(fd int, sig unix.Signal, _ *unix.Siginfo, flags int) error {
		if flags != 0 {
			t.Fatalf("PidfdSendSignal flags = %d, want 0", flags)
		}
		if sig == unix.SIGKILL {
			kills++
			if fd != 10078 {
				t.Fatalf("SIGKILL fd = %d, want child pidfd 10078", fd)
			}
			if err := os.RemoveAll(filepath.Join(procRoot, "78")); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	closeFD = func(int) error { return nil }
	terminateSleep = func(time.Duration) {}
	t.Cleanup(func() {
		pidfdOpen, pidfdSendSignal, closeFD, terminateSleep = oldOpen, oldSend, oldClose, oldSleep
	})

	if err := TerminateProcesses(uid); err != nil {
		t.Fatalf("TerminateProcesses missed forked child: %v", err)
	}
	if openCalls != 3 || kills != 1 {
		t.Fatalf("pidfd opens=%d SIGKILLs=%d, want TERM parent, raced parent, then killed child", openCalls, kills)
	}
}

func TestTerminateProcessesDoesNotAcceptUnstableFinalEmptyScan(t *testing.T) {
	const uid = 2345
	setProcRoot(t, map[int]string{77: "State:\tS (sleeping)\nUid:\t2345\t2345\t2345\t2345\n"})
	oldReadDir := readProcDirectory
	readCalls := 0
	readProcDirectory = func(path string) ([]os.DirEntry, error) {
		entries, err := oldReadDir(path)
		if err != nil {
			return nil, err
		}
		if path != procRoot {
			return entries, nil
		}
		readCalls++
		if readCalls == 3 {
			// Calls one and two are the TERM and first KILL signal snapshots. This
			// third call is the final credential check: its parent exits after the
			// directory snapshot and leaves a child absent from that old listing.
			if err := os.RemoveAll(filepath.Join(procRoot, "77")); err != nil {
				t.Fatal(err)
			}
			status := "State:\tS (sleeping)\nUid:\t2345\t2345\t2345\t2345\n"
			writeProcProcess(t, 78, status)
		}
		return entries, nil
	}

	oldOpen, oldSend, oldClose, oldSleep := pidfdOpen, pidfdSendSignal, closeFD, terminateSleep
	openCalls := 0
	pidfdOpen = func(pid, flags int) (int, error) {
		openCalls++
		if openCalls == 2 {
			return -1, unix.ESRCH
		}
		return pid + 10000, nil
	}
	kills := 0
	pidfdSendSignal = func(fd int, sig unix.Signal, _ *unix.Siginfo, _ int) error {
		if sig == unix.SIGKILL {
			kills++
			if fd != 10078 {
				t.Fatalf("SIGKILL fd = %d, want forked child pidfd 10078", fd)
			}
			if err := os.RemoveAll(filepath.Join(procRoot, "78")); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	closeFD = func(int) error { return nil }
	terminateSleep = func(time.Duration) {}
	t.Cleanup(func() {
		readProcDirectory = oldReadDir
		pidfdOpen, pidfdSendSignal, closeFD, terminateSleep = oldOpen, oldSend, oldClose, oldSleep
	})

	if err := TerminateProcesses(uid); err != nil {
		t.Fatalf("TerminateProcesses accepted no stable final scan: %v", err)
	}
	if kills != 1 {
		t.Fatalf("SIGKILL calls = %d, want forked child killed on the retry", kills)
	}
	if _, err := os.Lstat(filepath.Join(procRoot, "78")); !os.IsNotExist(err) {
		t.Fatalf("forked child survived unstable final scan: %v", err)
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
	_ = m.ClearExpiry("xxvcc-u")
	want := [][]string{
		{"usermod", "-L", "xxvcc-u"},
		{"chage", "-E", "2026-07-09", "xxvcc-u"},
		{"chage", "-E", "-1", "xxvcc-u"},
	}
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

func TestDeleteRequiresUserdel(t *testing.T) {
	setPasswd(t, "xxvcc-u:x:1001:1001::/home/xxvcc-u:/bin/sh\n")
	expected, ok, err := Lookup("xxvcc-u")
	if err != nil || !ok {
		t.Fatalf("Lookup = %+v, %v, %v", expected, ok, err)
	}
	f := &fakeRunner{available: map[string]bool{"deluser": true, "busybox": true}}
	err = managerWithStubbedHomeRemoval(f).DeleteExpected(expected.Name, expected, noOpBeforeDelete)
	if err == nil || !strings.Contains(err.Error(), "userdel not available") {
		t.Fatalf("DeleteExpected error = %v, want userdel refusal", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("unapproved deletion helper was invoked: %v", f.calls)
	}
}

func TestDeleteExpectedRequiresFinalQuiescenceCallback(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	if err := (&Manager{Runner: f}).DeleteExpected(expected.Name, expected, nil); err == nil || !strings.Contains(err.Error(), "quiescence") {
		t.Fatalf("DeleteExpected without callback error = %v, want refusal", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("missing quiescence callback reached userdel: %v", f.calls)
	}
}

func TestDeleteExpectedExactRejectsCurrentFormatMutableFieldChanges(t *testing.T) {
	expected := Passwd{
		Name: "xxvcc-u", UID: 1001, GID: 1001,
		GECOS: ",,,," + config.ManagedGenerationGECOSWitnessPrefix + testGeneration,
		Home:  "/home/xxvcc-u", Shell: "/bin/bash",
	}
	current := expected
	current.GECOS = "Changed Name,room,work,home," + config.ManagedGenerationGECOSWitnessPrefix + testGeneration
	current.Shell = "/bin/sh"
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	artifactCalls := 0
	m := &Manager{
		Runner:            f,
		LookupUser:        func(string) (Passwd, bool, error) { return current, true, nil },
		RemoveManagedMail: func(Passwd) error { artifactCalls++; return nil },
		RemoveManagedHome: func(Passwd) error { artifactCalls++; return nil },
	}
	err := m.DeleteExpectedExact(expected.Name, expected, noOpBeforeDelete)
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("DeleteExpectedExact error = %v, want exact-identity refusal", err)
	}
	if artifactCalls != 0 || len(f.calls) != 0 {
		t.Fatalf("exact-identity refusal reached cleanup: artifacts=%d helpers=%v", artifactCalls, f.calls)
	}
}

func TestDeleteExpectedIdentityPolicyPersistsAcrossLateBoundaries(t *testing.T) {
	expected := Passwd{
		Name: "xxvcc-u", UID: 1001, GID: 1001,
		GECOS: ",,,," + config.ManagedGenerationGECOSWitnessPrefix + testGeneration,
		Home:  "/home/xxvcc-u", Shell: "/bin/bash",
	}
	mutable := expected
	mutable.GECOS = "Changed Name,room,work,home," + config.ManagedGenerationGECOSWitnessPrefix + testGeneration
	mutable.Shell = "/bin/sh"
	if !SameAccountIdentity(expected, mutable) || expected == mutable {
		t.Fatal("fixture does not isolate user-changeable passwd fields")
	}

	policies := []struct {
		name          string
		delete        func(*Manager, string, Passwd, func() error) error
		wantIdentity  bool
		wantSucceeded bool
	}{
		{
			name: "pre-activation exact snapshot",
			delete: func(m *Manager, name string, expected Passwd, beforeDelete func() error) error {
				return m.DeleteExpectedExact(name, expected, beforeDelete)
			},
			wantIdentity: true,
		},
		{
			name: "activation may have started",
			delete: func(m *Manager, name string, expected Passwd, beforeDelete func() error) error {
				return m.DeleteExpected(name, expected, beforeDelete)
			},
			wantSucceeded: true,
		},
	}

	for _, policy := range policies {
		t.Run(policy.name+"/after artifact cleanup", func(t *testing.T) {
			current := expected
			exists := true
			f := &fakeRunner{available: map[string]bool{"userdel": true}}
			f.onRun = func(name string) {
				if name == "userdel" {
					exists = false
				}
			}
			m := stubAbsentAccountDatabaseChecks(&Manager{
				Runner:            f,
				LookupUser:        func(string) (Passwd, bool, error) { return current, exists, nil },
				RemoveManagedMail: func(Passwd) error { return nil },
				RemoveManagedHome: func(Passwd) error {
					current = mutable
					return nil
				},
			})
			err := policy.delete(m, expected.Name, expected, noOpBeforeDelete)
			if policy.wantIdentity {
				if err == nil || !strings.Contains(err.Error(), "identity changed") {
					t.Fatalf("delete error = %v, want exact-identity refusal", err)
				}
				if len(f.calls) != 0 {
					t.Fatalf("exact-identity refusal reached userdel: %v", f.calls)
				}
				return
			}
			if !policy.wantSucceeded || err != nil {
				t.Fatalf("stable-identity delete error = %v", err)
			}
			if exists || len(f.calls) != 1 || f.calls[0][0] != "userdel" {
				t.Fatalf("stable-identity delete did not finish: exists=%v calls=%v", exists, f.calls)
			}
		})

		t.Run(policy.name+"/after account helper", func(t *testing.T) {
			current := expected
			f := &fakeRunner{available: map[string]bool{"userdel": true}}
			f.onRun = func(name string) {
				if name == "userdel" {
					current = mutable
				}
			}
			m := &Manager{
				Runner:            f,
				LookupUser:        func(string) (Passwd, bool, error) { return current, true, nil },
				RemoveManagedMail: func(Passwd) error { return nil },
				RemoveManagedHome: func(Passwd) error { return nil },
			}
			err := policy.delete(m, expected.Name, expected, noOpBeforeDelete)
			if err == nil {
				t.Fatal("account helper that left the account present was reported as success")
			}
			if policy.wantIdentity {
				if !strings.Contains(err.Error(), "identity changed") {
					t.Fatalf("delete error = %v, want exact post-helper identity refusal", err)
				}
			} else if strings.Contains(err.Error(), "identity changed") || !strings.Contains(err.Error(), "still exists") {
				t.Fatalf("stable post-helper identity policy was not retained: %v", err)
			}
			if len(f.calls) != 1 || f.calls[0][0] != "userdel" {
				t.Fatalf("post-helper verification calls = %v, want one userdel", f.calls)
			}
		})
	}
}

func TestDeleteExpectedRefusesNameScopedFallbackAfterReplacement(t *testing.T) {
	const original = "xxvcc-u:x:1001:1001:original:/home/xxvcc-u:/bin/sh\n"
	const replacement = "xxvcc-u:x:2002:2002:replacement:/srv/xxvcc-u:/bin/bash\n"
	for _, firstSucceeded := range []bool{false, true} {
		t.Run(fmt.Sprintf("userdel-success-%v", firstSucceeded), func(t *testing.T) {
			setPasswd(t, original)
			expected, ok, err := Lookup("xxvcc-u")
			if err != nil || !ok {
				t.Fatalf("Lookup original = %+v, %v, %v", expected, ok, err)
			}
			f := &fakeRunner{available: map[string]bool{"deluser": true, "userdel": true}}
			if !firstSucceeded {
				f.failOn = map[string]bool{"userdel": true}
			}
			f.onRun = func(name string) {
				if name == "userdel" {
					if err := os.WriteFile(passwdPath, []byte(replacement), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = managerWithStubbedHomeRemoval(f).DeleteExpected("xxvcc-u", expected, noOpBeforeDelete)
			if err == nil || !strings.Contains(err.Error(), "identity changed") {
				t.Fatalf("DeleteExpected error = %v, want replacement refusal", err)
			}
			if len(f.calls) != 1 || f.calls[0][0] != "userdel" {
				t.Fatalf("replacement reached fallback helper: calls=%v", f.calls)
			}
		})
	}
}

func TestDeleteExpectedRejectsUnboundHomeBeforeHelper(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, GECOS: "managed", Home: "/srv/shared", Shell: "/bin/sh"}
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	if err := (&Manager{Runner: f}).DeleteExpected("xxvcc-u", expected, noOpBeforeDelete); err == nil || !strings.Contains(err.Error(), "invalid expected account identity") {
		t.Fatalf("DeleteExpected with unbound home error = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("unsafe home reached account helper: %v", f.calls)
	}
}

func TestValidateHomeRemovalRequiresDedicatedOwnedRealDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned Home fixtures are covered by required Root integration")
	}
	const testUID, testGID = 2345, 2346
	oldRoot := managedHomeRoot
	managedHomeRoot = t.TempDir()
	t.Cleanup(func() { managedHomeRoot = oldRoot })
	if err := os.Chown(managedHomeRoot, 0, 0); err != nil {
		t.Fatal(err)
	}
	home := managedHome("xxvcc-u")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, testUID, testGID); err != nil {
		t.Fatal(err)
	}
	expected := Passwd{Name: "xxvcc-u", UID: testUID, GID: testGID, Home: home}
	if err := validateHomeRemoval(expected); err != nil {
		t.Fatalf("safe dedicated home rejected: %v", err)
	}

	expected.UID++
	if err := validateHomeRemoval(expected); err == nil || !strings.Contains(err.Error(), "owner does not match") {
		t.Fatalf("owner mismatch error = %v", err)
	}
	expected.UID--
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), home); err != nil {
		t.Fatal(err)
	}
	if err := validateHomeRemoval(expected); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("symlink home error = %v", err)
	}
}

func TestRemoveManagedMailRequiresOwnedRegularSpool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mail-spool ownership checks require root")
	}
	root := t.TempDir()
	if err := os.Chown(root, 0, 2346); err != nil {
		t.Fatal(err)
	}
	// The target host that exposed this regression uses the traditional shared
	// sticky mail-spool layout: root:mail 3777.
	if err := os.Chmod(root, 0o777|os.ModeSetgid|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "mail-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	oldRoots := managedMailRoots
	managedMailRoots = []string{root, alias}
	t.Cleanup(func() { managedMailRoots = oldRoots })
	expected := Passwd{Name: "xxvcc-u", UID: 2345, GID: 2346, Home: "/home/xxvcc-u"}
	spool := filepath.Join(root, expected.Name)
	writeSpool := func() {
		t.Helper()
		if err := os.WriteFile(spool, []byte("mail\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(spool, expected.UID, 8); err != nil {
			t.Fatal(err)
		}
	}

	writeSpool()
	if err := removeManagedMail(expected); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(spool); !os.IsNotExist(err) {
		t.Fatalf("owned mail spool survived cleanup: %v", err)
	}

	writeSpool()
	if err := os.Chown(spool, expected.UID+1, 8); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedMail(expected); err == nil || !strings.Contains(err.Error(), "owner does not match") {
		t.Fatalf("wrong-owner spool error = %v", err)
	}
	if err := os.Remove(spool); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), spool); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedMail(expected); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink spool error = %v", err)
	}
}

func TestManagedMailRootModePolicy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mail-root ownership and special-mode checks require root")
	}
	expected := Passwd{Name: "xxvcc-u", UID: 2345, GID: 2346, Home: "/home/xxvcc-u"}
	tests := []struct {
		name   string
		uid    int
		gid    int
		mode   os.FileMode
		wantOK bool
	}{
		{name: "Debian root mail setgid", uid: 0, gid: 2346, mode: 0o775 | os.ModeSetgid, wantOK: true},
		{name: "Arch root sticky shared", uid: 0, gid: 0, mode: 0o777 | os.ModeSticky, wantOK: true},
		{name: "target root mail setgid sticky", uid: 0, gid: 2346, mode: 0o777 | os.ModeSetgid | os.ModeSticky, wantOK: true},
		{name: "world-writable without sticky", uid: 0, gid: 2346, mode: 0o777 | os.ModeSetgid},
		{name: "setuid sticky", uid: 0, gid: 2346, mode: 0o777 | os.ModeSetuid | os.ModeSticky},
		{name: "non-root sticky owner", uid: 1234, gid: 2346, mode: 0o777 | os.ModeSticky},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chown(root, tc.uid, tc.gid); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, tc.mode); err != nil {
				t.Fatal(err)
			}
			err := removeManagedMailAt(root, expected)
			if tc.wantOK && err != nil {
				t.Fatalf("safe mail-root mode %v rejected: %v", tc.mode, err)
			}
			if !tc.wantOK && (err == nil || !strings.Contains(err.Error(), "not a safe root-owned directory")) {
				t.Fatalf("unsafe mail-root mode %v/owner %d:%d error = %v", tc.mode, tc.uid, tc.gid, err)
			}
		})
	}
}

func TestRemoveManagedMailSyncsParentWhenSpoolDisappearsBeforeUnlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mail-spool ownership checks require root")
	}
	root := t.TempDir()
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal(err)
	}
	expected := Passwd{Name: "xxvcc-u", UID: 2345, GID: 2346, Home: "/home/xxvcc-u"}
	spool := filepath.Join(root, expected.Name)
	if err := os.WriteFile(spool, []byte("mail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(spool, expected.UID, 8); err != nil {
		t.Fatal(err)
	}

	oldUnlink := unlinkManagedMailAt
	unlinkManagedMailAt = func(dirfd int, path string, flags int) error {
		if err := oldUnlink(dirfd, path, flags); err != nil {
			return err
		}
		return unix.ENOENT
	}
	t.Cleanup(func() { unlinkManagedMailAt = oldUnlink })

	oldSync := syncRemovalDirectory
	syncs := 0
	syncRemovalDirectory = func(*os.File) error {
		syncs++
		return nil
	}
	t.Cleanup(func() { syncRemovalDirectory = oldSync })

	if err := removeManagedMailAt(root, expected); err != nil {
		t.Fatalf("mail spool disappearance race: %v", err)
	}
	if _, err := os.Lstat(spool); !os.IsNotExist(err) {
		t.Fatalf("mail spool still exists after simulated disappearance: %v", err)
	}
	if syncs != 1 {
		t.Fatalf("mail parent sync calls = %d, want one absence confirmation", syncs)
	}
}

func TestRemoveManagedMailRejectsSpoolRecreatedDuringDirectorySync(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mail-spool ownership checks require root")
	}
	root := t.TempDir()
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal(err)
	}
	expected := Passwd{Name: "xxvcc-u", UID: 2345, GID: 2346, Home: "/home/xxvcc-u"}
	spool := filepath.Join(root, expected.Name)
	if err := os.WriteFile(spool, []byte("old mail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(spool, expected.UID, 8); err != nil {
		t.Fatal(err)
	}

	oldSync := syncRemovalDirectory
	syncRemovalDirectory = func(dir *os.File) error {
		if err := os.WriteFile(spool, []byte("new mail\n"), 0o600); err != nil {
			return err
		}
		if err := os.Chown(spool, expected.UID, 8); err != nil {
			return err
		}
		return dir.Sync()
	}
	t.Cleanup(func() { syncRemovalDirectory = oldSync })

	err := removeManagedMailAt(root, expected)
	if err == nil || !strings.Contains(err.Error(), "reappeared during cleanup") {
		t.Fatalf("mail recreation error = %v, want fail-closed refusal", err)
	}
	if _, err := os.Lstat(spool); err != nil {
		t.Fatalf("recreated spool was not retained for recovery: %v", err)
	}
}

func TestAbsentManagedArtifactsResyncParentBeforeSuccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("managed artifact durability checks require root-owned directories")
	}
	wantErr := errors.New("forced absence-confirmation sync failure")

	t.Run("mail spool", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chown(root, 0, 0); err != nil {
			t.Fatal(err)
		}
		expected := Passwd{Name: "xxvcc-u", UID: 2345, GID: 2346, Home: "/home/xxvcc-u"}
		old := syncRemovalDirectory
		calls := 0
		syncRemovalDirectory = func(*os.File) error {
			calls++
			return wantErr
		}
		t.Cleanup(func() { syncRemovalDirectory = old })

		err := removeManagedMailAt(root, expected)
		var durability *fsutil.DurabilityError
		if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "managed mail spool absence confirmation" {
			t.Fatalf("absent mail cleanup error = %v, want durability error", err)
		}
		if calls != 1 {
			t.Fatalf("absent mail parent sync calls = %d, want 1", calls)
		}
	})

	t.Run("Home", func(t *testing.T) {
		root := useTemporaryManagedHomeRoot(t)
		expected := Passwd{Name: "xxvcc-u", UID: 2345, GID: 2346, Home: filepath.Join(root, "xxvcc-u"), Shell: "/bin/sh"}
		old := syncRemovalDirectory
		calls := 0
		syncRemovalDirectory = func(*os.File) error {
			calls++
			return wantErr
		}
		t.Cleanup(func() { syncRemovalDirectory = old })

		err := removeManagedHome(expected)
		var durability *fsutil.DurabilityError
		if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "managed home absence confirmation" {
			t.Fatalf("absent Home cleanup error = %v, want durability error", err)
		}
		if calls != 1 {
			t.Fatalf("absent Home parent sync calls = %d, want 1", calls)
		}
	})
}

func TestDeleteExpectedRemovesManagedArtifactsThenAccountWithoutRecursiveHelper(t *testing.T) {
	expected, home := managedHomeFixture(t, "xxvcc-u")
	exists := true
	var order []string
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	f.onRun = func(name string) {
		if name == "userdel" {
			order = append(order, "account")
			exists = false
		}
	}
	m := &Manager{
		Runner: f,
		LookupUser: func(string) (Passwd, bool, error) {
			return expected, exists, nil
		},
		RemoveManagedMail: func(Passwd) error {
			order = append(order, "mail")
			return nil
		},
		RemoveManagedHome: func(pw Passwd) error {
			order = append(order, "home")
			return removeManagedHome(pw)
		},
	}
	if err := m.DeleteExpected("xxvcc-u", expected, func() error {
		order = append(order, "quiesce")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, [][]string{{"userdel", "--", "xxvcc-u"}}) {
		t.Fatalf("account helper argv = %v", f.calls)
	}
	if !reflect.DeepEqual(order, []string{"mail", "home", "quiesce", "home", "account", "mail"}) {
		t.Fatalf("deletion order = %v, want artifacts, final quiescence, Home resweep, account helper, and mail resweep", order)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("managed home survived controlled cleanup: %v", err)
	}
}

func TestDeleteExpectedRemovesHomeRecreatedDuringFinalQuiescence(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	exists := true
	homePresent := true
	homeCalls := 0
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	f.onRun = func(name string) {
		if name != "userdel" {
			return
		}
		if homePresent {
			t.Error("userdel ran while Home recreated during final quiescence was still present")
		}
		exists = false
	}
	m := stubAbsentAccountDatabaseChecks(&Manager{
		Runner:     f,
		LookupUser: func(string) (Passwd, bool, error) { return expected, exists, nil },
		RemoveManagedMail: func(Passwd) error {
			return nil
		},
		RemoveManagedHome: func(Passwd) error {
			homeCalls++
			homePresent = false
			return nil
		},
	})
	if err := m.DeleteExpected(expected.Name, expected, func() error {
		if homeCalls != 1 || homePresent {
			t.Fatalf("initial Home cleanup state: calls=%d present=%v", homeCalls, homePresent)
		}
		homePresent = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if homeCalls != 2 || homePresent {
		t.Fatalf("final Home cleanup state: calls=%d present=%v, want two sweeps and absence", homeCalls, homePresent)
	}
	if exists || len(f.calls) != 1 || f.calls[0][0] != "userdel" {
		t.Fatalf("account deletion state: exists=%v calls=%v", exists, f.calls)
	}
}

func TestDeleteExpectedStopsAfterArtifactsWhenFinalQuiescenceFails(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	wantErr := errors.New("queued work is still present")
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	m := &Manager{
		Runner:            f,
		LookupUser:        func(string) (Passwd, bool, error) { return expected, true, nil },
		RemoveManagedMail: func(Passwd) error { return nil },
		RemoveManagedHome: func(Passwd) error { return nil },
	}
	err := m.DeleteExpected(expected.Name, expected, func() error { return wantErr })
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "before userdel") {
		t.Fatalf("DeleteExpected error = %v, want final quiescence failure", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("failed final quiescence reached userdel: %v", f.calls)
	}
}

func TestDeleteExpectedStopsBeforeHomeAndHelperWhenMailCleanupFails(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	wantErr := errors.New("mail spool unsafe")
	homeCalls := 0
	f := &fakeRunner{available: map[string]bool{"userdel": true, "deluser": true}}
	m := &Manager{
		Runner:            f,
		LookupUser:        func(string) (Passwd, bool, error) { return expected, true, nil },
		RemoveManagedMail: func(Passwd) error { return wantErr },
		RemoveManagedHome: func(Passwd) error { homeCalls++; return nil },
	}
	if err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete); !errors.Is(err, wantErr) {
		t.Fatalf("DeleteExpected error = %v, want %v", err, wantErr)
	}
	if homeCalls != 0 || len(f.calls) != 0 {
		t.Fatalf("mail cleanup failure reached home/helper: home=%d helper=%v", homeCalls, f.calls)
	}
}

func TestDeleteExpectedAbsentAccountOnlyCleansOwnerCheckedMail(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	var order []string
	m := stubAbsentAccountDatabaseChecks(&Manager{
		LookupUser: func(string) (Passwd, bool, error) { return Passwd{}, false, nil },
		NameInUse:  func(string) (bool, error) { return false, nil },
		RemoveManagedMail: func(Passwd) error {
			order = append(order, "mail")
			return nil
		},
		RemoveManagedHome: func(Passwd) error {
			order = append(order, "home")
			return nil
		},
	})
	if err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"mail", "mail"}) {
		t.Fatalf("absent-account cleanup order = %v, want two mail sweeps and no Home removal", order)
	}
}

func TestDeleteExpectedRechecksAbsenceBetweenMailSweeps(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	var events []string
	m := stubAbsentAccountDatabaseChecks(&Manager{
		LookupUser: func(string) (Passwd, bool, error) {
			events = append(events, "local")
			return Passwd{}, false, nil
		},
		NameInUse: func(string) (bool, error) {
			events = append(events, "nss")
			return false, nil
		},
		RemoveManagedMail: func(Passwd) error {
			events = append(events, "mail")
			return nil
		},
	})
	if err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete); err != nil {
		t.Fatal(err)
	}
	want := []string{"local", "nss", "mail", "local", "nss", "mail", "local", "nss", "local", "nss", "local", "nss"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("absent-account sweep sequence = %v, want %v", events, want)
	}
}

func TestDeleteExpectedFinalMailSweepRemovesSpoolRecreatedDuringHomeCleanup(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	exists := true
	spool := filepath.Join(t.TempDir(), expected.Name)
	mailCalls := 0
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	f.onRun = func(name string) {
		if name == "userdel" {
			exists = false
		}
	}
	m := stubAbsentAccountDatabaseChecks(&Manager{
		Runner:     f,
		LookupUser: func(string) (Passwd, bool, error) { return expected, exists, nil },
		RemoveManagedMail: func(Passwd) error {
			mailCalls++
			if err := os.Remove(spool); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		},
		RemoveManagedHome: func(Passwd) error {
			return os.WriteFile(spool, []byte("delivery raced with Home cleanup"), 0o600)
		},
	})
	if err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete); err != nil {
		t.Fatal(err)
	}
	if mailCalls != 2 {
		t.Fatalf("mail cleanup calls = %d, want initial and post-account sweeps", mailCalls)
	}
	if _, err := os.Lstat(spool); !os.IsNotExist(err) {
		t.Fatalf("mail spool recreated during Home cleanup survived: %v", err)
	}
}

func TestDeleteExpectedRetainsFailureWhenFinalMailSweepFails(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	exists := true
	wantErr := errors.New("final spool cleanup failed")
	mailCalls := 0
	f := &fakeRunner{available: map[string]bool{"userdel": true}}
	f.onRun = func(name string) {
		if name == "userdel" {
			exists = false
		}
	}
	m := &Manager{
		Runner:            f,
		LookupUser:        func(string) (Passwd, bool, error) { return expected, exists, nil },
		RemoveManagedHome: func(Passwd) error { return nil },
		RemoveManagedMail: func(Passwd) error {
			mailCalls++
			if mailCalls == 2 {
				return wantErr
			}
			return nil
		},
	}
	err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "final cleanup") {
		t.Fatalf("DeleteExpected error = %v, want final mail failure", err)
	}
	if exists || mailCalls != 2 {
		t.Fatalf("post-helper state: exists=%v mail calls=%d", exists, mailCalls)
	}
}

func TestDeleteExpectedRefusesAccountReappearanceAtSuccessBoundary(t *testing.T) {
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	replacement := expected
	replacement.UID = 2002
	replacement.GID = 2002
	replacement.GECOS = "replacement"

	t.Run("during cleanup of an already absent account", func(t *testing.T) {
		exists := false
		current := Passwd{}
		mailCalls := 0
		m := &Manager{
			LookupUser: func(string) (Passwd, bool, error) { return current, exists, nil },
			RemoveManagedMail: func(Passwd) error {
				mailCalls++
				if mailCalls == 2 {
					current, exists = replacement, true
				}
				return nil
			},
			RemoveManagedHome: func(Passwd) error { return nil },
		}
		err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete)
		if err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("DeleteExpected error = %v, want reappearance refusal", err)
		}
	})

	t.Run("during final cleanup after userdel", func(t *testing.T) {
		exists := true
		current := expected
		mailCalls := 0
		f := &fakeRunner{available: map[string]bool{"userdel": true}}
		f.onRun = func(name string) {
			if name == "userdel" {
				exists = false
			}
		}
		m := &Manager{
			Runner:     f,
			LookupUser: func(string) (Passwd, bool, error) { return current, exists, nil },
			RemoveManagedMail: func(Passwd) error {
				mailCalls++
				if mailCalls == 2 {
					current, exists = replacement, true
				}
				return nil
			},
			RemoveManagedHome: func(Passwd) error { return nil },
		}
		err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete)
		if err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("DeleteExpected error = %v, want final reappearance refusal", err)
		}
		if len(f.calls) != 1 || f.calls[0][0] != "userdel" {
			t.Fatalf("account replacement reached another helper: %v", f.calls)
		}
	})

	t.Run("after artifact cleanup but before userdel", func(t *testing.T) {
		lookupCalls := 0
		mailCalls := 0
		f := &fakeRunner{available: map[string]bool{"userdel": true}}
		m := &Manager{
			Runner: f,
			LookupUser: func(string) (Passwd, bool, error) {
				lookupCalls++
				switch lookupCalls {
				case 1:
					return expected, true, nil
				case 2:
					return Passwd{}, false, nil
				default:
					return replacement, true, nil
				}
			},
			RemoveManagedMail: func(Passwd) error {
				mailCalls++
				return nil
			},
			RemoveManagedHome: func(Passwd) error { return nil },
		}
		err := m.DeleteExpected(expected.Name, expected, noOpBeforeDelete)
		if err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("DeleteExpected error = %v, want pre-helper reappearance refusal", err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("account replacement reached helper: %v", f.calls)
		}
		if mailCalls != 1 {
			t.Fatalf("mail cleanup calls = %d, want replacement detection before another old-identity sweep", mailCalls)
		}
	})
}

func TestManagedHomeRemovalUnlinksInteriorSymlinkWithoutTouchingTarget(t *testing.T) {
	expected, home := managedHomeFixture(t, "xxvcc-u")
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err := os.WriteFile(sentinel, []byte("outside data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedHome(expected); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("managed Home survived cleanup: %v", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "outside data" {
		t.Fatalf("interior symlink target changed: content=%q err=%v", got, err)
	}
}

func TestManagedHomeRemovalBudgetsFailClosed(t *testing.T) {
	t.Run("entry limit", func(t *testing.T) {
		expected, home := managedHomeFixture(t, "xxvcc-u")
		for _, name := range []string{"a", "b", "c"} {
			if err := os.WriteFile(filepath.Join(home, name), []byte(name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		budget := &homeRemovalBudget{remaining: 2, maxDepth: 8, deadline: time.Now().Add(time.Minute)}
		if err := removeHomeTreeWithin(expected, budget); err == nil || !strings.Contains(err.Error(), "entry limit") {
			t.Fatalf("bounded removal error = %v, want entry-limit refusal", err)
		}
		if _, err := os.Lstat(home); err != nil {
			t.Fatalf("entry-limit refusal freed managed Home: %v", err)
		}
	})

	t.Run("depth limit", func(t *testing.T) {
		expected, home := managedHomeFixture(t, "xxvcc-u")
		if err := os.MkdirAll(filepath.Join(home, "one", "two"), 0o700); err != nil {
			t.Fatal(err)
		}
		budget := &homeRemovalBudget{remaining: 100, maxDepth: 1, deadline: time.Now().Add(time.Minute)}
		if err := removeHomeTreeWithin(expected, budget); err == nil || !strings.Contains(err.Error(), "depth limit") {
			t.Fatalf("bounded removal error = %v, want depth-limit refusal", err)
		}
		if _, err := os.Lstat(home); err != nil {
			t.Fatalf("depth-limit refusal freed managed Home: %v", err)
		}
	})

	t.Run("time limit", func(t *testing.T) {
		expected, home := managedHomeFixture(t, "xxvcc-u")
		budget := &homeRemovalBudget{
			remaining: 100,
			maxDepth:  8,
			deadline:  time.Unix(2, 0),
			now:       func() time.Time { return time.Unix(2, 0) },
		}
		if err := removeHomeTreeWithin(expected, budget); err == nil || !strings.Contains(err.Error(), "time limit") {
			t.Fatalf("bounded removal error = %v, want time-limit refusal", err)
		}
		if _, err := os.Lstat(home); err != nil {
			t.Fatalf("time-limit refusal freed managed Home: %v", err)
		}
	})
}

func TestDeleteExpectedRetainsAccountWhenHomeSafetyCheckFails(t *testing.T) {
	expected, _ := managedHomeFixture(t, "xxvcc-u")
	f := &fakeRunner{available: map[string]bool{"userdel": true, "deluser": true}}
	old := refuseMountsUnder
	refuseMountsUnder = func(string) error {
		return errors.New("nested mount")
	}
	t.Cleanup(func() { refuseMountsUnder = old })
	m := &Manager{
		Runner:            f,
		LookupUser:        func(string) (Passwd, bool, error) { return expected, true, nil },
		RemoveManagedMail: func(Passwd) error { return nil },
	}
	err := m.DeleteExpected("xxvcc-u", expected, noOpBeforeDelete)
	if err == nil || !strings.Contains(err.Error(), "nested mount") {
		t.Fatalf("home safety error = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("unsafe home reached account helper: %v", f.calls)
	}
}

func TestDeleteDoesNotHideHelperFailureAfterAccountDisappears(t *testing.T) {
	tests := []struct {
		name      string
		available map[string]bool
		command   string
	}{
		{name: "userdel", available: map[string]bool{"userdel": true}, command: "userdel"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setPasswd(t, "xxvcc-u:x:1001:1001::/home/xxvcc-u:/bin/sh\n")
			f := &fakeRunner{
				available: tc.available,
				failOn:    map[string]bool{tc.command: true},
			}
			f.onRun = func(name string) {
				if err := os.WriteFile(passwdPath, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			expected, ok, lookupErr := Lookup("xxvcc-u")
			if lookupErr != nil || !ok {
				t.Fatalf("Lookup = %+v, %v, %v", expected, ok, lookupErr)
			}
			err := managerWithStubbedHomeRemoval(f).DeleteExpected("xxvcc-u", expected, noOpBeforeDelete)
			if err == nil || !strings.Contains(err.Error(), "incomplete cleanup") {
				t.Fatalf("Delete after %s failure = %v, want incomplete-cleanup error", tc.name, err)
			}
			if len(f.calls) != 1 || f.calls[0][0] != tc.command {
				t.Fatalf("Delete calls = %v, want only %s", f.calls, tc.command)
			}
		})
	}
}

func TestDeleteRequiresConfirmedAccountRemoval(t *testing.T) {
	setPasswd(t, "xxvcc-u:x:1001:1001::/home/xxvcc-u:/bin/sh\n")
	f := &fakeRunner{available: map[string]bool{"busybox": true, "deluser": true, "userdel": true}}
	m := managerWithStubbedHomeRemoval(f)
	expected, ok, lookupErr := Lookup("xxvcc-u")
	if lookupErr != nil || !ok {
		t.Fatalf("Lookup = %+v, %v, %v", expected, ok, lookupErr)
	}
	if err := m.DeleteExpected("xxvcc-u", expected, noOpBeforeDelete); err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("Delete error = %v, want post-delete existence failure", err)
	}
	if len(f.calls) != 1 || f.calls[0][0] != "userdel" {
		t.Fatalf("Delete calls = %v, want only userdel", f.calls)
	}
	for _, call := range f.calls {
		if call[0] == "deluser" {
			t.Fatalf("distro deluser was invoked directly: %v", f.calls)
		}
	}
}

func TestDeleteFailsClosedWhenRemovalCannotBeVerified(t *testing.T) {
	old := passwdPath
	passwdPath = t.TempDir()
	t.Cleanup(func() { passwdPath = old })
	f := &fakeRunner{available: map[string]bool{"deluser": true}}
	expected := Passwd{Name: "xxvcc-u", UID: 1001, GID: 1001, Home: "/home/xxvcc-u", Shell: "/bin/sh"}
	if err := (&Manager{Runner: f}).DeleteExpected("xxvcc-u", expected, noOpBeforeDelete); err == nil || !strings.Contains(err.Error(), "verify account identity before deletion") {
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
		reservedKernelID := uint64(^uint32(0))
		reserved := int(reservedKernelID)
		if err := TerminateProcesses(reserved); err == nil || !strings.Contains(err.Error(), "invalid Linux UID") {
			t.Fatalf("TerminateProcesses(%d) error = %v, want range refusal", reserved, err)
		}
		if len(opened) != 0 {
			t.Fatalf("reserved uid must open no pidfds, opened %v", opened)
		}
	}
}
