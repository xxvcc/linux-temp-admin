//go:build integration

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/expiry"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

// fakeSys satisfies schedule.System without touching systemd or at.
type fakeSys struct{}

func (fakeSys) HasSystemctl() bool                           { return false }
func (fakeSys) Systemctl(...string) error                    { return nil }
func (fakeSys) HasAt() bool                                  { return false }
func (fakeSys) ScheduleAt(string, time.Time) (string, error) { return "", nil }
func (fakeSys) RemoveAtJobsFor(string) error                 { return nil }
func (fakeSys) AtrmJob(string) error                         { return nil }
func (fakeSys) AtJobs() ([]schedule.AtJob, error)            { return nil, nil }

type failedCreateRunner struct{}

func (failedCreateRunner) Look(name string) bool { return name == "useradd" }
func (failedCreateRunner) Run(string, ...string) error {
	return os.ErrInvalid
}
func (r failedCreateRunner) RunInput(_ string, name string, args ...string) error {
	return r.Run(name, args...)
}

type inviteTimingRunner struct {
	account                user.Passwd
	present                bool
	events                 *[]string
	eventsBeforeCredential []string
	registry               *registry.Store
	recordAtCredential     registry.Record
	recordFound            bool
	recordErr              error
	stopErr                error
	activationMutation     func(*user.Passwd)
	activationErr          error
}

type inviteBundleFailWriter struct {
	onBundle func()
	err      error
	wrote    int
}

func (w *inviteBundleFailWriter) Write(p []byte) (int, error) {
	if !bytes.Contains(p, []byte("----- BEGIN LINUX TEMP ADMIN INVITE -----")) {
		return len(p), nil
	}
	if w.onBundle != nil {
		w.onBundle()
	}
	w.wrote = len(p) / 2
	return w.wrote, w.err
}

func (*inviteTimingRunner) Look(name string) bool {
	switch name {
	case "useradd", "usermod", "chpasswd", "chage", "userdel":
		return true
	default:
		return false
	}
}

func (r *inviteTimingRunner) Run(name string, args ...string) error {
	switch name {
	case "useradd":
		valueAfter := func(flag string) (string, bool) {
			for i := 0; i+1 < len(args); i++ {
				if args[i] == flag {
					return args[i+1], true
				}
			}
			return "", false
		}
		home, homeOK := valueAfter("-d")
		shell, shellOK := valueAfter("-s")
		gecos, gecosOK := valueAfter("-c")
		if len(args) == 0 || !homeOK || !shellOK || !gecosOK {
			return fmt.Errorf("unexpected useradd arguments")
		}
		r.account.Name = args[len(args)-1]
		r.account.Home = home
		r.account.Shell = shell
		r.account.GECOS = gecos
		r.present = true
	case "usermod":
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "-c" {
				r.account.GECOS = args[i+1]
			}
		}
		if len(args) == 2 && args[0] == "-L" {
			*r.events = append(*r.events, "password-lock")
		}
	case "chage":
		if len(args) != 3 || args[0] != "-E" {
			return fmt.Errorf("unexpected chage arguments: %v", args)
		}
		*r.events = append(*r.events, "expiry:"+args[1])
		if args[1] != "1970-01-01" && (r.activationMutation != nil || r.activationErr != nil) {
			if r.activationMutation != nil {
				r.activationMutation(&r.account)
			}
			return r.activationErr
		}
	case "userdel":
		*r.events = append(*r.events, "userdel")
		r.present = false
	}
	return nil
}

func (r *inviteTimingRunner) RunInput(_ string, name string, args ...string) error {
	if name != "chpasswd" {
		return r.Run(name, args...)
	}
	r.eventsBeforeCredential = append([]string(nil), (*r.events)...)
	*r.events = append(*r.events, "credential")
	r.recordAtCredential, r.recordFound, r.recordErr = r.registry.Lookup(r.account.Name)
	return r.stopErr
}

func (r *inviteTimingRunner) lookup(name string) (user.Passwd, bool, error) {
	if !r.present || name != r.account.Name {
		return user.Passwd{}, false, nil
	}
	return r.account, true, nil
}

func mustUserExists(t *testing.T, name string) bool {
	t.Helper()
	exists, err := user.Exists(name)
	if err != nil {
		t.Fatal(err)
	}
	return exists
}

func mustUserLookup(t *testing.T, name string) (user.Passwd, bool) {
	t.Helper()
	pw, ok, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return pw, ok
}

func mustUserManaged(t *testing.T, name string) bool {
	t.Helper()
	managed, err := user.IsManaged(name)
	if err != nil {
		t.Fatal(err)
	}
	return managed
}

func TestRunInviteReleasesIntentWhenCreatePreflightFails(t *testing.T) {
	dir := rootOwnedDir(t)
	username := "ltapreflight"
	if inUse, err := user.NameInUse(username); err != nil {
		t.Fatal(err)
	} else if inUse {
		t.Skipf("test username %s is already in use", username)
	}

	a, _, errb := newTestApp(t, "")
	regDir := filepath.Join(dir, "registry")
	a.Registry = &registry.Store{
		Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
	}
	wantErr := errors.New("unsafe mail root")
	a.Users = &user.Manager{
		Runner:                   failedCreateRunner{},
		ValidateManagedMailRoots: func() error { return wantErr },
		PrepareManagedHome: func(string) error {
			t.Fatal("managed Home preflight ran after mail-root preflight failed")
			return nil
		},
	}
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: filepath.Join(dir, "systemd"), InstallPath: filepath.Join(dir, "linux-temp-admin"),
		UnitPrefix: config.AutoRevokeUnitPrefix, Now: a.Now, Sys: fakeSys{},
	}
	a.RandHex = func(n int) (string, error) {
		if n == 16 {
			return "0123456789abcdef0123456789abcdef", nil
		}
		return "abcdef0123", nil
	}

	if rc := a.runInviteWithIdentityPolicy(username, "192.0.2.1", 22, 1, false, true, loginPlan{verified: true}, false); rc != 1 {
		t.Fatalf("runInvite rc=%d, want preflight failure", rc)
	}
	if found, err := a.Registry.Contains(username); err != nil || found {
		t.Fatalf("creation intent after preflight failure: found=%v err=%v", found, err)
	}
	if !strings.Contains(errb.String(), wantErr.Error()) || strings.Contains(errb.String(), "account artifact cleanup is unconfirmed") {
		t.Fatalf("preflight rollback output = %q", errb.String())
	}
}

func TestRunInviteRetainsPendingRegistryWhenCreateHelperReportsFailure(t *testing.T) {
	dir := rootOwnedDir(t)
	username := ""
	for i := 0; i < 100; i++ {
		candidate := fmt.Sprintf("ltagate%02d", i)
		inUse, err := user.NameInUse(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !inUse {
			username = candidate
			break
		}
	}
	if username == "" {
		t.Fatal("could not find an unused test username")
	}

	a, _, errb := newTestApp(t, "")
	regDir := filepath.Join(dir, "registry")
	a.Registry = &registry.Store{
		Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
	}
	a.Users = &user.Manager{
		Runner: failedCreateRunner{},
		LookupUser: func(string) (user.Passwd, bool, error) {
			return user.Passwd{
				Name: username, UID: 4242, GID: 4242,
				GECOS: config.PendingGenerationGECOSPrefix + "0123456789abcdef0123456789abcdef",
				Home:  "/home/" + username, Shell: resolveShell(),
			}, true, nil
		},
		PrepareManagedHome: func(string) error { return nil },
		CreateManagedHome:  func(user.Passwd) error { return nil },
	}
	a.LookupUser = a.Users.LookupUser
	a.IdentityAllocationRange = func() (int, int, error) { return 4242, 4242, nil }
	createdAt := time.Date(2026, 7, 7, 12, 34, 59, 0, time.FixedZone("test", 8*60*60))
	clockCalls := 0
	a.Now = func() time.Time {
		clockCalls++
		return createdAt.Add(time.Duration(clockCalls-1) * time.Hour)
	}
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: filepath.Join(dir, "systemd"), InstallPath: filepath.Join(dir, "linux-temp-admin"),
		UnitPrefix: config.AutoRevokeUnitPrefix, Now: a.Now, Sys: fakeSys{},
	}
	a.RandHex = func(n int) (string, error) {
		if n == 16 {
			return "0123456789abcdef0123456789abcdef", nil
		}
		return "abcdef0123", nil
	}

	if rc := a.runInviteWithIdentityPolicy(username, "192.0.2.1", 22, 1, false, true, loginPlan{verified: true}, false); rc != 1 {
		t.Fatalf("runInvite rc=%d, want helper failure", rc)
	}
	rec, found, err := a.Registry.Lookup(username)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !rec.Pending || rec.UID != 4242 || !rec.IdentityBound || !rec.SequentialID {
		t.Fatalf("pending recovery witness was removed after ambiguous helper failure: found=%v rec=%+v", found, rec)
	}
	if clockCalls != 1 {
		t.Fatalf("invite transaction read its creation clock %d times, want once", clockCalls)
	}
	if got, want := rec.Created, createdAt.Format("2006-01-02 15:04:05 MST"); got != want {
		t.Fatalf("recorded creation = %q, want %q", got, want)
	}
	if got, want := rec.Expires, expiry.DisplayLocal(expiry.Deadline(createdAt, 1)); got != want {
		t.Fatalf("recorded deadline = %q, want %q", got, want)
	}
	if !strings.Contains(errb.String(), "account artifact cleanup is unconfirmed") {
		t.Fatalf("ambiguous helper failure did not report retained registry evidence: %q", errb.String())
	}
}

func TestRunInviteClearsStaleJobsBeforeCredentialAndRebasesLifetime(t *testing.T) {
	const (
		username   = "xxvcc-timing1"
		generation = "0123456789abcdef0123456789abcdef"
		uid        = 4_000_000
	)
	if _, exists, err := user.Lookup(username); err != nil {
		t.Fatal(err)
	} else if exists {
		t.Fatalf("test username %s already exists", username)
	}

	binDir := t.TempDir()
	idScript := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-u\" ]; then\n" +
		"  printf \"id: '%s': no such user\\n\" \"$3\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if [ \"$1\" = \"-Gn\" ]; then\n" +
		"  printf '%s\\n' \"$2\"\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 2\n"
	if err := os.WriteFile(filepath.Join(binDir, "id"), []byte(idScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	baseDir := rootOwnedDir(t)
	regDir := filepath.Join(baseDir, "registry")
	a, _, errb := newTestApp(t, "")
	a.Registry = &registry.Store{
		Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
	}
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: filepath.Join(baseDir, "systemd"), InstallPath: filepath.Join(baseDir, "linux-temp-admin"),
		UnitPrefix: config.AutoRevokeUnitPrefix, Sys: fakeSys{},
	}

	events := []string{}
	stopErr := errors.New("stop after credential timing observation")
	runner := &inviteTimingRunner{
		account:  user.Passwd{UID: uid, GID: uid},
		events:   &events,
		registry: a.Registry,
		stopErr:  stopErr,
	}
	mailCalls := 0
	a.Users = &user.Manager{
		Runner:             runner,
		LookupUser:         runner.lookup,
		PrepareManagedHome: func(string) error { return nil },
		CreateManagedHome: func(user.Passwd) error {
			events = append(events, "home")
			return nil
		},
		ValidateManagedHome: func(user.Passwd) error {
			events = append(events, "home-validate")
			return nil
		},
		RemoveManagedMail: func(user.Passwd) error {
			mailCalls++
			events = append(events, "mail")
			return nil
		},
		RemoveManagedHome: func(user.Passwd) error { return nil },
	}
	a.LookupUser = runner.lookup
	a.IdentityAllocationRange = func() (int, int, error) { return uid, uid, nil }

	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.FixedZone("test", 8*60*60))
	t1 := t0.Add(65 * time.Second)
	drained := false
	beforeDrainClockCalls := 0
	afterDrainClockCalls := 0
	a.Now = func() time.Time {
		if drained {
			afterDrainClockCalls++
			return t1
		}
		beforeDrainClockCalls++
		return t0
	}
	a.Scheduler.Now = a.Now
	a.ClearScheduledJobs = func(name string, gotUID int) error {
		if name != username || gotUID != uid {
			t.Fatalf("ClearScheduledJobs(%q, %d), want (%q, %d)", name, gotUID, username, uid)
		}
		events = append(events, "clear")
		return nil
	}
	a.TerminateProcesses = func(gotUID int) error {
		if gotUID != uid {
			t.Fatalf("TerminateProcesses UID = %d, want %d", gotUID, uid)
		}
		events = append(events, "kill")
		return nil
	}
	a.DrainScheduledJobs = func() error {
		events = append(events, "drain")
		drained = true
		return nil
	}
	a.RandHex = func(n int) (string, error) {
		if n != 16 {
			return "", fmt.Errorf("unexpected random byte count %d", n)
		}
		return generation, nil
	}
	a.RandPassword = func(int) (string, error) { return "password-for-timing-test", nil }
	sshdConfig := sysinfo.ParseSSHD("passwordauthentication yes\n")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return sshdConfig, nil }

	if rc := a.runInviteWithIdentityPolicy(username, "192.0.2.1", 22, 1, false, true, loginPlan{password: true, verified: true}, false); rc != 1 {
		t.Fatalf("runInvite rc = %d, want injected credential failure", rc)
	}
	if !strings.Contains(errb.String(), stopErr.Error()) {
		t.Fatalf("runInvite did not reach the injected credential stop: %q", errb.String())
	}
	if runner.recordErr != nil || !runner.recordFound {
		t.Fatalf("registry row at credential: found=%v err=%v", runner.recordFound, runner.recordErr)
	}
	if got, want := strings.Join(runner.eventsBeforeCredential, ","), "mail,expiry:1970-01-01,password-lock,kill,clear,drain,kill,clear,mail,home,home-validate"; got != want {
		t.Fatalf("events before credential = %q, want %q", got, want)
	}
	if mailCalls < 2 {
		t.Fatalf("mail cleanup calls before/during rollback = %d, want at least create and post-drain sweeps", mailCalls)
	}
	if got, want := runner.recordAtCredential.Created, t1.Format("2006-01-02 15:04:05 MST"); got != want {
		t.Fatalf("creation time at credential = %q, want %q", got, want)
	}
	if got, want := runner.recordAtCredential.Expires, expiry.DisplayLocal(expiry.Deadline(t1, 1)); got != want {
		t.Fatalf("expiry at credential = %q, want %q", got, want)
	}
	if runner.recordAtCredential.Pending {
		t.Fatal("credential was attempted before the rebased registry record was finalized")
	}
	if beforeDrainClockCalls != 1 || afterDrainClockCalls != 1 {
		t.Fatalf("clock calls before/after drain = %d/%d, want 1/1", beforeDrainClockCalls, afterDrainClockCalls)
	}
}

func TestGeneratedInviteHonorsLegacyMigrationIsolationWindow(t *testing.T) {
	const (
		generation = "0123456789abcdef0123456789abcdef"
		uid        = 4_000_010
	)
	migratedAt := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name      string
		now       time.Time
		wantDrain bool
	}{
		{name: "inside migration isolation window", now: migratedAt, wantDrain: true},
		{name: "after migration isolation window", now: migratedAt.Add(65 * time.Second), wantDrain: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			username := "xxvcc-migrate1"
			if _, exists, err := user.Lookup(username); err != nil {
				t.Fatal(err)
			} else if exists {
				t.Fatalf("test username %s already exists", username)
			}

			baseDir := rootOwnedDir(t)
			regDir := filepath.Join(baseDir, "registry")
			if err := os.Mkdir(regDir, 0o700); err != nil {
				t.Fatal(err)
			}
			store := &registry.Store{
				Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
				Now: func() time.Time { return migratedAt },
			}
			if err := os.WriteFile(store.File, []byte("# linux-temp-admin registry v4\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			store.Now = func() time.Time { return tc.now }

			a, out, errb := newTestApp(t, "")
			a.Registry = store
			a.Scheduler = &schedule.Scheduler{
				SystemdDir: filepath.Join(baseDir, "systemd"), InstallPath: filepath.Join(baseDir, "linux-temp-admin"),
				UnitPrefix: config.AutoRevokeUnitPrefix, Sys: fakeSys{},
			}
			events := []string{}
			runner := &inviteTimingRunner{
				account: user.Passwd{UID: uid, GID: uid}, events: &events, registry: store,
			}
			a.Users = &user.Manager{
				Runner:             runner,
				LookupUser:         runner.lookup,
				PrepareManagedHome: func(string) error { return nil },
				CreateManagedHome: func(user.Passwd) error {
					events = append(events, "home")
					return errors.New("stop after identity isolation check")
				},
				RemoveManagedMail: func(user.Passwd) error { return nil },
				RemoveManagedHome: func(user.Passwd) error { return nil },
			}
			a.LookupUser = runner.lookup
			a.IdentityAllocationRange = func() (int, int, error) { return uid, uid, nil }
			a.Now = func() time.Time { return tc.now }
			a.Scheduler.Now = a.Now
			a.ClearScheduledJobs = func(string, int) error {
				events = append(events, "clear")
				return nil
			}
			a.TerminateProcesses = func(int) error {
				events = append(events, "kill")
				return nil
			}
			a.DrainScheduledJobs = func() error {
				events = append(events, "drain")
				return nil
			}
			a.RandHex = func(n int) (string, error) {
				if n != 16 {
					return "", fmt.Errorf("unexpected random byte count %d", n)
				}
				return generation, nil
			}
			a.RandPassword = func(int) (string, error) { return "password-for-migration-test", nil }
			a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
				return sysinfo.ParseSSHD("passwordauthentication yes\n"), nil
			}

			if rc := a.runInviteWithIdentityPolicy(username, "192.0.2.1", 22, 1, false, false,
				loginPlan{password: true, verified: true}, true); rc != 1 {
				t.Fatalf("runInviteWithIdentityPolicy rc=%d, want injected Home failure", rc)
			}
			joinedEvents := strings.Join(events, ",")
			drainAt, homeAt := strings.Index(joinedEvents, "drain"), strings.Index(joinedEvents, "home")
			drainedBeforeHome := drainAt >= 0 && homeAt >= 0 && drainAt < homeAt
			if drainedBeforeHome != tc.wantDrain {
				t.Fatalf("pre-Home drain called=%v, want %v; events=%v; stderr=%q", drainedBeforeHome, tc.wantDrain, events, errb.String())
			}
			if tc.wantDrain && !strings.Contains(out.String(), "one-time isolation window") {
				t.Fatalf("migration wait was not explained: %q", out.String())
			}
			if strings.Contains(errb.String(), "rollback did not complete") {
				t.Fatalf("injected failure left incomplete rollback: %q", errb.String())
			}
		})
	}
}

func TestRunPermanentInviteClearsSafetyExpiry(t *testing.T) {
	const (
		username   = "xxvcc-permtime"
		generation = "fedcba9876543210fedcba9876543210"
		uid        = 4_000_001
	)
	if _, exists, err := user.Lookup(username); err != nil {
		t.Fatal(err)
	} else if exists {
		t.Fatalf("test username %s already exists", username)
	}

	binDir := t.TempDir()
	idScript := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-u\" ]; then printf \"id: '%s': no such user\\n\" \"$3\" >&2; exit 1; fi\n" +
		"if [ \"$1\" = \"-Gn\" ]; then printf '%s\\n' \"$2\"; exit 0; fi\n" +
		"exit 2\n"
	if err := os.WriteFile(filepath.Join(binDir, "id"), []byte(idScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	baseDir := rootOwnedDir(t)
	regDir := filepath.Join(baseDir, "registry")
	a, _, errb := newTestApp(t, "")
	a.Registry = &registry.Store{
		Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
	}
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: filepath.Join(baseDir, "systemd"), InstallPath: filepath.Join(baseDir, "linux-temp-admin"),
		UnitPrefix: config.AutoRevokeUnitPrefix, Sys: fakeSys{},
	}
	events := []string{}
	runner := &inviteTimingRunner{
		account: user.Passwd{UID: uid, GID: uid}, events: &events, registry: a.Registry,
	}
	mailCalls := 0
	a.Users = &user.Manager{
		Runner:             runner,
		LookupUser:         runner.lookup,
		PrepareManagedHome: func(string) error { return nil },
		CreateManagedHome: func(user.Passwd) error {
			events = append(events, "home")
			return nil
		},
		ValidateManagedHome: func(user.Passwd) error {
			events = append(events, "home-validate")
			return nil
		},
		RemoveManagedMail: func(user.Passwd) error {
			mailCalls++
			events = append(events, "mail")
			return nil
		},
		RemoveManagedHome: func(user.Passwd) error { return nil },
	}
	a.LookupUser = runner.lookup
	a.IdentityAllocationRange = func() (int, int, error) { return uid, uid, nil }
	a.ClearScheduledJobs = func(string, int) error { events = append(events, "clear"); return nil }
	a.TerminateProcesses = func(int) error { events = append(events, "kill"); return nil }
	a.DrainScheduledJobs = func() error { events = append(events, "drain"); return nil }
	a.RandHex = func(int) (string, error) { return generation, nil }
	a.RandPassword = func(int) (string, error) { return "password-for-permanent-test", nil }
	sshdConfig := sysinfo.ParseSSHD("passwordauthentication yes\n")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return sshdConfig, nil }

	if rc := a.runInviteWithIdentityPolicy(username, "192.0.2.1", 22, 1, false, false, loginPlan{password: true, verified: true}, false); rc != 0 {
		t.Fatalf("permanent runInvite rc = %d: %s", rc, errb.String())
	}
	want := "mail,expiry:1970-01-01,password-lock,kill,clear,drain,kill,clear,mail,home,home-validate,credential,expiry:-1"
	if got := strings.Join(events, ","); got != want {
		t.Fatalf("permanent invite events = %q, want %q", got, want)
	}
	if mailCalls != 2 {
		t.Fatalf("permanent invite mail cleanup calls = %d, want create and post-drain sweeps", mailCalls)
	}
	rec, found, err := a.Registry.Lookup(username)
	if err != nil || !found {
		t.Fatalf("permanent registry row: found=%v err=%v", found, err)
	}
	if rec.AutoRevoke || rec.Expires != "never (does not expire or auto-delete)" {
		t.Fatalf("permanent registry row = %+v", rec)
	}
}

func TestRunInviteRollbackUsesStableIdentityOnceActivationMayStart(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		uid           int
		wantAuto      bool
		activationErr error
		outputErr     error
	}{
		{
			name:          "permanent activation helper may have succeeded",
			username:      "xxvcc-actperm",
			uid:           4_000_101,
			activationErr: errors.New("activation helper reported failure after applying expiry"),
		},
		{
			name:          "temporary activation helper may have succeeded",
			username:      "xxvcc-acttemp",
			uid:           4_000_102,
			wantAuto:      true,
			activationErr: errors.New("activation helper reported failure after applying expiry"),
		},
		{
			name:      "credential output fails after activation",
			username:  "xxvcc-actout",
			uid:       4_000_103,
			outputErr: errors.New("credential output stopped after activation"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, exists, err := user.Lookup(tc.username); err != nil {
				t.Fatal(err)
			} else if exists {
				t.Fatalf("test username %s already exists", tc.username)
			}

			binDir := t.TempDir()
			idScript := "#!/bin/sh\n" +
				"if [ \"$1\" = \"-u\" ]; then printf \"id: '%s': no such user\\n\" \"$3\" >&2; exit 1; fi\n" +
				"if [ \"$1\" = \"-Gn\" ]; then printf '%s\\n' \"$2\"; exit 0; fi\n" +
				"exit 2\n"
			if err := os.WriteFile(filepath.Join(binDir, "id"), []byte(idScript), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", binDir)

			baseDir := rootOwnedDir(t)
			regDir := filepath.Join(baseDir, "registry")
			installPath := filepath.Join(baseDir, "linux-temp-admin")
			if err := os.WriteFile(installPath, []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 0.0.0-dev\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			a, _, errb := newTestApp(t, "")
			testNow := time.Now().UTC().Truncate(time.Second)
			a.Now = func() time.Time { return testNow }
			a.InstallPath = installPath
			a.Selfmanage = &selfmanage.Manager{InstallPath: installPath}
			a.Executable = func() (string, error) { return installPath, nil }
			a.Registry = &registry.Store{
				Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
			}
			a.Scheduler = &schedule.Scheduler{
				SystemdDir: filepath.Join(baseDir, "systemd"), InstallPath: installPath,
				UnitPrefix: config.AutoRevokeUnitPrefix, Now: func() time.Time { return testNow }, Sys: revokeTestScheduleSystem{},
			}
			events := []string{}
			runner := &inviteTimingRunner{
				account: user.Passwd{UID: tc.uid, GID: tc.uid}, events: &events, registry: a.Registry,
				activationErr: tc.activationErr,
			}
			var activationIdentity user.Passwd
			mutated := false
			mutateIdentity := func(p *user.Passwd) {
				activationIdentity = *p
				parts := strings.SplitN(p.GECOS, ",", 5)
				if len(parts) != 5 || parts[4] == "" {
					t.Fatalf("activation identity has no trailing witness: %+v", *p)
				}
				p.GECOS = "Changed Name,room,work,home," + parts[4]
				p.Shell = "/bin/sh"
				mutated = true
			}
			if tc.activationErr != nil {
				runner.activationMutation = mutateIdentity
			}
			a.Users = &user.Manager{
				Runner:             runner,
				LookupUser:         runner.lookup,
				PrepareManagedHome: func(string) error { return nil },
				CreateManagedHome: func(user.Passwd) error {
					events = append(events, "home")
					return nil
				},
				ValidateManagedHome: func(user.Passwd) error {
					events = append(events, "home-validate")
					return nil
				},
				RemoveManagedMail: func(user.Passwd) error {
					events = append(events, "mail")
					return nil
				},
				RemoveManagedHome: func(user.Passwd) error {
					events = append(events, "remove-home")
					return nil
				},
			}
			a.LookupUser = runner.lookup
			a.IdentityAllocationRange = func() (int, int, error) { return tc.uid, tc.uid, nil }
			a.ClearScheduledJobs = func(string, int) error { events = append(events, "clear"); return nil }
			a.TerminateProcesses = func(int) error { events = append(events, "kill"); return nil }
			a.DrainScheduledJobs = func() error { events = append(events, "drain"); return nil }
			a.RandHex = func(int) (string, error) { return "fedcba9876543210fedcba9876543210", nil }
			a.RandPassword = func(int) (string, error) { return "password-for-activation-test", nil }
			a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
				return sysinfo.ParseSSHD("passwordauthentication yes\n"), nil
			}

			var outputWriter *inviteBundleFailWriter
			if tc.outputErr != nil {
				outputWriter = &inviteBundleFailWriter{onBundle: func() { mutateIdentity(&runner.account) }, err: tc.outputErr}
				a.Out = outputWriter
			}
			if rc := a.runInviteWithIdentityPolicy(tc.username, "192.0.2.1", 22, 1, false, tc.wantAuto,
				loginPlan{password: true, verified: true}, false); rc != 1 {
				t.Fatalf("runInviteWithIdentityPolicy rc=%d, want injected failure", rc)
			}
			wantErr := tc.activationErr
			if wantErr == nil {
				wantErr = tc.outputErr
			}
			if !strings.Contains(errb.String(), wantErr.Error()) {
				t.Fatalf("invite failure did not report %q: %s", wantErr, errb.String())
			}
			if !mutated || activationIdentity == runner.account || !user.SameAccountIdentity(activationIdentity, runner.account) {
				t.Fatalf("fixture did not preserve only the stable identity: before=%+v after=%+v", activationIdentity, runner.account)
			}
			if runner.present || !strings.Contains(strings.Join(events, ","), "userdel") {
				t.Fatalf("activation-aware rollback did not delete the account: present=%v events=%v", runner.present, events)
			}
			if found, err := a.Registry.Contains(tc.username); err != nil || found {
				t.Fatalf("activation-aware rollback retained registry state: found=%v err=%v", found, err)
			}
			if outputWriter != nil && outputWriter.wrote == 0 {
				t.Fatal("output failure did not occur after partial credential output")
			}
		})
	}
}

// newManageApp is newTestApp plus the collaborators a revoke reached from the
// menu actually touches, all pointed at temp dirs. It needs root: the registry
// is root-owned state by design — every write goes through a chown to 0:0 into a
// directory checked for root ownership — so seeding a row cannot be done without
// it, and faking that away would be testing something the tool does not do. The accounts named here do
// not exist on the test host, so revoke takes its "user is gone, clean up the
// registry row" path: no real account is ever involved, and what the test can
// still see is which row that clean-up named — which is the thing under test.
func newManageApp(t *testing.T, in string, users ...string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	a, out, errb := newTestApp(t, in)
	dir := t.TempDir()
	a.Sudoers = &sudoers.Manager{
		Dir:      dir,
		Validate: func([]byte) error { return nil },
		Verify:   func(string) error { return nil },
	}
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: dir, InstallPath: a.InstallPath, UnitPrefix: "lta-test-",
		Now: a.Now, Sys: fakeSys{},
	}
	// The store's dir has to be root-owned for its symlink-safety checks to pass;
	// t.TempDir() belongs to whoever runs the suite.
	if err := os.Chown(a.Registry.Dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.Registry.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	if len(users) > 0 {
		reserveTestIdentity(t, a, 4242)
	}
	for _, u := range users {
		rec := registry.Record{
			User: u, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
			Sudo: true, Host: "203.0.113.5", Port: 22, AutoRevoke: true, UID: 4242,
		}
		if err := a.Registry.Record(rec); err != nil {
			t.Fatal(err)
		}
	}
	return a, out, errb
}

func regUsers(t *testing.T, a *App) []string {
	t.Helper()
	recs, err := a.Registry.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range recs {
		names = append(names, r.User)
	}
	return names
}

// TestManageUsersEnterIsLookOnly pins the default: this screen's job is to show
// the list, so leaving it must be one keystroke and must change nothing.
func TestManageUsersEnterIsLookOnly(t *testing.T) {
	a, _, _ := newManageApp(t, "\n", "ltamanage-a1")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if got := regUsers(t, a); len(got) != 1 {
		t.Errorf("Enter must not touch the registry; rows now %v", got)
	}
}

// TestManageUsersRowNumberPicksThatRow is the whole risk of numbering a table:
// the number the operator types has to name the row they are looking at. It
// deletes the second of two rows and checks the first survived.
func TestManageUsersRowNumberPicksThatRow(t *testing.T) {
	a, _, _ := newManageApp(t, "2\n", "ltamanage-a1", "ltamanage-b2")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	got := regUsers(t, a)
	if len(got) != 1 || got[0] != "ltamanage-a1" {
		t.Errorf("row 2 should have taken ltamanage-b2 and only it; rows now %v", got)
	}
}

// TestManageUsersOutOfRangeRowIsRefused covers the digits either side of the
// table. An out-of-range number must not fall through to being read as a
// username, and must not act on anything.
func TestManageUsersOutOfRangeRowIsRefused(t *testing.T) {
	for _, choice := range []string{"0", "3", "-1"} {
		a, _, errb := newManageApp(t, choice+"\n", "ltamanage-a1", "ltamanage-b2")
		if rc := a.manageUsers(); rc != 1 {
			t.Errorf("choice %q: rc=%d, want 1", choice, rc)
		}
		if !strings.Contains(errb.String(), "no such row") {
			t.Errorf("choice %q: want a no-such-row warning", choice)
		}
		if got := regUsers(t, a); len(got) != 2 {
			t.Errorf("choice %q must act on nothing; rows now %v", choice, got)
		}
	}
}

// TestManageUsersRejectsAnIllegalName: a typed answer is a username, and this
// screen must not be the thing that decides what a legal one is — it hands it to
// the same validation `revoke --user` uses.
func TestManageUsersRejectsAnIllegalName(t *testing.T) {
	a, _, _ := newManageApp(t, "../../etc/passwd\n", "ltamanage-a1")
	if rc := a.manageUsers(); rc != 1 {
		t.Errorf("rc=%d, want 1 for an illegal username", rc)
	}
	if got := regUsers(t, a); len(got) != 1 {
		t.Errorf("registry should be untouched; rows now %v", got)
	}
}

// TestManageUsersCleanupPrunesTheMissingRows is why cleanup belongs on this
// screen rather than beside it as its own menu entry: what --compact prunes is
// exactly the rows this table marks "missing" — a registry row whose account is
// gone. It was never a separate object to manage, only a separate way in.
func TestManageUsersCleanupPrunesTheMissingRows(t *testing.T) {
	a, _, _ := newManageApp(t, "c\n", "ltamanage-a1", "ltamanage-b2")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	// Neither account exists on this host, so both rows are "missing" rows.
	if got := regUsers(t, a); len(got) != 0 {
		t.Errorf("cleanup should have pruned every missing row; rows now %v", got)
	}
}

// TestManageUsersCleanupSparesTheAccountsThatExist is the other half of that
// claim: cleanup must only ever take the rows whose account is gone. root is
// here as a stand-in for "a row whose account exists" — it is the one account
// every test host is guaranteed to have. Nothing deletes it: --compact only
// rewrites registry rows, and the row is a fake this test wrote.
func TestManageUsersCleanupSparesTheAccountsThatExist(t *testing.T) {
	a, _, _ := newManageApp(t, "c\n", "ltamanage-a1", "root")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	got := regUsers(t, a)
	if len(got) != 1 || got[0] != "root" {
		t.Errorf("cleanup must spare rows whose account exists; rows now %v", got)
	}
}

// TestManageUsersCleanupRequiresRoot pins a gate that is easy to lose: the
// cleanup here calls the bare sweep, not the `cleanup-expired` subcommand that
// opens by checking for root, so this screen has to do that check itself.
func TestManageUsersCleanupRequiresRoot(t *testing.T) {
	a, _, _ := newManageApp(t, "c\n", "ltamanage-a1")
	a.Geteuid = func() int { return 1000 }
	if rc := a.manageUsers(); rc != 1 {
		t.Errorf("rc=%d, want 1 when not root", rc)
	}
	if got := regUsers(t, a); len(got) != 1 {
		t.Errorf("a non-root cleanup must change nothing; rows now %v", got)
	}
}

// parseNumberedTable reads back the rendered table: it returns the "#" cell and
// the user cell of each body row, in the order printed. It deliberately parses
// the real output rather than trusting the model that produced it — the point is
// to compare what the operator SEES against what selection DOES.
func parseNumberedTable(t *testing.T, out string) (nums []string, users []string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "│") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "│"), "│")
		if len(cells) < 2 {
			continue
		}
		n, u := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1])
		if n == "#" || n == "" { // header, or a row with no number column
			continue
		}
		nums = append(nums, n)
		users = append(users, u)
	}
	return nums, users
}

// TestManageUsersDisplayedNumberIsTheOneThatActs pins the half of the invariant
// that the mapping test cannot reach. "A row number must map to exactly the row
// displayed" is two claims: that selection resolves recs[n-1], and that the "#"
// the operator reads is that same n. A test that only inspects the registry
// afterwards pins the first and lets the second rot: invert the rendered "#"
// column alone and every other test here still passes, while the screen now tells
// the operator to type the number of a different account.
//
// So this one reads the number off the rendered table and feeds that back in.
func TestManageUsersDisplayedNumberIsTheOneThatActs(t *testing.T) {
	// Render first, with an input that changes nothing, and see what is on screen.
	view, out, _ := newManageApp(t, "\n", "ltarender-a1", "ltarender-b2", "ltarender-c3")
	if rc := view.manageUsers(); rc != 0 {
		t.Fatalf("view rc=%d", rc)
	}
	nums, users := parseNumberedTable(t, out.String())
	if len(nums) != 3 {
		t.Fatalf("want 3 numbered rows, parsed %d from:\n%s", len(nums), out.String())
	}
	// Whatever the screen labels a row, typing that label must act on that row's
	// account — checked for every row, so no single lucky alignment passes.
	for i := range nums {
		a, _, _ := newManageApp(t, nums[i]+"\n", "ltarender-a1", "ltarender-b2", "ltarender-c3")
		if rc := a.manageUsers(); rc != 0 {
			t.Fatalf("row %q: rc=%d", nums[i], rc)
		}
		got := regUsers(t, a)
		for _, g := range got {
			if g == users[i] {
				t.Errorf("screen labels %q as row %q, but typing %q left it registered (rows now %v)",
					users[i], nums[i], nums[i], got)
			}
		}
		if len(got) != 2 {
			t.Errorf("row %q should have taken exactly one account; rows now %v", nums[i], got)
		}
	}
}

// newRealAccount creates an actual local account and registers it with its REAL
// uid, returning that uid. The confirmation gate is only reachable when the
// account exists — revoke returns from its "user is gone, clean up" branch first
// otherwise — so a fake row cannot reach it, which is exactly why the gate went
// untested. The uid must be the real one or IsProtectedRevokeTarget refuses the
// account as UID-tampered before the confirmation gets to be what is under test.
func newRealAccount(t *testing.T, a *App, name string) int {
	t.Helper()
	const generation = "0123456789abcdef0123456789abcdef"
	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", config.ManagedGenerationGECOSPrefix+generation, name).CombinedOutput(); err != nil {
		t.Fatalf("useradd %s: %v: %s", name, err, out)
	}
	pw, ok := mustUserLookup(t, name)
	if !ok {
		t.Fatalf("%s was not created", name)
	}
	reserveTestIdentity(t, a, pw.UID)
	if err := a.Registry.Record(registry.Record{
		User: name, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
		Host: "203.0.113.5", Port: 22, UID: pw.UID, Generation: generation, IdentityBound: true,
	}); err != nil {
		t.Fatal(err)
	}
	return pw.UID
}

// TestManageUsersRevokeRefusesWithoutTheFullName pins the merge's entire safety
// argument, which until now no test in this repo executed: picking a row does not
// delete it — revoke makes you type the account's full name, and a mistyped one
// is refused. Delete the confirmation block from revoke and every other test
// still passes; this one fails, because the account is really there to lose.
func TestManageUsersRevokeRefusesWithoutTheFullName(t *testing.T) {
	const name = "ltaconfirm1"
	a, _, errb := newManageApp(t, "1\nltaconfirm-typo\n")
	a.Users = user.New()
	newRealAccount(t, a, name)

	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("a refused confirmation is a cancel, not an error: rc=%d", rc)
	}
	if !mustUserExists(t, name) {
		t.Fatal("THE ACCOUNT WAS DELETED without the operator typing its name")
	}
	if got := regUsers(t, a); len(got) != 1 || got[0] != name {
		t.Errorf("a cancelled revoke must leave the registry alone; rows now %v", got)
	}
	if !strings.Contains(errb.String(), "confirmation mismatch") {
		t.Errorf("want the cancel to say why; stderr: %q", errb.String())
	}
}

// TestManageUsersRevokeDeletesOnceTheFullNameIsTyped is the other half: the gate
// must open for the operator who actually names the account, or "the number is
// how you revoke" would be a lie in the safe direction.
func TestManageUsersRevokeDeletesOnceTheFullNameIsTyped(t *testing.T) {
	const name = "ltaconfirm2"
	a, _, _ := newManageApp(t, "1\n"+name+"\n")
	a.Users = user.New()
	newRealAccount(t, a, name)

	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if mustUserExists(t, name) {
		t.Error("the account survived a confirmed revoke")
	}
	if got := regUsers(t, a); len(got) != 0 {
		t.Errorf("the registry row should be gone; rows now %v", got)
	}
}

func TestManageUsersAddsForceForPendingAndLegacyRecovery(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name  string
		user  string
		gecos string
		seed  func(*testing.T, *App, string)
	}{
		{
			name: "pending", user: "ltamenupending", gecos: config.PendingGenerationGECOSPrefix + generation,
			seed: func(t *testing.T, a *App, name string) {
				setTestRegistryRecord(t, a, registry.Record{
					User: name, UID: 1001, Generation: generation,
					IdentityBound: true, Pending: true, Port: 22,
				})
			},
		},
		{
			name: "unbound legacy", user: "ltamenulegacy", gecos: config.ManagedGECOS,
			seed: func(t *testing.T, a *App, name string) {
				setLegacyV2RevokeRegistry(t, a, name, 10, 1001, "")
			},
		},
		{
			name: "UID-only recovery", user: "ltamenuuidonly",
			gecos: config.ManagedGenerationGECOSPrefix + generation,
			seed: func(t *testing.T, a *App, name string) {
				setTestRegistryRecord(t, a, registry.Record{
					User: name, UID: 1001, DeletionStarted: true, Port: 22,
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := newTestApp(t, "1\n"+tc.user+"\n")
			a.StdinIsTTY = func() bool { return true }
			tc.seed(t, a, tc.user)
			pw := user.Passwd{
				Name: tc.user, UID: 1001, GID: 1001, GECOS: tc.gecos,
				Home: "/home/" + tc.user, Shell: "/bin/sh",
			}
			present := true
			events := []string{}
			lookup := func(string) (user.Passwd, bool, error) {
				if !present {
					return user.Passwd{}, false, nil
				}
				return pw, true, nil
			}
			a.Users = &user.Manager{
				Runner:            &orderedTeardownRunner{events: &events, present: &present},
				LookupUser:        lookup,
				NameInUse:         func(string) (bool, error) { return false, nil },
				RemoveManagedMail: func(user.Passwd) error { return nil },
				RemoveManagedHome: func(user.Passwd) error { return nil },
			}
			a.LookupUser = lookup
			a.TerminateProcesses = func(int) error { return nil }
			a.ClearScheduledJobs = func(string, int) error { return nil }
			a.DrainScheduledJobs = func() error { return nil }
			a.Scheduler = &schedule.Scheduler{
				SystemdDir: t.TempDir(), InstallPath: a.InstallPath,
				UnitPrefix: config.AutoRevokeUnitPrefix, Now: a.Now, Sys: fakeSys{},
			}

			if rc := a.manageUsers(); rc != 0 {
				t.Fatalf("menu recovery rc = %d; force was not applied or recovery failed: %q", rc, errb.String())
			}
			if present {
				t.Fatalf("menu recovery left %s account present; force was not applied", tc.name)
			}
			if found, err := a.Registry.Contains(tc.user); err != nil || found {
				t.Fatalf("menu recovery registry result: found=%v err=%v", found, err)
			}
		})
	}
}

// TestManageUsersMissingRowIsSweptWithoutAPrompt pins the deliberate asymmetry a
// review caught the docs overstating. Picking a 缺失 row does NOT ask for the
// full name: revoke's "the account is gone, clean up after it" branch runs before
// the confirmation. That is intended — there is no account to lose, and "c" on
// this same screen sweeps every missing row without asking either — but it makes
// "a number opens a confirmation" false for exactly these rows, so it is pinned
// here rather than left as folklore.
//
// The input carries a second line that would be the confirmation. Nothing must
// consume it: if a prompt ever appears here, "no-such-user" is not a legal
// username and the test fails on the changed exit code rather than passing
// quietly.
func TestManageUsersMissingRowIsSweptWithoutAPrompt(t *testing.T) {
	a, _, errb := newManageApp(t, "1\nno-such-user\n", "ltamissing-a1")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if got := regUsers(t, a); len(got) != 0 {
		t.Errorf("the missing row should have been swept; rows now %v", got)
	}
	if strings.Contains(errb.String(), "to confirm deletion") {
		t.Errorf("a missing row has no account to lose and must not demand a name: %q", errb.String())
	}
}

// TestRevokeRefusesAndReportsAUIDTamperedAccount is the CLI-level half of the
// user package's protection fix. An account whose current UID contradicts the one
// the registry pinned at creation is not the account this tool made, and revoke
// must refuse it rather than delete it — and, critically, must refuse BEFORE
// TerminateProcesses, which aims a SIGKILL sweep at the UID standing in passwd.
// A contradicting UID is by definition one the tool never issued, so that sweep
// would have been pointed at whatever the account's UID now collides with.
//
// It also pins that the refusal is not silent: UIDTampered's report only ever ran
// inside the branch something else had already refused, so on the one path where
// it was the whole story it never spoke.
func TestRevokeRefusesAndReportsAUIDTamperedAccount(t *testing.T) {
	const name = "ltatamper1"
	a, _, errb := newManageApp(t, "")
	a.Users = user.New()

	rm := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	rm()
	t.Cleanup(rm)
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-c", "linux-temp-admin temporary admin", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	pw, ok := mustUserLookup(t, name)
	if !ok {
		t.Fatal("account not created")
	}
	// The row pins a UID this account does not have: the shape of an account that
	// rewrote its own passwd entry, and of a name whose account was recreated.
	// The GECOS marker is intact, which is exactly the case that used to pass.
	reserveTestIdentity(t, a, pw.UID+4242)
	if err := a.Registry.Record(registry.Record{
		User: name, Created: "2026-07-07 12:00:00 UTC", Expires: "2026-07-08 12:00:00 UTC",
		Host: "203.0.113.5", Port: 22, UID: pw.UID + 4242,
	}); err != nil {
		t.Fatal(err)
	}

	if rc := a.revoke([]string{"--user", name, "--yes"}); rc != 1 {
		t.Errorf("rc=%d, want 1 (refused)", rc)
	}
	if !mustUserExists(t, name) {
		t.Error("THE ACCOUNT WAS DELETED even though its UID proves it is not the one the tool made")
	}
	if !strings.Contains(errb.String(), "UID") {
		t.Errorf("the refusal must name the tamper, or the operator cannot act on it: %q", errb.String())
	}
}

// TestRevokeShoutsWhenTheSudoGrantSurvives pins what used to be the quietest
// failure in the tool. revoke strips the sudo drop-in FIRST, deliberately, so an
// account that survives a refused revoke cannot survive holding passwordless
// root — and the removal's error was discarded, so when it did survive, nothing
// said so.
//
// Making a real os.Remove fail AS ROOT is the trick here: a read-only directory
// does not do it (root bypasses the permission check and the test would skip,
// asserting nothing — in CI, which runs this suite as root, always). A non-empty
// directory at the grant's path fails for everyone, root included, and it fails
// inside the real os.Remove rather than a mock, so the test still bites if the
// reporting path is rewritten.
func TestRevokeShoutsWhenTheSudoGrantSurvives(t *testing.T) {
	a, _, errb := newManageApp(t, "", "ltasudogrant-a1")
	grant := a.Sudoers.FilePath("ltasudogrant-a1")
	if err := os.MkdirAll(filepath.Join(grant, "wedge"), 0o700); err != nil {
		t.Fatal(err)
	}

	a.revoke([]string{"--user", "ltasudogrant-a1", "--yes"})

	if _, err := os.Stat(grant); err != nil {
		t.Fatalf("the wedge should have survived; the test proves nothing: %v", err)
	}
	// Match the distinctive phrase, not "sudo": revoke's absent-account branch says
	// "cleaning up registry/sudoers/sshd exception/..." on this very path, so a
	// substring that loose passes with the reporting deleted (it did — this test was
	// vacuous until the mutation caught it).
	if !strings.Contains(errb.String(), "passwordless root") {
		t.Errorf("a surviving NOPASSWD grant must be reported, not discarded; stderr: %q", errb.String())
	}
}

func mustWriteManage(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o440); err != nil {
		t.Fatal(err)
	}
}

func TestManageUsersShowsOrphansWithNoRegistryRow(t *testing.T) {
	a, out, errb := newManageApp(t, "\n", "ltamanage-live")
	mustWriteManage(t, a.Sudoers.FilePath("ltaorphan-x"), "ltaorphan-x ALL=(ALL) NOPASSWD:ALL\n")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(out.String(), "ltaorphan-x") {
		t.Errorf("orphan not surfaced: %q // errb=%q", out.String(), errb.String())
	}
}

func TestManageUsersEmptyRegistryStillOffersCleanupForOrphans(t *testing.T) {
	a, out, errb := newManageApp(t, "\n")
	mustWriteManage(t, a.Sudoers.FilePath("ltaorphan-y"), "ltaorphan-y ALL=(ALL) NOPASSWD:ALL\n")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(out.String(), "ltaorphan-y") {
		t.Errorf("orphan not surfaced: %q", out.String())
	}
	if !strings.Contains(errb.String(), "Enter returns") {
		t.Errorf("no prompt: %q", errb.String())
	}
}

// TestManageUsersTrulyEmptyStillReturns: no rows AND no orphans is the one case
// that prints "(none)" and leaves without a prompt — the guard's other direction.
func TestManageUsersTrulyEmptyStillReturns(t *testing.T) {
	a, out, errb := newManageApp(t, "")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(out.String(), "(none)") {
		t.Errorf("want (none): %q", out.String())
	}
	if strings.Contains(errb.String(), "Enter returns") {
		t.Errorf("must not prompt when truly empty: %q", errb.String())
	}
}
