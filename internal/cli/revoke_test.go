package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

type orderedTeardownRunner struct {
	events        *[]string
	present       *bool
	beforeUserdel func()
}

type revokeTestScheduleSystem struct {
	removeAtCalls *int
	hasSystemctl  bool
}

func (s revokeTestScheduleSystem) HasSystemctl() bool                         { return s.hasSystemctl }
func (revokeTestScheduleSystem) Systemctl(...string) error                    { return nil }
func (revokeTestScheduleSystem) HasAt() bool                                  { return true }
func (revokeTestScheduleSystem) ScheduleAt(string, time.Time) (string, error) { return "1", nil }
func (s revokeTestScheduleSystem) RemoveAtJobsFor(string) error {
	if s.removeAtCalls != nil {
		*s.removeAtCalls++
	}
	return nil
}
func (revokeTestScheduleSystem) AtrmJob(string) error              { return nil }
func (revokeTestScheduleSystem) AtJobs() ([]schedule.AtJob, error) { return nil, nil }

func (r *orderedTeardownRunner) Run(name string, _ ...string) error {
	*r.events = append(*r.events, name)
	if name == "userdel" {
		if r.beforeUserdel != nil {
			r.beforeUserdel()
		}
		*r.present = false
	}
	return nil
}

func (r *orderedTeardownRunner) RunInput(_ string, name string, args ...string) error {
	return r.Run(name, args...)
}

func (*orderedTeardownRunner) Look(name string) bool { return name == "userdel" }

func newOrderedTeardownApp(t *testing.T, pw user.Passwd, failClearCall int, clearErr error) (*App, *[]string, *bool) {
	t.Helper()
	events := []string{}
	present := true
	lookup := func(name string) (user.Passwd, bool, error) {
		if name != pw.Name {
			t.Fatalf("LookupUser name = %q, want %q", name, pw.Name)
		}
		if !present {
			return user.Passwd{}, false, nil
		}
		return pw, true, nil
	}
	appendArtifact := func(event string) func(user.Passwd) error {
		return func(got user.Passwd) error {
			if got != pw {
				t.Fatalf("%s cleanup identity = %+v, want %+v", event, got, pw)
			}
			events = append(events, event)
			return nil
		}
	}
	clearCalls := 0
	a := &App{
		Users: &user.Manager{
			Runner:            &orderedTeardownRunner{events: &events, present: &present},
			LookupUser:        lookup,
			NameInUse:         func(string) (bool, error) { return false, nil },
			RemoveManagedMail: appendArtifact("mail"),
			RemoveManagedHome: appendArtifact("home"),
		},
		LookupUser: lookup,
		ClearScheduledJobs: func(name string, uid int) error {
			if name != pw.Name || uid != pw.UID {
				t.Fatalf("ClearScheduledJobs(%q, %d), want (%q, %d)", name, uid, pw.Name, pw.UID)
			}
			clearCalls++
			events = append(events, "clear")
			if clearCalls == failClearCall {
				return clearErr
			}
			return nil
		},
		DrainScheduledJobs: func() error {
			events = append(events, "drain")
			return nil
		},
		TerminateProcesses: func(uid int) error {
			if uid != pw.UID {
				t.Fatalf("TerminateProcesses UID = %d, want %d", uid, pw.UID)
			}
			events = append(events, "kill")
			return nil
		},
	}
	return a, &events, &present
}

func requireTeardownEvents(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("teardown events = %v, want %v", got, want)
	}
}

func TestLegacyRecoveryAuthorizationRequiresInteractiveConfirmation(t *testing.T) {
	base := revokeOptions{
		username:         "xxvcc-a1",
		force:            true,
		manualInvocation: true,
		liveConfirmed:    true,
	}
	tests := []struct {
		name           string
		registered     bool
		identityBound  bool
		stdinTTY       bool
		mutate         func(*revokeOptions)
		wantAuthorized bool
	}{
		{name: "interactive direct recovery", registered: true, stdinTTY: true, wantAuthorized: true},
		{name: "piped full-name confirmation", registered: true},
		{name: "historical eight argument timer", registered: true, mutate: func(o *revokeOptions) {
			o.yes = true
			o.confirmForce = o.username
		}},
		{name: "uninstall internal", registered: true, stdinTTY: true, mutate: func(o *revokeOptions) { o.manualInvocation = false }},
		{name: "no full-name confirmation", registered: true, stdinTTY: true, mutate: func(o *revokeOptions) { o.liveConfirmed = false }},
		{name: "generation-bound", registered: true, stdinTTY: true, mutate: func(o *revokeOptions) {
			o.expectedUID = 1001
			o.generation = "0123456789abcdef0123456789abcdef"
		}},
		{name: "current identity", registered: true, identityBound: true, stdinTTY: true},
		{name: "unregistered interactive recovery", stdinTTY: true, wantAuthorized: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			if tc.mutate != nil {
				tc.mutate(&opts)
			}
			if got := legacyRecoveryAuthorized(tc.identityBound, opts, tc.stdinTTY); got != tc.wantAuthorized {
				t.Fatalf("legacyRecoveryAuthorized = %v, want %v", got, tc.wantAuthorized)
			}
		})
	}
}

func TestPendingRecoveryAuthorizationRequiresInteractiveConfirmation(t *testing.T) {
	base := revokeOptions{
		username:         "xxvcc-pending1",
		force:            true,
		manualInvocation: true,
		liveConfirmed:    true,
	}
	tests := []struct {
		name           string
		stdinTTY       bool
		mutate         func(*revokeOptions)
		wantAuthorized bool
	}{
		{name: "interactive direct recovery", stdinTTY: true, wantAuthorized: true},
		{name: "piped full-name confirmation"},
		{name: "noninteractive yes", stdinTTY: true, mutate: func(o *revokeOptions) { o.yes = true }},
		{name: "uninstall internal", stdinTTY: true, mutate: func(o *revokeOptions) { o.manualInvocation = false }},
		{name: "without force", stdinTTY: true, mutate: func(o *revokeOptions) { o.force = false }},
		{name: "without full-name confirmation", stdinTTY: true, mutate: func(o *revokeOptions) { o.liveConfirmed = false }},
		{name: "generation-bound task", stdinTTY: true, mutate: func(o *revokeOptions) {
			o.expectedUID = 1001
			o.generation = "0123456789abcdef0123456789abcdef"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			if tc.mutate != nil {
				tc.mutate(&opts)
			}
			if got := pendingRecoveryAuthorized(opts, tc.stdinTTY); got != tc.wantAuthorized {
				t.Fatalf("pendingRecoveryAuthorized = %v, want %v", got, tc.wantAuthorized)
			}
		})
	}
}

func TestPendingCreationRecordRequiresExactBoundShape(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-pending1", UID: 1001, GID: 1001,
		GECOS: config.PendingGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-pending1", Shell: "/bin/sh",
	}
	base := registry.Record{
		User: pw.Name, Generation: generation, IdentityBound: true, Pending: true, Port: 22,
	}
	if !pendingCreationRecordMatchesPasswd(base, pw) {
		t.Fatal("exact UID-zero pending identity was rejected")
	}
	withUID := base
	withUID.UID = pw.UID
	if !pendingCreationRecordMatchesPasswd(withUID, pw) {
		t.Fatal("exact UID-bound pending identity was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*registry.Record, *user.Passwd)
	}{
		{name: "wrong recorded UID", mutate: func(r *registry.Record, _ *user.Passwd) { r.UID = 1002 }},
		{name: "not pending", mutate: func(r *registry.Record, _ *user.Passwd) { r.Pending = false }},
		{name: "unbound row", mutate: func(r *registry.Record, _ *user.Passwd) { r.IdentityBound = false }},
		{name: "deletion already started", mutate: func(r *registry.Record, _ *user.Passwd) { r.DeletionStarted = true }},
		{name: "wrong marker", mutate: func(_ *registry.Record, p *user.Passwd) { p.GECOS = config.ManagedGenerationGECOSPrefix + generation }},
		{name: "wrong home", mutate: func(_ *registry.Record, p *user.Passwd) { p.Home = "/srv/pending" }},
		{name: "root UID", mutate: func(_ *registry.Record, p *user.Passwd) { p.UID = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, gotPW := base, pw
			tc.mutate(&rec, &gotPW)
			if pendingCreationRecordMatchesPasswd(rec, gotPW) {
				t.Fatal("unsafe pending identity was accepted")
			}
		})
	}
}

func TestInteractiveRevokeBindsConfirmationToAccountGeneration(t *testing.T) {
	const (
		username      = "xxvcc-confirm1"
		oldGeneration = "0123456789abcdef0123456789abcdef"
		newGeneration = "fedcba9876543210fedcba9876543210"
	)
	oldRecord := registry.Record{
		User: username, UID: 1001, Generation: oldGeneration,
		IdentityBound: true, Port: 22,
	}
	newRecord := registry.Record{
		User: username, UID: 1002, Generation: newGeneration,
		IdentityBound: true, Port: 22,
	}
	oldPasswd := user.Passwd{
		Name: username, UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + oldGeneration,
		Home:  "/home/" + username, Shell: "/bin/sh",
	}
	newPasswd := user.Passwd{
		Name: username, UID: 1002, GID: 1002,
		GECOS: config.ManagedGenerationGECOSPrefix + newGeneration,
		Home:  "/home/" + username, Shell: "/bin/sh",
	}

	a, _, errb := newTestApp(t, username+"\n")
	setTestRegistryRecord(t, a, oldRecord)
	runner := &revokeRunner{}
	a.Users = &user.Manager{Runner: runner}
	lookupCalls := 0
	a.LookupUser = func(name string) (user.Passwd, bool, error) {
		if name != username {
			t.Fatalf("LookupUser name = %q, want %q", name, username)
		}
		lookupCalls++
		if lookupCalls == 1 {
			// Model a complete same-name replacement while the operator is at the
			// confirmation boundary and before revoke acquires its account lock.
			if err := a.Registry.Record(newRecord); err != nil {
				t.Fatal(err)
			}
			return oldPasswd, true, nil
		}
		return newPasswd, true, nil
	}

	if rc := a.revoke([]string{"--user", username}); rc != 1 {
		t.Fatalf("revoke rc = %d, want changed-generation refusal", rc)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("revoke mutated the replacement account after stale confirmation: %v", runner.calls)
	}
	if got := errb.String(); !strings.Contains(got, "identity changed after confirmation") {
		t.Fatalf("revoke did not explain the stale confirmation: %q", got)
	}
	stored, found, err := a.Registry.Lookup(username)
	if err != nil || !found || stored != newRecord {
		t.Fatalf("replacement registry identity changed: found=%v record=%+v err=%v", found, stored, err)
	}
}

func TestInteractiveRevokeConfirmationAllowsOnlyCurrentUserWritableFields(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	witness := config.ManagedGenerationGECOSWitnessPrefix + generation
	expected := user.Passwd{
		Name: "xxvcc-confirm2", UID: 1001, GID: 1001, GECOS: ",,,," + witness,
		Home: "/home/xxvcc-confirm2", Shell: "/bin/bash",
	}
	rec := registry.Record{
		User: expected.Name, UID: expected.UID, Generation: generation,
		IdentityBound: true, Port: 22,
	}

	for _, tc := range []struct {
		name        string
		current     user.Passwd
		wantMatches bool
	}{
		{
			name: "full-name and shell changed",
			current: user.Passwd{
				Name: expected.Name, UID: expected.UID, GID: expected.GID,
				GECOS: "Changed Name,room,work,home," + witness,
				Home:  expected.Home, Shell: "/bin/sh",
			},
			wantMatches: true,
		},
		{
			name: "protected witness changed",
			current: user.Passwd{
				Name: expected.Name, UID: expected.UID, GID: expected.GID,
				GECOS: ",,,," + config.ManagedGenerationGECOSWitnessPrefix + "fedcba9876543210fedcba9876543210",
				Home:  expected.Home, Shell: expected.Shell,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := &revokeIdentitySnapshot{registered: true, record: rec, passwd: expected}
			if got := snapshot.matches(true, rec, tc.current, true); got != tc.wantMatches {
				t.Fatalf("confirmation identity match=%v, want %v", got, tc.wantMatches)
			}
		})
	}

	old := expected
	old.GECOS = config.ManagedGenerationGECOSPrefix + generation
	oldChanged := old
	oldChanged.Shell = "/bin/sh"
	snapshot := &revokeIdentitySnapshot{registered: true, record: rec, passwd: old}
	if snapshot.matches(true, rec, oldChanged, true) {
		t.Fatal("legacy first-field confirmation accepted a changed snapshot")
	}
}

func TestInteractiveLegacyAndUnregisteredDeletionPersistUIDWitnessBeforeUserdel(t *testing.T) {
	requireRootRegistryFixture(t)
	const generation = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name       string
		registered bool
		marker     string
	}{
		{name: "registered legacy", registered: true, marker: config.ManagedGECOS},
		{name: "unregistered generation marker", marker: config.ManagedGenerationGECOSPrefix + generation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const username = "xxvcc-recovery1"
			pw := user.Passwd{
				Name: username, UID: 1001, GID: 1001, GECOS: tc.marker,
				Home: "/home/" + username, Shell: "/bin/sh",
			}
			a, _, _ := newTestApp(t, "")
			a.StdinIsTTY = func() bool { return true }
			if err := a.Registry.Init(); err != nil {
				t.Fatal(err)
			}
			if tc.registered {
				if err := a.Registry.Record(registry.Record{
					User: username, Port: 22, UID: pw.UID, Generation: generation,
				}); err != nil {
					t.Fatal(err)
				}
			}
			present := true
			events := []string{}
			lookup := func(string) (user.Passwd, bool, error) {
				if !present {
					return user.Passwd{}, false, nil
				}
				return pw, true, nil
			}
			runner := &orderedTeardownRunner{events: &events, present: &present}
			runner.beforeUserdel = func() {
				got, found, err := a.Registry.Lookup(username)
				if err != nil || !found || !got.DeletionStarted || got.UID != pw.UID ||
					got.IdentityBound || got.Generation != "" || got.Pending {
					t.Fatalf("pre-userdel UID witness: found=%v rec=%+v err=%v", found, got, err)
				}
			}
			a.Users = &user.Manager{
				Runner: runner, LookupUser: lookup,
				RemoveManagedMail: func(user.Passwd) error { return nil },
				RemoveManagedHome: func(user.Passwd) error { return nil },
			}
			a.LookupUser = lookup
			a.TerminateProcesses = func(int) error { return nil }
			a.ClearScheduledJobs = func(string, int) error { return nil }
			a.DrainScheduledJobs = func() error { return nil }
			a.Scheduler = &schedule.Scheduler{
				SystemdDir: t.TempDir(), InstallPath: t.TempDir() + "/linux-temp-admin",
				UnitPrefix: config.AutoRevokeUnitPrefix, Sys: revokeTestScheduleSystem{},
			}

			if rc := a.revokeOptionsLocked(revokeOptions{
				username: username, force: true, manualInvocation: true, liveConfirmed: true,
			}); rc != 0 {
				t.Fatalf("interactive recovery rc = %d", rc)
			}
			if present || !strings.Contains(strings.Join(events, ","), "userdel") {
				t.Fatalf("account deletion state: present=%v events=%v", present, events)
			}
			if found, err := a.Registry.Contains(username); err != nil || found {
				t.Fatalf("completed recovery witness: found=%v err=%v", found, err)
			}
		})
	}
}

func TestInteractivePendingCreationRecoveryPersistsUIDWitnessBeforeUserdel(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		username   = "xxvcc-pending2"
		generation = "0123456789abcdef0123456789abcdef"
	)
	pw := user.Passwd{
		Name: username, UID: 1001, GID: 1001,
		GECOS: config.PendingGenerationGECOSPrefix + generation,
		Home:  "/home/" + username, Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: username, Generation: generation, IdentityBound: true, Pending: true, Port: 22,
	}
	a, _, _ := newTestApp(t, "")
	a.StdinIsTTY = func() bool { return true }
	setTestRegistryRecord(t, a, rec)

	present := true
	events := []string{}
	lookup := func(string) (user.Passwd, bool, error) {
		if !present {
			return user.Passwd{}, false, nil
		}
		return pw, true, nil
	}
	runner := &orderedTeardownRunner{events: &events, present: &present}
	runner.beforeUserdel = func() {
		got, found, err := a.Registry.Lookup(username)
		if err != nil || !found || !got.DeletionStarted || got.UID != pw.UID ||
			got.IdentityBound || got.Generation != "" || got.Pending {
			t.Fatalf("pending recovery pre-userdel witness: found=%v rec=%+v err=%v", found, got, err)
		}
	}
	a.Users = &user.Manager{
		Runner: runner, LookupUser: lookup,
		NameInUse:         func(string) (bool, error) { return false, nil },
		RemoveManagedMail: func(user.Passwd) error { events = append(events, "mail"); return nil },
		RemoveManagedHome: func(user.Passwd) error { events = append(events, "home"); return nil },
	}
	a.LookupUser = lookup
	a.TerminateProcesses = func(int) error { events = append(events, "kill"); return nil }
	a.ClearScheduledJobs = func(string, int) error { events = append(events, "clear"); return nil }
	a.DrainScheduledJobs = func() error { events = append(events, "drain"); return nil }
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: t.TempDir() + "/linux-temp-admin",
		UnitPrefix: config.AutoRevokeUnitPrefix, Sys: revokeTestScheduleSystem{},
	}

	if rc := a.revokeOptionsLocked(revokeOptions{
		username: username, force: true, manualInvocation: true, liveConfirmed: true,
	}); rc != 0 {
		t.Fatalf("interactive pending recovery rc = %d", rc)
	}
	if present || !strings.Contains(strings.Join(events, ","), "userdel") {
		t.Fatalf("pending recovery account state: present=%v events=%v", present, events)
	}
	if found, err := a.Registry.Contains(username); err != nil || found {
		t.Fatalf("completed pending recovery witness: found=%v err=%v", found, err)
	}
}

func TestInteractivePendingRecoveryReturnsAfterDurableIdentityQuarantine(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		username   = "xxvcc-pendingq"
		generation = "0123456789abcdef0123456789abcdef"
	)
	pw := user.Passwd{
		Name: username, UID: 1001, GID: 1001,
		GECOS: config.PendingGenerationGECOSPrefix + generation,
		Home:  "/home/" + username, Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: username, Generation: generation, IdentityBound: true, Pending: true, Port: 22,
	}
	a, _, _ := newTestApp(t, "")
	a.StdinIsTTY = func() bool { return true }
	setTestRegistryRecord(t, a, rec)

	present := true
	events := []string{}
	lookup := func(string) (user.Passwd, bool, error) {
		if !present {
			return user.Passwd{}, false, nil
		}
		return pw, true, nil
	}
	runner := &orderedTeardownRunner{events: &events, present: &present}
	a.Users = &user.Manager{
		Runner: runner, LookupUser: lookup,
		NameInUse:         func(string) (bool, error) { return false, nil },
		RemoveManagedMail: func(user.Passwd) error { events = append(events, "mail"); return nil },
		RemoveManagedHome: func(user.Passwd) error { events = append(events, "home"); return nil },
	}
	a.LookupUser = lookup
	a.TerminateProcesses = func(int) error { events = append(events, "kill"); return nil }
	a.ClearScheduledJobs = func(string, int) error { events = append(events, "clear"); return nil }
	a.DrainScheduledJobs = func() error { events = append(events, "drain"); return nil }
	now := time.Date(2026, 8, 1, 12, 0, 1, 0, time.UTC)
	a.Now = func() time.Time { return now }
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: t.TempDir() + "/linux-temp-admin",
		UnitPrefix: config.AutoRevokeUnitPrefix, Now: a.Now,
		Sys: revokeTestScheduleSystem{hasSystemctl: true},
	}
	ensureCalls := 0
	a.EnsureScheduledCommand = func() error {
		ensureCalls++
		return nil
	}

	if rc := a.revokeOptionsLocked(revokeOptions{
		username: username, force: true, manualInvocation: true, liveConfirmed: true,
	}); rc != 0 {
		t.Fatalf("pending quarantine revoke rc = %d", rc)
	}
	stored, found, err := a.Registry.Lookup(username)
	if err != nil || !found || !stored.Pending || !stored.DeletionStarted || stored.UID != pw.UID ||
		stored.QuarantineUnit != config.QuarantineUnitPrefix+username {
		t.Fatalf("pending quarantine state: found=%v rec=%+v err=%v", found, stored, err)
	}
	if !present || strings.Contains(strings.Join(events, ","), "drain") || strings.Contains(strings.Join(events, ","), "userdel") {
		t.Fatalf("foreground pending revoke did not return in quarantine: present=%v events=%v", present, events)
	}
	if ensureCalls != 1 {
		t.Fatalf("stable finalizer command preflight calls = %d, want 1", ensureCalls)
	}
	if got := strings.Join(events, ","); !strings.Contains(got, "kill,clear,kill,clear") {
		t.Fatalf("immediate quarantine cleanup missed its final queue pass: %v", events)
	}

	deadline, err := time.Parse(time.RFC3339, stored.QuarantineUntil)
	if err != nil {
		t.Fatal(err)
	}
	scheduled := revokeOptions{
		username: username, yes: true, force: true, confirmForce: username,
		expectedUID: pw.UID, generation: generation,
	}
	now = deadline.Add(-time.Second)
	if rc := a.revokeOptionsLocked(scheduled); rc != 0 || !present {
		t.Fatalf("pre-deadline finalizer rc=%d present=%v", rc, present)
	}
	now = deadline.Add(time.Second)
	if rc := a.revokeOptionsLocked(scheduled); rc != 0 || present {
		t.Fatalf("mature finalizer rc=%d present=%v events=%v", rc, present, events)
	}
	if found, err := a.Registry.Contains(username); err != nil || found {
		t.Fatalf("mature quarantine retained registry: found=%v err=%v", found, err)
	}
	for _, suffix := range []string{".service", ".timer"} {
		path := filepath.Join(a.Scheduler.SystemdDir, config.QuarantineUnitPrefix+username+suffix)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("mature quarantine retained %s: %v", path, err)
		}
	}
}

func TestRevokeFallsBackToSynchronousDeletionWhenFinalizerCommandIsUnavailable(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		username   = "xxvcc-commandq"
		generation = "0123456789abcdef0123456789abcdef"
	)
	pw := user.Passwd{
		Name: username, UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/" + username, Shell: "/bin/sh",
	}
	a, _, _ := newTestApp(t, "")
	ordered, events, present := newOrderedTeardownApp(t, pw, 0, nil)
	a.Users = ordered.Users
	a.LookupUser = ordered.LookupUser
	a.ClearScheduledJobs = ordered.ClearScheduledJobs
	a.DrainScheduledJobs = ordered.DrainScheduledJobs
	a.TerminateProcesses = ordered.TerminateProcesses
	a.StdinIsTTY = func() bool { return true }
	setTestRegistryRecord(t, a, registry.Record{
		User: username, UID: pw.UID, Port: 22, Generation: generation, IdentityBound: true,
	})
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: t.TempDir() + "/linux-temp-admin",
		UnitPrefix: config.AutoRevokeUnitPrefix, Now: time.Now,
		Sys: revokeTestScheduleSystem{hasSystemctl: true},
	}
	preflightErr := errors.New("installed command is missing")
	a.EnsureScheduledCommand = func() error { return preflightErr }

	if rc := a.revokeOptionsLocked(revokeOptions{
		username: username, manualInvocation: true, liveConfirmed: true,
	}); rc != 0 {
		t.Fatalf("synchronous fallback revoke rc = %d", rc)
	}
	if *present {
		t.Fatal("synchronous fallback retained the account")
	}
	if got := strings.Join(*events, ","); !strings.Contains(got, "drain") || !strings.Contains(got, "userdel") {
		t.Fatalf("synchronous fallback events = %v, want drain and userdel", *events)
	}
	if found, err := a.Registry.Contains(username); err != nil || found {
		t.Fatalf("synchronous fallback retained registry row: found=%v err=%v", found, err)
	}
}

func TestImmediateQuiescenceEndsWithASecondQueueSweep(t *testing.T) {
	pw := user.Passwd{Name: "xxvcc-immediate", UID: 1001, GID: 1001, Home: "/home/xxvcc-immediate", Shell: "/bin/sh"}
	a, events, _ := newOrderedTeardownApp(t, pw, 0, nil)
	if err := a.quiesceScheduledAccountImmediate(pw.Name, pw); err != nil {
		t.Fatal(err)
	}
	requireTeardownEvents(t, *events, "kill", "clear", "kill", "clear")
}

func TestUnregisteredDeletionWitnessWriteFailureBlocksUserdel(t *testing.T) {
	requireRootRegistryFixture(t)
	const username = "xxvcc-recovery2"
	pw := user.Passwd{
		Name: username, UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + "0123456789abcdef0123456789abcdef",
		Home:  "/home/" + username, Shell: "/bin/sh",
	}
	a, _, _ := newTestApp(t, "")
	a.StdinIsTTY = func() bool { return true }
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	present := true
	events := []string{}
	lookup := func(string) (user.Passwd, bool, error) { return pw, present, nil }
	a.Users = &user.Manager{
		Runner: &orderedTeardownRunner{events: &events, present: &present}, LookupUser: lookup,
		RemoveManagedMail: func(user.Passwd) error { return nil },
		RemoveManagedHome: func(user.Passwd) error { return nil },
	}
	a.LookupUser = lookup
	a.TerminateProcesses = func(int) error { return nil }
	a.ClearScheduledJobs = func(string, int) error { return nil }
	a.DrainScheduledJobs = func() error { return nil }
	a.Registry.Lock = filepath.Join(t.TempDir(), "missing", "registry.lock")

	if rc := a.revokeOptionsLocked(revokeOptions{
		username: username, force: true, manualInvocation: true, liveConfirmed: true,
	}); rc != 1 {
		t.Fatalf("revoke rc = %d, want persistence refusal", rc)
	}
	if !present || strings.Contains(strings.Join(events, ","), "userdel") {
		t.Fatalf("witness failure reached userdel: present=%v events=%v", present, events)
	}
}

func TestRevokeUnsafeHomeAndGrantFailureStillDisableAndRetainAccount(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		name       = "xxvcc-a1"
		generation = "0123456789abcdef0123456789abcdef"
	)
	pw := user.Passwd{
		Name: name, UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/srv/changed-home", Shell: "/bin/sh",
	}
	a, _, errb := newTestApp(t, "")
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	rec := registry.Record{
		User: name, UID: pw.UID, Generation: generation, IdentityBound: true,
		Port: 22,
	}
	if err := a.Registry.Record(rec); err != nil {
		t.Fatal(err)
	}

	grantErr := errors.New("sudo drop-in unlink failed")
	a.Sudoers = &sudoers.Manager{
		Dir:        t.TempDir(),
		RemoveFile: func(string) error { return grantErr },
	}
	runner := &revokeRunner{}
	a.Users = &user.Manager{Runner: runner}
	a.LookupUser = func(string) (user.Passwd, bool, error) { return pw, true, nil }
	terminated := 0
	a.TerminateProcesses = func(uid int) error {
		if uid != pw.UID {
			t.Fatalf("TerminateProcesses UID = %d, want %d", uid, pw.UID)
		}
		terminated++
		return nil
	}

	if rc := a.revokeOptionsLocked(revokeOptions{username: name, yes: true}); rc != 1 {
		t.Fatalf("revoke rc = %d, want retained-account failure", rc)
	}
	if got := strings.Join(runner.calls, ","); got != "chage,usermod" {
		t.Fatalf("account commands = %q, want login disable without userdel", got)
	}
	if terminated != 2 {
		t.Fatalf("TerminateProcesses called %d times, want two-pass quiescence", terminated)
	}
	if _, found, err := a.Registry.Lookup(name); err != nil || !found {
		t.Fatalf("registry witness was not retained: found=%v err=%v", found, err)
	}
	gotErr := errb.String()
	for _, want := range []string{grantErr.Error(), "differs from managed path", "disabled but not deleted"} {
		if !strings.Contains(gotErr, want) {
			t.Fatalf("stderr missing %q: %q", want, gotErr)
		}
	}
}

func TestTeardownLocalAccountOrdersFinalCleanupBeforeUserdel(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-a1", UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	a, events, present := newOrderedTeardownApp(t, pw, 0, nil)

	stage, err := a.teardownLocalAccount(pw.Name, pw, func() error {
		*events = append(*events, "persist")
		return nil
	})
	if err != nil || stage != revokeAccountRemoved {
		t.Fatalf("teardownLocalAccount = stage %v, err %v; want account removed", stage, err)
	}
	if *present {
		t.Fatal("account still present after successful userdel")
	}
	requireTeardownEvents(t, *events,
		"chage", "usermod",
		"kill", "clear", "drain", "kill", "clear",
		"persist",
		"mail", "home",
		"kill", "clear",
		"userdel", "mail",
	)
}

func TestTeardownContinuesAcrossConcurrentUserWritablePasswdChanges(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	marker := config.ManagedGenerationGECOSWitnessPrefix + generation
	expected := user.Passwd{
		Name: "xxvcc-mutable1", UID: 1001, GID: 1001,
		GECOS: ",,,," + marker,
		Home:  "/home/xxvcc-mutable1", Shell: "/bin/bash",
	}
	events := []string{}
	present := true
	lookups := 0
	lookup := func(string) (user.Passwd, bool, error) {
		if !present {
			return user.Passwd{}, false, nil
		}
		lookups++
		current := expected
		if lookups%2 == 0 {
			current.GECOS = "Changed Name,office,work,home," + marker
			current.Shell = "/bin/sh"
		} else {
			current.GECOS = "Another Name,room,,," + marker
		}
		return current, true, nil
	}
	a := &App{
		Users: &user.Manager{
			Runner:            &orderedTeardownRunner{events: &events, present: &present},
			LookupUser:        lookup,
			NameInUse:         func(string) (bool, error) { return false, nil },
			RemoveManagedMail: func(user.Passwd) error { events = append(events, "mail"); return nil },
			RemoveManagedHome: func(user.Passwd) error { events = append(events, "home"); return nil },
		},
		LookupUser:         lookup,
		TerminateProcesses: func(int) error { events = append(events, "kill"); return nil },
		ClearScheduledJobs: func(string, int) error { events = append(events, "clear"); return nil },
		DrainScheduledJobs: func() error { events = append(events, "drain"); return nil },
	}

	stage, err := a.teardownLocalAccount(expected.Name, expected, func() error {
		events = append(events, "persist")
		return nil
	})
	if err != nil || stage != revokeAccountRemoved {
		t.Fatalf("teardownLocalAccount = stage %v, err %v; want removal across chfn/chsh changes", stage, err)
	}
	if present || lookups < 10 || !strings.Contains(strings.Join(events, ","), "userdel") {
		t.Fatalf("mutable-field teardown did not complete: present=%v lookups=%d events=%v", present, lookups, events)
	}
}

func TestInviteAndRevokeIdentityComparisonsUseDifferentPolicies(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	witness := config.ManagedGenerationGECOSWitnessPrefix + generation
	expected := user.Passwd{
		Name: "xxvcc-policy1", UID: 1001, GID: 1001, GECOS: ",,,," + witness,
		Home: "/home/xxvcc-policy1", Shell: "/bin/bash",
	}
	current := expected
	current.GECOS = "Changed Name,room,work,home," + witness
	current.Shell = "/bin/sh"
	a := &App{LookupUser: func(string) (user.Passwd, bool, error) { return current, true, nil }}

	if err := a.accountStillMatches(expected.Name, expected); err == nil {
		t.Fatal("invite identity comparison accepted a changed passwd snapshot")
	}
	if err := a.revokeAccountStillMatches(expected.Name, expected); err != nil {
		t.Fatalf("revoke identity comparison rejected user-writable field changes: %v", err)
	}
}

func TestRollbackInviteAccountUsesOrderedTeardown(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-a1", UID: 1001, GID: 1001,
		GECOS: config.PendingGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: pw.Name, UID: pw.UID, Generation: generation,
		IdentityBound: true, Pending: true,
	}
	a, events, present := newOrderedTeardownApp(t, pw, 0, nil)
	setTestRegistryRecord(t, a, rec)

	if err := a.rollbackInviteAccount(pw.Name, rec, pw, true, false); err != nil {
		t.Fatal(err)
	}
	if *present {
		t.Fatal("pending account still present after successful rollback")
	}
	requireTeardownEvents(t, *events,
		"chage", "usermod",
		"kill", "clear", "drain", "kill", "clear",
		"mail", "home",
		"kill", "clear",
		"userdel", "mail",
	)
}

func TestTeardownLocalAccountFinalScheduledCleanupFailureBlocksUserdel(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-a1", UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	wantErr := errors.New("final scheduled cleanup failed")
	a, events, present := newOrderedTeardownApp(t, pw, 3, wantErr)

	stage, err := a.teardownLocalAccount(pw.Name, pw, func() error { return nil })
	if stage != revokeDeleteAccount || !errors.Is(err, wantErr) {
		t.Fatalf("teardownLocalAccount = stage %v, err %v; want delete-stage %v", stage, err, wantErr)
	}
	if !*present {
		t.Fatal("userdel ran after the final scheduled-job cleanup failed")
	}
	requireTeardownEvents(t, *events,
		"chage", "usermod",
		"kill", "clear", "drain", "kill", "clear",
		"mail", "home", "kill", "clear",
	)
}

func TestTeardownLocalAccountPersistsDeletionPhaseBeforeUserdel(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-a1", UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: pw.Name, UID: pw.UID, Generation: generation, IdentityBound: true, Port: 22,
	}
	a, events, present := newOrderedTeardownApp(t, pw, 0, nil)
	setTestRegistryRecord(t, a, rec)

	stage, err := a.teardownLocalAccount(pw.Name, pw, func() error {
		if err := a.persistDeletionStarted(rec, true, pw); err != nil {
			return err
		}
		*events = append(*events, "persist")
		return nil
	})
	if err != nil || stage != revokeAccountRemoved {
		t.Fatalf("teardownLocalAccount = stage %v, err %v; want account removed", stage, err)
	}
	if *present {
		t.Fatal("account still present after successful userdel")
	}
	stored, found, err := a.Registry.Lookup(pw.Name)
	if err != nil || !found || !stored.DeletionStarted {
		t.Fatalf("durable deletion phase = found %v record %+v err %v", found, stored, err)
	}
	requireTeardownEvents(t, *events,
		"chage", "usermod",
		"kill", "clear", "drain", "kill", "clear",
		"persist", "mail", "home", "kill", "clear", "userdel", "mail",
	)
}

func TestAccountDisappearanceDuringTeardownRetainsMailRecoveryWitness(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-a1", UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: pw.Name, UID: pw.UID, Generation: generation, IdentityBound: true, Port: 22,
	}
	a, events, present := newOrderedTeardownApp(t, pw, 0, nil)
	setTestRegistryRecord(t, a, rec)
	wantErr := errors.New("mail absence fsync failed")
	mailCalls := 0
	a.Users.RemoveManagedMail = func(got user.Passwd) error {
		if got.Name != pw.Name || got.UID != pw.UID {
			t.Fatalf("mail recovery identity = %+v, want %+v", got, pw)
		}
		mailCalls++
		*events = append(*events, "mail")
		if mailCalls == 2 {
			return wantErr
		}
		return nil
	}

	stage, err := a.teardownLocalAccount(pw.Name, pw, func() error {
		if err := a.persistDeletionStarted(rec, true, pw); err != nil {
			return err
		}
		*events = append(*events, "persist")
		*present = false
		return nil
	})
	if stage != revokeDeleteAccount || !errors.Is(err, wantErr) {
		t.Fatalf("teardownLocalAccount = stage %v, err %v; want retained mail failure", stage, err)
	}
	stored, found, lookupErr := a.Registry.Lookup(pw.Name)
	if lookupErr != nil || !found || !stored.DeletionStarted || stored.UID != pw.UID || stored.Generation != generation {
		t.Fatalf("mail recovery witness = found %v record %+v err %v", found, stored, lookupErr)
	}
	requireTeardownEvents(t, *events,
		"chage", "usermod",
		"kill", "clear", "drain", "kill", "clear",
		"persist", "mail", "mail",
	)

	a.Users.RemoveManagedMail = func(user.Passwd) error { return nil }
	if err := a.reconcileDeletionStarted(stored); err != nil {
		t.Fatalf("retry post-deletion mail recovery: %v", err)
	}
	if err := a.releaseRegistryAfterCleanup(pw.Name); err != nil {
		t.Fatalf("release recovered registry witness: %v", err)
	}
	if found, err := a.Registry.Contains(pw.Name); err != nil || found {
		t.Fatalf("recovered registry witness remains: found=%v err=%v", found, err)
	}
}

func TestDeletionPhaseRegistryWriteFailureBlocksUserdel(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-a1", UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-a1", Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: pw.Name, UID: pw.UID, Generation: generation, IdentityBound: true, Port: 22,
	}
	a, events, present := newOrderedTeardownApp(t, pw, 0, nil)
	setTestRegistryRecord(t, a, rec)
	workingLock := a.Registry.Lock
	a.Registry.Lock = t.TempDir() + "/missing/registry.lock"

	stage, err := a.teardownLocalAccount(pw.Name, pw, func() error {
		return a.persistDeletionStarted(rec, true, pw)
	})
	if err == nil || stage != revokeDeleteAccount || !strings.Contains(err.Error(), "deletion-started") {
		t.Fatalf("teardownLocalAccount = stage %v, err %v; want durable-state failure", stage, err)
	}
	if !*present {
		t.Fatal("userdel ran after deletion-phase persistence failed")
	}
	for _, event := range *events {
		if event == "userdel" {
			t.Fatalf("userdel event survived persistence failure: %v", *events)
		}
	}
	a.Registry.Lock = workingLock
	stored, found, lookupErr := a.Registry.Lookup(pw.Name)
	if lookupErr != nil || !found || stored.DeletionStarted {
		t.Fatalf("failed write changed recovery record: found=%v record=%+v err=%v", found, stored, lookupErr)
	}
}

func TestRevokeRetriesPostDeletionMailAndKeepsOrdinaryAbsentRowsNarrow(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	newAbsentApp := func(t *testing.T, rec registry.Record, removeMail func(user.Passwd) error) *App {
		t.Helper()
		a, _, _ := newTestApp(t, "")
		setTestRegistryRecord(t, a, rec)
		lookup := func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
		a.LookupUser = lookup
		a.Users = &user.Manager{LookupUser: lookup, RemoveManagedMail: removeMail}
		a.Scheduler = &schedule.Scheduler{
			SystemdDir: t.TempDir(), InstallPath: t.TempDir() + "/linux-temp-admin",
			UnitPrefix: config.AutoRevokeUnitPrefix, Sys: revokeTestScheduleSystem{},
		}
		return a
	}

	t.Run("deletion-started row retries then releases witness", func(t *testing.T) {
		rec := registry.Record{
			User: "xxvcc-mail1", UID: 1001, Generation: generation, IdentityBound: true,
			DeletionStarted: true, Port: 22,
		}
		wantErr := errors.New("mail spool still busy")
		mailCalls := 0
		a := newAbsentApp(t, rec, func(got user.Passwd) error {
			mailCalls++
			if got.Name != rec.User || got.UID != rec.UID {
				t.Fatalf("mail recovery identity = %+v, want %s/%d", got, rec.User, rec.UID)
			}
			if mailCalls == 1 {
				return wantErr
			}
			return nil
		})
		if rc := a.revokeOptionsLocked(revokeOptions{username: rec.User, yes: true}); rc != 1 {
			t.Fatalf("first recovery revoke rc = %d, want retained failure", rc)
		}
		if present, err := a.Registry.Contains(rec.User); err != nil || !present {
			t.Fatalf("failed mail retry lost registry witness: present=%v err=%v", present, err)
		}
		if rc := a.revokeOptionsLocked(revokeOptions{username: rec.User, yes: true}); rc != 0 {
			t.Fatalf("second recovery revoke rc = %d, want success", rc)
		}
		if present, err := a.Registry.Contains(rec.User); err != nil || present {
			t.Fatalf("successful mail retry retained registry witness: present=%v err=%v", present, err)
		}
		if mailCalls != 2 {
			t.Fatalf("mail recovery calls = %d, want 2", mailCalls)
		}
	})

	t.Run("UID-only row authorizes only absent mail recovery", func(t *testing.T) {
		rec := registry.Record{
			User: "xxvcc-mail2", UID: 1002, DeletionStarted: true, Port: 22,
		}
		mailCalls := 0
		a := newAbsentApp(t, rec, func(got user.Passwd) error {
			mailCalls++
			if got.Name != rec.User || got.UID != rec.UID || got.Home != "" {
				t.Fatalf("UID-only mail recovery identity = %+v", got)
			}
			return nil
		})
		if rc := a.revokeOptionsLocked(revokeOptions{username: rec.User, yes: true}); rc != 0 {
			t.Fatalf("UID-only absent recovery rc = %d, want success", rc)
		}
		if mailCalls != 1 {
			t.Fatalf("UID-only mail recovery calls = %d, want 1", mailCalls)
		}
		if found, err := a.Registry.Contains(rec.User); err != nil || found {
			t.Fatalf("UID-only witness retained after recovery: found=%v err=%v", found, err)
		}
	})

	t.Run("ordinary absent row never authorizes mail deletion", func(t *testing.T) {
		rec := registry.Record{
			User: "xxvcc-stale1", UID: 1001, Generation: generation, IdentityBound: true, Port: 22,
		}
		mailCalls := 0
		a := newAbsentApp(t, rec, func(user.Passwd) error { mailCalls++; return nil })
		if rc := a.revokeOptionsLocked(revokeOptions{username: rec.User, yes: true}); rc != 0 {
			t.Fatalf("ordinary stale-row cleanup rc = %d, want success", rc)
		}
		if mailCalls != 0 {
			t.Fatalf("ordinary absent row authorized %d mail cleanup call(s)", mailCalls)
		}
	})
}

func TestUIDOnlyPendingRollbackRequiresInteractiveRecovery(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-pending1", UID: 1001, GID: 1001,
		GECOS: config.PendingGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-pending1", Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: pw.Name, UID: pw.UID, Generation: generation, IdentityBound: true,
		Pending: true, DeletionStarted: true, Port: 22,
	}
	events := []string{}
	present := true
	lookup := func(string) (user.Passwd, bool, error) {
		if !present {
			return user.Passwd{}, false, nil
		}
		return pw, true, nil
	}
	a, _, _ := newTestApp(t, "")
	a.Users = &user.Manager{
		Runner:              &orderedTeardownRunner{events: &events, present: &present},
		LookupUser:          lookup,
		RemoveManagedMail:   func(user.Passwd) error { events = append(events, "mail"); return nil },
		RemoveManagedHome:   func(user.Passwd) error { events = append(events, "home"); return nil },
		ValidateManagedHome: func(user.Passwd) error { return nil },
	}
	a.LookupUser = lookup
	a.TerminateProcesses = func(int) error { events = append(events, "kill"); return nil }
	a.ClearScheduledJobs = func(string, int) error { events = append(events, "clear"); return nil }
	a.DrainScheduledJobs = func() error { events = append(events, "drain"); return nil }
	cancelCalls := 0
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: t.TempDir() + "/linux-temp-admin",
		UnitPrefix: config.AutoRevokeUnitPrefix, Sys: revokeTestScheduleSystem{removeAtCalls: &cancelCalls},
	}
	setTestRegistryRecord(t, a, rec)

	if rc := a.revokeOptionsLocked(revokeOptions{username: rec.User, yes: true, force: true}); rc != 1 {
		t.Fatalf("unattended pending rollback recovery rc = %d, want refusal", rc)
	}
	if !present {
		t.Fatal("unattended recovery deleted a live UID-only account")
	}
	if strings.Contains(strings.Join(events, ","), "userdel") {
		t.Fatalf("unattended recovery reached userdel: %v", events)
	}
	if cancelCalls != 1 {
		t.Fatalf("unattended UID-only recovery cancelled %d auto-delete tasks, want 1", cancelCalls)
	}
	if rc := a.revokeOptionsLocked(revokeOptions{
		username: rec.User, force: true, manualInvocation: true, liveConfirmed: true,
	}); rc != 1 {
		t.Fatalf("non-TTY full-name recovery rc = %d, want refusal", rc)
	}
	if !present || strings.Contains(strings.Join(events, ","), "userdel") {
		t.Fatalf("non-TTY recovery reached userdel: present=%v events=%v", present, events)
	}

	a.StdinIsTTY = func() bool { return true }
	if rc := a.revokeOptionsLocked(revokeOptions{
		username: rec.User, force: true, manualInvocation: true, liveConfirmed: true,
	}); rc != 0 {
		t.Fatalf("interactive pending rollback recovery rc = %d, want success", rc)
	}
	if present {
		t.Fatal("pending account survived deletion-started rollback recovery")
	}
	if found, err := a.Registry.Contains(rec.User); err != nil || found {
		t.Fatalf("pending recovery registry state: found=%v err=%v", found, err)
	}
	if !strings.Contains(strings.Join(events, ","), "userdel") {
		t.Fatalf("pending recovery never reached userdel: %v", events)
	}
}

func TestInteractiveUIDOnlyRecoveryRejectsSameUIDPasswdReplacement(t *testing.T) {
	const (
		name       = "xxvcc-replaced1"
		generation = "0123456789abcdef0123456789abcdef"
	)
	original := user.Passwd{
		Name: name, UID: 1001, GID: 1001,
		GECOS: config.PendingGenerationGECOSPrefix + generation,
		Home:  "/home/" + name, Shell: "/bin/sh",
	}
	replacement := original
	replacement.GECOS = config.ManagedGenerationGECOSPrefix + generation
	replacement.Shell = "/bin/bash"

	a, _, _ := newTestApp(t, "")
	a.StdinIsTTY = func() bool { return true }
	setTestRegistryRecord(t, a, registry.Record{
		User: name, UID: original.UID, DeletionStarted: true, Port: 22,
	})
	lookups := 0
	a.LookupUser = func(string) (user.Passwd, bool, error) {
		lookups++
		if lookups == 1 {
			return original, true, nil
		}
		return replacement, true, nil
	}
	runner := &revokeRunner{}
	a.Users = &user.Manager{Runner: runner}
	a.TerminateProcesses = func(int) error {
		t.Fatal("same-UID replacement reached process termination")
		return nil
	}

	if rc := a.revokeOptionsLocked(revokeOptions{
		username: name, force: true, manualInvocation: true, liveConfirmed: true,
	}); rc != 1 {
		t.Fatalf("same-UID replacement revoke rc = %d, want refusal", rc)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("same-UID replacement reached account helpers: %v", runner.calls)
	}
	if found, err := a.Registry.Contains(name); err != nil || !found {
		t.Fatalf("same-UID replacement lost recovery witness: found=%v err=%v", found, err)
	}
}

func TestCompactPreservesDeletionStartedRecoveryRow(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	rec := registry.Record{
		User: "xxvcc-compact1", UID: 1001, Generation: generation, IdentityBound: true,
		DeletionStarted: true, Port: 22,
	}
	a, _, _ := newTestApp(t, "")
	setTestRegistryRecord(t, a, rec)
	if rc := a.compactLocked(); rc != 0 {
		t.Fatalf("compact rc = %d, want success with retained recovery row", rc)
	}
	stored, found, err := a.Registry.Lookup(rec.User)
	if err != nil || !found || !stored.DeletionStarted {
		t.Fatalf("compact lost deletion recovery row: found=%v record=%+v err=%v", found, stored, err)
	}
}

func TestAutoRevokeRetentionSeparatesRetryableAndManualRecovery(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	boundPW := user.Passwd{
		Name: "xxvcc-timer1", UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-timer1", Shell: "/bin/sh",
	}
	legacyPW := boundPW
	legacyPW.GECOS = config.ManagedGECOS
	for _, tc := range []struct {
		name   string
		rec    registry.Record
		pw     user.Passwd
		exists bool
		want   bool
	}{
		{
			name: "legacy identity cancels unattended timer",
			rec: registry.Record{
				User: boundPW.Name, UID: boundPW.UID, AutoRevoke: true,
				AutoUnit: "linux-temp-admin-revoke-xxvcc-timer1", Port: 22,
			},
			pw: legacyPW, exists: true, want: false,
		},
		{
			name: "absent UID-only witness keeps retry timer",
			rec:  registry.Record{User: boundPW.Name, UID: boundPW.UID, DeletionStarted: true, Port: 22},
			want: true,
		},
		{
			name: "live UID-only witness cancels unattended timer",
			rec:  registry.Record{User: boundPW.Name, UID: boundPW.UID, DeletionStarted: true, Port: 22},
			pw:   boundPW, exists: true, want: false,
		},
		{
			name: "live exact bound witness keeps retry timer",
			rec: registry.Record{
				User: boundPW.Name, UID: boundPW.UID, Generation: generation,
				IdentityBound: true, DeletionStarted: true, Port: 22,
			},
			pw: boundPW, exists: true, want: true,
		},
		{
			name: "live mismatched bound witness cancels unattended timer",
			rec: registry.Record{
				User: boundPW.Name, UID: boundPW.UID, Generation: generation,
				IdentityBound: true, DeletionStarted: true, Port: 22,
			},
			pw: func() user.Passwd {
				pw := boundPW
				pw.GECOS = config.ManagedGenerationGECOSPrefix + "fedcba9876543210fedcba9876543210"
				return pw
			}(),
			exists: true, want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := newTestApp(t, "")
			setTestRegistryRecord(t, a, tc.rec)
			a.LookupUser = func(string) (user.Passwd, bool, error) { return tc.pw, tc.exists, nil }
			got, err := a.accountNeedsAutoRevoke(tc.rec.User)
			if err != nil || got != tc.want {
				t.Fatalf("accountNeedsAutoRevoke = %v, err=%v, want %v", got, err, tc.want)
			}
		})
	}
}

func TestFinalScheduledAccountCheckClearsWorkQueuedBeforeTerminationCompletes(t *testing.T) {
	pw := user.Passwd{Name: "xxvcc-a1", UID: 1001, GID: 1001, Home: "/home/xxvcc-a1", Shell: "/bin/sh"}
	queued := false
	a := &App{
		LookupUser: func(string) (user.Passwd, bool, error) { return pw, true, nil },
		TerminateProcesses: func(int) error {
			queued = true
			return nil
		},
		ClearScheduledJobs: func(string, int) error {
			if !queued {
				t.Fatal("scheduled-job inventory ran before process termination completed")
			}
			queued = false
			return nil
		},
	}

	if err := a.finalScheduledAccountCheck(pw.Name, pw); err != nil {
		t.Fatal(err)
	}
	if queued {
		t.Fatal("work queued by a dying process survived the final inventory")
	}
}
