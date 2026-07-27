package schedule

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeSystem struct {
	hasSystemctl bool
	hasAt        bool
	calls        [][]string
	atCommand    string
	atHours      int
	atID         string
	removedFor   []string
	atrmd        []string
	atJobs       []AtJob
	removeAtErr  error
	atrmErr      error
	atJobsErr    error
	systemctlErr func(args ...string) error
}

func (f *fakeSystem) HasSystemctl() bool { return f.hasSystemctl }
func (f *fakeSystem) HasAt() bool        { return f.hasAt }
func (f *fakeSystem) Systemctl(args ...string) error {
	f.calls = append(f.calls, args)
	if f.systemctlErr != nil {
		return f.systemctlErr(args...)
	}
	return nil
}
func (f *fakeSystem) ScheduleAt(command string, hours int) (string, error) {
	f.atCommand, f.atHours = command, hours
	return f.atID, nil
}
func (f *fakeSystem) RemoveAtJobsFor(command string) error {
	f.removedFor = append(f.removedFor, command)
	return f.removeAtErr
}
func (f *fakeSystem) AtrmJob(id string) error  { f.atrmd = append(f.atrmd, id); return f.atrmErr }
func (f *fakeSystem) AtJobs() ([]AtJob, error) { return f.atJobs, f.atJobsErr }

func newScheduler(dir string, sys System) *Scheduler {
	return &Scheduler{
		SystemdDir:           dir,
		SystemdTimerStateDir: filepath.Join(dir, "timer-state"),
		InstallPath:          "/usr/local/sbin/linux-temp-admin",
		UnitPrefix:           "linux-temp-admin-v2-revoke-",
		Now:                  func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) },
		Sys:                  sys,
	}
}

func TestOnCalendarAndNames(t *testing.T) {
	if got := OnCalendar(time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC), 24); got != "2026-07-08 12:00:00 UTC" {
		t.Errorf("OnCalendar = %q", got)
	}
	s := newScheduler("/x", &fakeSystem{})
	if got := s.UnitName("xxvcc-a1"); got != "linux-temp-admin-v2-revoke-xxvcc-a1" {
		t.Errorf("UnitName = %q", got)
	}
	if got := s.RevokeCommand("xxvcc-a1", 1001, "0123456789abcdef0123456789abcdef"); got != "/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef" {
		t.Errorf("RevokeCommand = %q", got)
	}
}

func TestUnitContents(t *testing.T) {
	s := newScheduler("/x", &fakeSystem{})
	svc := s.serviceContent("xxvcc-a1", 1001, "0123456789abcdef0123456789abcdef")
	for _, want := range []string{"Type=oneshot", "NoNewPrivileges=yes", "User=root",
		"Restart=on-failure", "--expected-uid 1001", "--generation 0123456789abcdef0123456789abcdef",
		"ExecStart=/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %q:\n%s", want, svc)
		}
	}
	tmr := timerContent("linux-temp-admin-v2-revoke-xxvcc-a1", "2026-07-08 12:00:00 UTC")
	for _, want := range []string{"OnCalendar=2026-07-08 12:00:00 UTC", "Persistent=true",
		"Unit=linux-temp-admin-v2-revoke-xxvcc-a1.service", "WantedBy=timers.target"} {
		if !strings.Contains(tmr, want) {
			t.Errorf("timer missing %q:\n%s", want, tmr)
		}
	}
}

func TestScheduleFallsBackToAt(t *testing.T) {
	sys := &fakeSystem{hasSystemctl: false, hasAt: true, atID: "42"}
	s := newScheduler(t.TempDir(), sys)
	unit, err := s.Schedule("xxvcc-a1", 1001, "0123456789abcdef0123456789abcdef", 6)
	if err != nil {
		t.Fatal(err)
	}
	if unit != "at:42" {
		t.Errorf("unit = %q, want at:42", unit)
	}
	if sys.atCommand != s.RevokeCommand("xxvcc-a1", 1001, "0123456789abcdef0123456789abcdef") || sys.atHours != 6 {
		t.Errorf("ScheduleAt got %q, %d", sys.atCommand, sys.atHours)
	}
	// The queued command carries --force --confirm-force so a lost registry row at
	// expiry cannot make the unattended revoke refuse the account.
	if !strings.Contains(sys.atCommand, "--force --confirm-force xxvcc-a1") {
		t.Errorf("at command lacks the force tokens: %q", sys.atCommand)
	}
}

func TestScheduleNoBackend(t *testing.T) {
	s := newScheduler(t.TempDir(), &fakeSystem{})
	if _, err := s.Schedule("xxvcc-a1", 1001, "0123456789abcdef0123456789abcdef", 6); err == nil {
		t.Fatal("expected error when no systemctl or at")
	}
}

func TestScheduleRejectsReservedLinuxUIDBeforeMutation(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot represent the reserved uint32 uid sentinel")
	}
	sys := &fakeSystem{hasSystemctl: true, hasAt: true, atID: "42"}
	s := newScheduler(t.TempDir(), sys)
	reserved := int(uint64(^uint32(0)))
	if _, err := s.Schedule("xxvcc-a1", reserved, testGeneration, 6); err == nil || !strings.Contains(err.Error(), "invalid Linux account UID") {
		t.Fatalf("Schedule reserved UID error = %v, want range refusal", err)
	}
	if len(sys.calls) != 0 || sys.atCommand != "" {
		t.Fatalf("Schedule mutated a backend before rejecting UID: systemctl=%v at=%q", sys.calls, sys.atCommand)
	}
}

func TestScheduleRejectsInvalidIdentityAndLifetimeBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		user       string
		generation string
		hours      int
	}{
		{name: "username", user: "bad user", generation: testGeneration, hours: 1},
		{name: "generation", user: "xxvcc-a1", generation: "bad", hours: 1},
		{name: "zero hours", user: "xxvcc-a1", generation: testGeneration, hours: 0},
		{name: "excessive hours", user: "xxvcc-a1", generation: testGeneration, hours: 24*366 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys := &fakeSystem{hasSystemctl: true, hasAt: true}
			s := &Scheduler{SystemdDir: t.TempDir(), InstallPath: "/usr/local/sbin/linux-temp-admin", UnitPrefix: "lta-", Now: time.Now, Sys: sys}
			if _, err := s.Schedule(tc.user, 1001, tc.generation, tc.hours); err == nil {
				t.Fatal("Schedule accepted invalid input")
			}
			if len(sys.calls) != 0 || sys.atCommand != "" {
				t.Fatalf("invalid input reached scheduler backend: calls=%v at=%q", sys.calls, sys.atCommand)
			}
			if entries, err := os.ReadDir(s.SystemdDir); err != nil || len(entries) != 0 {
				t.Fatalf("invalid input changed systemd directory: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestScheduleRollsBackPartiallyEnabledSystemdTimerBeforeAtFallback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("systemd schedule rollback requires root-owned fixtures")
	}
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true, hasAt: true, atID: "42"}
	sys.systemctlErr = func(args ...string) error {
		if len(args) == 3 && args[0] == "enable" {
			return errors.New("enable failed after starting timer")
		}
		return nil
	}
	s := newScheduler(dir, sys)
	if err := os.Mkdir(s.SystemdTimerStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unit := s.UnitName("xxvcc-a1")
	stamp := filepath.Join(s.SystemdTimerStateDir, "stamp-"+unit+".timer")
	if err := os.WriteFile(stamp, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := s.Schedule("xxvcc-a1", 1001, "0123456789abcdef0123456789abcdef", 6)
	if err != nil {
		t.Fatal(err)
	}
	if got != "at:42" {
		t.Fatalf("Schedule = %q, want at fallback", got)
	}
	wantCalls := []string{
		"daemon-reload",
		"enable --now " + unit + ".timer",
		"disable --now " + unit + ".timer",
		"daemon-reload",
	}
	if gotCalls := joinedSystemctlCalls(sys.calls); strings.Join(gotCalls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("systemctl calls = %v, want %v", gotCalls, wantCalls)
	}
	for _, suffix := range []string{".service", ".timer"} {
		if _, statErr := os.Lstat(filepath.Join(dir, unit+suffix)); !os.IsNotExist(statErr) {
			t.Errorf("%s survived rollback", suffix)
		}
	}
	if _, statErr := os.Lstat(stamp); !os.IsNotExist(statErr) {
		t.Errorf("persistent timer timestamp survived rollback: %v", statErr)
	}
}

func TestScheduleDoesNotFallbackWhenSystemdRollbackFails(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("systemd schedule rollback requires root-owned fixtures")
	}
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true, hasAt: true, atID: "42"}
	sys.systemctlErr = func(args ...string) error {
		if len(args) == 3 && args[0] == "enable" {
			return errors.New("enable failed after starting timer")
		}
		if len(args) == 3 && args[0] == "disable" {
			return errors.New("rollback disable failed")
		}
		return nil
	}
	s := newScheduler(dir, sys)

	_, err := s.Schedule("xxvcc-a1", 1001, "0123456789abcdef0123456789abcdef", 6)
	if err == nil || !strings.Contains(err.Error(), "enable failed") || !strings.Contains(err.Error(), "rollback disable failed") {
		t.Fatalf("Schedule error = %v, want original and rollback failures", err)
	}
	if sys.atCommand != "" {
		t.Fatalf("unsafe at fallback was attempted after incomplete rollback: %q", sys.atCommand)
	}
	unit := s.UnitName("xxvcc-a1")
	for _, suffix := range []string{".service", ".timer"} {
		if _, statErr := os.Lstat(filepath.Join(dir, unit+suffix)); statErr != nil {
			t.Errorf("%s was removed after rollback could not stop the timer: %v", suffix, statErr)
		}
	}
}

func joinedSystemctlCalls(calls [][]string) []string {
	joined := make([]string, 0, len(calls))
	for _, call := range calls {
		joined = append(joined, strings.Join(call, " "))
	}
	return joined
}

func TestCancelCleansBothAndRemovesUnits(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	unit := s.UnitName("xxvcc-a1")
	svc := filepath.Join(dir, unit+".service")
	tmr := filepath.Join(dir, unit+".timer")
	if err := os.Mkdir(s.SystemdTimerStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stamp := filepath.Join(s.SystemdTimerStateDir, "stamp-"+unit+".timer")
	os.WriteFile(svc, []byte("x"), 0o644)
	os.WriteFile(tmr, []byte("x"), 0o644)
	os.WriteFile(stamp, nil, 0o644)

	if err := s.Cancel("xxvcc-a1", ""); err != nil {
		t.Fatal(err)
	}

	// The sweep matches on the stable "--yes" prefix, so it still finds an at job
	// queued by an OLDER version whose body has no --force tokens.
	needle := sys.removedFor[0]
	if len(sys.removedFor) != 1 || needle != "/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes" {
		t.Errorf("RemoveAtJobsFor = %v", sys.removedFor)
	}
	if strings.Contains(needle, "--force") {
		t.Errorf("at-sweep needle must not include --force (old jobs lack it): %q", needle)
	}
	if _, err := os.Lstat(svc); !os.IsNotExist(err) {
		t.Error("service file should be removed")
	}
	if _, err := os.Lstat(tmr); !os.IsNotExist(err) {
		t.Error("timer file should be removed")
	}
	if _, err := os.Lstat(stamp); !os.IsNotExist(err) {
		t.Error("persistent timer timestamp should be removed")
	}
	// systemctl disable + reset-failed + daemon-reload were invoked
	var seen []string
	for _, c := range sys.calls {
		seen = append(seen, c[0])
	}
	joined := strings.Join(seen, ",")
	for _, want := range []string{"disable", "reset-failed", "daemon-reload"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing systemctl %q; calls=%v", want, sys.calls)
		}
	}
}

func TestCancelUnlinksSystemdTimerStampSymlinkWithoutFollowingIt(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	if err := os.Mkdir(s.SystemdTimerStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unit := s.UnitName("xxvcc-a1")
	target := filepath.Join(dir, "must-survive")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := filepath.Join(s.SystemdTimerStateDir, "stamp-"+unit+".timer")
	if err := os.Symlink(target, stamp); err != nil {
		t.Fatal(err)
	}

	if err := s.Cancel("xxvcc-a1", unit); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stamp); !os.IsNotExist(err) {
		t.Fatalf("timer timestamp symlink survived cancellation: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep" {
		t.Fatalf("timer timestamp target changed: content=%q err=%v", got, err)
	}
}

func TestCleanupTimerStampsRemovesManagedNamespacesOnly(t *testing.T) {
	dir := t.TempDir()
	s := newScheduler(dir, &fakeSystem{})
	s.LegacyUnitPrefixes = []string{"linux-temp-admin-revoke-"}
	if err := os.Mkdir(s.SystemdTimerStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := []string{
		"stamp-linux-temp-admin-v2-revoke-oldgone.timer",
		"stamp-linux-temp-admin-revoke-oldergone.timer",
		// Corrupt names in the owned namespace still belong to the old install and
		// must not become permanent residue.
		"stamp-linux-temp-admin-v2-revoke-bad$name.timer",
	}
	unrelated := []string{
		"stamp-apt-daily.timer",
		"stamp-linux-temp-admin-v2-revoke-.timer",
		"linux-temp-admin-v2-revoke-no-stamp-prefix.timer",
		"stamp-linux-temp-admin-v2-revoke-wrong.service",
	}
	for _, name := range append(append([]string(nil), managed...), unrelated...) {
		if err := os.WriteFile(filepath.Join(s.SystemdTimerStateDir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.CleanupTimerStamps(); err != nil {
		t.Fatal(err)
	}
	for _, name := range managed {
		if _, err := os.Lstat(filepath.Join(s.SystemdTimerStateDir, name)); !os.IsNotExist(err) {
			t.Errorf("managed timestamp survived cleanup: %s", name)
		}
	}
	for _, name := range unrelated {
		if _, err := os.Lstat(filepath.Join(s.SystemdTimerStateDir, name)); err != nil {
			t.Errorf("unrelated timestamp was removed: %s: %v", name, err)
		}
	}
}

func TestCleanupTimerStampsRejectsUnsafeStateDirectory(t *testing.T) {
	s := newScheduler(t.TempDir(), &fakeSystem{})
	for _, path := range []string{"relative", "/"} {
		s.SystemdTimerStateDir = path
		if err := s.CleanupTimerStamps(); err == nil || !strings.Contains(err.Error(), "unsafe systemd timer state directory") {
			t.Errorf("CleanupTimerStamps(%q) error = %v, want unsafe-path refusal", path, err)
		}
	}
}

func TestCancelTreatsMissingTimerAsSuccessWhenOnlyServiceRemains(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	unit := s.UnitName("xxvcc-a1")
	servicePath := filepath.Join(dir, unit+".service")
	if err := os.WriteFile(servicePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sys.systemctlErr = func(args ...string) error {
		if len(args) == 3 && args[0] == "disable" {
			return &systemctlError{
				args:   append([]string(nil), args...),
				err:    errors.New("exit status 1"),
				output: "Failed to disable unit: Unit file " + unit + ".timer does not exist.",
			}
		}
		return nil
	}

	if err := s.Cancel("xxvcc-a1", ""); err != nil {
		t.Fatalf("missing timer should be idempotent success: %v", err)
	}
	if _, err := os.Lstat(servicePath); !os.IsNotExist(err) {
		t.Error("service-only orphan should be removed")
	}
	if !calledSystemctl(sys.calls, "daemon-reload") {
		t.Errorf("removing the service must reload systemd; calls=%v", sys.calls)
	}
}

func TestCancelStillReportsNonMissingTimerFailure(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	unit := s.UnitName("xxvcc-a1")
	servicePath := filepath.Join(dir, unit+".service")
	if err := os.WriteFile(servicePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sys.systemctlErr = func(args ...string) error {
		if len(args) == 3 && args[0] == "disable" {
			return &systemctlError{
				args:   append([]string(nil), args...),
				err:    errors.New("exit status 1"),
				output: "Failed to connect to bus: Permission denied",
			}
		}
		return nil
	}

	err := s.Cancel("xxvcc-a1", "")
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("Cancel error = %v, want the real systemctl failure", err)
	}
	if _, err := os.Lstat(servicePath); err != nil {
		t.Error("cleanup must preserve the service as retry evidence after a systemctl failure")
	}
}

func TestCancelReportsStopFailureEvenWithoutUnitFiles(t *testing.T) {
	sys := &fakeSystem{hasSystemctl: true}
	sys.systemctlErr = func(args ...string) error {
		if len(args) == 3 && args[0] == "disable" {
			return &systemctlError{args: append([]string(nil), args...), err: errors.New("exit status 1"), output: "Failed to connect to bus: Permission denied"}
		}
		return nil
	}
	s := newScheduler(t.TempDir(), sys)
	err := s.Cancel("xxvcc-a1", "")
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("Cancel error = %v, want an in-memory timer stop failure", err)
	}
}

func TestCancelPreservesSystemdEvidenceWhenSystemctlIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: false}
	s := newScheduler(dir, sys)
	unit := s.UnitName("xxvcc-a1")
	for _, suffix := range []string{".service", ".timer"} {
		if err := os.WriteFile(filepath.Join(dir, unit+suffix), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	err := s.Cancel("xxvcc-a1", unit)
	if err == nil || !strings.Contains(err.Error(), "systemctl is unavailable") {
		t.Fatalf("Cancel error = %v, want inability to prove the timer stopped", err)
	}
	for _, suffix := range []string{".service", ".timer"} {
		if _, statErr := os.Lstat(filepath.Join(dir, unit+suffix)); statErr != nil {
			t.Errorf("%s was removed without stopping systemd: %v", suffix, statErr)
		}
	}
}

func TestCancelKeepsRecordedSystemdTaskWithoutFilesWhenSystemctlIsUnavailable(t *testing.T) {
	sys := &fakeSystem{hasSystemctl: false}
	s := newScheduler(t.TempDir(), sys)
	unit := s.UnitName("xxvcc-a1")

	if err := s.Cancel("xxvcc-a1", unit); err == nil || !strings.Contains(err.Error(), "systemctl is unavailable") {
		t.Fatalf("Cancel error = %v, want recorded in-memory timer uncertainty", err)
	}
}

func calledSystemctl(calls [][]string, command string) bool {
	for _, call := range calls {
		if len(call) > 0 && call[0] == command {
			return true
		}
	}
	return false
}

func TestCancelPropagatesAtRemovalFailure(t *testing.T) {
	sys := &fakeSystem{removeAtErr: errors.New("atq failed")}
	s := newScheduler(t.TempDir(), sys)
	if err := s.Cancel("xxvcc-a1", ""); err == nil || !strings.Contains(err.Error(), "atq failed") {
		t.Fatalf("Cancel error = %v, want at removal failure", err)
	}
}

// TestCancelUnderFiringServiceRemovesBothFiles pins the successful firing path:
// the unit is already loaded, so unlinking its configuration and reloading does
// not stop the oneshot process and avoids a permanent orphaned .service.
func TestCancelUnderFiringServiceRemovesBothFiles(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	t.Setenv("INVOCATION_ID", "test-firing-service")
	unit := s.UnitName("xxvcc-a1")
	svc := filepath.Join(dir, unit+".service")
	tmr := filepath.Join(dir, unit+".timer")
	os.WriteFile(svc, []byte("x"), 0o644)
	os.WriteFile(tmr, []byte("x"), 0o644)

	if err := s.Cancel("xxvcc-a1", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(tmr); !os.IsNotExist(err) {
		t.Error("timer file should still be removed under the firing service")
	}
	if _, err := os.Lstat(svc); !os.IsNotExist(err) {
		t.Error("service file should be removed under the firing service")
	}
	var seen []string
	for _, c := range sys.calls {
		seen = append(seen, c[0])
	}
	joined := strings.Join(seen, ",")
	if !strings.Contains(joined, "disable") || !strings.Contains(joined, "reset-failed") {
		t.Errorf("expected disable + reset-failed even under the firing service; calls=%v", sys.calls)
	}
	if !strings.Contains(joined, "daemon-reload") {
		t.Errorf("daemon-reload must run after firing-service cleanup; calls=%v", sys.calls)
	}
}

func TestParseAtJobID(t *testing.T) {
	cases := map[string]string{
		"job 7 at Wed Jul  8 12:00:00 2026":                 "7",
		"warning: commands will be executed\njob 12 at ...": "12",
		"9\tWed Jul 8":   "9",
		"job -1 at ...":  "",
		"nothing useful": "",
	}
	for in, want := range cases {
		if got := parseAtJobID(in); got != want {
			t.Errorf("parseAtJobID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCancelRemovesLegacyUnitsToo pins the fix for a v1 timer surviving an
// uninstall. v1's units carry no "-v2-" infix and v1's install path was identical
// to v2's, so a v1 timer left enabled fires this binary; if Cancel disables only
// the v2 name, an uninstall that removes the binary strands it — a timer that
// fails forever, the exact footgun the uninstall exists to close.
func TestCancelRemovesLegacyUnitsToo(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := &Scheduler{
		SystemdDir: dir, InstallPath: "/usr/local/sbin/linux-temp-admin",
		UnitPrefix: "linux-temp-admin-v2-revoke-", LegacyUnitPrefixes: []string{"linux-temp-admin-revoke-"},
		Now: func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) }, Sys: sys,
	}
	v1timer := filepath.Join(dir, "linux-temp-admin-revoke-oldu.timer")
	v1svc := filepath.Join(dir, "linux-temp-admin-revoke-oldu.service")
	for _, p := range []string{v1timer, v1svc} {
		if err := os.WriteFile(p, []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.Cancel("oldu", ""); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{v1timer, v1svc} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived Cancel", filepath.Base(p))
		}
	}
	// It must also have been disabled by its v1 name, not just unlinked, or a
	// timers.target.wants symlink lingers.
	var disabled bool
	for _, call := range sys.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "disable") && strings.Contains(joined, "linux-temp-admin-revoke-oldu.timer") {
			disabled = true
		}
	}
	if !disabled {
		t.Errorf("the v1 timer was never disabled; systemctl calls: %v", sys.calls)
	}
}
