package schedule

import (
	"errors"
	"os"
	"path/filepath"
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
}

func (f *fakeSystem) HasSystemctl() bool { return f.hasSystemctl }
func (f *fakeSystem) HasAt() bool        { return f.hasAt }
func (f *fakeSystem) Systemctl(args ...string) error {
	f.calls = append(f.calls, args)
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
		SystemdDir:  dir,
		InstallPath: "/usr/local/sbin/linux-temp-admin",
		UnitPrefix:  "linux-temp-admin-v2-revoke-",
		Now:         func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) },
		Sys:         sys,
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

func TestCancelCleansBothAndRemovesUnits(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	s.UnderUnit = func(string) bool { return false } // not the firing service -> full cleanup
	unit := s.UnitName("xxvcc-a1")
	svc := filepath.Join(dir, unit+".service")
	tmr := filepath.Join(dir, unit+".timer")
	os.WriteFile(svc, []byte("x"), 0o644)
	os.WriteFile(tmr, []byte("x"), 0o644)

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

func TestCancelPropagatesAtRemovalFailure(t *testing.T) {
	sys := &fakeSystem{removeAtErr: errors.New("atq failed")}
	s := newScheduler(t.TempDir(), sys)
	if err := s.Cancel("xxvcc-a1", ""); err == nil || !strings.Contains(err.Error(), "atq failed") {
		t.Fatalf("Cancel error = %v, want at removal failure", err)
	}
}

// TestCancelUnderFiringServiceLeavesServiceFile documents the INVOCATION_ID guard:
// when Cancel runs inside the firing systemd service, it still disables the timer
// and removes the .timer file, but leaves its own .service file and skips
// daemon-reload so the currently-executing unit is not disturbed.
func TestCancelUnderFiringServiceLeavesServiceFile(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	s.UnderUnit = func(string) bool { return true } // simulate running as the firing service
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
	if _, err := os.Lstat(svc); err != nil {
		t.Error("service file should be left in place under the firing service")
	}
	var seen []string
	for _, c := range sys.calls {
		seen = append(seen, c[0])
	}
	joined := strings.Join(seen, ",")
	if !strings.Contains(joined, "disable") || !strings.Contains(joined, "reset-failed") {
		t.Errorf("expected disable + reset-failed even under the firing service; calls=%v", sys.calls)
	}
	if strings.Contains(joined, "daemon-reload") {
		t.Errorf("daemon-reload must be skipped under the firing service; calls=%v", sys.calls)
	}
}

func TestParseAtJobID(t *testing.T) {
	cases := map[string]string{
		"job 7 at Wed Jul  8 12:00:00 2026":                 "7",
		"warning: commands will be executed\njob 12 at ...": "12",
		"9\tWed Jul 8":   "9",
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
