package schedule

import (
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
func (f *fakeSystem) RemoveAtJobsFor(command string) { f.removedFor = append(f.removedFor, command) }

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
	if got := s.RevokeCommand("xxvcc-a1"); got != "/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes" {
		t.Errorf("RevokeCommand = %q", got)
	}
}

func TestUnitContents(t *testing.T) {
	s := newScheduler("/x", &fakeSystem{})
	svc := s.serviceContent("xxvcc-a1")
	for _, want := range []string{"Type=oneshot", "NoNewPrivileges=yes", "User=root",
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
	unit, err := s.Schedule("xxvcc-a1", 6)
	if err != nil {
		t.Fatal(err)
	}
	if unit != "at:42" {
		t.Errorf("unit = %q, want at:42", unit)
	}
	if sys.atCommand != "/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes" || sys.atHours != 6 {
		t.Errorf("ScheduleAt got %q, %d", sys.atCommand, sys.atHours)
	}
}

func TestScheduleNoBackend(t *testing.T) {
	s := newScheduler(t.TempDir(), &fakeSystem{})
	if _, err := s.Schedule("xxvcc-a1", 6); err == nil {
		t.Fatal("expected error when no systemctl or at")
	}
}

func TestCancelCleansBothAndRemovesUnits(t *testing.T) {
	dir := t.TempDir()
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)
	unit := s.UnitName("xxvcc-a1")
	svc := filepath.Join(dir, unit+".service")
	tmr := filepath.Join(dir, unit+".timer")
	os.WriteFile(svc, []byte("x"), 0o644)
	os.WriteFile(tmr, []byte("x"), 0o644)

	s.Cancel("xxvcc-a1")

	if len(sys.removedFor) != 1 || sys.removedFor[0] != s.RevokeCommand("xxvcc-a1") {
		t.Errorf("RemoveAtJobsFor = %v", sys.removedFor)
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
