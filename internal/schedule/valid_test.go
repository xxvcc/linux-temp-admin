package schedule

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"golang.org/x/sys/unix"
)

const testGeneration = "0123456789abcdef0123456789abcdef"

var validTestDeadline = time.Date(2026, 7, 7, 13, 0, 0, 0, time.UTC)

func TestValidScheduleAcceptsExactCurrentAtJob(t *testing.T) {
	sys := &fakeSystem{}
	s := newScheduler(t.TempDir(), sys)
	sys.atJobs = []AtJob{
		{ID: "41", Body: s.RevokeCommand("xxvcc-a1", 1001, testGeneration) + "\n"},
		{ID: "42", Body: "SHELL=/bin/sh\n" + s.RevokeCommand("xxvcc-a1", 1001, testGeneration) + "\n", ScheduledAt: validTestDeadline},
	}

	valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:42", validTestDeadline)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("exact queued at job was reported invalid")
	}
}

func TestReadScheduleFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schedule.timer")
	if err := unix.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	content, valid, err := readScheduleFile(path)
	if err != nil || valid || content != nil {
		t.Fatalf("FIFO schedule read = %q, valid=%v, err=%v; want rejected special file", content, valid, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("FIFO schedule read blocked for %s", elapsed)
	}
}

func TestValidScheduleRejectsReservedLinuxUID(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot represent the reserved uint32 uid sentinel")
	}
	sys := &fakeSystem{atJobsErr: errors.New("must not inventory")}
	s := newScheduler(t.TempDir(), sys)
	reservedKernelID := uint64(^uint32(0))
	valid, err := s.ValidSchedule("xxvcc-a1", int(reservedKernelID), testGeneration, "at:42", validTestDeadline)
	if err != nil || valid {
		t.Fatalf("ValidSchedule reserved UID = %v, %v; want false, nil", valid, err)
	}
}

func TestValidScheduleRejectsWrongAtIdentityAndPropagatesInventoryError(t *testing.T) {
	sys := &fakeSystem{}
	s := newScheduler(t.TempDir(), sys)
	sys.atJobs = []AtJob{{ID: "42", Body: s.RevokeCommand("xxvcc-a1", 1002, testGeneration) + "\n"}}

	valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:42", validTestDeadline)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("at job for the wrong UID was accepted")
	}

	sys.atJobsErr = errors.New("atq failed")
	if _, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:42", validTestDeadline); err == nil || !strings.Contains(err.Error(), "atq failed") {
		t.Fatalf("ValidSchedule error = %v, want inventory failure", err)
	}
}

func TestValidScheduleAtJobRequiresSystemBackend(t *testing.T) {
	s := newScheduler(t.TempDir(), nil)
	valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:42", validTestDeadline)
	if err == nil || valid || !strings.Contains(err.Error(), "no system backend") {
		t.Fatalf("ValidSchedule = %v, %v; want bounded backend error", valid, err)
	}
}

func TestValidScheduleAcceptsExactRootOwnedSystemdPair(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("valid systemd schedule files must be root-owned")
	}
	dir := t.TempDir()
	s := newScheduler(dir, &fakeSystem{})
	unit := s.UnitName("xxvcc-a1")
	writeSchedulePair(t, s, "xxvcc-a1", 1001, testGeneration, s.Now().Add(time.Hour))

	valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, unit, validTestDeadline)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("exact root-owned systemd pair was reported invalid")
	}
}

func TestValidQuarantineRequiresExactNamespaceIdentityAndDeadline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("valid systemd schedule files must be root-owned")
	}
	dir := t.TempDir()
	sys := &fakeSystem{}
	s := newScheduler(dir, sys)
	deadline := s.Now().Add(2 * time.Minute)
	q := *s
	q.UnitPrefix = config.QuarantineUnitPrefix
	writeSchedulePair(t, &q, "xxvcc-a1", 1001, testGeneration, deadline)
	unit := q.UnitName("xxvcc-a1")
	valid, err := s.ValidQuarantine("xxvcc-a1", 1001, testGeneration, unit, deadline)
	if err != nil || !valid {
		t.Fatalf("ValidQuarantine exact pair = %v, %v", valid, err)
	}
	for _, tc := range []struct {
		uid      int
		unit     string
		deadline time.Time
	}{
		{uid: 1002, unit: unit, deadline: deadline},
		{uid: 1001, unit: s.UnitName("xxvcc-a1"), deadline: deadline},
		{uid: 1001, unit: unit, deadline: deadline.Add(time.Minute)},
		{uid: 1001, unit: unit, deadline: s.Now()},
	} {
		valid, err := s.ValidQuarantine("xxvcc-a1", tc.uid, testGeneration, tc.unit, tc.deadline)
		if err != nil || valid {
			t.Fatalf("mismatched quarantine accepted: %+v valid=%v err=%v", tc, valid, err)
		}
	}
}

func TestValidScheduleAcceptsLegacyOneMinuteAccuracyTimer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("valid systemd schedule files must be root-owned")
	}
	dir := t.TempDir()
	s := newScheduler(dir, &fakeSystem{})
	unit := s.UnitName("xxvcc-a1")
	trigger := s.Now().Add(time.Hour)
	writeSchedulePair(t, s, "xxvcc-a1", 1001, testGeneration, trigger)
	timerPath := filepath.Join(dir, unit+".timer")
	calendar := trigger.UTC().Format("2006-01-02 15:04:05 UTC")
	if err := os.WriteFile(timerPath, []byte(legacyTimerContent(unit, calendar)), 0o644); err != nil {
		t.Fatal(err)
	}

	valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, unit, validTestDeadline)
	if err != nil || !valid {
		t.Fatalf("legacy timer validity = %v, %v; want true", valid, err)
	}
}

func TestValidScheduleRequiresEnabledAndActiveSystemdTimer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("systemd schedule files must be root-owned")
	}
	tests := []struct {
		name      string
		stateErr  func(args ...string) error
		wantValid bool
		wantErr   string
		wantCalls int
	}{
		{
			name:      "enabled and active",
			wantValid: true,
			wantCalls: 2,
		},
		{
			name: "disabled",
			stateErr: func(args ...string) error {
				if args[0] == "is-enabled" {
					return errSystemdUnitNotPersistent
				}
				return nil
			},
			wantCalls: 1,
		},
		{
			name: "inactive",
			stateErr: func(args ...string) error {
				if args[0] == "is-active" {
					return errSystemdUnitInactive
				}
				return nil
			},
			wantCalls: 2,
		},
		{
			name: "enabled query error",
			stateErr: func(args ...string) error {
				if args[0] == "is-enabled" {
					return errors.New("D-Bus unavailable")
				}
				return nil
			},
			wantErr:   "D-Bus unavailable",
			wantCalls: 1,
		},
		{
			name: "active query error",
			stateErr: func(args ...string) error {
				if args[0] == "is-active" {
					return errors.New("permission denied")
				}
				return nil
			},
			wantErr:   "permission denied",
			wantCalls: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			sys := &fakeSystem{systemctlErr: tt.stateErr}
			s := newScheduler(dir, sys)
			unit := s.UnitName("xxvcc-a1")
			writeSchedulePair(t, s, "xxvcc-a1", 1001, testGeneration, s.Now().Add(time.Hour))

			valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, unit, validTestDeadline)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("ValidSchedule: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("ValidSchedule error = %v, want %q", err, tt.wantErr)
			}
			if valid != tt.wantValid {
				t.Fatalf("ValidSchedule valid = %v, want %v", valid, tt.wantValid)
			}
			if len(sys.calls) != tt.wantCalls {
				t.Fatalf("systemctl calls = %v, want %d", sys.calls, tt.wantCalls)
			}
			if len(sys.calls) > 0 && strings.Join(sys.calls[0], " ") != "is-enabled "+unit+".timer" {
				t.Fatalf("first systemctl call = %v", sys.calls[0])
			}
			if len(sys.calls) > 1 && strings.Join(sys.calls[1], " ") != "is-active --quiet "+unit+".timer" {
				t.Fatalf("second systemctl call = %v", sys.calls[1])
			}
		})
	}
}

func TestValidScheduleRejectsTamperedOrExpiredSystemdPair(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("systemd schedule validation requires root-owned fixtures")
	}
	tests := []struct {
		name   string
		mutate func(*testing.T, *Scheduler, string)
	}{
		{
			name: "service command",
			mutate: func(t *testing.T, s *Scheduler, unit string) {
				t.Helper()
				path := filepath.Join(s.SystemdDir, unit+".service")
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(b, []byte("ExecStart=/bin/true\n")...), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicate OnCalendar",
			mutate: func(t *testing.T, s *Scheduler, unit string) {
				t.Helper()
				path := filepath.Join(s.SystemdDir, unit+".timer")
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteString("OnCalendar=2026-07-07 14:00:00 UTC\n"); err != nil {
					f.Close()
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong timer target",
			mutate: func(t *testing.T, s *Scheduler, unit string) {
				t.Helper()
				path := filepath.Join(s.SystemdDir, unit+".timer")
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				b = []byte(strings.ReplaceAll(string(b), "Unit="+unit+".service", "Unit=other.service"))
				if err := os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown accuracy window",
			mutate: func(t *testing.T, s *Scheduler, unit string) {
				t.Helper()
				path := filepath.Join(s.SystemdDir, unit+".timer")
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				b = []byte(strings.ReplaceAll(string(b), "AccuracySec=1us", "AccuracySec=5min"))
				if err := os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe mode",
			mutate: func(t *testing.T, s *Scheduler, unit string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(s.SystemdDir, unit+".timer"), 0o664); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, s *Scheduler, unit string) {
				t.Helper()
				path := filepath.Join(s.SystemdDir, unit+".timer")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(unit+".service", path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non-regular",
			mutate: func(t *testing.T, s *Scheduler, unit string) {
				t.Helper()
				path := filepath.Join(s.SystemdDir, unit+".timer")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			s := newScheduler(dir, &fakeSystem{})
			unit := s.UnitName("xxvcc-a1")
			writeSchedulePair(t, s, "xxvcc-a1", 1001, testGeneration, s.Now().Add(time.Hour))
			tt.mutate(t, s, unit)

			valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, unit, validTestDeadline)
			if err != nil {
				t.Fatal(err)
			}
			if valid {
				t.Fatal("tampered systemd pair was accepted")
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		dir := t.TempDir()
		s := newScheduler(dir, &fakeSystem{})
		unit := s.UnitName("xxvcc-a1")
		writeSchedulePair(t, s, "xxvcc-a1", 1001, testGeneration, s.Now().Add(-time.Second))
		valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, unit, validTestDeadline)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Fatal("expired systemd timer was accepted")
		}
	})
}

func TestValidScheduleMetadataRequiresRootOwnedRegular0644File(t *testing.T) {
	tests := []struct {
		name string
		stat unix.Stat_t
		want bool
	}{
		{name: "valid", stat: unix.Stat_t{Mode: unix.S_IFREG | 0o644, Uid: 0}, want: true},
		{name: "non-root owner", stat: unix.Stat_t{Mode: unix.S_IFREG | 0o644, Uid: 1}},
		{name: "non-root group", stat: unix.Stat_t{Mode: unix.S_IFREG | 0o644, Uid: 0, Gid: 1}},
		{name: "group writable", stat: unix.Stat_t{Mode: unix.S_IFREG | 0o664, Uid: 0}},
		{name: "directory", stat: unix.Stat_t{Mode: unix.S_IFDIR | 0o644, Uid: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validScheduleMetadata(&tt.stat); got != tt.want {
				t.Fatalf("validScheduleMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidScheduleRejectsUnexpectedRecordedUnit(t *testing.T) {
	s := newScheduler(t.TempDir(), &fakeSystem{})
	for _, recorded := range []string{"", "other-unit", "at:not-a-number", "at:42.timer"} {
		valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, recorded, validTestDeadline)
		if err != nil {
			t.Fatalf("recorded %q: %v", recorded, err)
		}
		if valid {
			t.Fatalf("recorded unit %q was accepted", recorded)
		}
	}
}

func TestValidScheduleRejectsNilSchedulerWithoutPanicking(t *testing.T) {
	var s *Scheduler
	valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:42", validTestDeadline)
	if err == nil || valid || !strings.Contains(err.Error(), "no scheduler configured") {
		t.Fatalf("nil ValidSchedule = %v, %v", valid, err)
	}
}

func writeSchedulePair(t *testing.T, s *Scheduler, user string, uid int, generation string, trigger time.Time) {
	t.Helper()
	unit := s.UnitName(user)
	files := map[string]string{
		unit + ".service": s.serviceContent(user, uid, generation),
		unit + ".timer":   timerContent(unit, trigger.UTC().Format("2006-01-02 15:04:05 UTC")),
	}
	for name, content := range files {
		path := filepath.Join(s.SystemdDir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A queued at job is only a schedule if its deadline is still ahead and
// something is left to dispatch it. Presence in the queue proves neither.
func TestValidScheduleRejectsAtJobWhoseDeadlinePassedOrWhoseDaemonIsGone(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	setup := func(t *testing.T) (*Scheduler, *fakeSystem) {
		t.Helper()
		sys := &fakeSystem{}
		s := newScheduler(t.TempDir(), sys)
		s.Now = func() time.Time { return now }
		sys.atJobs = []AtJob{{
			ID:          "57",
			Body:        s.RevokeCommand("xxvcc-a1", 1001, testGeneration) + "\n",
			ScheduledAt: now.Add(24 * time.Hour),
		}}
		return s, sys
	}

	t.Run("future deadline with a running atd is valid", func(t *testing.T) {
		s, _ := setup(t)
		valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:57", now.Add(24*time.Hour))
		if err != nil || !valid {
			t.Fatalf("ValidSchedule = %v, %v; want true, nil", valid, err)
		}
	})

	t.Run("deadline already passed while the job sat in the queue", func(t *testing.T) {
		s, sys := setup(t)
		sys.atJobs[0].ScheduledAt = now.Add(-96 * time.Hour)
		valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:57", now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Fatal("a job whose deadline passed four days ago was reported as a valid schedule")
		}
	})

	t.Run("atd is not running, so nothing will ever dispatch the job", func(t *testing.T) {
		s, sys := setup(t)
		sys.atdStopped = true
		valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:57", now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Fatal("a queued job on a host with a stopped atd was reported as a valid schedule")
		}
	})

	t.Run("no probe could answer, so it fails closed with an error", func(t *testing.T) {
		s, sys := setup(t)
		sys.atdProbeErr = errors.New("no available probe")
		valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:57", now.Add(24*time.Hour))
		if err == nil || valid {
			t.Fatalf("ValidSchedule = %v, %v; want false and an error", valid, err)
		}
		if !strings.Contains(err.Error(), "atd") {
			t.Fatalf("error = %v, want it to name the atd probe", err)
		}
	})

	t.Run("an atq without a parseable time cannot prove the deadline", func(t *testing.T) {
		s, sys := setup(t)
		sys.atJobs[0].ScheduledAt = time.Time{}
		valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:57", now.Add(24*time.Hour))
		if err != nil || valid {
			t.Fatalf("ValidSchedule = %v, %v; want false, nil for an unknown deadline", valid, err)
		}
	})
}

// Cancel must never report success while the timer it was asked to cancel is
// still active in the manager: that is the shape that leaves a stale task able
// to delete a later account that reused the name.
func TestCancelFailsClosedWhenTheTimerSurvivesAnExplicitStop(t *testing.T) {
	unitFileMissing := func(unit string) *systemctlError {
		return &systemctlError{
			args:   []string{"disable", "--now", unit},
			err:    errors.New("exit status 1"),
			output: fmt.Sprintf("Failed to disable unit: Unit file %s does not exist.", unit),
		}
	}

	newCase := func(t *testing.T, isActive error) error {
		t.Helper()
		sys := &fakeSystem{hasSystemctl: true}
		s := newScheduler(t.TempDir(), sys)
		unit := s.UnitName("xxvcc-a1") + ".timer"
		sys.systemctlErr = func(args ...string) error {
			switch {
			case len(args) == 3 && args[0] == "disable":
				return unitFileMissing(unit)
			case len(args) == 2 && args[0] == "stop":
				return nil
			case len(args) == 2 && args[0] == "is-active":
				return isActive
			}
			return nil
		}
		return s.Cancel("xxvcc-a1", s.UnitName("xxvcc-a1"))
	}

	t.Run("is-active reports the timer is still running", func(t *testing.T) {
		err := newCase(t, nil)
		if err == nil {
			t.Fatal("Cancel reported success while the timer was still active")
		}
		if !strings.Contains(err.Error(), "remains active after stop") {
			t.Fatalf("error = %v, want it to name the surviving timer", err)
		}
	})

	t.Run("is-active failed in a way that proves nothing", func(t *testing.T) {
		err := newCase(t, &systemctlError{
			args:   []string{"is-active", "linux-temp-admin-v2-revoke-xxvcc-a1.timer"},
			err:    errors.New("exit status 1"),
			output: "Failed to connect to bus: No such file or directory",
		})
		if err == nil {
			t.Fatal("Cancel reported success though no probe confirmed the timer stopped")
		}
		if !strings.Contains(err.Error(), "confirm timer stopped") {
			t.Fatalf("error = %v, want the unconfirmed-state refusal", err)
		}
	})

	t.Run("a confirmed inactive timer is success", func(t *testing.T) {
		err := newCase(t, &systemctlError{
			args:   []string{"is-active", "linux-temp-admin-v2-revoke-xxvcc-a1.timer"},
			err:    errSystemdUnitInactive,
			output: "inactive",
		})
		if err != nil {
			t.Fatalf("Cancel with a confirmed-inactive timer = %v, want nil", err)
		}
	})
}

// Hosts that upgrade to the pinned-CWD release still carry jobs queued by the old
// one, each with at(1)'s `cd <submitting CWD> || exit 1` prologue. Once that
// directory is gone the job exits before reaching revoke, so it is in the queue
// but is not a schedule.
func TestValidScheduleRejectsAnAtJobPinnedToAVanishedDirectory(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	build := func(t *testing.T, prologue string) (bool, error) {
		t.Helper()
		sys := &fakeSystem{}
		s := newScheduler(t.TempDir(), sys)
		s.Now = func() time.Time { return now }
		sys.atJobs = []AtJob{{
			ID:          "57",
			Body:        prologue + s.RevokeCommand("xxvcc-a1", 1001, testGeneration) + "\n",
			ScheduledAt: now.Add(24 * time.Hour),
		}}
		return s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:57", now.Add(24*time.Hour))
	}

	gone := filepath.Join(t.TempDir(), "deploy-2026-09")
	present := t.TempDir()

	for _, tc := range []struct {
		name     string
		prologue string
		want     bool
	}{
		{"pinned to the always-present directory", "cd / || {\n echo bad >&2\n exit 1\n}\nunset TZ\n", true},
		{"no prologue at all", "unset TZ\n", true},
		{"a caller CWD that still exists", "cd " + present + " || {\n exit 1\n}\nunset TZ\n", true},
		{"a caller CWD that is gone", "cd " + gone + " || {\n echo 'Execution directory inaccessible' >&2\n exit 1\n}\nunset TZ\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := build(t, tc.prologue)
			if err != nil {
				t.Fatal(err)
			}
			if valid != tc.want {
				t.Fatalf("ValidSchedule = %v, want %v", valid, tc.want)
			}
		})
	}
}
