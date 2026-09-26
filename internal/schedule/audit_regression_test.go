package schedule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemdAbsenceRequiresBothBootMarkerAndInitEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, comm     string
		marker, absent bool
	}{
		{"non-systemd init", "openrc-init\n", false, true},
		{"systemd init without marker", "systemd\n", false, false},
		{"booted marker", "container-init\n", true, false},
		{"unreadable init", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker, comm := filepath.Join(dir, "system"), filepath.Join(dir, "comm")
			if tc.marker {
				if err := os.Mkdir(marker, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.comm != "" {
				if err := os.WriteFile(comm, []byte(tc.comm), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := systemdDefinitelyAbsent(marker, comm); got != tc.absent {
				t.Fatalf("absent=%v want=%v", got, tc.absent)
			}
		})
	}
}

func TestEnsureAtdVerifiesBootPersistenceEvenWhenAlreadyRunning(t *testing.T) {
	for _, backend := range []string{"systemd", "openrc", "chkconfig", "update-rc.d"} {
		failures := []string{"", "enable", "verify", "running"}
		if backend == "systemd" {
			failures = append(failures, "enabled-runtime", "static", "indirect", "alias")
		}
		for _, failure := range failures {
			t.Run(backend+"/"+failure, func(t *testing.T) {
				dir := t.TempDir()
				log := filepath.Join(dir, "commands")
				write := func(name, body string) {
					writeCommand(t, dir, name, "printf '%s %s\\n' '"+name+"' \"$*\" >> '"+log+"'\n"+body)
				}
				status := "exit 0"
				if failure == "running" {
					status = "exit 1"
				}
				enable := "exit 0"
				if failure == "enable" {
					enable = "exit 1"
				}
				switch backend {
				case "systemd":
					verify := "printf 'enabled\\n'"
					if failure == "enabled-runtime" || failure == "static" || failure == "indirect" || failure == "alias" {
						verify = "printf '" + failure + "\\n'"
					}
					if failure == "verify" {
						verify = "exit 1"
					}
					write("systemctl", "case \"$1\" in enable) "+enable+";; is-enabled) "+verify+";; is-active) "+status+";; *) exit 91;; esac")
				case "openrc":
					verify := "printf 'atd | default\\n'"
					if failure == "verify" {
						verify = "printf 'crond | default\\n'"
					}
					write("rc-update", "case \"$1\" in add) "+enable+";; show) "+verify+";; *) exit 91;; esac")
					write("rc-service", status)
				case "chkconfig":
					verify := "printf 'atd 0:off 1:off 2:on 3:on 4:on 5:on 6:off\\n'"
					if failure == "verify" {
						verify = "printf 'atd 0:off 1:off 2:on 3:off 4:on 5:on 6:off\\n'"
					}
					write("chkconfig", "if [ \"$1\" = --list ]; then "+verify+"; else "+enable+"; fi")
					write("service", status)
				case "update-rc.d":
					write("update-rc.d", enable)
					write("service", status)
					init := filepath.Join(dir, "init.d")
					if err := os.Mkdir(init, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(init, "atd"), []byte("#!/bin/sh\n"), 0o755); err != nil {
						t.Fatal(err)
					}
					for level := 2; level <= 5; level++ {
						rc := filepath.Join(dir, fmt.Sprintf("rc%d.d", level))
						if err := os.Mkdir(rc, 0o755); err != nil {
							t.Fatal(err)
						}
						if failure == "verify" && level == 3 {
							continue
						}
						if err := os.Symlink("../init.d/atd", filepath.Join(rc, "S01atd")); err != nil {
							t.Fatal(err)
						}
					}
				}
				t.Setenv("PATH", dir)
				if got := ensureAtdWithSystemd(backend == "systemd", dir); got != (failure == "") {
					t.Fatalf("ensureAtd=%v failure=%q", got, failure)
				}
				calls, err := os.ReadFile(log)
				if err != nil {
					t.Fatal(err)
				}
				if backend == "openrc" && !strings.Contains(string(calls), "rc-update add atd default") {
					t.Fatalf("running atd was never enabled: %s", calls)
				}
			})
		}
	}
}

func TestValidScheduleChecksRecordedDeadlineOnBothBackends(t *testing.T) {
	for _, backend := range []string{"at", "systemd"} {
		if backend == "systemd" && os.Geteuid() != 0 {
			continue
		}
		for _, tc := range []struct {
			name    string
			shift   time.Duration
			missing bool
			want    bool
		}{
			{"matching", 0, false, true},
			{"late by minute", time.Minute, false, false},
			{"late by day", 24 * time.Hour, false, false},
			{"early", -time.Minute, false, false},
			{"unknown recorded deadline", 0, true, false},
		} {
			t.Run(backend+"/"+tc.name, func(t *testing.T) {
				sys := &fakeSystem{}
				s := newScheduler(t.TempDir(), sys)
				deadline := s.Now().Add(time.Hour)
				unit := "at:42"
				if backend == "at" {
					sys.atJobs = []AtJob{{ID: "42", Body: s.RevokeCommand("xxvcc-a1", 1001, testGeneration), ScheduledAt: deadline.Add(tc.shift)}}
				} else {
					unit = s.UnitName("xxvcc-a1")
					writeSchedulePair(t, s, "xxvcc-a1", 1001, testGeneration, deadline.Add(tc.shift))
				}
				if tc.missing {
					deadline = time.Time{}
				}
				valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, unit, deadline)
				if err != nil || valid != tc.want {
					t.Fatalf("ValidSchedule=%v err=%v want=%v", valid, err, tc.want)
				}
			})
		}
	}
}

func TestScheduleDeadlineMinuteRounding(t *testing.T) {
	deadline := time.Date(2026, 9, 26, 12, 0, 17, 0, time.UTC)
	for _, tc := range []struct {
		trigger time.Time
		want    bool
	}{
		{deadline, true}, {deadline.Truncate(time.Minute).Add(time.Minute), true},
		{deadline.Truncate(time.Minute), false}, {deadline.Add(time.Minute), false},
		{time.Time{}, false},
	} {
		if got := scheduleDeadlineMatches(tc.trigger, deadline); got != tc.want {
			t.Fatalf("trigger=%v valid=%v want=%v", tc.trigger, got, tc.want)
		}
	}
}

func TestNonSystemdHostWithSystemctlAllowsEmptyCleanupAndAtInventory(t *testing.T) {
	if !systemdDefinitelyAbsent("/run/systemd/system", "/proc/1/comm") {
		t.Skip("requires an actual non-systemd PID 1; exercised in the ordinary test container")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "systemctl-called")
	writeCommand(t, dir, "systemctl", "printf '%s\\n' \"$*\" > '"+marker+"'; echo 'System has not been booted with systemd as init system (PID 1). Cannot operate.' >&2; exit 1")
	t.Setenv("PATH", dir)
	s := newScheduler(t.TempDir(), realSystem{})
	if err := s.Cancel("xxvcc-a1", ""); err != nil {
		t.Fatalf("empty Cancel on a confirmed non-systemd host: %v", err)
	}
	if users, err := s.ScheduledUsers(); err != nil || len(users) != 0 {
		t.Fatalf("empty inventory=%v err=%v", users, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("queried an absent manager: %v", err)
	}
	unit := s.UnitName("xxvcc-a1")
	path := filepath.Join(s.SystemdDir, unit+".timer")
	if err := os.WriteFile(path, []byte("evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel("xxvcc-a1", unit); err == nil {
		t.Fatal("discarded managed unit evidence while manager was absent")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unit evidence not preserved: %v", err)
	}
}

func TestSystemdCleanupDoesNotTreatDBusFailureAsManagerAbsence(t *testing.T) {
	sys := &fakeSystem{hasSystemctl: true, systemctlErr: func(...string) error { return fmt.Errorf("Failed to connect to bus: Permission denied") }}
	s := newScheduler(t.TempDir(), sys)
	if err := s.Cancel("xxvcc-a1", ""); err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("broken manager was suppressed: %v", err)
	}
}
