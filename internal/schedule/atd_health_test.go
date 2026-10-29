package schedule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
)

type atdHealthSystem struct {
	*fakeSystem
	systemd bool
	initDir string
}

func (s atdHealthSystem) AtDaemonReady() (bool, error) {
	return atdReadyWithSystemd(s.systemd, s.initDir)
}

func TestValidAtScheduleRequiresReadOnlyPersistentBackend(t *testing.T) {
	for _, backend := range []string{"systemd", "openrc", "chkconfig", "update-rc.d"} {
		states := []string{"enabled", "disabled", "status-error"}
		if backend != "update-rc.d" {
			states = append(states, "query-error")
		}
		if backend == "systemd" {
			states = append(states, "enabled-runtime", "static", "indirect", "alias", "unknown")
		}
		for _, state := range states {
			t.Run(backend+"/"+state, func(t *testing.T) {
				dir := t.TempDir()
				log := filepath.Join(dir, "commands")
				write := func(name, body string) {
					writeCommand(t, dir, name, "printf '%s %s\\n' '"+name+"' \"$*\" >> '"+log+"'\n"+body)
				}
				status := "exit 0"
				if state == "status-error" {
					status = "exit 1"
				}
				switch backend {
				case "systemd":
					query := "printf 'enabled\\n'"
					switch state {
					case "disabled":
						query = "printf 'disabled\\n'; exit 1"
					case "query-error":
						query = "printf 'Failed to connect to bus\\n'; exit 1"
					case "enabled-runtime", "static", "indirect", "alias", "unknown":
						query = "printf '" + state + "\\n'"
					}
					write("systemctl", "case \"$*\" in 'is-enabled atd') "+query+";; 'is-active --quiet atd') "+status+";; *) exit 91;; esac")
					// A broken manager must not be hidden by a successful fallback.
					write("rc-update", "printf 'atd | default\\n'")
					write("rc-service", "exit 0")
				case "openrc":
					query := "printf 'atd | default\\n'"
					if state == "disabled" {
						query = "printf 'crond | default\\n'"
					} else if state == "query-error" {
						query = "exit 1"
					}
					write("rc-update", "[ \"$*\" = 'show default' ] || exit 91\n"+query)
					write("rc-service", "[ \"$*\" = 'atd status' ] || exit 91\n"+status)
				case "chkconfig":
					query := "printf 'atd 0:off 1:off 2:on 3:on 4:on 5:on 6:off\\n'"
					if state == "disabled" {
						query = "printf 'atd 0:off 1:off 2:on 3:off 4:on 5:on 6:off\\n'"
					} else if state == "query-error" {
						query = "exit 1"
					}
					write("chkconfig", "[ \"$*\" = '--list atd' ] || exit 91\n"+query)
					write("service", "[ \"$*\" = 'atd status' ] || exit 91\n"+status)
				case "update-rc.d":
					write("update-rc.d", "exit 91") // presence only; diagnosis must never run it
					write("service", "[ \"$*\" = 'atd status' ] || exit 91\n"+status)
					writeAtdInitLinks(t, dir, state != "disabled")
				}
				// Neither process presence nor a second init backend may bypass a
				// disabled or uninspectable native backend.
				write("pgrep", "exit 0")
				t.Setenv("PATH", dir)
				sys := atdHealthSystem{fakeSystem: &fakeSystem{}, systemd: backend == "systemd", initDir: dir}
				s := newScheduler(t.TempDir(), sys)
				deadline := s.Now().Add(time.Hour)
				sys.atJobs = []AtJob{{ID: "42", Body: s.RevokeCommand("xxvcc-a1", 1001, testGeneration), ScheduledAt: deadline}}
				valid, err := s.ValidSchedule("xxvcc-a1", 1001, testGeneration, "at:42", deadline)
				if valid != (state == "enabled") {
					t.Fatalf("valid=%v err=%v, want valid only for a running persistently enabled backend", valid, err)
				}
				wantErr := state == "status-error" || state == "query-error" || state == "unknown"
				if (err != nil) != wantErr {
					t.Fatalf("err=%v, want error=%v", err, wantErr)
				}
				calls, readErr := os.ReadFile(log)
				if readErr != nil && !os.IsNotExist(readErr) {
					t.Fatal(readErr)
				}
				for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 0 {
						continue
					}
					for _, field := range fields[1:] {
						if field == "enable" || field == "start" || field == "add" || field == "on" {
							t.Fatalf("read-only diagnosis mutated the backend: %s", calls)
						}
					}
					if fields[0] == "pgrep" || fields[0] == "update-rc.d" || (backend == "systemd" && fields[0] != "systemctl") {
						t.Fatalf("diagnosis used an untrusted fallback or enable command: %s", calls)
					}
				}
			})
		}
	}
}

func writeAtdInitLinks(t *testing.T, dir string, enabled bool) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, "init.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.d", "atd"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for level := 2; level <= 5; level++ {
		rc := filepath.Join(dir, fmt.Sprintf("rc%d.d", level))
		if err := os.Mkdir(rc, 0o755); err != nil {
			t.Fatal(err)
		}
		if !enabled && level == 3 {
			continue
		}
		if err := os.Symlink("../init.d/atd", filepath.Join(rc, "S01atd")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAtDaemonReadyRejectsProcessOnlyAndPartialBackends(t *testing.T) {
	for _, commands := range [][]string{{}, {"pgrep"}, {"rc-service"}, {"service"}} {
		t.Run(strings.Join(commands, "+"), func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range commands {
				writeCommand(t, dir, name, "exit 0")
			}
			t.Setenv("PATH", dir)
			ready, err := atdReadyWithSystemd(false, dir)
			if ready || err == nil {
				t.Fatalf("ready=%v err=%v; missing persistence evidence must fail closed", ready, err)
			}
		})
	}
}

func TestAtDaemonReadyUsesNativeBackendWhenSystemctlIsOnlyInstalled(t *testing.T) {
	booted, err := sysinfo.SystemdBooted()
	if err != nil || booted {
		t.Skip("requires a positively non-systemd host; exercised in the ordinary test container")
	}
	dir := t.TempDir()
	called := filepath.Join(dir, "wrong-backend")
	writeCommand(t, dir, "systemctl", ": > '"+called+"'; exit 0")
	writeCommand(t, dir, "rc-update", "[ \"$*\" = 'show default' ] || exit 91\nprintf 'atd | default\\n'")
	writeCommand(t, dir, "rc-service", "[ \"$*\" = 'atd status' ]")
	t.Setenv("PATH", dir)
	ready, err := (realSystem{}).AtDaemonReady()
	if !ready || err != nil {
		t.Fatalf("native OpenRC backend ready=%v err=%v", ready, err)
	}
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatalf("an installed systemctl replaced the native init check: %v", err)
	}
}
