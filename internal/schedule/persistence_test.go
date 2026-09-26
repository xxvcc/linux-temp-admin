package schedule

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
)

func TestSystemdTimerRequiresExplicitPersistentEnablement(t *testing.T) {
	for _, tc := range []struct {
		state, active string
		exit          int
		valid, err    bool
	}{
		{state: "enabled", valid: true},
		{state: "enabled-runtime"},
		{state: "static"},
		{state: "indirect"},
		{state: "alias"},
		{state: "generated"},
		{state: "transient"},
		{state: "disabled", exit: 1},
		{state: "linked", exit: 1},
		{state: "linked-runtime", exit: 1},
		{state: "masked", exit: 1},
		{state: "masked-runtime", exit: 1},
		{state: "bad", exit: 1},
		{state: "not-found", exit: 4},
		{state: "", err: true},
		{state: "new-state", err: true},
		{state: "enabled", exit: 1, err: true},
		{state: "disabled", exit: 2, err: true},
		{state: "Failed to connect to bus", exit: 1, err: true},
		{state: "enabled\nFailed to connect to bus", err: true},
		{state: "enabled", active: "exit 3"},
		{state: "enabled", active: "echo 'Failed to connect to bus' >&2; exit 1", err: true},
	} {
		t.Run(fmt.Sprintf("%s/%d/%s", tc.state, tc.exit, tc.active), func(t *testing.T) {
			dir := t.TempDir()
			active := tc.active
			if active == "" {
				active = "exit 0"
			}
			writeCommand(t, dir, "systemctl", fmt.Sprintf(`case "$1" in
is-enabled) [ "$#" = 2 ] || exit 91; printf '%%s\n' '%s'; exit %d;;
is-active) %s;;
*) exit 92;;
esac`, tc.state, tc.exit, active))
			t.Setenv("PATH", dir)
			valid, err := (&Scheduler{Sys: realSystem{}}).systemdTimerExecutable("lta-test.timer")
			if valid != tc.valid || (err != nil) != tc.err {
				t.Fatalf("valid=%v err=%v want valid=%v error=%v", valid, err, tc.valid, tc.err)
			}
		})
	}
}

func TestValidScheduleAndQuarantineRejectRuntimeOnlyTimers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("schedule metadata fixtures must be root-owned")
	}
	for _, quarantine := range []bool{false, true} {
		for _, state := range []string{"enabled", "enabled-runtime"} {
			t.Run(fmt.Sprintf("quarantine=%v/%s", quarantine, state), func(t *testing.T) {
				bin := t.TempDir()
				writeCommand(t, bin, "systemctl", "case \"$1\" in is-enabled) echo "+state+";; is-active) exit 0;; *) exit 91;; esac")
				t.Setenv("PATH", bin)
				s := newScheduler(t.TempDir(), realSystem{})
				if quarantine {
					s.UnitPrefix = config.QuarantineUnitPrefix
				}
				deadline := s.Now().Add(time.Hour)
				writeSchedulePair(t, s, "xxvcc-a1", 1001, testGeneration, deadline)
				check := s.ValidSchedule
				if quarantine {
					check = s.ValidQuarantine
				}
				valid, err := check("xxvcc-a1", 1001, testGeneration, s.UnitName("xxvcc-a1"), deadline)
				if err != nil || valid != (state == "enabled") {
					t.Fatalf("valid=%v err=%v for state=%s", valid, err, state)
				}
			})
		}
	}
}

// The real systemctl operates exclusively on an offline temporary root. Active
// state is mocked because no host manager or service is needed for this check.
func TestRealSystemctlOfflinePersistentTimer(t *testing.T) {
	tool, err := exec.LookPath("systemctl")
	if err != nil {
		t.Skip("systemctl is unavailable")
	}
	for _, runtimeOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("runtime=%v", runtimeOnly), func(t *testing.T) {
			root := t.TempDir()
			units := filepath.Join(root, "etc/systemd/system")
			if err := os.MkdirAll(units, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"lta-test.timer":   "[Timer]\nOnCalendar=2099-01-01 00:00:00 UTC\n[Install]\nWantedBy=timers.target\n",
				"lta-test.service": "[Service]\nType=oneshot\nExecStart=/bin/true\n",
				"timers.target":    "[Unit]\nDescription=Offline timers\n",
			} {
				if err := os.WriteFile(filepath.Join(units, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--root", root, "enable"}
			if runtimeOnly {
				args = append(args, "--runtime")
			}
			args = append(args, "lta-test.timer")
			if out, err := exec.Command(tool, args...).CombinedOutput(); err != nil {
				t.Fatalf("offline enable: %v: %s", err, out)
			}
			out, err := exec.Command(tool, "--root", root, "is-enabled", "lta-test.timer").CombinedOutput()
			if err != nil {
				t.Fatalf("offline state: %v: %s", err, out)
			}
			state := strings.TrimSpace(string(out))
			wantState := "enabled"
			if runtimeOnly {
				wantState = "enabled-runtime"
			}
			if state != wantState {
				t.Fatalf("state=%q want %q", state, wantState)
			}
			bin := t.TempDir()
			quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
			writeCommand(t, bin, "systemctl", "if [ \"$1\" = is-active ]; then exit 0; fi\nexec "+quote(tool)+" --root "+quote(root)+" \"$@\"")
			t.Setenv("PATH", bin)
			valid, err := (&Scheduler{Sys: realSystem{}}).systemdTimerExecutable("lta-test.timer")
			if err != nil || valid == runtimeOnly {
				t.Fatalf("state=%q valid=%v err=%v", state, valid, err)
			}
			t.Logf("offline real systemctl state=%s; timer valid=%v; active mocked", state, valid)
		})
	}
}
