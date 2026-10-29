package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/expiry"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

type doctorAtdSystem struct {
	schedule.System
	jobs []schedule.AtJob
}

func (s doctorAtdSystem) AtJobs() ([]schedule.AtJob, error) { return s.jobs, nil }

func TestDoctorRejectsRunningAtdWithoutPersistentEnablement(t *testing.T) {
	const name = "xxvcc-a1"
	const generation = "0123456789abcdef0123456789abcdef"
	for _, enabled := range []bool{true, false} {
		label := "disabled"
		if enabled {
			label = "enabled"
		}
		t.Run(label, func(t *testing.T) {
			a, _, errb := newTestApp(t, "")
			a.LookupUser = func(string) (user.Passwd, bool, error) {
				return user.Passwd{Name: name, UID: 1001}, true, nil
			}
			s := schedule.New()
			s.Now = a.Now
			deadline := a.Now().Add(time.Hour)
			s.Sys = doctorAtdSystem{System: s.Sys, jobs: []schedule.AtJob{{
				ID: "57", OwnerUID: 0, ScheduledAt: deadline,
				Body: s.RevokeCommand(name, 1001, generation) + "\n",
			}}}
			a.Scheduler = s
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			write := func(command, body string) {
				t.Helper()
				content := "#!/bin/sh\nprintf '%s %s\\n' '" + command + "' \"$*\" >> '" + log + "'\n" + body + "\n"
				if err := os.WriteFile(filepath.Join(dir, command), []byte(content), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			systemdState := "printf 'disabled\\n'; exit 1"
			openRCState := "printf 'crond | default\\n'"
			if enabled {
				systemdState = "printf 'enabled\\n'"
				openRCState = "printf 'atd | default\\n'"
			}
			// All status probes report a live daemon. Only persistent enablement
			// differs, with fixtures for either native init environment.
			write("systemctl", "case \"$*\" in 'is-enabled atd') "+systemdState+";; 'is-active --quiet atd') exit 0;; *) exit 91;; esac")
			write("rc-update", "[ \"$*\" = 'show default' ] || exit 91\n"+openRCState)
			write("rc-service", "[ \"$*\" = 'atd status' ]")
			t.Setenv("PATH", dir)
			rec := registry.Record{User: name, UID: 1001, Generation: generation, IdentityBound: true,
				Expires: expiry.Display(deadline), AutoRevoke: true, AutoUnit: "at:57"}
			result := a.doctorScheduleValidity(doctorRegistryState{readable: true, records: []registry.Record{rec}})
			if (result.status() == 0) != enabled {
				t.Fatalf("doctor status=%d enabled=%v diagnostics=%s", result.status(), enabled, errb.String())
			}
			if !enabled && !strings.Contains(errb.String(), name) {
				t.Fatalf("missing affected account diagnostic: %s", errb.String())
			}
			calls, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
				switch line {
				case "systemctl is-enabled atd", "systemctl is-active --quiet atd", "rc-update show default", "rc-service atd status":
				default:
					t.Fatalf("doctor executed a mutating or unexpected command: %q", line)
				}
			}
		})
	}
}
