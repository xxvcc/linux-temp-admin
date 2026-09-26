package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

type doctorDeadlineSystem struct {
	failingScheduleSystem
	jobs []schedule.AtJob
}

func (s doctorDeadlineSystem) AtJobs() ([]schedule.AtJob, error) { return s.jobs, nil }

func TestDoctorChecksRecordedRevokeDeadline(t *testing.T) {
	const name = "xxvcc-a1"
	const generation = "0123456789abcdef0123456789abcdef"
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, expires string
		queued        time.Time
		want          int
	}{
		{"matching", "2026-07-07 13:00:00 UTC", now.Add(time.Hour), 0},
		{"later job", "2026-07-07 13:00:00 UTC", now.Add(24 * time.Hour), 1},
		{"expired record but future job", "2026-07-07 11:00:00 UTC", now.Add(24 * time.Hour), 1},
		{"unknown legacy timezone", "2026-07-07 13:00:00 CST", now.Add(time.Hour), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := newTestApp(t, "")
			a.LookupUser = func(string) (user.Passwd, bool, error) { return user.Passwd{Name: name, UID: 1001}, true, nil }
			a.Scheduler = &schedule.Scheduler{InstallPath: "/usr/local/sbin/linux-temp-admin", Now: func() time.Time { return now }}
			a.Scheduler.Sys = doctorDeadlineSystem{jobs: []schedule.AtJob{{ID: "57", OwnerUID: 0, ScheduledAt: tc.queued, Body: a.Scheduler.RevokeCommand(name, 1001, generation) + "\n"}}}
			rec := registry.Record{User: name, Expires: tc.expires, AutoRevoke: true, AutoUnit: "at:57", UID: 1001, Generation: generation, IdentityBound: true}
			result := a.doctorScheduleValidity(doctorRegistryState{readable: true, records: []registry.Record{rec}})
			if result.status() != tc.want {
				t.Fatalf("status=%d want=%d diagnostics=%s", result.status(), tc.want, errb.String())
			}
			if tc.want != 0 && !strings.Contains(errb.String(), name) {
				t.Fatalf("missing account diagnostic: %s", errb.String())
			}
		})
	}
}
