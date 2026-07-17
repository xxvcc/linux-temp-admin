// Package schedule creates and cancels the auto-revoke task that deletes a
// temporary account at expiry. It prefers a systemd timer (absolute OnCalendar
// in UTC) and falls back to an at job. Cancellation always cleans BOTH a systemd
// unit and any matching at job, so a reused username cannot leave a stale task
// that later deletes a fresh account.
package schedule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

// System abstracts the external schedulers so orchestration is testable.
type System interface {
	HasSystemctl() bool
	Systemctl(args ...string) error
	HasAt() bool
	// ScheduleAt queues command to run in `hours` hours and returns the job id.
	ScheduleAt(command string, hours int) (jobID string, err error)
	// RemoveAtJobsFor atrm's every queued job whose body contains command.
	RemoveAtJobsFor(command string)
	// AtrmJob removes a specific at job by id (no-op if id is empty/invalid).
	AtrmJob(id string)
}

// Scheduler writes units / queues jobs. Paths and time source are fields for tests.
type Scheduler struct {
	SystemdDir  string
	InstallPath string
	UnitPrefix  string
	// LegacyUnitPrefixes are older namespaces whose units this Scheduler must still
	// be able to FIND (see UnitUsers) though it never writes them. It is a field
	// rather than a constant so a test can point the whole namespace at a temp dir
	// without picking up the real one.
	LegacyUnitPrefixes []string
	Now                func() time.Time
	Sys                System
	// UnderUnit reports whether the current process is executing inside the given
	// systemd service (i.e. the firing auto-revoke run for that unit); when true,
	// Cancel leaves that .service file in place rather than deleting the file it is
	// running from. Defaults to a /proc/self/cgroup check; injectable for tests.
	UnderUnit func(unit string) bool
}

// New returns a Scheduler backed by real systemctl/at.
func New() *Scheduler {
	return &Scheduler{
		SystemdDir:  config.SystemdDir,
		InstallPath: config.InstallPath,
		UnitPrefix:  config.AutoRevokeUnitPrefix,
		// v1's units are still findable, never written. v1 installed to the same path
		// this binary occupies, so its timers invoke THIS code and its accounts strand
		// exactly like v2's would.
		LegacyUnitPrefixes: []string{config.V1AutoRevokeUnitPrefix},
		Now:                time.Now,
		Sys:                realSystem{},
		UnderUnit:          runningUnderFiringUnit,
	}
}

// runningUnderFiringUnit reports whether the current process is executing inside
// the systemd service <unit>.service — i.e. this run is the auto-revoke task
// firing for this very unit, so Cancel must not delete the .service file it is
// running from. It reads /proc/self/cgroup, whose path for a service contains
// "<unit>.service". If that is unavailable it falls back to the coarse "any
// systemd scope" signal (INVOCATION_ID), erring toward leaving the file rather
// than risking removal of a live unit.
func runningUnderFiringUnit(unit string) bool {
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		return strings.Contains(string(b), unit+".service")
	}
	return os.Getenv("INVOCATION_ID") != ""
}

// UnitName is the deterministic systemd unit basename for user (validated
// usernames are already safe as a plain unit name).
func (s *Scheduler) UnitName(user string) string { return s.UnitPrefix + user }

// RevokeCommand is the command the auto-revoke task runs.
func (s *Scheduler) RevokeCommand(user string) string {
	return fmt.Sprintf("%s revoke --user %s --yes", s.InstallPath, user)
}

// OnCalendar formats the absolute UTC trigger time for a systemd timer.
func OnCalendar(now time.Time, hours int) string {
	return now.UTC().Add(time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05 UTC")
}

func (s *Scheduler) serviceContent(user string) string {
	return fmt.Sprintf(`[Unit]
Description=linux-temp-admin auto revoke %s
Documentation=https://github.com/xxvcc/linux-temp-admin

[Service]
Type=oneshot
NoNewPrivileges=yes
PrivateTmp=yes
User=root
ExecStart=%s revoke --user %s --yes
`, user, s.InstallPath, user)
}

func timerContent(unit, onCalendar string) string {
	return fmt.Sprintf(`[Unit]
Description=linux-temp-admin auto revoke timer for %s

[Timer]
OnCalendar=%s
Persistent=true
AccuracySec=1min
Unit=%s.service

[Install]
WantedBy=timers.target
`, unit, onCalendar, unit)
}

// Schedule creates the auto-revoke task and returns its recorded identifier
// ("<unit>" for systemd or "at:<id>" for the fallback).
func (s *Scheduler) Schedule(user string, hours int) (string, error) {
	if s.Sys.HasSystemctl() {
		if unit, err := s.scheduleSystemd(user, hours); err == nil {
			return unit, nil
		}
	}
	return s.scheduleAt(user, hours)
}

func (s *Scheduler) scheduleSystemd(user string, hours int) (string, error) {
	unit := s.UnitName(user)
	if strings.ContainsAny(unit, "/ ") {
		return "", fmt.Errorf("invalid unit name %q", unit)
	}
	servicePath := filepath.Join(s.SystemdDir, unit+".service")
	timerPath := filepath.Join(s.SystemdDir, unit+".timer")
	if err := fsutil.WriteRootFile(servicePath, []byte(s.serviceContent(user)), 0o644); err != nil {
		return "", err
	}
	oc := OnCalendar(s.Now(), hours)
	if err := fsutil.WriteRootFile(timerPath, []byte(timerContent(unit, oc)), 0o644); err != nil {
		_ = os.Remove(servicePath)
		return "", err
	}
	if err := s.Sys.Systemctl("daemon-reload"); err != nil {
		_ = os.Remove(servicePath)
		_ = os.Remove(timerPath)
		return "", err
	}
	if err := s.Sys.Systemctl("enable", "--now", unit+".timer"); err != nil {
		_ = os.Remove(servicePath)
		_ = os.Remove(timerPath)
		_ = s.Sys.Systemctl("daemon-reload")
		return "", err
	}
	return unit, nil
}

func (s *Scheduler) scheduleAt(user string, hours int) (string, error) {
	if !s.Sys.HasAt() {
		return "", fmt.Errorf("no systemctl or at available; account expiry only")
	}
	id, err := s.Sys.ScheduleAt(s.RevokeCommand(user), hours)
	if err != nil {
		return "", err
	}
	return "at:" + id, nil
}

// Cancel removes the auto-revoke task for user. It always sweeps a matching at
// job AND cleans the systemd units, regardless of which was recorded, so a
// reused username never leaves a stale task behind. Only when this run is the
// firing service for THIS unit (UnderUnit) is the .service file left and
// daemon-reload skipped, so it never deletes the file it is executing from; a
// manual revoke — even from another systemd scope — cleans the .service up.
func (s *Scheduler) Cancel(user, recordedUnit string) {
	// Remove a specifically-recorded at job even where atq is unavailable (so
	// RemoveAtJobsFor's body sweep can't run).
	if strings.HasPrefix(recordedUnit, "at:") {
		s.Sys.AtrmJob(strings.TrimPrefix(recordedUnit, "at:"))
	}
	s.Sys.RemoveAtJobsFor(s.RevokeCommand(user))

	unit := s.UnitName(user)
	if strings.ContainsAny(unit, "/ ") {
		return
	}
	if s.Sys.HasSystemctl() {
		_ = s.Sys.Systemctl("disable", "--now", unit+".timer")
		_ = s.Sys.Systemctl("reset-failed", unit+".timer", unit+".service")
	}
	timerPath := filepath.Join(s.SystemdDir, unit+".timer")
	removeIfNotSymlink(timerPath)
	if s.UnderUnit == nil || !s.UnderUnit(unit) {
		removeIfNotSymlink(filepath.Join(s.SystemdDir, unit+".service"))
		if s.Sys.HasSystemctl() {
			_ = s.Sys.Systemctl("daemon-reload")
		}
	}
}

func removeIfNotSymlink(path string) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		_ = os.Remove(path)
	}
}
