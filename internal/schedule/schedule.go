// Package schedule creates and cancels the auto-revoke task that deletes a
// temporary account at expiry. It prefers a systemd timer (absolute OnCalendar
// in UTC) and falls back to an at job. Cancellation always cleans BOTH a systemd
// unit and any matching at job, so a reused username cannot leave a stale task
// that later deletes a fresh account.
package schedule

import (
	"errors"
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
	RemoveAtJobsFor(command string) error
	// AtrmJob removes a specific at job by id. An already-absent job is success.
	AtrmJob(id string) error
	// AtJobs returns queued job bodies so uninstall can inventory jobs whose
	// registry row has been lost.
	AtJobs() ([]AtJob, error)
}

type AtJob struct {
	ID   string
	Body string
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

// RevokeCommand is the command the auto-revoke task runs at expiry.
//
// It carries the UID and a random generation token recorded with the account.
// Revoke requires both to match the current registry row before an unattended
// deletion can proceed, so a stale task cannot delete a replacement account even
// when Linux reuses the same username and UID. The force confirmation is retained
// for command-line compatibility, but it cannot bypass the generation check.
func (s *Scheduler) RevokeCommand(user string, uid int, generation string) string {
	return fmt.Sprintf("%s revoke --user %s --yes --force --confirm-force %s --expected-uid %d --generation %s",
		s.InstallPath, user, user, uid, generation)
}

// revokeAtNeedle is the stable substring used to FIND this account's queued at
// job, as opposed to the full command used to queue it. It must match jobs queued
// by any version of this tool, so it stops at "--yes" — the part every past and
// present RevokeCommand shares — and does not include the newer --force tokens.
func (s *Scheduler) revokeAtNeedle(user string) string {
	return fmt.Sprintf("%s revoke --user %s --yes", s.InstallPath, user)
}

// OnCalendar formats the absolute UTC trigger time for a systemd timer.
func OnCalendar(now time.Time, hours int) string {
	return now.UTC().Add(time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05 UTC")
}

func (s *Scheduler) serviceContent(user string, uid int, generation string) string {
	return fmt.Sprintf(`[Unit]
Description=linux-temp-admin auto revoke %s
Documentation=https://github.com/xxvcc/linux-temp-admin
StartLimitIntervalSec=1h
StartLimitBurst=12

[Service]
Type=oneshot
NoNewPrivileges=yes
PrivateTmp=yes
User=root
ExecStart=%s
Restart=on-failure
RestartSec=5min
`, user, s.RevokeCommand(user, uid, generation))
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
//
// When systemd is present but scheduling on it fails, the real cause (a read-only
// /etc/systemd/system, a daemon-reload failure) is kept and, if the at fallback
// then also fails, reported alongside it. Discarding the systemd error made a
// systemd host that could not write a unit report the fallback's misleading "no
// systemctl or at available", sending the operator to debug a missing tool that
// was in fact present.
func (s *Scheduler) Schedule(user string, uid int, generation string, hours int) (string, error) {
	var systemdErr error
	if s.Sys.HasSystemctl() {
		unit, err := s.scheduleSystemd(user, uid, generation, hours)
		if err == nil {
			return unit, nil
		}
		systemdErr = err
	}
	unit, atErr := s.scheduleAt(user, uid, generation, hours)
	if atErr != nil && systemdErr != nil {
		return "", fmt.Errorf("systemd: %w; at fallback: %v", systemdErr, atErr)
	}
	return unit, atErr
}

func (s *Scheduler) scheduleSystemd(user string, uid int, generation string, hours int) (string, error) {
	unit := s.UnitName(user)
	if strings.ContainsAny(unit, "/ ") {
		return "", fmt.Errorf("invalid unit name %q", unit)
	}
	servicePath := filepath.Join(s.SystemdDir, unit+".service")
	timerPath := filepath.Join(s.SystemdDir, unit+".timer")
	if err := fsutil.WriteRootFile(servicePath, []byte(s.serviceContent(user, uid, generation)), 0o644); err != nil {
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

func (s *Scheduler) scheduleAt(user string, uid int, generation string, hours int) (string, error) {
	if !s.Sys.HasAt() {
		return "", fmt.Errorf("no systemctl or at available; account expiry only")
	}
	id, err := s.Sys.ScheduleAt(s.RevokeCommand(user, uid, generation), hours)
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
func (s *Scheduler) Cancel(user, recordedUnit string) error {
	var errs []error
	// Remove a specifically-recorded at job even where atq is unavailable (so
	// RemoveAtJobsFor's body sweep can't run).
	if strings.HasPrefix(recordedUnit, "at:") {
		if err := s.Sys.AtrmJob(strings.TrimPrefix(recordedUnit, "at:")); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.Sys.RemoveAtJobsFor(s.revokeAtNeedle(user)); err != nil {
		errs = append(errs, err)
	}

	// Cancel every unit namespace that could name this account, not only the one
	// this build writes. A v1 unit carries no "-v2-" infix and v1's install path
	// was identical to v2's, so a v1 timer left enabled fires THIS binary — and if
	// an uninstall then removes the binary, that timer fails forever. Disabling by
	// the v2 name alone would leave it armed. There is normally at most one unit per
	// account, so the extra names are no-ops on a pure-v2 host.
	reloadNeeded := false
	skipReload := false
	for _, prefix := range s.unitPrefixes() {
		unit := prefix + user
		if strings.ContainsAny(unit, "/ ") {
			continue
		}
		timerPath := filepath.Join(s.SystemdDir, unit+".timer")
		servicePath := filepath.Join(s.SystemdDir, unit+".service")
		_, timerErr := os.Lstat(timerPath)
		_, serviceErr := os.Lstat(servicePath)
		hadUnit := timerErr == nil || serviceErr == nil
		if s.Sys.HasSystemctl() {
			if err := s.Sys.Systemctl("disable", "--now", unit+".timer"); err != nil && hadUnit {
				errs = append(errs, err)
			}
			_ = s.Sys.Systemctl("reset-failed", unit+".timer", unit+".service")
		}
		if removed, err := removeIfNotSymlink(timerPath); err != nil {
			errs = append(errs, err)
		} else if removed {
			reloadNeeded = true
		}
		// Never delete the .service this very run is executing from (a firing v2
		// auto-revoke); a manual revoke, even from another systemd scope, does clean
		// it. The firing unit is always the v2 one, so this only guards that name.
		underUnit := s.UnderUnit != nil && s.UnderUnit(unit)
		if underUnit {
			skipReload = true
		} else {
			if removed, err := removeIfNotSymlink(servicePath); err != nil {
				errs = append(errs, err)
			} else if removed {
				reloadNeeded = true
			}
		}
	}
	if reloadNeeded && !skipReload && s.Sys.HasSystemctl() {
		if err := s.Sys.Systemctl("daemon-reload"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeIfNotSymlink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing to remove symlinked schedule file %s", path)
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	return true, nil
}
