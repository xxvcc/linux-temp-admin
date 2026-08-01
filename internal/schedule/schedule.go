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
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// System abstracts the external schedulers so orchestration is testable.
type System interface {
	HasSystemctl() bool
	Systemctl(args ...string) error
	// HasAt reports any installed at-backend footprint. A completely absent
	// backend is not an inventory error; a partial backend is and must fail closed.
	HasAt() bool
	// ScheduleAt queues command for the absolute, minute-aligned deadline and
	// returns its canonical positive decimal job id. If it returns an error after
	// an ambiguous submission, it first attempts to remove every queued job whose
	// body contains that exact standalone command.
	ScheduleAt(command string, deadline time.Time) (jobID string, err error)
	// RemoveAtJobsFor removes queued jobs matching a known standalone revoke
	// command selected by command's legacy-compatible prefix.
	RemoveAtJobsFor(command string) error
	// AtrmJob removes a specific at job by id. An already-absent job is success.
	AtrmJob(id string) error
	// AtJobs returns queued job bodies and their generated owner UID so uninstall
	// can inventory root-created jobs whose registry row has been lost. Missing
	// inventory commands or an unparseable owner header are errors.
	AtJobs() ([]AtJob, error)
}

type AtJob struct {
	ID       string
	Body     string
	OwnerUID uint32
}

// Scheduler writes units / queues jobs. Paths and time source are fields for tests.
type Scheduler struct {
	SystemdDir           string
	SystemdTimerStateDir string
	InstallPath          string
	UnitPrefix           string
	// LegacyUnitPrefixes are older namespaces whose units this Scheduler must still
	// be able to FIND (see UnitUsers) though it never writes them. It is a field
	// rather than a constant so a test can point the whole namespace at a temp dir
	// without picking up the real one.
	LegacyUnitPrefixes []string
	Now                func() time.Time
	Sys                System
}

// New returns a Scheduler backed by real systemctl/at.
func New() *Scheduler {
	return &Scheduler{
		SystemdDir:           config.SystemdDir,
		SystemdTimerStateDir: config.SystemdTimerStateDir,
		InstallPath:          config.InstallPath,
		UnitPrefix:           config.AutoRevokeUnitPrefix,
		// v1's units are still findable, never written. v1 installed to the same path
		// this binary occupies, so its timers invoke THIS code and its accounts strand
		// exactly like v2's would.
		LegacyUnitPrefixes: []string{config.V1AutoRevokeUnitPrefix, config.QuarantineUnitPrefix},
		Now:                time.Now,
		Sys:                realSystem{},
	}
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

// revokeAtNeedle is the stable selector used to find this account's queued at
// job. The matcher accepts only complete command forms emitted by known releases,
// but this selector stops at "--yes" so it covers all of those forms.
func (s *Scheduler) revokeAtNeedle(user string) string {
	return fmt.Sprintf("%s revoke --user %s --yes", s.InstallPath, user)
}

// OnCalendar formats the absolute UTC trigger time for a systemd timer.
func OnCalendar(deadline time.Time) string {
	return deadline.UTC().Format("2006-01-02 15:04:05 UTC")
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
	return timerContentWithAccuracy(unit, onCalendar, "1us")
}

// legacyTimerContent is accepted only when inventorying timers written by
// releases that used systemd's one-minute coalescing window.
func legacyTimerContent(unit, onCalendar string) string {
	return timerContentWithAccuracy(unit, onCalendar, "1min")
}

func timerContentWithAccuracy(unit, onCalendar, accuracy string) string {
	return fmt.Sprintf(`[Unit]
Description=linux-temp-admin auto revoke timer for %s

[Timer]
OnCalendar=%s
Persistent=true
AccuracySec=%s
Unit=%s.service

[Install]
WantedBy=timers.target
`, unit, onCalendar, accuracy, unit)
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
func (s *Scheduler) Schedule(user string, uid int, generation string, deadline time.Time) (string, error) {
	if !validate.Username(user) {
		return "", fmt.Errorf("invalid temporary username %q", user)
	}
	if !validate.AccountID(uid) {
		return "", fmt.Errorf("invalid Linux account UID %d", uid)
	}
	if !validate.Generation(generation) {
		return "", fmt.Errorf("invalid account generation %q", generation)
	}
	if s == nil || s.Sys == nil {
		return "", fmt.Errorf("no scheduler backend configured")
	}
	now := s.now()
	if !validDeadline(now, deadline) {
		return "", fmt.Errorf("invalid auto-revoke deadline %s", deadline.Format(time.RFC3339Nano))
	}
	deadline = deadline.UTC()
	var systemdErr error
	if s.Sys.HasSystemctl() {
		unit, err := s.scheduleSystemd(user, uid, generation, deadline)
		if err == nil {
			return unit, nil
		}
		systemdErr = err
		var rollbackErr *systemdRollbackError
		if errors.As(err, &rollbackErr) {
			return "", fmt.Errorf("systemd: %w", err)
		}
	}
	unit, atErr := s.scheduleAt(user, uid, generation, deadline)
	if atErr != nil && systemdErr != nil {
		return "", fmt.Errorf("systemd: %w; at fallback: %v", systemdErr, atErr)
	}
	return unit, atErr
}

// ScheduleQuarantine creates a systemd-only finalizer in a separate namespace.
// The original expiry task may be firing while revoke performs this handoff, so
// the two unit names must coexist until the quarantine row is durable. Hosts
// without a reliable systemd backend use the synchronous drain fallback instead.
func (s *Scheduler) ScheduleQuarantine(user string, uid int, generation string, deadline time.Time) (string, error) {
	if !validate.Username(user) || !validate.AccountID(uid) || !validate.Generation(generation) {
		return "", fmt.Errorf("invalid quarantine schedule identity")
	}
	if s == nil || s.Sys == nil || !s.Sys.HasSystemctl() {
		return "", fmt.Errorf("persistent systemd quarantine is unavailable")
	}
	if !validDeadline(s.now(), deadline) {
		return "", fmt.Errorf("invalid quarantine deadline %s", deadline.Format(time.RFC3339Nano))
	}
	q := *s
	q.UnitPrefix = config.QuarantineUnitPrefix
	q.LegacyUnitPrefixes = nil
	return q.scheduleSystemd(user, uid, generation, deadline.UTC())
}

// CancelAuto removes only expiry-era namespaces, leaving a just-created
// quarantine finalizer intact during the handoff.
func (s *Scheduler) CancelAuto(user, recordedUnit string) error {
	if s == nil {
		return fmt.Errorf("no scheduler backend configured")
	}
	auto := *s
	auto.LegacyUnitPrefixes = []string{config.V1AutoRevokeUnitPrefix}
	return auto.Cancel(user, recordedUnit)
}

// CancelQuarantine removes only the asynchronous deletion finalizer namespace.
func (s *Scheduler) CancelQuarantine(user, recordedUnit string) error {
	if s == nil || s.Sys == nil {
		return fmt.Errorf("no scheduler backend configured")
	}
	q := *s
	q.UnitPrefix = config.QuarantineUnitPrefix
	q.LegacyUnitPrefixes = nil
	q.Sys = systemdOnlySystem{System: s.Sys}
	return q.Cancel(user, recordedUnit)
}

// systemdOnlySystem prevents quarantine cleanup from sweeping an unrelated
// expiry-era at job. Quarantine scheduling never uses at; the wrapper retains
// only the systemd operations needed by Cancel.
type systemdOnlySystem struct{ System }

func (s systemdOnlySystem) HasAt() bool { return false }
func (s systemdOnlySystem) ScheduleAt(string, time.Time) (string, error) {
	return "", fmt.Errorf("at is disabled for identity quarantine")
}
func (s systemdOnlySystem) RemoveAtJobsFor(string) error { return nil }
func (s systemdOnlySystem) AtrmJob(string) error         { return nil }
func (s systemdOnlySystem) AtJobs() ([]AtJob, error)     { return nil, nil }

func (s *Scheduler) scheduleSystemd(user string, uid int, generation string, deadline time.Time) (string, error) {
	if !validManagedUnitPrefix(s.UnitPrefix) {
		return "", fmt.Errorf("unsafe managed systemd unit prefix %q", s.UnitPrefix)
	}
	unit := s.UnitName(user)
	servicePath := filepath.Join(s.SystemdDir, unit+".service")
	timerPath := filepath.Join(s.SystemdDir, unit+".timer")
	if err := fsutil.WriteRootFile(servicePath, []byte(s.serviceContent(user, uid, generation)), 0o644); err != nil {
		var committed *fsutil.DurabilityError
		if errors.As(err, &committed) {
			return "", systemdWriteRollback(err, servicePath)
		}
		return "", err
	}
	oc := OnCalendar(deadline)
	if err := fsutil.WriteRootFile(timerPath, []byte(timerContent(unit, oc)), 0o644); err != nil {
		var committed *fsutil.DurabilityError
		if errors.As(err, &committed) {
			return "", systemdWriteRollback(err, timerPath, servicePath)
		}
		return "", systemdWriteRollback(err, servicePath)
	}
	if err := s.Sys.Systemctl("daemon-reload"); err != nil {
		return "", systemdWriteRollback(err, timerPath, servicePath)
	}
	if err := s.Sys.Systemctl("enable", "--now", unit+".timer"); err != nil {
		return "", s.rollbackFailedEnable(unit, servicePath, timerPath, err)
	}
	return unit, nil
}

func (s *Scheduler) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func validDeadline(now, deadline time.Time) bool {
	if deadline.IsZero() || deadline.Second() != 0 || deadline.Nanosecond() != 0 || !deadline.After(now) {
		return false
	}
	maxDelay := time.Duration(config.MaxExpireHours)*time.Hour + time.Minute
	return deadline.Sub(now) <= maxDelay
}

func systemdWriteRollback(cause error, paths ...string) error {
	errs := []error{cause}
	rollbackFailed := false
	for _, path := range paths {
		if err := fsutil.RemoveFile(path); err != nil {
			errs = append(errs, fmt.Errorf("remove partially committed file %s: %w", path, err))
			rollbackFailed = true
		}
	}
	joined := errors.Join(errs...)
	if rollbackFailed {
		return &systemdRollbackError{err: joined}
	}
	return joined
}

type systemdRollbackError struct{ err error }

func (e *systemdRollbackError) Error() string { return e.err.Error() }
func (e *systemdRollbackError) Unwrap() error { return e.err }

func (s *Scheduler) rollbackFailedEnable(unit, servicePath, timerPath string, enableErr error) error {
	errs := []error{fmt.Errorf("enable systemd timer: %w", enableErr)}
	rollbackFailed := false
	timerUnit := unit + ".timer"
	if err := s.disableAndConfirmTimerStopped(timerUnit); err != nil {
		errs = append(errs, fmt.Errorf("rollback disable systemd timer: %w", err))
		// enable --now may have started the timer before returning its error. If
		// stopping it cannot be confirmed, keep both files as durable inventory and
		// retry evidence; deleting them can leave the only surviving timer hidden in
		// systemd's in-memory state.
		return &systemdRollbackError{err: errors.Join(errs...)}
	}
	if err := s.removeSystemdTimerStamp(timerUnit); err != nil {
		errs = append(errs, err)
		rollbackFailed = true
	}
	for _, path := range []string{timerPath, servicePath} {
		if err := fsutil.RemoveFile(path); err != nil {
			errs = append(errs, fmt.Errorf("rollback remove %s: %w", path, err))
			rollbackFailed = true
		}
	}
	if err := s.Sys.Systemctl("daemon-reload"); err != nil {
		errs = append(errs, fmt.Errorf("rollback daemon-reload: %w", err))
		rollbackFailed = true
	}
	joined := errors.Join(errs...)
	if rollbackFailed {
		return &systemdRollbackError{err: joined}
	}
	return joined
}

// disableAndConfirmTimerStopped handles systemctl's split disable/--now
// implementation. When the unit file is missing, `disable --now` returns before
// it reaches the stop phase, even though an already-loaded timer may still be
// active in the manager. Treat that diagnostic only as a reason to explicitly
// stop the loaded timer and confirm its final state, never as proof it stopped.
func (s *Scheduler) disableAndConfirmTimerStopped(timerUnit string) error {
	disableErr := s.Sys.Systemctl("disable", "--now", timerUnit)
	if disableErr == nil {
		return nil
	}
	if !systemctlUnitFileMissing(disableErr, timerUnit) {
		return disableErr
	}

	stopErr := s.Sys.Systemctl("stop", timerUnit)
	if stopErr != nil {
		if systemctlStopUnitNotLoaded(stopErr, timerUnit) {
			return nil
		}
		return errors.Join(
			fmt.Errorf("disable systemd timer: %w", disableErr),
			fmt.Errorf("stop missing-file timer: %w", stopErr),
		)
	}

	stateErr := s.Sys.Systemctl("is-active", timerUnit)
	if stateErr == nil {
		return errors.Join(
			fmt.Errorf("disable systemd timer: %w", disableErr),
			fmt.Errorf("timer %s remains active after stop", timerUnit),
		)
	}
	if !systemctlTimerStoppedState(stateErr, timerUnit) {
		return errors.Join(
			fmt.Errorf("disable systemd timer: %w", disableErr),
			fmt.Errorf("confirm timer stopped: %w", stateErr),
		)
	}
	return nil
}

func (s *Scheduler) scheduleAt(user string, uid int, generation string, deadline time.Time) (string, error) {
	if !s.Sys.HasAt() {
		return "", fmt.Errorf("no systemctl or at available")
	}
	if !deadline.After(s.now()) {
		return "", fmt.Errorf("auto-revoke deadline %s passed before the at fallback could be queued", deadline.Format(time.RFC3339))
	}
	command := s.RevokeCommand(user, uid, generation)
	id, err := s.Sys.ScheduleAt(command, deadline)
	if err != nil {
		return "", err
	}
	if !numericJobID(id) {
		cause := fmt.Errorf("at scheduler returned invalid job id %q", id)
		if cleanupErr := s.Sys.RemoveAtJobsFor(s.revokeAtNeedle(user)); cleanupErr != nil {
			return "", errors.Join(cause, fmt.Errorf("sweep jobs after invalid at id: %w", cleanupErr))
		}
		return "", cause
	}
	return "at:" + id, nil
}

// Cancel removes the auto-revoke task for user. It always sweeps a matching at
// job AND cleans the systemd units, regardless of which was recorded, so a
// reused username never leaves a stale task behind. A firing oneshot may unlink
// its own unit file safely: systemd has already
// loaded the unit and the file is not the running process image. Removing both
// files and reloading prevents every successful automatic revoke from leaving a
// permanent orphaned .service behind.
func (s *Scheduler) Cancel(user, recordedUnit string) error {
	if !validate.Username(user) {
		return fmt.Errorf("invalid temporary username %q", user)
	}
	if s == nil || s.Sys == nil {
		return fmt.Errorf("no scheduler backend configured")
	}
	var errs []error
	hasSystemctl := s.Sys.HasSystemctl()
	prefixes := s.unitPrefixes()
	validPrefixes := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !validManagedUnitPrefix(prefix) {
			errs = append(errs, fmt.Errorf("unsafe managed systemd unit prefix %q", prefix))
			continue
		}
		validPrefixes = append(validPrefixes, prefix)
	}
	// A recorded at id is inventory evidence, not deletion authority. at job ids
	// are eventually reusable, so handing a stale id directly to atrm can remove an
	// unrelated job that later acquired the same number. The body sweep below is
	// the only safe removal path: it accepts only standalone revoke commands emitted
	// by known releases. If that inventory backend has disappeared, preserve the
	// registry evidence and fail closed instead of guessing from the id.
	if strings.HasPrefix(recordedUnit, "at:") {
		id := strings.TrimPrefix(recordedUnit, "at:")
		if !numericJobID(id) {
			errs = append(errs, fmt.Errorf("unsupported recorded auto-revoke identifier %q", recordedUnit))
		} else if !s.Sys.HasAt() {
			errs = append(errs, fmt.Errorf("at backend is unavailable; cannot verify recorded auto-revoke job %s before preserving its registry evidence", id))
		}
	} else if recordedUnit != "" {
		known := false
		for _, prefix := range validPrefixes {
			if recordedUnit == prefix+user {
				known = true
				break
			}
		}
		if !known {
			errs = append(errs, fmt.Errorf("unsupported recorded auto-revoke identifier %q", recordedUnit))
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
	for _, prefix := range validPrefixes {
		unit := prefix + user
		if strings.ContainsAny(unit, "/ ") {
			continue
		}
		timerPath := filepath.Join(s.SystemdDir, unit+".timer")
		servicePath := filepath.Join(s.SystemdDir, unit+".service")
		if !hasSystemctl {
			hasUnitEvidence := recordedUnit == unit
			for _, path := range []string{timerPath, servicePath} {
				exists, err := schedulePathExists(path)
				if err != nil {
					errs = append(errs, err)
					hasUnitEvidence = true
				} else if exists {
					hasUnitEvidence = true
				}
			}
			if hasUnitEvidence {
				errs = append(errs, fmt.Errorf("systemctl is unavailable; cannot confirm %s.timer is stopped, preserving its unit files and registry evidence", unit))
				continue
			}
		}
		if hasSystemctl {
			timerUnit := unit + ".timer"
			if err := s.disableAndConfirmTimerStopped(timerUnit); err != nil {
				errs = append(errs, err)
				// Preserve both files as retry/inventory evidence. Deleting them after
				// a stop failure can leave a timer active only in systemd's memory.
				continue
			}
			_ = s.Sys.Systemctl("reset-failed", unit+".timer", unit+".service")
			if err := s.removeSystemdTimerStamp(timerUnit); err != nil {
				errs = append(errs, err)
			}
		}
		if _, err := removeIfNotSymlink(timerPath); err != nil {
			errs = append(errs, err)
		}
		if _, err := removeIfNotSymlink(servicePath); err != nil {
			errs = append(errs, err)
		}
	}
	if hasSystemctl {
		// Always reload, even when both files were already absent. ScheduledUsers can
		// discover a managed timer that survives only in PID 1's manager state; after
		// stopping it, daemon-reload is what drops the deleted fragment. It also makes
		// a retry repair an earlier cleanup whose file removals committed before its
		// daemon-reload failed.
		if err := s.Sys.Systemctl("daemon-reload"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Scheduler) removeSystemdTimerStamp(timerUnit string) error {
	stateDir, configured, err := s.systemdTimerStateDirectory()
	if err != nil {
		return err
	}
	if !configured {
		return nil
	}
	if filepath.Base(timerUnit) != timerUnit || !strings.HasSuffix(timerUnit, ".timer") {
		return fmt.Errorf("invalid systemd timer unit %q", timerUnit)
	}
	stampPath := filepath.Join(stateDir, "stamp-"+timerUnit)
	if err := fsutil.RemoveFile(stampPath); err != nil {
		return fmt.Errorf("remove systemd timer timestamp %s: %w", stampPath, err)
	}
	return nil
}

// CleanupTimerStamps removes persistent-timer timestamps left by older
// releases after their unit and registry evidence had already disappeared. It
// is intended for the final uninstall sweep, after callers have proved no
// managed timer remains active. Removing a stamp while its timer is live would
// alter systemd's catch-up behavior after a reboot, so ordinary cleanup uses
// Cancel instead.
func (s *Scheduler) CleanupTimerStamps() error {
	stateDir, configured, err := s.systemdTimerStateDirectory()
	if err != nil {
		return err
	}
	if !configured {
		return nil
	}
	entries, err := os.ReadDir(stateDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read systemd timer state directory %s: %w", stateDir, err)
	}

	var errs []error
	for _, entry := range entries {
		if !s.managedTimerStamp(entry.Name()) {
			continue
		}
		path := filepath.Join(stateDir, entry.Name())
		if err := fsutil.RemoveFile(path); err != nil {
			errs = append(errs, fmt.Errorf("remove systemd timer timestamp %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Scheduler) systemdTimerStateDirectory() (string, bool, error) {
	if s == nil || s.SystemdTimerStateDir == "" {
		return "", false, nil
	}
	stateDir := filepath.Clean(s.SystemdTimerStateDir)
	if !filepath.IsAbs(stateDir) || stateDir == string(filepath.Separator) {
		return "", false, fmt.Errorf("unsafe systemd timer state directory %q", s.SystemdTimerStateDir)
	}
	return stateDir, true, nil
}

func (s *Scheduler) managedTimerStamp(name string) bool {
	if !strings.HasSuffix(name, ".timer") {
		return false
	}
	for _, prefix := range s.unitPrefixes() {
		if !validManagedUnitPrefix(prefix) {
			continue
		}
		stem := strings.TrimSuffix(strings.TrimPrefix(name, "stamp-"+prefix), ".timer")
		if strings.HasPrefix(name, "stamp-"+prefix) && stem != "" {
			return true
		}
	}
	return false
}

func schedulePathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("inspect schedule file %s: %w", path, err)
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
	if err := fsutil.RemoveFile(path); err != nil {
		return false, err
	}
	return true, nil
}
