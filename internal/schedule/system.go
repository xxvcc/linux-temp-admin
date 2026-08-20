package schedule

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/atqueue"
	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

const (
	schedulerCommandTimeout = 15 * time.Second
	schedulerOutputLimit    = int64(64 << 10)
	atQueueOutputLimit      = int64(4 << 20)
	atJobBodyLimit          = int64(1 << 20)
	atOwnerProbeLimit       = int64(64 << 10)
	maxLoadedSystemdUnits   = 16384
)

var (
	stableCommandLocale     = []string{"LC_ALL=C", "LANG=C"}
	atInventoryTimeout      = 30 * time.Second
	atInventoryMaxBodyBytes = int64(16 << 20)
)

func schedulerCommandOptions(maxOutput int64) executil.Options {
	return executil.Options{
		Timeout: schedulerCommandTimeout, MaxOutput: maxOutput,
		ExtraEnv: stableCommandLocale,
	}
}

// realSystem drives systemctl and at via os/exec.
type realSystem struct{}

// systemctlError retains the command and its output so callers can classify the
// small set of failures that are safe to treat as idempotent success without
// hiding unrelated systemd, permission, or D-Bus errors.
type systemctlError struct {
	args   []string
	err    error
	output string
}

func (e *systemctlError) Error() string {
	return fmt.Sprintf("systemctl %s: %v: %s", strings.Join(e.args, " "), e.err, e.output)
}

func (e *systemctlError) Unwrap() error { return e.err }

func has(name string) bool { _, err := exec.LookPath(name); return err == nil }

func (realSystem) HasSystemctl() bool { return has("systemctl") }
func (realSystem) HasAt() bool {
	return has("at") || has("atq") || has("atrm") || has("atd") || has("batch")
}

func (realSystem) Systemctl(args ...string) error {
	// Classification below relies on systemctl's diagnostics. Force the stable C
	// locale instead of trying to recognize every translated error message.
	out, err := executil.CombinedOutput("systemctl", args, schedulerCommandOptions(schedulerOutputLimit))
	if err != nil {
		return &systemctlError{
			args:   append([]string(nil), args...),
			err:    err,
			output: strings.TrimSpace(string(out)),
		}
	}
	return nil
}

// loadedSystemdUnits inventories the manager, not only unit files on disk.
// A timer whose file was removed before daemon-reload can remain loaded and
// armed, so uninstall must still be able to derive its account name.
func (realSystem) loadedSystemdUnits() ([]string, error) {
	if !has("systemctl") {
		return nil, fmt.Errorf("systemctl is unavailable")
	}
	args := []string{
		"list-units", "--all", "--type=service", "--type=timer",
		"--plain", "--full", "--no-legend", "--no-pager",
	}
	out, err := executil.Output("systemctl", args, schedulerCommandOptions(atQueueOutputLimit))
	if err != nil {
		return nil, fmt.Errorf("systemctl list loaded schedule units: %w", err)
	}
	return parseLoadedSystemdUnits(string(out))
}

func parseLoadedSystemdUnits(out string) ([]string, error) {
	var units []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1024), int(schedulerOutputLimit))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// list-units always emits UNIT LOAD ACTIVE SUB, with DESCRIPTION optional.
		if len(fields) < 4 || (!strings.HasSuffix(fields[0], ".service") && !strings.HasSuffix(fields[0], ".timer")) {
			return nil, fmt.Errorf("parse systemctl list-units line %d: %q", lineNo, line)
		}
		unit := fields[0]
		if seen[unit] {
			return nil, fmt.Errorf("parse systemctl list-units line %d: duplicate unit %q", lineNo, unit)
		}
		seen[unit] = true
		units = append(units, unit)
		if len(units) > maxLoadedSystemdUnits {
			return nil, fmt.Errorf("systemd manager contains more than %d loaded service/timer units", maxLoadedSystemdUnits)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse systemctl list-units: %w", err)
	}
	return units, nil
}

// systemctlUnitFileMissing reports only the exact C-locale failures produced when
// `systemctl disable --now` races with (or follows) removal of its target unit.
// systemd 256 and later dropped "file" and the final period from this diagnostic.
// Neither form is success by itself: systemctl returns from the disable phase
// before --now reaches stop, so callers must independently confirm the timer is
// inactive.
func systemctlUnitFileMissing(err error, unit string) bool {
	var commandErr *systemctlError
	if !errors.As(err, &commandErr) || len(commandErr.args) != 3 {
		return false
	}
	if commandErr.args[0] != "disable" || commandErr.args[1] != "--now" || commandErr.args[2] != unit {
		return false
	}
	oldDiagnostic := fmt.Sprintf("Failed to disable unit: Unit file %s does not exist.", unit)
	modernDiagnostic := fmt.Sprintf("Failed to disable unit: Unit %s does not exist", unit)
	return commandErr.output == oldDiagnostic || commandErr.output == modernDiagnostic
}

func systemctlStopUnitNotLoaded(err error, unit string) bool {
	var commandErr *systemctlError
	if !errors.As(err, &commandErr) || len(commandErr.args) != 2 ||
		commandErr.args[0] != "stop" || commandErr.args[1] != unit {
		return false
	}
	want := fmt.Sprintf("Failed to stop %s: Unit %s not loaded.", unit, unit)
	return commandErr.output == want
}

// systemctlTimerStoppedState accepts only explicit non-running states from the
// non-quiet `is-active` query used after a successful stop. Exit status 3 alone
// is insufficient because systemd also uses it for "activating".
func systemctlTimerStoppedState(err error, timer string) bool {
	var commandErr *systemctlError
	if !errors.As(err, &commandErr) || len(commandErr.args) != 2 ||
		commandErr.args[0] != "is-active" || commandErr.args[1] != timer {
		return false
	}
	var exitErr *exec.ExitError
	if !errors.As(commandErr, &exitErr) {
		return errors.Is(commandErr, errSystemdUnitInactive) && commandErr.output == "inactive"
	}
	switch commandErr.output {
	case "inactive", "failed":
		return exitErr.ExitCode() == 3
	case "unknown":
		return exitErr.ExitCode() == 4
	default:
		return false
	}
}

func (realSystem) ScheduleAt(command string, deadline time.Time) (string, error) {
	for _, tool := range []string{"at", "atq", "atrm"} {
		if !has(tool) {
			return "", fmt.Errorf("%s is unavailable; refusing to create an at job that cannot be inventoried and cancelled", tool)
		}
	}
	if !ensureAtd() {
		return "", fmt.Errorf("atd is not running and could not be started; use systemd or start atd")
	}
	opts := schedulerCommandOptions(schedulerOutputLimit)
	// POSIX at -t is minute-granular and interprets its operand in the process
	// timezone. Force UTC so DST gaps/folds cannot move the job by an hour. at
	// copies its own environment into the queued script, so undo TZ before the
	// revoke command to preserve the host's normal timezone at execution.
	opts.ExtraEnv = append(opts.ExtraEnv, "TZ=UTC")
	opts.Stdin = strings.NewReader("unset TZ\n" + command + "\n")
	atTime := deadline.UTC().Format("200601021504")
	out, err := executil.CombinedOutput("at", []string{"-t", atTime}, opts)
	if err != nil {
		cause := fmt.Errorf("at: %w: %s", err, strings.TrimSpace(string(out)))
		return "", (realSystem{}).cleanupAmbiguousAtSubmission(command, cause)
	}
	id := parseAtJobID(string(out))
	if id == "" {
		cause := fmt.Errorf("could not parse at job id from %q", string(out))
		return "", (realSystem{}).cleanupAmbiguousAtSubmission(command, cause)
	}
	return id, nil
}

// cleanupAmbiguousAtSubmission closes the commit-unknown window where `at` may
// have queued a job before its process failed or emitted an unparseable id. The
// current revoke command contains a random account generation, so exact-command
// matches are owned retries of this same scheduling attempt rather than a broad
// username selector. Inventory/removal uncertainty is joined with the original
// error so the caller cannot mistake an unconfirmed rollback for a clean failure.
func (r realSystem) cleanupAmbiguousAtSubmission(command string, cause error) error {
	errs := []error{cause}
	jobs, err := r.AtJobs()
	if err != nil {
		return errors.Join(cause, fmt.Errorf("inventory at jobs after ambiguous submission: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), atInventoryTimeout)
	defer cancel()
	for _, job := range jobs {
		if job.OwnerUID != 0 || !atBodyHasExactCommand(job.Body, command) {
			continue
		}
		err := r.removeAtJobIf(ctx, job.ID, func(body string) (bool, error) {
			return rootAtBodyMatches(body, func(body string) (bool, error) {
				return atBodyHasExactCommand(body, command), nil
			})
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("roll back ambiguously submitted at job %s: %w", job.ID, err))
		}
	}
	return errors.Join(errs...)
}

// parseAtJobID accepts exactly one C-locale submission record ("job 7 at ...").
// Choosing the first of multiple candidates, or an unrelated numeric line, can
// record another user's job while leaving the newly queued revoke untracked.
func parseAtJobID(out string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1024), int(schedulerOutputLimit))
	id := ""
	matches := 0
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[0] == "job" && fields[2] == "at" && atqueue.ValidJobID(fields[1]) {
			id = fields[1]
			matches++
		}
	}
	if sc.Err() != nil || matches != 1 {
		return ""
	}
	return id
}

// ensureAtd confirms or starts the atd daemon so queued jobs actually fire. It
// fails closed when no available service manager or process probe can confirm it.
func ensureAtd() bool {
	run := func(name string, args ...string) bool {
		return executil.Run(name, args, schedulerCommandOptions(schedulerOutputLimit)) == nil
	}
	// Try each init system in turn (not first-match), returning as soon as atd is
	// confirmed runnable; do not claim success without confirmation.
	if has("systemctl") {
		if run("systemctl", "is-active", "--quiet", "atd") {
			return true
		}
		_ = executil.Run("systemctl", []string{"enable", "--now", "atd"}, schedulerCommandOptions(schedulerOutputLimit))
		if run("systemctl", "is-active", "--quiet", "atd") {
			return true
		}
	}
	if has("rc-service") {
		if run("rc-service", "atd", "status") {
			return true
		}
		_ = executil.Run("rc-service", []string{"atd", "start"}, schedulerCommandOptions(schedulerOutputLimit))
		if run("rc-service", "atd", "status") {
			return true
		}
	}
	if has("service") {
		if run("service", "atd", "status") {
			return true
		}
		_ = run("service", "atd", "start")
		if run("service", "atd", "status") {
			return true
		}
	}
	if has("pgrep") {
		// atd starts as root and may drop its effective credentials to the daemon
		// account, but its real UID remains 0. Binding the fallback probe to real root
		// prevents an unprivileged process from spoofing only the short name "atd".
		return run("pgrep", "-x", "-U", "0", "atd")
	}
	return false
}

func (realSystem) AtrmJob(id string) error {
	if id == "" {
		return fmt.Errorf("empty at job id")
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return fmt.Errorf("invalid at job id %q", id)
		}
	}
	if !has("atrm") {
		return fmt.Errorf("atrm is unavailable")
	}
	// at removes a one-shot job from the queue before running its command. The
	// firing auto-revoke therefore sees its recorded job id as already absent;
	// that is the desired state, not a cleanup failure.
	if queued, err := atJobQueued(id); err == nil && !queued {
		return nil
	}
	if out, err := executil.CombinedOutput("atrm", []string{id}, schedulerCommandOptions(schedulerOutputLimit)); err != nil {
		// The job may have fired between the queue check and atrm. Confirm absence
		// once more before reporting the command failure.
		if queued, qerr := atJobQueued(id); qerr == nil && !queued {
			return nil
		}
		return fmt.Errorf("atrm %s: %w: %s", id, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func atJobQueued(id string) (bool, error) {
	return atJobQueuedContext(context.Background(), id)
}

func atJobQueuedContext(ctx context.Context, id string) (bool, error) {
	if !has("atq") {
		return false, fmt.Errorf("atq is unavailable")
	}
	opts := schedulerCommandOptions(atQueueOutputLimit)
	opts.Context = ctx
	out, err := executil.Output("atq", nil, opts)
	if err != nil {
		return false, fmt.Errorf("atq: %w", err)
	}
	ids, err := atqueue.ParseInventory(out, int(schedulerOutputLimit))
	if err != nil {
		return false, err
	}
	for _, queuedID := range ids {
		if queuedID == id {
			return true, nil
		}
	}
	return false, nil
}

func (r realSystem) RemoveAtJobsFor(command string) error {
	selector, ok := parseAtRevokeCommand(command, "")
	if !ok || selector.kind != atRevokeLegacy {
		return fmt.Errorf("invalid at revoke selector %q", command)
	}
	// `at` is an optional fallback. A systemd-only host with no trace of that
	// backend has nothing to sweep and must still be able to revoke and uninstall.
	// HasAt is deliberately true for a partial installation, so missing inventory
	// commands in that case remain an error instead of hiding a possibly-live job.
	if !r.HasAt() {
		return nil
	}
	jobs, err := r.AtJobs()
	if err != nil {
		return err
	}
	var errs []error
	ctx, cancel := context.WithTimeout(context.Background(), atInventoryTimeout)
	defer cancel()
	for _, job := range jobs {
		if job.OwnerUID != 0 {
			continue
		}
		match, inspectErr := atBodyHasKnownRevoke(job.Body, selector.installPath, selector.user)
		if inspectErr != nil {
			errs = append(errs, fmt.Errorf("inspect at job %s: %w", job.ID, inspectErr))
			continue
		}
		if match {
			if err := r.removeAtJobIf(ctx, job.ID, func(body string) (bool, error) {
				return rootAtBodyMatches(body, func(body string) (bool, error) {
					return atBodyHasKnownRevoke(body, selector.installPath, selector.user)
				})
			}); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// removeAtJobIf binds an at deletion to a fresh body read. At job IDs are
// eventually reusable, so a body observed during the earlier queue inventory is
// not authority to pass that ID to atrm later. If the ID now names an unrelated
// job, the original target is already gone and the replacement is preserved.
// GNU/POSIX at exposes no atomic compare-and-delete primitive; this recheck makes
// the remaining read-to-atrm interval as small as the external interface allows.
func (r realSystem) removeAtJobIf(ctx context.Context, id string, match func(string) (bool, error)) error {
	if !atqueue.ValidJobID(id) {
		return fmt.Errorf("invalid at job id %q", id)
	}
	if match == nil {
		return fmt.Errorf("at job matcher is not configured")
	}
	if !has("at") || !has("atq") || !has("atrm") {
		return fmt.Errorf("complete at inventory/removal tools are unavailable")
	}
	body, owner, present, err := readAtJobContext(ctx, id)
	if err != nil {
		return fmt.Errorf("revalidate at job %s before removal: %w", id, err)
	}
	if !present || owner != 0 {
		return nil
	}
	matched, err := match(body)
	if err != nil {
		return fmt.Errorf("revalidate at job %s before removal: %w", id, err)
	}
	if !matched {
		return nil
	}
	opts := schedulerCommandOptions(schedulerOutputLimit)
	opts.Context = ctx
	out, removeErr := executil.CombinedOutput("atrm", []string{id}, opts)
	current, currentOwner, stillPresent, inspectErr := readAtJobContext(ctx, id)
	if inspectErr != nil {
		if removeErr != nil {
			return errors.Join(
				fmt.Errorf("atrm %s: %w: %s", id, removeErr, strings.TrimSpace(string(out))),
				fmt.Errorf("recheck at job %s: %w", id, inspectErr),
			)
		}
		return fmt.Errorf("recheck at job %s after atrm success: %w", id, inspectErr)
	}
	if !stillPresent {
		return nil
	}
	if currentOwner != 0 {
		return nil
	}
	stillMatched, matchErr := match(current)
	if matchErr != nil {
		if removeErr != nil {
			return errors.Join(
				fmt.Errorf("atrm %s: %w: %s", id, removeErr, strings.TrimSpace(string(out))),
				fmt.Errorf("recheck at job %s: %w", id, matchErr),
			)
		}
		return fmt.Errorf("recheck at job %s after atrm success: %w", id, matchErr)
	}
	if !stillMatched {
		return nil
	}
	if removeErr != nil {
		return fmt.Errorf("atrm %s: %w: %s", id, removeErr, strings.TrimSpace(string(out)))
	}
	return fmt.Errorf("atrm %s reported success but the matching job remains queued", id)
}

// readAtJobContext probes the generated owner header under a small output bound
// before retaining a body. Non-root users can queue arbitrarily large jobs; an
// owner-first probe lets complete root inventory ignore those bodies without
// letting their size poison cleanup or uninstall. Root jobs are read in full
// under the ordinary body bound and their owner header is checked again.
func readAtJobContext(ctx context.Context, id string) (string, uint32, bool, error) {
	if !atqueue.ValidJobID(id) {
		return "", 0, false, fmt.Errorf("invalid at job id %q", id)
	}
	opts := schedulerCommandOptions(atOwnerProbeLimit)
	opts.Context = ctx
	prefix, err := executil.Output("at", []string{"-c", id}, opts)
	if err != nil && !errors.Is(err, executil.ErrOutputLimit) {
		queued, queueErr := atJobQueuedContext(ctx, id)
		if queueErr != nil {
			return "", 0, false, errors.Join(
				fmt.Errorf("read at job %s: %w", id, err),
				fmt.Errorf("recheck at job %s: %w", id, queueErr),
			)
		}
		if !queued {
			return "", 0, false, nil
		}
		return "", 0, false, fmt.Errorf("read at job %s: %w", id, err)
	}
	owner, ownerErr := atqueue.ParseOwner(prefix, int(atJobBodyLimit))
	if ownerErr != nil {
		return "", 0, false, ownerErr
	}
	if owner != 0 {
		return "", owner, true, nil
	}
	if err == nil {
		return string(prefix), owner, true, nil
	}

	// A root-owned body exceeded the owner probe. Read it once under the full
	// bound, then require the same root header from those exact bytes.
	opts = schedulerCommandOptions(atJobBodyLimit)
	opts.Context = ctx
	body, err := executil.Output("at", []string{"-c", id}, opts)
	if err != nil {
		queued, queueErr := atJobQueuedContext(ctx, id)
		if queueErr != nil {
			return "", 0, false, errors.Join(
				fmt.Errorf("read at job %s: %w", id, err),
				fmt.Errorf("recheck at job %s: %w", id, queueErr),
			)
		}
		if !queued {
			return "", 0, false, nil
		}
		return "", 0, false, fmt.Errorf("read at job %s: %w", id, err)
	}
	owner, ownerErr = atqueue.ParseOwner(body, int(atJobBodyLimit))
	if ownerErr != nil {
		return "", 0, false, ownerErr
	}
	if owner != 0 {
		return "", owner, true, nil
	}
	return string(body), owner, true, nil
}

func (realSystem) AtJobs() ([]AtJob, error) {
	if !has("atq") {
		return nil, fmt.Errorf("atq is unavailable")
	}
	if !has("at") {
		return nil, fmt.Errorf("at is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), atInventoryTimeout)
	defer cancel()
	queueOpts := schedulerCommandOptions(atQueueOutputLimit)
	queueOpts.Context = ctx
	out, err := executil.Output("atq", nil, queueOpts)
	if err != nil {
		return nil, fmt.Errorf("atq: %w", err)
	}
	ids, err := atqueue.ParseInventory(out, int(schedulerOutputLimit))
	if err != nil {
		return nil, err
	}
	var jobs []AtJob
	totalBodyBytes := int64(0)
	for _, id := range ids {
		body, owner, present, err := readAtJobContext(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("inspect at job %s: %w", id, err)
		}
		if !present {
			continue
		}
		if owner != 0 {
			jobs = append(jobs, AtJob{ID: id, OwnerUID: owner})
			continue
		}
		totalBodyBytes += int64(len(body))
		if totalBodyBytes > atInventoryMaxBodyBytes {
			return nil, fmt.Errorf("at job inventory exceeds %d bytes", atInventoryMaxBodyBytes)
		}
		jobs = append(jobs, AtJob{ID: id, Body: body, OwnerUID: owner})
	}
	return jobs, nil
}

func rootAtBodyMatches(body string, match func(string) (bool, error)) (bool, error) {
	owner, err := atqueue.ParseOwner([]byte(body), int(atJobBodyLimit))
	if err != nil {
		return false, err
	}
	if owner != 0 {
		return false, nil
	}
	return match(body)
}

type atRevokeKind uint8

const (
	atRevokeLegacy atRevokeKind = iota + 1
	atRevokeForced
	atRevokeCurrent
)

type atRevokeCommand struct {
	installPath string
	user        string
	kind        atRevokeKind
}

// parseAtRevokeCommand accepts only command lines emitted by known releases.
// It deliberately does not treat an arbitrary suffix after the stable legacy
// prefix as one of our jobs.
func parseAtRevokeCommand(line, expectedInstallPath string) (atRevokeCommand, bool) {
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) != 5 && len(fields) != 8 && len(fields) != 12 {
		return atRevokeCommand{}, false
	}
	if fields[1] != "revoke" || fields[2] != "--user" || fields[4] != "--yes" {
		return atRevokeCommand{}, false
	}
	if expectedInstallPath != "" && fields[0] != expectedInstallPath {
		return atRevokeCommand{}, false
	}
	user := fields[3]
	if !validate.Username(user) {
		return atRevokeCommand{}, false
	}
	parsed := atRevokeCommand{installPath: fields[0], user: user, kind: atRevokeLegacy}
	want := fmt.Sprintf("%s revoke --user %s --yes", fields[0], user)
	switch len(fields) {
	case 5:
	case 8:
		if fields[5] != "--force" || fields[6] != "--confirm-force" || fields[7] != user {
			return atRevokeCommand{}, false
		}
		parsed.kind = atRevokeForced
		want += " --force --confirm-force " + user
	case 12:
		if fields[5] != "--force" || fields[6] != "--confirm-force" || fields[7] != user ||
			fields[8] != "--expected-uid" || fields[10] != "--generation" {
			return atRevokeCommand{}, false
		}
		uid, err := strconv.Atoi(fields[9])
		if err != nil || !validate.AccountID(uid) || !validate.Generation(fields[11]) {
			return atRevokeCommand{}, false
		}
		parsed.kind = atRevokeCurrent
		want += fmt.Sprintf(" --force --confirm-force %s --expected-uid %d --generation %s", user, uid, fields[11])
	}
	if line != want {
		return atRevokeCommand{}, false
	}
	return parsed, true
}

func atBodyHasKnownRevoke(body, installPath, user string) (bool, error) {
	matched := false
	for _, line := range strings.Split(body, "\n") {
		command, ok := parseAtRevokeCommand(line, installPath)
		if ok && command.user == user {
			matched = true
			continue
		}
		if !ok && atLineTargetsRevoke(line, installPath, user) {
			return false, fmt.Errorf("owned revoke command for %s has an unsupported or corrupt shape", user)
		}
	}
	return matched, nil
}

// atLineTargetsRevoke identifies an owned-looking command without authorizing
// deletion of its job. It is used only to fail closed when the exact parser
// rejects a command that still invokes this installation's revoke entry point.
func atLineTargetsRevoke(line, installPath, user string) bool {
	fields := strings.Fields(strings.TrimSpace(line))
	if installPath == "" || len(fields) < 2 || fields[0] != installPath || fields[1] != "revoke" {
		return false
	}
	if user == "" {
		return true
	}
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "--user", "-user":
			if i+1 < len(fields) && fields[i+1] == user {
				return true
			}
		default:
			for _, prefix := range []string{"--user=", "-user="} {
				if strings.TrimPrefix(fields[i], prefix) == user && strings.HasPrefix(fields[i], prefix) {
					return true
				}
			}
		}
	}
	return false
}

func atBodyHasExactCommand(body, command string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == command {
			return true
		}
	}
	return false
}
