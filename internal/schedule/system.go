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

	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

const (
	schedulerCommandTimeout = 15 * time.Second
	schedulerOutputLimit    = int64(64 << 10)
	atQueueOutputLimit      = int64(4 << 20)
	atJobBodyLimit          = int64(1 << 20)
	maxAtJobs               = 4096
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
	return has("at") || has("atq") || has("atrm") || has("atd")
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

// systemctlUnitFileMissing reports only the exact, benign failure produced when
// `systemctl disable --now` races with (or follows) removal of its target unit.
// All other exit failures remain visible to the caller.
func systemctlUnitFileMissing(err error, unit string) bool {
	var commandErr *systemctlError
	if !errors.As(err, &commandErr) || len(commandErr.args) != 3 {
		return false
	}
	if commandErr.args[0] != "disable" || commandErr.args[1] != "--now" || commandErr.args[2] != unit {
		return false
	}
	want := fmt.Sprintf("Failed to disable unit: Unit file %s does not exist.", unit)
	return commandErr.output == want
}

func (realSystem) ScheduleAt(command string, hours int) (string, error) {
	for _, tool := range []string{"at", "atq", "atrm"} {
		if !has(tool) {
			return "", fmt.Errorf("%s is unavailable; refusing to create an at job that cannot be inventoried and cancelled", tool)
		}
	}
	if !ensureAtd() {
		return "", fmt.Errorf("atd is not running and could not be started; use systemd or start atd")
	}
	opts := schedulerCommandOptions(schedulerOutputLimit)
	opts.Stdin = strings.NewReader(command + "\n")
	out, err := executil.CombinedOutput("at", []string{"now", "+", strconv.Itoa(hours), "hours"}, opts)
	if err != nil {
		return "", fmt.Errorf("at: %w: %s", err, strings.TrimSpace(string(out)))
	}
	id := parseAtJobID(string(out))
	if id == "" {
		return "", fmt.Errorf("could not parse at job id from %q", string(out))
	}
	return id, nil
}

// parseAtJobID extracts the numeric job id from at's output ("job 7 at ...").
func parseAtJobID(out string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1024), int(schedulerOutputLimit))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "job" {
			if numericJobID(fields[1]) {
				return fields[1]
			}
		}
	}
	// Fallback: first line whose first field is numeric.
	sc = bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1024), int(schedulerOutputLimit))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 1 {
			if numericJobID(fields[0]) {
				return fields[0]
			}
		}
	}
	return ""
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
		return run("pgrep", "-x", "atd")
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
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1024), int(schedulerOutputLimit))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 0 && fields[0] == id {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
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
	for _, job := range jobs {
		if atBodyHasKnownRevoke(job.Body, selector.installPath, selector.user) {
			if err := r.AtrmJob(job.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
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
	var jobs []AtJob
	inspected := 0
	totalBodyBytes := int64(0)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1024), int(schedulerOutputLimit))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		if !numericJobID(id) {
			continue
		}
		inspected++
		if inspected > maxAtJobs {
			return nil, fmt.Errorf("at queue contains more than %d inspectable jobs", maxAtJobs)
		}
		bodyOpts := schedulerCommandOptions(atJobBodyLimit)
		bodyOpts.Context = ctx
		body, err := executil.Output("at", []string{"-c", id}, bodyOpts)
		if err != nil {
			queued, queueErr := atJobQueuedContext(ctx, id)
			if queueErr != nil {
				return nil, errors.Join(
					fmt.Errorf("read at job %s: %w", id, err),
					fmt.Errorf("recheck at job %s: %w", id, queueErr),
				)
			}
			if !queued {
				continue
			}
			return nil, fmt.Errorf("read at job %s: %w", id, err)
		}
		totalBodyBytes += int64(len(body))
		if totalBodyBytes > atInventoryMaxBodyBytes {
			return nil, fmt.Errorf("at job inventory exceeds %d bytes", atInventoryMaxBodyBytes)
		}
		jobs = append(jobs, AtJob{ID: id, Body: string(body)})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return jobs, nil
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

func atBodyHasKnownRevoke(body, installPath, user string) bool {
	for _, line := range strings.Split(body, "\n") {
		command, ok := parseAtRevokeCommand(line, installPath)
		if ok && command.user == user {
			return true
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
