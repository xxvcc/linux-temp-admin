package schedule

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// realSystem drives systemctl and at via os/exec.
type realSystem struct{}

func has(name string) bool { _, err := exec.LookPath(name); return err == nil }

func (realSystem) HasSystemctl() bool { return has("systemctl") }
func (realSystem) HasAt() bool        { return has("at") }

func (realSystem) Systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (realSystem) ScheduleAt(command string, hours int) (string, error) {
	if !ensureAtd() {
		return "", fmt.Errorf("atd is not running and could not be started; use systemd or start atd")
	}
	cmd := exec.Command("at", "now", "+", strconv.Itoa(hours), "hours")
	cmd.Stdin = strings.NewReader(command + "\n")
	out, err := cmd.CombinedOutput()
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
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "job" {
			if _, err := strconv.Atoi(fields[1]); err == nil {
				return fields[1]
			}
		}
	}
	// Fallback: first line whose first field is numeric.
	sc = bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 1 {
			if _, err := strconv.Atoi(fields[0]); err == nil {
				return fields[0]
			}
		}
	}
	return ""
}

// ensureAtd makes a best effort to confirm/start the atd daemon so queued at
// jobs actually fire. Returns true if atd appears runnable.
func ensureAtd() bool {
	run := func(name string, args ...string) bool { return exec.Command(name, args...).Run() == nil }
	// Try each init system in turn (not first-match), returning as soon as atd is
	// confirmed runnable; do not claim success without confirmation.
	if has("systemctl") {
		if run("systemctl", "is-active", "--quiet", "atd") {
			return true
		}
		_ = exec.Command("systemctl", "enable", "--now", "atd").Run()
		if run("systemctl", "is-active", "--quiet", "atd") {
			return true
		}
	}
	if has("rc-service") {
		if run("rc-service", "atd", "status") {
			return true
		}
		_ = exec.Command("rc-service", "atd", "start").Run()
		if run("rc-service", "atd", "status") {
			return true
		}
	}
	if has("service") {
		if run("service", "atd", "status") {
			return true
		}
		if run("service", "atd", "start") { // start exit 0 = running
			return true
		}
	}
	if has("pgrep") {
		return run("pgrep", "-x", "atd")
	}
	return true // no way to probe; proceed best-effort rather than disable at entirely
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
	if out, err := exec.Command("atrm", id).CombinedOutput(); err != nil {
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
	if !has("atq") {
		return false, fmt.Errorf("atq is unavailable")
	}
	out, err := exec.Command("atq").Output()
	if err != nil {
		return false, fmt.Errorf("atq: %w", err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
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
	jobs, err := r.AtJobs()
	if err != nil {
		return err
	}
	var errs []error
	for _, job := range jobs {
		if strings.Contains(job.Body, command) {
			if err := r.AtrmJob(job.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (realSystem) AtJobs() ([]AtJob, error) {
	if !has("atq") || !has("at") || !has("atrm") {
		return nil, nil
	}
	out, err := exec.Command("atq").Output()
	if err != nil {
		return nil, fmt.Errorf("atq: %w", err)
	}
	var jobs []AtJob
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		if _, err := strconv.Atoi(id); err != nil {
			continue
		}
		body, err := exec.Command("at", "-c", id).Output()
		if err != nil {
			return nil, fmt.Errorf("read at job %s: %w", id, err)
		}
		jobs = append(jobs, AtJob{ID: id, Body: string(body)})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return jobs, nil
}
