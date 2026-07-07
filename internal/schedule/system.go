package schedule

import (
	"bufio"
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

func (realSystem) RemoveAtJobsFor(command string) {
	if !has("atq") || !has("at") || !has("atrm") {
		return
	}
	out, err := exec.Command("atq").Output()
	if err != nil {
		return
	}
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
			continue
		}
		if strings.Contains(string(body), command) {
			_ = exec.Command("atrm", id).Run()
		}
	}
}
