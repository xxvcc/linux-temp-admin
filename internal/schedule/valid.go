package schedule

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

const maxScheduleFileSize = 64 << 10

var (
	errSystemdUnitDisabled = errors.New("systemd unit is disabled")
	errSystemdUnitInactive = errors.New("systemd unit is inactive")
)

// ValidSchedule reports whether recordedUnit still names this exact account
// generation's queued revoke task. Invalid or stale artifacts return false;
// failures that prevent a reliable inventory return an error.
func (s *Scheduler) ValidSchedule(user string, uid int, generation, recordedUnit string) (bool, error) {
	if !validate.Username(user) || !validate.AccountID(uid) || !validate.Generation(generation) {
		return false, nil
	}

	if strings.HasPrefix(recordedUnit, "at:") {
		id := strings.TrimPrefix(recordedUnit, "at:")
		if !numericJobID(id) {
			return false, nil
		}
		if s.Sys == nil {
			return false, fmt.Errorf("inventory at jobs: no system backend")
		}
		jobs, err := s.Sys.AtJobs()
		if err != nil {
			return false, fmt.Errorf("inventory at jobs: %w", err)
		}
		found := false
		for _, job := range jobs {
			if job.ID != id {
				continue
			}
			if found || !atBodyHasExactCommand(job.Body, s.RevokeCommand(user, uid, generation)) {
				return false, nil
			}
			found = true
		}
		return found, nil
	}

	unit := s.UnitName(user)
	if recordedUnit != unit || strings.ContainsAny(unit, "/ ") {
		return false, nil
	}
	service, valid, err := readScheduleFile(filepath.Join(s.SystemdDir, unit+".service"))
	if err != nil || !valid {
		return false, err
	}
	if string(service) != s.serviceContent(user, uid, generation) {
		return false, nil
	}
	timer, valid, err := readScheduleFile(filepath.Join(s.SystemdDir, unit+".timer"))
	if err != nil || !valid {
		return false, err
	}

	calendar, ok := uniqueCalendar(timer)
	if !ok || string(timer) != timerContent(unit, calendar) {
		return false, nil
	}
	trigger, err := time.Parse("2006-01-02 15:04:05 UTC", calendar)
	if err != nil {
		return false, nil
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if !trigger.After(now().UTC()) {
		return false, nil
	}
	return s.systemdTimerExecutable(unit + ".timer")
}

func (s *Scheduler) systemdTimerExecutable(timer string) (bool, error) {
	if s.Sys == nil {
		return false, fmt.Errorf("query systemd timer %s: no system backend", timer)
	}
	for _, query := range []string{"is-enabled", "is-active"} {
		if err := s.Sys.Systemctl(query, "--quiet", timer); err != nil {
			if systemctlTimerStateNegative(err, query, timer) {
				return false, nil
			}
			return false, fmt.Errorf("systemctl %s %s: %w", query, timer, err)
		}
	}
	return true, nil
}

// systemctlTimerStateNegative recognizes only documented, quiet state-query
// exits. Diagnostics or unrelated failures remain errors so doctor cannot turn
// an unqueryable timer into a merely disabled one.
func systemctlTimerStateNegative(err error, query, timer string) bool {
	switch query {
	case "is-enabled":
		if errors.Is(err, errSystemdUnitDisabled) {
			return true
		}
	case "is-active":
		if errors.Is(err, errSystemdUnitInactive) {
			return true
		}
	default:
		return false
	}

	var commandErr *systemctlError
	if !errors.As(err, &commandErr) || len(commandErr.args) != 3 ||
		commandErr.args[0] != query || commandErr.args[1] != "--quiet" || commandErr.args[2] != timer ||
		commandErr.output != "" {
		return false
	}
	var exitErr *exec.ExitError
	if !errors.As(commandErr, &exitErr) {
		return false
	}
	switch query {
	case "is-enabled":
		return exitErr.ExitCode() == 1
	case "is-active":
		return exitErr.ExitCode() == 3 || exitErr.ExitCode() == 4
	}
	return false
}

func numericJobID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func uniqueCalendar(content []byte) (string, bool) {
	var value string
	count := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "OnCalendar=") {
			value = strings.TrimPrefix(line, "OnCalendar=")
			count++
		}
	}
	return value, count == 1
}

// readScheduleFile opens the leaf with O_NOFOLLOW and validates metadata on the
// descriptor, closing the lstat/open race that a path-based read would leave.
func readScheduleFile(path string) ([]byte, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("open schedule file %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, false, fmt.Errorf("stat schedule file %s: %w", path, err)
	}
	if !validScheduleMetadata(&stat) {
		return nil, false, nil
	}
	content, err := io.ReadAll(io.LimitReader(f, maxScheduleFileSize+1))
	if err != nil {
		return nil, false, fmt.Errorf("read schedule file %s: %w", path, err)
	}
	if len(content) > maxScheduleFileSize {
		return nil, false, nil
	}
	return content, true, nil
}

func validScheduleMetadata(stat *unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == 0 && stat.Gid == 0 && stat.Mode&0o7777 == 0o644
}
