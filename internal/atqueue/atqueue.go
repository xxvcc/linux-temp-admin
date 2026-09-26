// Package atqueue parses the security-relevant protocol emitted by at and atq.
package atqueue

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MaxJobs bounds a complete queue inventory before callers inspect each job.
//
// The bound is deliberately not raised. Each inventoried job costs one `at -c`
// probe, and the caller's whole inventory runs under a 30-second deadline, so
// 4096 already sits at what that deadline can complete: a larger bound would
// only trade a fast, explicit refusal for a slow timeout. The inventory also
// spans every account's jobs, because atq's owner column is not trusted and the
// owner is established per job from the atrun header instead. A local account
// with at access can therefore fill the queue and stop this inventory from
// completing.
//
// That is contained rather than dangerous: the caller reaches this cleanup only
// after revoke has already removed the sudo grant and the sshd exception and
// disabled the login, so a filled queue delays account deletion and leaves the
// account retained and disabled. It never leaves privileged access in place.
const MaxJobs = 4096

// ValidJobID reports whether id is a canonical positive decimal at job ID.
func ValidJobID(id string) bool {
	if id == "" || len(id) > 20 || id[0] == '0' {
		return false
	}
	for i := range len(id) {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}

// Entry is one atq inventory line. ScheduledAt is the queued run time when atq
// printed one in the C-locale shape this tool pins; it stays zero for the
// implementations that print something else, because an unparsed column must not
// be mistaken for "no deadline".
type Entry struct {
	ID          string
	ScheduledAt time.Time
}

// ParseInventory treats every non-empty atq line as inventory evidence. It
// fails closed rather than returning a partial inventory when any line is
// malformed, an ID is duplicated, or the queue exceeds MaxJobs.
func ParseInventory(out []byte, maxTokenBytes int) ([]string, error) {
	entries, err := ParseInventoryEntries(out, maxTokenBytes)
	if err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, nil
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	return ids, nil
}

// ParseInventoryEntries is ParseInventory plus each job's queued run time, which
// callers need to tell a pending job from one whose deadline has already passed
// while atd was not running.
func ParseInventoryEntries(out []byte, maxTokenBytes int) ([]Entry, error) {
	var ids []Entry
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 1024), maxTokenBytes)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !ValidJobID(fields[0]) {
			return nil, fmt.Errorf("parse atq line %d: invalid job id in %q", lineNo, line)
		}
		id := fields[0]
		if seen[id] {
			return nil, fmt.Errorf("parse atq line %d: duplicate job id %s", lineNo, id)
		}
		seen[id] = true
		ids = append(ids, Entry{ID: id, ScheduledAt: parseQueuedTime(fields)})
		if len(ids) > MaxJobs {
			// Name what the operator can act on: the count spans every account's
			// jobs, so the blocker is usually not the account being cleaned up.
			return nil, fmt.Errorf("at queue contains more than %d inspectable jobs across all accounts, so this inventory cannot complete; list the queue with atq to find the owner filling it", MaxJobs)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse atq: %w", err)
	}
	return ids, nil
}

// parseQueuedTime reads the five-field date atq prints under the pinned C locale
// ("Fri Jul 24 00:00:00 2026"). It returns the zero time for any other shape:
// guessing a deadline is worse than admitting the queue did not state one.
//
// The instant is read as UTC, which is correct ONLY because the caller runs atq
// with TZ=UTC. Parsing in time.Local would read the child's output in this
// process's own zone — two different zones on any host whose $TZ differs from
// /etc/localtime, since helpers inherit no TZ.
func parseQueuedTime(fields []string) time.Time {
	if len(fields) < 6 {
		return time.Time{}
	}
	when, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(fields[1:6], " "), time.UTC)
	if err != nil {
		return time.Time{}
	}
	return when
}

// ParseOwner returns the UID from the first atrun-shaped owner header. The GID
// is validated even though callers currently need only the UID. A malformed
// first header is authoritative because later lines may be user-controlled.
func ParseOwner(body []byte, maxTokenBytes int) (uint32, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1024), maxTokenBytes)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "#" || fields[1] != "atrun" {
			continue
		}
		if len(fields) != 4 || !strings.HasPrefix(fields[2], "uid=") || !strings.HasPrefix(fields[3], "gid=") {
			return 0, fmt.Errorf("invalid atrun owner header")
		}
		uid, err := parseKernelID(strings.TrimPrefix(fields[2], "uid="))
		if err != nil {
			return 0, fmt.Errorf("invalid atrun UID %q", fields[2])
		}
		if _, err := parseKernelID(strings.TrimPrefix(fields[3], "gid=")); err != nil {
			return 0, fmt.Errorf("invalid atrun GID %q", fields[3])
		}
		return uid, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan at job: %w", err)
	}
	return 0, fmt.Errorf("job has no atrun owner header")
}

func parseKernelID(value string) (uint32, error) {
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil || id == uint64(^uint32(0)) {
		return 0, fmt.Errorf("invalid kernel ID %q", value)
	}
	return uint32(id), nil
}
