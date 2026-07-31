package schedule

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// UnitUsers returns every account named by an auto-revoke unit file on disk,
// whichever version of this tool wrote it.
//
// It exists because Cancel is name-keyed: it derives every path from a username
// you must already know. Every other way of knowing a username — the registry —
// can be missing, stale, or hand-edited, and the unit outlives all of them. So a
// unit whose registry row is gone was, until this, unreachable: nothing could
// name it, so nothing could cancel it.
//
// That gap has teeth because of what a unit IS: an ExecStart on the installed
// binary. A unit nobody can name still fires, and if the binary it names has been
// removed it fires forever and fails forever, leaving the account it was supposed
// to delete alive with whatever grants it holds.
//
// Both prefixes are globbed. v1's units carry no "-v2-" infix (see
// config.V1AutoRevokeUnitPrefix), and v1's install path was byte-identical to
// v2's, so a v1 unit on an upgraded host invokes the binary running this code.
// Globbing only the v2 prefix walks straight past it.
func (s *Scheduler) UnitUsers() ([]string, error) {
	if s == nil {
		return nil, fmt.Errorf("no scheduler configured")
	}
	prefixes := s.unitPrefixes()
	for _, prefix := range prefixes {
		if !validManagedUnitPrefix(prefix) {
			return nil, fmt.Errorf("unsafe managed systemd unit prefix %q", prefix)
		}
	}
	seen := map[string]bool{}
	entries, err := readSystemdDir(s.SystemdDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read systemd unit directory %s: %w", s.SystemdDir, err)
	}
	for _, entry := range entries {
		user, managed, err := managedUnitUser(entry.Name(), prefixes)
		if err != nil {
			return nil, err
		}
		if managed {
			seen[user] = true
		}
	}
	users := make([]string, 0, len(seen))
	for u := range seen {
		users = append(users, u)
	}
	sort.Strings(users)
	return users, nil
}

var readSystemdDir = os.ReadDir

// ScheduledUsers returns accounts named by either systemd units or queued at
// jobs. This is the complete uninstall inventory even when registry rows vanish.
func (s *Scheduler) ScheduledUsers() ([]string, error) {
	if s == nil || s.Sys == nil {
		return nil, fmt.Errorf("no scheduler backend configured")
	}
	users, err := s.UnitUsers()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(users))
	for _, user := range users {
		seen[user] = true
	}
	// A failed earlier cleanup can remove the files before daemon-reload. Active or
	// otherwise loaded units then exist only in PID 1's manager state, so supplement
	// the disk inventory whenever the backend exposes the production capability.
	if s.Sys.HasSystemctl() {
		if lister, ok := s.Sys.(loadedSystemdUnitLister); ok {
			loaded, err := lister.loadedSystemdUnits()
			if err != nil {
				return nil, err
			}
			prefixes := s.unitPrefixes()
			for _, unit := range loaded {
				user, managed, err := managedUnitUser(unit, prefixes)
				if err != nil {
					return nil, err
				}
				if managed {
					seen[user] = true
				}
			}
		}
	}
	// `at` is optional. No installed backend footprint means there cannot be a
	// runnable queue to inventory; a partial installation still calls AtJobs and
	// fails closed below because it may leave live jobs hidden from teardown.
	if !s.Sys.HasAt() {
		return sortedScheduledUsers(seen), nil
	}
	jobs, err := s.Sys.AtJobs()
	if err != nil {
		return nil, err
	}
	for _, job := range jobs {
		// Invites run as root, so only a root-owned at job can be this tool's
		// schedule. A local user may submit an identical command line; treating it as
		// inventory would let that user block cleanup or have root remove their job.
		if job.OwnerUID != 0 {
			continue
		}
		for _, line := range strings.Split(job.Body, "\n") {
			command, ok := parseAtRevokeCommand(line, s.InstallPath)
			if ok {
				seen[command.user] = true
			} else if atLineTargetsRevoke(line, s.InstallPath, "") {
				return nil, fmt.Errorf("at job %s contains an unsupported or corrupt owned revoke command", job.ID)
			}
		}
	}
	return sortedScheduledUsers(seen), nil
}

func sortedScheduledUsers(seen map[string]bool) []string {
	users := make([]string, 0, len(seen))
	for user := range seen {
		users = append(users, user)
	}
	sort.Strings(users)
	return users
}

func validManagedUnitPrefix(prefix string) bool {
	if prefix == "" || filepath.Base(prefix) != prefix || len(prefix) > 200 {
		return false
	}
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '@':
		default:
			return false
		}
	}
	return true
}

// loadedSystemdUnitLister is an optional production capability so injected
// System test doubles outside this package do not need to contact the host's PID
// 1. realSystem implements it; ScheduledUsers uses it whenever available.
type loadedSystemdUnitLister interface {
	loadedSystemdUnits() ([]string, error)
}

func managedUnitUser(name string, prefixes []string) (string, bool, error) {
	for _, prefix := range prefixes {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		base := name
		switch {
		case strings.HasSuffix(base, ".timer"):
			base = strings.TrimSuffix(base, ".timer")
		case strings.HasSuffix(base, ".service"):
			base = strings.TrimSuffix(base, ".service")
		default:
			continue
		}
		user := strings.TrimPrefix(base, prefix)
		// A malformed suffix cannot be acted on safely because Cancel is keyed by a
		// validated username. It is still evidence inside this tool's owned namespace.
		if user == "" || !validate.Username(user) {
			return "", true, fmt.Errorf("managed systemd unit %q has an invalid account suffix", name)
		}
		return user, true, nil
	}
	return "", false, nil
}

// Orphans returns the accounts whose auto-revoke unit is still on disk although
// the account itself is gone. exists reports whether an account is still present.
//
// It mirrors sudoers.Orphans and sshdconf.Orphans, which had no counterpart here:
// of the three things an invite leaves on a host, the unit was the one no sweep
// could find.
func (s *Scheduler) Orphans(exists func(string) (bool, error)) ([]string, error) {
	users, err := s.ScheduledUsers()
	if err != nil {
		return nil, err
	}
	var orphans []string
	for _, u := range users {
		live, err := exists(u)
		if err != nil {
			return nil, err
		}
		if !live {
			orphans = append(orphans, u)
		}
	}
	return orphans, nil
}

// unitPrefixes is the set of unit namespaces this tool must recognise: its own,
// plus v1's. UnitPrefix is a field (tests point it elsewhere), so the v1 prefix is
// only added for a Scheduler actually using the real namespace — otherwise a test
// pointing UnitPrefix at a temp namespace would start matching unrelated files.
func (s *Scheduler) unitPrefixes() []string {
	prefixes := []string{s.UnitPrefix}
	for _, extra := range s.LegacyUnitPrefixes {
		if extra != "" && extra != s.UnitPrefix {
			prefixes = append(prefixes, extra)
		}
	}
	return prefixes
}
