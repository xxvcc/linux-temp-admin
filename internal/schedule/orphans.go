package schedule

import (
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
	seen := map[string]bool{}
	for _, prefix := range s.unitPrefixes() {
		matches, err := filepath.Glob(filepath.Join(s.SystemdDir, prefix+"*"))
		if err != nil {
			return nil, err
		}
		for _, path := range matches {
			base := filepath.Base(path)
			// Units come in .service/.timer pairs; both name the same account.
			base = strings.TrimSuffix(strings.TrimSuffix(base, ".timer"), ".service")
			user := strings.TrimPrefix(base, prefix)
			// validate.Username keeps a hand-made file with a strange name from being
			// reported — and later acted on — as if this tool had written it.
			if user != "" && validate.Username(user) {
				seen[user] = true
			}
		}
	}
	users := make([]string, 0, len(seen))
	for u := range seen {
		users = append(users, u)
	}
	sort.Strings(users)
	return users, nil
}

// ScheduledUsers returns accounts named by either systemd units or queued at
// jobs. This is the complete uninstall inventory even when registry rows vanish.
func (s *Scheduler) ScheduledUsers() ([]string, error) {
	users, err := s.UnitUsers()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(users))
	for _, user := range users {
		seen[user] = true
	}
	jobs, err := s.Sys.AtJobs()
	if err != nil {
		return nil, err
	}
	prefix := s.InstallPath + " revoke --user "
	for _, job := range jobs {
		i := strings.Index(job.Body, prefix)
		if i < 0 {
			continue
		}
		fields := strings.Fields(job.Body[i+len(prefix):])
		if len(fields) > 0 && validate.Username(fields[0]) {
			seen[fields[0]] = true
		}
	}
	users = users[:0]
	for user := range seen {
		users = append(users, user)
	}
	sort.Strings(users)
	return users, nil
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
