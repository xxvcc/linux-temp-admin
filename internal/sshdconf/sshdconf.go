// Package sshdconf grants and removes a per-account sshd exception, so an invite
// can work on a server that does not accept public-key logins by default.
//
// The exception is a drop-in file of its own, containing nothing but a
// `Match User <account>` block. That shape is the whole design:
//
//   - The global policy is never edited. Every other account on the host keeps
//     the operator's baseline, byte for byte.
//   - "Restoring" is deleting our own file. There is no backup to keep, so the
//     tool can never clobber a change the operator (or their config management)
//     made in the days between the invite and its expiry, and it can never
//     restore a stale config from an unattended timer at 3am.
//   - It is removed by revoke, exactly like the sudoers drop-in next to it.
//
// A grant is written, syntax-checked with `sshd -t`, and then *proved* against
// `sshd -T -C user=<account>` before the running sshd is reloaded. If the proof
// fails — a missing Include, a competing Match block, an sshd too old for a
// directive — the file is removed and the grant fails. An invite is never
// printed on top of a half-applied sshd change.
//
// sshd is reloaded, never restarted: a restart drops every live session, and a
// botched restart on a remote box cannot be undone from the far end. Every
// reload — on the way in AND on the way out — is gated on `sshd -t` first,
// because a reload re-execs sshd against whatever is on disk: if someone else
// left a typo in sshd_config hours ago, the running daemon is still fine on its
// old in-memory config, and an ungated reload from an unattended revoke timer
// would be what finally takes SSH off the machine.
package sshdconf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// filePrefix namespaces the drop-in files this tool manages. The "10-" sorts the
// file early in the include glob, so its Match block is parsed before any the
// host already had: for a directive set in more than one matching Match block,
// sshd keeps the first value it obtained.
const filePrefix = "10-" + config.ManagedTag + "-"

// DefaultDir is where sshd's per-file configuration drop-ins live.
const DefaultDir = "/etc/ssh/sshd_config.d"

// DefaultLock guards the write/validate/prove/reload sequence. It lives outside
// DefaultDir so it can never be swept into sshd's `*.conf` include glob.
const DefaultLock = "/run/" + config.ManagedTag + "-sshd.lock"

// ErrNoReloadMechanism means there was no running sshd to notify: no init system
// took the reload, and no live sshd process could be found to signal.
//
// It is not a failure. A socket-activated sshd (and one that simply is not
// running) starts a fresh process per connection and reads the new configuration
// then. But it is not a success either: we cannot say the running daemon adopted
// the change, so a caller must not go on to claim the login is verified.
var ErrNoReloadMechanism = errors.New("no running sshd could be asked to re-read its configuration")

// GrantResult describes what a grant actually achieved.
type GrantResult struct {
	Path string
	// Reloaded says the running sshd was asked to re-read its configuration and
	// did. When false, the drop-in is on disk and proved correct there, but no
	// running daemon confirmed it — the invite must say so rather than claim a
	// verified login.
	Reloaded bool
}

// Manager writes per-account sshd drop-ins. The directory, the lock, and the
// three external steps are fields so tests can point at a temp dir and inject
// fakes.
type Manager struct {
	Dir        string
	Lock       string                                         // exclusive lock path; "" disables locking
	Validate   func() error                                   // syntax check (default: sshd -t)
	Effective  func(user string) (*sysinfo.SSHDConfig, error) // effective config (default: sshd -T -C user=)
	Reload     func() error                                   // ask sshd to re-read its config
	RemoveFile func(path string) error                        // defaults to os.Remove; injectable for rollback tests
}

// New returns a Manager for the real /etc/ssh/sshd_config.d.
func New() *Manager {
	return &Manager{
		Dir:        DefaultDir,
		Lock:       DefaultLock,
		Validate:   sshdSyntaxCheck,
		Effective:  sysinfo.SSHDEffective,
		Reload:     reload,
		RemoveFile: os.Remove,
	}
}

// FilePath is the drop-in path for user.
func (m *Manager) FilePath(user string) string {
	return filepath.Join(m.Dir, filePrefix+user+".conf")
}

// Grant writes a Match block for user that lifts exactly the blockers in report,
// proves it took effect, and reloads sshd. On any failure the file is removed,
// sshd is left as it was found, and an error is returned.
//
// groups are the account's real group names (not a prediction), used when an
// AllowGroups whitelist has to be satisfied.
func (m *Manager) Grant(user string, groups []string, report sysinfo.LoginReport) (GrantResult, error) {
	// Defense in depth: never let an unvalidated name reach an sshd directive,
	// even if a future caller forgets to validate.
	if !validate.Username(user) {
		return GrantResult{}, fmt.Errorf("refusing an sshd grant for invalid username %q", user)
	}
	if report.OK() {
		return GrantResult{}, fmt.Errorf("no sshd grant needed")
	}
	if !report.Fixable() {
		return GrantResult{}, fmt.Errorf("sshd policy cannot be lifted for one account: %s", strings.Join(unfixable(report), ", "))
	}
	content, err := dropIn(user, groups, report)
	if err != nil {
		return GrantResult{}, err
	}
	if err := m.ensureDir(); err != nil {
		return GrantResult{}, err
	}

	var res GrantResult
	err = m.withLock(func() error {
		// `sshd -t`, `sshd -T` and the reload all read the whole config directory, so
		// they are not scoped to our own file: without this check a pre-existing
		// syntax error elsewhere would be blamed on the file we are about to write.
		if m.Validate != nil {
			if err := m.Validate(); err != nil {
				return fmt.Errorf("the host's sshd configuration is already invalid; refusing to touch it: %w", err)
			}
		}
		path := m.FilePath(user)
		if err := fsutil.WriteRootFile(path, content, 0o644); err != nil {
			return err
		}
		// Everything below reads the config from disk, so the grant is proved correct
		// before the running sshd is asked to adopt it. Until the reload, the running
		// daemon has not seen this file at all, so removing it fully undoes the grant.
		rollback := func(cause error, restoreDaemon bool) error {
			var rollbackErrs []error
			if err := m.removeFile(path); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("remove failed sshd drop-in %s: %w", path, err))
			} else if restoreDaemon && m.Reload != nil {
				if err := m.Reload(); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("restore sshd after failed reload: %w", err))
				}
			}
			return errors.Join(append([]error{cause}, rollbackErrs...)...)
		}
		if m.Validate != nil {
			if err := m.Validate(); err != nil {
				return rollback(fmt.Errorf("sshd rejected the configuration this grant produced: %w", err), false)
			}
		}
		if m.Effective != nil {
			cfg, err := m.Effective(user)
			if err != nil {
				return rollback(fmt.Errorf("cannot re-read the effective sshd config: %w", err), false)
			}
			// OK, not Certain: this proves the blockers we set out to lift are gone.
			// It must NOT demand Certain(), because a rule we can never evaluate — an
			// address-qualified AllowUsers, which is Unverifiable rather than a blocker —
			// would make Certain() unreachable for any drop-in, and this proof would then
			// roll back a file that took effect perfectly and blame a missing Include.
			// Whether such an unevaluable rule downgrades the invite to UNVERIFIED is the
			// caller's decision, taken from the same report; it is not this proof's job.
			if rep := sysinfo.CheckKeyLogin(cfg, user, groups); !rep.OK() {
				return rollback(fmt.Errorf("the sshd drop-in did not take effect (is `Include %s/*.conf` present in /etc/ssh/sshd_config?)", m.Dir), false)
			}
		}
		if m.Reload != nil {
			switch err := m.Reload(); {
			case err == nil:
				res.Reloaded = true
			case errors.Is(err, ErrNoReloadMechanism):
				// Keep the file: it is correct on disk, and a socket-activated sshd will
				// read it on the next connection. But leave Reloaded false — the caller
				// must not claim a verified login on a daemon we never reached.
				res.Reloaded = false
			default:
				return rollback(fmt.Errorf("sshd reload failed: %w", err), true)
			}
		}
		res.Path = path
		return nil
	})
	if err != nil {
		return GrantResult{}, err
	}
	return res, nil
}

// Remove deletes the drop-in for user and reloads sshd. It is safe to call
// blindly — like the sudoers drop-in next to it, it only ever removes the
// managed file for this one account — so revoke need not know whether a grant
// was ever made. Removing a file that is not there is not an error and does not
// disturb sshd.
func (m *Manager) Remove(user string) error {
	if !validate.Username(user) {
		return fmt.Errorf("refusing to remove an sshd drop-in for invalid username %q", user)
	}
	path := m.FilePath(user)
	if !strings.HasPrefix(filepath.Base(path), filePrefix) {
		return fmt.Errorf("refusing to remove an unmanaged file: %s", path)
	}
	return m.withLock(func() error {
		if _, err := os.Lstat(path); err != nil {
			if os.IsNotExist(err) {
				return nil // nothing was granted; do not disturb sshd
			}
			return err
		}
		if err := m.removeFile(path); err != nil {
			return err
		}
		// The exception is gone from disk — the removal itself has succeeded, and the
		// caller must not be told otherwise. What remains is whether the running sshd
		// can safely be asked to notice.
		//
		// It must NOT be asked if the host's config is invalid, and the invalid part
		// is very unlikely to be ours (we just deleted our only file). A reload
		// re-execs sshd against what is on disk: if an operator left a typo in
		// sshd_config this afternoon and never reloaded, the running daemon is still
		// happily serving its old in-memory config — and this reload, fired at 3am by
		// an unattended auto-revoke timer, would be the thing that finally takes SSH
		// off the machine. A missed reload is recoverable. A dead sshd on a remote
		// box is not.
		if m.Validate != nil {
			if err := m.Validate(); err != nil {
				return fmt.Errorf("the sshd exception was removed, but sshd was NOT reloaded: the host's sshd configuration is invalid and a reload would take sshd down: %w", err)
			}
		}
		if m.Reload != nil {
			if err := m.Reload(); err != nil && !errors.Is(err, ErrNoReloadMechanism) {
				return fmt.Errorf("the sshd exception was removed, but the reload failed: %w", err)
			}
		}
		return nil
	})
}

func (m *Manager) removeFile(path string) error {
	if m.RemoveFile != nil {
		return m.RemoveFile(path)
	}
	return os.Remove(path)
}

// Orphans returns the accounts whose managed drop-in is still on disk although
// the account itself is gone. A grant
// outlives its account only if something went wrong (a revoke run by an older
// binary that did not know about these files, or an account deleted out of
// band), and an orphan is a standing loosening of sshd policy that re-arms the
// moment the username is reused — so something has to be able to find them.
// All returns every account this tool has an sshd exception for, whether or not
// the account still exists. Orphans answers "which exceptions outlived their
// account", which is the wrong question for a teardown: an exception whose
// account is alive is precisely what has to go.
func (m *Manager) All() ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(m.Dir, filePrefix+"*.conf"))
	if err != nil {
		return nil, err
	}
	var users []string
	for _, path := range matches {
		user := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), filePrefix), ".conf")
		if user != "" && validate.Username(user) {
			users = append(users, user)
		}
	}
	sort.Strings(users)
	return users, nil
}

func (m *Manager) Orphans(exists func(string) (bool, error)) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(m.Dir, filePrefix+"*.conf"))
	if err != nil {
		return nil, err
	}
	var orphans []string
	for _, path := range matches {
		user := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), filePrefix), ".conf")
		if user != "" && validate.Username(user) {
			live, err := exists(user)
			if err != nil {
				return nil, err
			}
			if !live {
				orphans = append(orphans, user)
			}
		}
	}
	return orphans, nil
}

// withLock serializes the whole write/validate/prove/reload sequence. `sshd -t`,
// `sshd -T` and the reload are all global over the config directory, so two
// concurrent invites are not independent: without this, one grant's reload could
// push the other's not-yet-validated file live.
//
// A host with no usable lock path still gets the feature, just unserialized —
// losing the ability to invite would be the worse failure.
func (m *Manager) withLock(fn func() error) error {
	if m.Lock == "" {
		return fn()
	}
	f, err := os.OpenFile(m.Lock, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fn()
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fn()
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// ensureDir creates the drop-in directory if it is absent and verifies it is a
// root-owned, non-writable real directory.
func (m *Manager) ensureDir() error {
	if _, err := os.Lstat(m.Dir); os.IsNotExist(err) {
		if err := fsutil.EnsureDir(m.Dir, 0o755, 0, 0); err != nil {
			return fmt.Errorf("create %s: %w", m.Dir, err)
		}
	}
	if err := fsutil.RootSafeDir(m.Dir); err != nil {
		return fmt.Errorf("unsafe sshd config directory: %w", err)
	}
	return nil
}

// MatchBlock renders the exception this package would write for report, so the
// cli can show an operator who declined the automatic fix exactly what to apply
// by hand — the same block, not a canned global directive.
func MatchBlock(user string, groups []string, report sysinfo.LoginReport) (string, error) {
	b, err := dropIn(user, groups, report)
	return string(b), err
}

// dropIn renders the drop-in file: a header explaining what it is and how it
// goes away, then a single Match block carrying only the directives needed to
// lift the blockers that were actually found. Nothing outside the Match block is
// emitted, so the file cannot change any other account's policy.
func dropIn(user string, groups []string, report sysinfo.LoginReport) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: temporary public-key exception for the account %q.\n", config.ManagedTag, user)
	fmt.Fprintf(&b, "# Everything below is scoped to `Match User %s` and changes no other account's policy.\n", user)
	fmt.Fprintf(&b, "# `%s revoke --user %s` deletes this file and reloads sshd. It is safe to delete by hand.\n", config.InstallPath, user)
	fmt.Fprintf(&b, "Match User %s\n", user)
	if report.Has(sysinfo.BlockPubkeyDisabled) {
		b.WriteString("    PubkeyAuthentication yes\n")
	}
	if report.Has(sysinfo.BlockAuthorizedKeysFile) {
		b.WriteString("    AuthorizedKeysFile .ssh/authorized_keys\n")
	}
	if report.Has(sysinfo.BlockAuthMethods) {
		b.WriteString("    AuthenticationMethods publickey\n")
	}
	if report.Has(sysinfo.BlockKeyAlgorithm) {
		// Deliberately NOT `+ssh-ed25519`. OpenSSH's leading `+` appends to its
		// COMPILED-IN DEFAULT list, not to the value the operator configured, and a
		// Match block starts from the defaults rather than inheriting the global
		// value. On the only hosts where this blocker can fire — the ones that
		// deliberately narrowed the algorithm set (FIPS, a distro crypto policy) —
		// `+ssh-ed25519` would hand this account sshd's entire default algorithm set
		// instead of the one algorithm it needs, silently undoing the very policy the
		// operator went out of their way to set. Re-state the effective list verbatim
		// and append only ed25519.
		//
		// The directive is written back under the name this host's own sshd used for
		// it: sshd renamed it in 8.5, and the 8.5 spelling is a fatal
		// "Bad configuration option" on the 8.2/8.4 releases that still support Include.
		if report.AlgoDirective == "" {
			return nil, fmt.Errorf("cannot lift the key-algorithm policy: sshd reported no PubkeyAccepted* directive")
		}
		fmt.Fprintf(&b, "    %s %s,ssh-ed25519\n", report.AlgoDirective, report.Detail[sysinfo.BlockKeyAlgorithm])
	}
	if report.Has(sysinfo.BlockAllowUsers) {
		fmt.Fprintf(&b, "    AllowUsers %s\n", user)
	}
	if report.Has(sysinfo.BlockAllowGroups) {
		// An AllowGroups whitelist is satisfied by the account's own groups, so we
		// name its primary group here — never one of the operator's existing groups,
		// which would hand the account whatever else that group carries.
		g := primaryGroup(groups)
		if g == "" {
			return nil, fmt.Errorf("cannot satisfy AllowGroups: the account has no known group")
		}
		if !validate.Username(g) {
			return nil, fmt.Errorf("refusing an sshd grant for invalid group name %q", g)
		}
		fmt.Fprintf(&b, "    AllowGroups %s\n", g)
	}
	return []byte(b.String()), nil
}

func primaryGroup(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	return groups[0]
}

// unfixable names the blockers a per-user Match block cannot lift, for the error
// message that refuses the grant.
func unfixable(report sysinfo.LoginReport) []string {
	var out []string
	for _, b := range report.Blockers {
		if !b.Fixable() {
			out = append(out, b.String())
		}
	}
	return out
}

// sshdSyntaxCheck runs `sshd -t`, surfacing sshd's own complaint on failure.
func sshdSyntaxCheck() error {
	out, err := exec.Command("sshd", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// reload asks the running sshd to re-read its configuration, trying the init
// system first and falling back to SIGHUP on the master process. It never
// restarts sshd.
//
// Finding nothing to reload returns ErrNoReloadMechanism rather than nil: the
// caller decides what that means. Reporting it as success would let an invite
// claim a "verified" login against a daemon that never re-read the file.
func reload() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		// The unit is "ssh" on Debian/Ubuntu and "sshd" on RHEL/Arch; one is usually
		// an alias of the other, so trying both is how we stay distro-neutral.
		for _, unit := range []string{"sshd", "ssh"} {
			if exec.Command("systemctl", "reload", unit).Run() == nil {
				return nil
			}
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		if exec.Command("rc-service", "sshd", "reload").Run() == nil {
			return nil
		}
	}
	if _, err := exec.LookPath("service"); err == nil {
		for _, unit := range []string{"sshd", "ssh"} {
			if exec.Command("service", unit, "reload").Run() == nil {
				return nil
			}
		}
	}
	if pid, ok := sshdPID(); ok {
		return syscall.Kill(pid, syscall.SIGHUP)
	}
	return ErrNoReloadMechanism
}

// sshdPID returns the master sshd's pid, but only after confirming the process
// it names really is sshd.
//
// SIGHUP's default action is to TERMINATE. A pid file outlives its process (that
// is precisely what "stale" means), and pids are recycled — so signalling the
// number on faith is not a no-op that might miss, it is a root-privileged kill
// aimed at whatever inherited the number. That risk lands exactly where this
// fallback is reached: hosts with no working init integration, which are the
// stripped-down images most likely to be carrying a stale pid file.
func sshdPID() (int, bool) {
	for _, p := range []string{"/run/sshd.pid", "/var/run/sshd.pid"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 0 {
			continue
		}
		if !isSSHD(pid) {
			continue
		}
		return pid, true
	}
	return 0, false
}

// isSSHD reports whether pid is a live process whose executable is sshd.
func isSSHD(pid int) bool {
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return false // no such process, or no /proc: signalling it is not safe
	}
	return strings.TrimSpace(string(comm)) == "sshd"
}
