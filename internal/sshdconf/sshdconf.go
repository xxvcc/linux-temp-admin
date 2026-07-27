// Package sshdconf grants and removes a per-account sshd exception, so an invite
// can work on a server that does not accept public-key logins by default.
//
// The exception is a drop-in file of its own, containing a
// `Match User <account>` block followed by an empty `Match all` scope reset.
// That shape is the whole design:
//
//   - The global policy is never edited. Every other account on the host keeps
//     the operator's baseline, byte for byte. The final scope reset is required
//     because Match state persists between files expanded by one Include glob;
//     without it, this early-sorting drop-in would capture later global entries.
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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

// filePrefix namespaces the drop-in files this tool manages. The "10-" sorts the
// file early in the include glob, so its Match block is parsed before any the
// host already had: for a directive set in more than one matching Match block,
// sshd keeps the first value it obtained.
const filePrefix = "10-" + config.ManagedTag + "-"

const removePendingSuffix = ".remove-pending"

var (
	sshdCheckOptions = executil.Options{
		Timeout:   10 * time.Second,
		MaxOutput: 256 << 10,
		ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
	}
	sshdReloadOptions = executil.Options{
		Timeout:   30 * time.Second,
		MaxOutput: 256 << 10,
		ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
	}
)

// DefaultDir is where sshd's per-file configuration drop-ins live.
const DefaultDir = "/etc/ssh/sshd_config.d"

// DefaultLock guards the write/validate/prove/reload sequence. It lives outside
// DefaultDir so it can never be swept into sshd's `*.conf` include glob.
const DefaultLock = "/run/" + config.ManagedTag + "-sshd.lock"

// ErrNoReloadMechanism means there was no running sshd to notify: no init system
// took the reload, and no live sshd process could be found to signal.
//
// A socket-activated sshd (and one that simply is not running) starts a fresh
// process per connection and reads the new configuration then, so a grant may
// remain on disk as explicitly unverified. A removal is different: this error
// cannot prove that an undiscovered long-running daemon stopped using the old
// name-scoped exception, so the pending removal must be retained for retry.
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
	RemoveFile func(path string) error                        // defaults to durable unlink; injectable for rollback tests
}

// New returns a Manager for the real /etc/ssh/sshd_config.d.
func New() *Manager {
	return &Manager{
		Dir:        DefaultDir,
		Lock:       DefaultLock,
		Validate:   sshdSyntaxCheck,
		Effective:  sysinfo.SSHDEffective,
		Reload:     reload,
		RemoveFile: fsutil.RemoveFile,
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
		rollback := func(cause error, restoreDaemon bool) error {
			pendingExisted, staged, err := m.stageRemovalLocked(path)
			if err != nil {
				return errors.Join(cause, fmt.Errorf("stage failed sshd grant removal: %w", err))
			}
			if !staged {
				return cause
			}
			// Before the first reload attempt, a newly-created drop-in cannot be in
			// daemon memory. Its unlink still goes through the durable marker protocol,
			// but no reload is needed unless this call inherited older pending state.
			if !restoreDaemon && !pendingExisted {
				if err := clearPending(path + removePendingSuffix); err != nil {
					return errors.Join(cause, fmt.Errorf("complete failed sshd grant removal: %w", err))
				}
				return cause
			}
			if err := m.finishRemovalLocked(path); err != nil {
				return errors.Join(cause, fmt.Errorf("restore sshd after failed grant: %w", err))
			}
			return cause
		}
		if err := fsutil.WriteRootFile(path, content, 0o644); err != nil {
			var committed *fsutil.DurabilityError
			if errors.As(err, &committed) {
				return rollback(err, false)
			}
			return err
		}
		// Everything below reads the config from disk, so the grant is proved correct
		// before the running sshd is asked to adopt it. Until the reload, the running
		// daemon has not seen this file at all, so removing it fully undoes the grant.
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
// disturb sshd unless a pending marker says an earlier removal still needs to
// be adopted by the running daemon.
func (m *Manager) Remove(user string) error {
	if !validate.Username(user) {
		return fmt.Errorf("refusing to remove an sshd drop-in for invalid username %q", user)
	}
	path := m.FilePath(user)
	if !strings.HasPrefix(filepath.Base(path), filePrefix) {
		return fmt.Errorf("refusing to remove an unmanaged file: %s", path)
	}
	return m.withLock(func() error {
		_, staged, err := m.stageRemovalLocked(path)
		if err != nil {
			return err
		}
		if !staged {
			return nil // nothing was granted; do not disturb sshd
		}
		return m.finishRemovalLocked(path)
	})
}

// stageRemovalLocked records durable retry state, then durably removes path.
// It returns whether a marker predated this call and whether there was any state
// to remove. The caller must hold m's lock through the eventual finish/clear.
func (m *Manager) stageRemovalLocked(path string) (pendingExisted, staged bool, err error) {
	pending := path + removePendingSuffix
	dropInExists, err := pathExists(path)
	if err != nil {
		return false, false, err
	}
	pendingExists, err := pathExists(pending)
	if err != nil {
		return false, false, err
	}
	if !dropInExists && !pendingExists {
		return false, false, nil
	}
	if pendingExists {
		if err := validatePending(pending); err != nil {
			return true, true, fmt.Errorf("unsafe pending sshd removal: %w", err)
		}
	}
	if !dropInExists {
		return pendingExists, true, nil
	}
	// The marker is empty, so even an unusually broad Include cannot turn it into
	// an sshd directive; its non-.conf suffix also keeps it out of the normal glob.
	// WriteRootFile syncs the directory before the policy file is unlinked.
	if !pendingExists {
		if err := fsutil.WriteRootFile(pending, nil, 0o600); err != nil {
			return false, true, fmt.Errorf("record pending sshd reload: %w", err)
		}
	}
	if err := m.removeFile(path); err != nil {
		return pendingExists, true, fmt.Errorf("remove failed sshd drop-in %s: %w", path, err)
	}
	if stillExists, err := pathExists(path); err != nil {
		return pendingExists, true, err
	} else if stillExists {
		return pendingExists, true, fmt.Errorf("remove reported success but sshd exception still exists: %s", path)
	}
	if err := syncParent(path); err != nil {
		return pendingExists, true, fmt.Errorf("sync removed sshd exception: %w", err)
	}
	return pendingExists, true, nil
}

// finishRemovalLocked validates the post-removal host config, requires a
// confirmed reload, and only then clears the retry marker.
func (m *Manager) finishRemovalLocked(path string) error {
	if m.Validate == nil {
		return fmt.Errorf("the sshd exception was removed, but no configuration validator is available")
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("the sshd exception was removed, but sshd was NOT reloaded: the host's sshd configuration is invalid and a reload would take sshd down: %w", err)
	}
	if m.Reload == nil {
		return fmt.Errorf("the sshd exception was removed, but its removal could not be confirmed: %w", ErrNoReloadMechanism)
	}
	if err := m.Reload(); err != nil {
		if errors.Is(err, ErrNoReloadMechanism) {
			return fmt.Errorf("the sshd exception was removed, but its removal could not be confirmed: %w", err)
		}
		return fmt.Errorf("the sshd exception was removed, but the reload failed: %w", err)
	}
	return clearPending(path + removePendingSuffix)
}

func clearPending(pending string) error {
	if err := fsutil.RemoveFile(pending); err != nil {
		return fmt.Errorf("clear pending sshd reload: %w", err)
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func syncParent(path string) error {
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validatePending(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot stat %s", path)
	}
	if st.Uid != 0 || st.Gid != 0 {
		return fmt.Errorf("%s is not owned by root:root (owner %d:%d)", path, st.Uid, st.Gid)
	}
	if fi.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s has mode %o, want 600", path, fi.Mode().Perm())
	}
	if fi.Size() != 0 {
		return fmt.Errorf("%s is not empty", path)
	}
	return nil
}

func (m *Manager) removeFile(path string) error {
	if m.RemoveFile != nil {
		return m.RemoveFile(path)
	}
	return fsutil.RemoveFile(path)
}

// All returns every account this tool has an sshd exception for, whether or not
// the account still exists. A pending removal is included too: its drop-in is
// already gone, but the running daemon may still hold the exception until a
// retry validates and reloads sshd.
func (m *Manager) All() ([]string, error) {
	entries, err := readDir(m.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan sshd drop-in directory %s: %w", m.Dir, err)
	}
	users := make(map[string]struct{})
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, filePrefix) {
			continue
		}
		var suffix string
		switch {
		case strings.HasSuffix(name, ".conf"+removePendingSuffix):
			suffix = ".conf" + removePendingSuffix
		case strings.HasSuffix(name, ".conf"):
			suffix = ".conf"
		default:
			continue
		}
		user := strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), suffix)
		if user == "" || !validate.Username(user) {
			return nil, fmt.Errorf("managed sshd artifact has an invalid account name: %s", filepath.Join(m.Dir, name))
		}
		users[user] = struct{}{}
	}
	out := make([]string, 0, len(users))
	for user := range users {
		out = append(out, user)
	}
	sort.Strings(out)
	return out, nil
}

var readDir = readDirectory

func readDirectory(path string) ([]os.DirEntry, error) {
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	return entries, errors.Join(readErr, closeErr)
}

// Orphans returns the accounts whose managed drop-in or pending daemon reload
// outlived the account itself. A grant outlives its account only if something
// went wrong (a revoke run by an older binary that did not know about these
// files, or an account deleted out of band), and the exception can re-arm the
// moment the username is reused — so cleanup must be able to find it.
func (m *Manager) Orphans(exists func(string) (bool, error)) ([]string, error) {
	users, err := m.All()
	if err != nil {
		return nil, err
	}
	var orphans []string
	for _, user := range users {
		live, err := exists(user)
		if err != nil {
			return nil, err
		}
		if !live {
			orphans = append(orphans, user)
		}
	}
	return orphans, nil
}

// withLock serializes the whole write/validate/prove/reload sequence. `sshd -t`,
// `sshd -T` and the reload are all global over the config directory, so two
// concurrent invites are not independent: without this, one grant's reload could
// push the other's not-yet-validated file live.
//
// Lock acquisition fails closed. Continuing without serialization would let one
// caller reload another caller's not-yet-validated file and defeat the transaction
// this lock exists to protect.
func (m *Manager) withLock(fn func() error) error {
	if m.Lock == "" {
		return fn()
	}
	f, err := os.OpenFile(m.Lock, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("open sshd transaction lock %s: %w", m.Lock, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat sshd transaction lock %s: %w", m.Lock, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() {
		return fmt.Errorf("sshd transaction lock %s is not a regular file", m.Lock)
	}
	if int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid() || fi.Mode().Perm() != 0o600 {
		return fmt.Errorf("sshd transaction lock %s has unsafe metadata: owner %d:%d mode %o, want %d:%d mode 600",
			m.Lock, st.Uid, st.Gid, fi.Mode().Perm(), os.Geteuid(), os.Getegid())
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock sshd transaction %s: %w", m.Lock, err)
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
	// OpenSSH restores the caller's Match state after an Include directive, but
	// files expanded by the same Include glob share state with each other. Since
	// this file deliberately sorts first, leave the include stream in global scope
	// so later drop-ins keep their intended host-wide meaning.
	b.WriteString("Match all\n")
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
	out, err := executil.CombinedOutput("sshd", []string{"-t"}, sshdCheckOptions)
	if err != nil {
		return fmt.Errorf("sshd -t: %w: %s", err, strings.TrimSpace(string(out)))
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
			if executil.Run("systemctl", []string{"reload", unit}, sshdReloadOptions) == nil {
				return nil
			}
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		if executil.Run("rc-service", []string{"sshd", "reload"}, sshdReloadOptions) == nil {
			return nil
		}
	}
	if _, err := exec.LookPath("service"); err == nil {
		for _, unit := range []string{"sshd", "ssh"} {
			if executil.Run("service", []string{unit, "reload"}, sshdReloadOptions) == nil {
				return nil
			}
		}
	}
	return signalSSHDMaster()
}

var (
	sshdPIDFiles    = []string{"/run/sshd.pid", "/var/run/sshd.pid"}
	sshdPIDOwnerUID = uint32(0)
	sshdProcessUID  = uint32(0)
	sshdProcRoot    = "/proc"
	pidfdOpen       = unix.PidfdOpen
	pidfdSendSignal = unix.PidfdSendSignal
	closeFD         = unix.Close
)

const maxSSHDMasterPIDBytes = int64(64)

// signalSSHDMaster opens a pidfd, proves the referenced process is a current sshd
// listener from the pid file's generation, then sends SIGHUP through that
// descriptor. The descriptor keeps that identity stable during validation and
// signalling; stale pid files fail closed.
func signalSSHDMaster() error {
	for _, p := range sshdPIDFiles {
		pid, pidFileTime, err := readSSHDMasterPID(p)
		if err != nil {
			continue
		}
		fd, err := pidfdOpen(pid, 0)
		if err == unix.ESRCH || err == unix.ENOENT {
			continue
		}
		if err != nil {
			return fmt.Errorf("open pidfd for sshd pid %d: %w", pid, err)
		}
		if !isSSHDMaster(pid, pidFileTime) {
			_ = closeFD(fd)
			continue
		}
		signalErr := pidfdSendSignal(fd, unix.SIGHUP, nil, 0)
		closeErr := closeFD(fd)
		if signalErr == unix.ESRCH {
			if closeErr != nil {
				return fmt.Errorf("close pidfd for exited sshd pid %d: %w", pid, closeErr)
			}
			continue
		}
		if signalErr != nil {
			return errors.Join(fmt.Errorf("signal sshd pid %d: %w", pid, signalErr), closeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close pidfd for sshd pid %d: %w", pid, closeErr)
		}
		return nil
	}
	return ErrNoReloadMechanism
}

// readSSHDMasterPID treats the runtime pid file as untrusted filesystem input.
// O_NONBLOCK prevents a planted FIFO from hanging a privileged reload forever;
// the descriptor checks and hard read limit reject every non-regular, writable,
// symlinked, or oversized substitute before its content is parsed.
func readSSHDMasterPID(path string) (int, time.Time, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, time.Time{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return 0, time.Time{}, fmt.Errorf("open sshd pid file %s", path)
	}
	defer f.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, time.Time{}, fmt.Errorf("stat sshd pid file %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != sshdPIDOwnerUID || stat.Mode&0o022 != 0 {
		return 0, time.Time{}, fmt.Errorf("sshd pid file %s has unsafe metadata", path)
	}
	if stat.Size > maxSSHDMasterPIDBytes {
		return 0, time.Time{}, fmt.Errorf("sshd pid file %s exceeds %d-byte limit", path, maxSSHDMasterPIDBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSSHDMasterPIDBytes+1))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("read sshd pid file %s: %w", path, err)
	}
	if int64(len(b)) > maxSSHDMasterPIDBytes {
		return 0, time.Time{}, fmt.Errorf("sshd pid file %s exceeds %d-byte limit", path, maxSSHDMasterPIDBytes)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, time.Time{}, fmt.Errorf("sshd pid file %s has invalid pid", path)
	}
	return pid, time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec), nil
}

// isSSHDMaster proves that pid is a root sshd listener from the same process
// generation that wrote the pid file. A pidfd prevents reuse after it is opened;
// this timestamp check closes the remaining stale-pidfile window before open.
func isSSHDMaster(pid int, pidFileTime time.Time) bool {
	procDir := filepath.Join(sshdProcRoot, strconv.Itoa(pid))
	var stat unix.Stat_t
	if err := unix.Stat(procDir, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != sshdProcessUID {
		return false
	}
	comm, err := readBoundedSSHDProcFile(filepath.Join(procDir, "comm"), 64)
	if err != nil || strings.TrimSpace(string(comm)) != "sshd" {
		return false
	}
	cmdline, err := readBoundedSSHDProcFile(filepath.Join(procDir, "cmdline"), 4<<10)
	if err != nil || !strings.Contains(string(cmdline), "[listener]") {
		return false
	}
	started, err := sshdProcessStartTime(pid)
	if err != nil {
		return false
	}
	// btime has one-second precision. Comparing whole seconds accepts a genuine
	// pid file written in the same second as process start while rejecting a stale
	// file from every earlier process generation.
	return pidFileTime.Unix() >= started.Unix()
}

func readBoundedSSHDProcFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	return b, nil
}

func sshdProcessStartTime(pid int) (time.Time, error) {
	data, err := readBoundedSSHDProcFile(filepath.Join(sshdProcRoot, strconv.Itoa(pid), "stat"), 4<<10)
	if err != nil {
		return time.Time{}, err
	}
	// comm is parenthesized and may itself contain spaces or ')', so split after
	// the final closing parenthesis. starttime is field 22, index 19 from state.
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 {
		return time.Time{}, fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(string(data[closeParen+1:]))
	if len(fields) <= 19 {
		return time.Time{}, fmt.Errorf("process stat has too few fields")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("malformed process start time: %w", err)
	}
	procStat, err := readBoundedSSHDProcFile(filepath.Join(sshdProcRoot, "stat"), 1<<20)
	if err != nil {
		return time.Time{}, err
	}
	var bootSeconds int64 = -1
	for _, line := range strings.Split(string(procStat), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "btime" {
			bootSeconds, err = strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("malformed kernel boot time: %w", err)
			}
			break
		}
	}
	if bootSeconds < 0 {
		return time.Time{}, fmt.Errorf("kernel stat has no boot time")
	}
	// Linux exposes process starttime in USER_HZ ticks. The supported Linux
	// amd64/arm64 ABIs both define USER_HZ as 100 regardless of CONFIG_HZ.
	const linuxUserHZ = uint64(100)
	seconds := startTicks / linuxUserHZ
	nanos := (startTicks % linuxUserHZ) * uint64(time.Second) / linuxUserHZ
	return time.Unix(bootSeconds, 0).Add(time.Duration(seconds)*time.Second + time.Duration(nanos)), nil
}
