// Package sudoers grants and removes a per-user NOPASSWD sudoers drop-in. A
// grant is written atomically, syntax-checked with visudo, and confirmed to
// actually take effect via `sudo -n -l -U <user>`; any failure removes the file.
package sudoers

import (
	"bytes"
	"errors"
	"fmt"
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
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// filePrefix namespaces the drop-in files this tool manages.
const filePrefix = config.ManagedTag + "-"

var sudoProbeOptions = executil.Options{
	Timeout:   10 * time.Second,
	MaxOutput: 256 << 10,
	ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
}

// Manager writes sudoers drop-ins. Its paths and external operations are fields
// so tests can point at a temporary directory and inject failures.
type Manager struct {
	Dir      string
	Validate func(content []byte) error // syntax check (default: visudo -cf -)
	Verify   func(user string) error    // effective-policy check (default: sudo -n -l -U)
	// RemoveFile defaults to a durable, directory-fsynced unlink. Tests inject
	// failures here to verify that
	// callers retain the account while a name-scoped root grant may still exist.
	RemoveFile func(path string) error
}

// New returns a Manager for the real /etc/sudoers.d using visudo and sudo.
func New() *Manager {
	return &Manager{
		Dir:        "/etc/sudoers.d",
		Validate:   visudoValidate,
		Verify:     verifyNopasswd,
		RemoveFile: fsutil.RemoveFile,
	}
}

// FilePath is the drop-in path for user. Exported so a diagnostic can name the
// exact file it is reporting.
func (m *Manager) FilePath(user string) string {
	return filepath.Join(m.Dir, filePrefix+user)
}

// Grant writes a NOPASSWD:ALL drop-in for user, validates it, and confirms it is
// effective. On any validation/verification failure the file is removed and an
// error returned. user must already be a validated username.
func (m *Manager) Grant(user string) error {
	// Defense in depth: never let an unvalidated username reach a sudoers line,
	// even if a future caller forgets to validate.
	if !validate.Username(user) {
		return fmt.Errorf("refusing sudoers grant for invalid username %q", user)
	}
	if m.Validate == nil {
		return fmt.Errorf("sudoers validator is not configured")
	}
	fi, err := os.Lstat(m.Dir)
	if err != nil {
		return fmt.Errorf("sudoers dir: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a safe directory", m.Dir)
	}
	content := []byte(fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", user))
	// Validate the exact bytes through stdin BEFORE the drop-in goes live in
	// sudoers.d, so a syntactically broken file never briefly breaks sudo
	// system-wide and no attacker-controlled temporary pathname is involved.
	if err := m.Validate(content); err != nil {
		return fmt.Errorf("sudoers validation failed: %w", err)
	}
	if m.Verify == nil {
		return fmt.Errorf("sudo policy verifier is not configured")
	}
	path := m.FilePath(user)
	if err := fsutil.WriteRootFile(path, content, 0o440); err != nil {
		var committed *fsutil.DurabilityError
		if errors.As(err, &committed) {
			if rmErr := m.removeFile(path); rmErr != nil && !os.IsNotExist(rmErr) {
				return errors.Join(err, fmt.Errorf("remove committed sudoers file after durability failure: %w", rmErr))
			}
		}
		return err
	}
	if err := m.Verify(user); err != nil {
		// The drop-in is already live (WriteRootFile succeeded), so the grant is
		// real — back it out. If removal also fails, surface that loudly rather
		// than swallowing it, because the caller must know a NOPASSWD grant may
		// still be on disk and needs manual cleanup.
		if rmErr := m.removeFile(path); rmErr != nil {
			return fmt.Errorf("sudo policy did not take effect (%w) and rollback failed: %v; NOPASSWD drop-in may persist at %s", err, rmErr, path)
		}
		return fmt.Errorf("sudo policy did not take effect: %w", err)
	}
	return nil
}

// Remove deletes the managed drop-in for user, if any. A file that is already
// absent is success — the caller wants the grant gone, and it is.
//
// It reports failure because a caller may need to know: an uninstall removes the
// binary only once nothing root-capable is left behind it, and a NOPASSWD:ALL
// file that could not be deleted is exactly that. Silently discarding the error
// let the removal fail and the teardown call it done.
func (m *Manager) Remove(user string) error {
	// FilePath joins user onto a privileged directory. Reject path separators and
	// every other invalid account name before constructing that path; checking the
	// final basename is insufficient because filepath.Join cleans ".." segments.
	if !validate.Username(user) {
		return fmt.Errorf("refusing sudoers removal for invalid username %q", user)
	}
	path := m.FilePath(user)
	if err := m.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove sudo grant %s: %w", path, err)
	}
	return nil
}

func (m *Manager) removeFile(path string) error {
	if m.RemoveFile != nil {
		return m.RemoveFile(path)
	}
	return fsutil.RemoveFile(path)
}

// All returns every account this tool has a sudo drop-in for, whether or not the
// account still exists.
//
// Orphans answers a different question — "which grants outlived their account" —
// and an uninstall must not ask that one: a grant whose account is very much
// alive is the most important thing on the host to remove, and it is exactly what
// Orphans filters out. This is also the teardown's sturdiest witness. An account
// can be hidden from the registry by editing a file, but not from this: the grant
// IS the passwordless root, so hiding an account means keeping the file that
// names it.
func (m *Manager) All() ([]string, error) {
	entries, err := readManagedDir(m.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sudoers directory %s: %w", m.Dir, err)
	}
	var users []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), filePrefix) {
			continue
		}
		user := strings.TrimPrefix(entry.Name(), filePrefix)
		if user == "" || !validate.Username(user) {
			return nil, fmt.Errorf("managed sudoers artifact has an invalid account name: %s", filepath.Join(m.Dir, entry.Name()))
		}
		users = append(users, user)
	}
	sort.Strings(users)
	return users, nil
}

var readManagedDir = readSudoersDirectory

func readSudoersDirectory(path string) ([]os.DirEntry, error) {
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	return entries, errors.Join(readErr, closeErr)
}

// Orphans returns the accounts whose managed drop-in is still on disk although
// the account itself is gone. exists reports whether an account is still present.
//
// An orphaned NOPASSWD:ALL file is the most dangerous leftover this tool can
// produce: it grants nothing while its username is unused, then re-arms full
// root the instant that name is reused. Grants outlive their account only when
// something went wrong — an account deleted out of band, or a revoke that could
// not finish — so nothing else will notice them. This is what lets `doctor`
// report them and `cleanup-expired --compact` remove them.
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

// visudoValidate syntax-checks a sudoers file. Missing visudo is a hard failure:
// writing a root-capable policy without its canonical parser would discard the
// pre-commit safety gate this package promises.
func visudoValidate(content []byte) error {
	if _, err := exec.LookPath("visudo"); err != nil {
		return fmt.Errorf("visudo is required to validate sudo policy: %w", err)
	}
	opts := sudoProbeOptions
	opts.Stdin = bytes.NewReader(content)
	out, err := executil.CombinedOutput("visudo", []string{"-cf", "-"}, opts)
	if err != nil {
		return fmt.Errorf("visudo -cf: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifyNopasswd confirms the effective policy grants user NOPASSWD sudo.
func verifyNopasswd(user string) error {
	out, err := executil.Output("sudo", []string{"-n", "-l", "-U", user}, sudoProbeOptions)
	if err != nil {
		return fmt.Errorf("sudo -n -l -U %s: %w", user, err)
	}
	return verifyNopasswdOutput(out)
}

func verifyNopasswdOutput(out []byte) error {
	foundAll := false
	nopasswd := false
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "(") {
			continue
		}
		endRunas := strings.IndexByte(line, ')')
		if endRunas < 2 {
			continue
		}
		switch runasRootScope(line[1:endRunas]) {
		case runasRootAmbiguous:
			return fmt.Errorf("effective policy has an ambiguous RunAs user list while verifying root NOPASSWD: ALL")
		case runasRootExcluded:
			continue
		}
		mode, exactAll := allAuthenticationMode(strings.TrimSpace(line[endRunas+1:]))
		if !exactAll {
			// A later root-applicable command list or restricted command can change
			// the authentication tag for some commands. This narrow verifier does
			// not fully parse Cmnd_Spec_List inheritance, aliases, or exclusions, so
			// invalidate any earlier full-grant proof. A subsequent exact
			// NOPASSWD: ALL line may establish it again.
			foundAll = false
			nopasswd = false
			continue
		}
		// sudoers applies matching entries in policy order and uses the last
		// match. Keep scanning so a later policy line cannot be hidden by an
		// earlier NOPASSWD: ALL match.
		foundAll = true
		nopasswd = mode
	}
	if foundAll && nopasswd {
		return nil
	}
	return fmt.Errorf("effective policy has no root NOPASSWD: ALL grant")
}

type rootRunasScope uint8

const (
	runasRootExcluded rootRunasScope = iota
	runasRootIncluded
	runasRootAmbiguous
)

// runasRootScope classifies whether the RunAs user list applies to root. Only
// literal users and numeric UIDs are decidable without evaluating sudoers
// aliases, Unix groups, or netgroups. Any dynamic or negated item invalidates
// the complete policy proof instead of letting an earlier NOPASSWD verdict
// survive a rule that may apply to root.
func runasRootScope(runas string) rootRunasScope {
	users := runas
	if colon := strings.IndexByte(users, ':'); colon >= 0 {
		users = users[:colon]
	}
	if strings.TrimSpace(users) == "" {
		return runasRootAmbiguous
	}

	includesRoot := false
	for _, raw := range strings.Split(users, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" || strings.HasPrefix(entry, "!") {
			return runasRootAmbiguous
		}
		switch entry {
		case "root", "ALL":
			includesRoot = true
			continue
		}
		if strings.HasPrefix(entry, "#") {
			uid, err := strconv.ParseUint(strings.TrimPrefix(entry, "#"), 10, 32)
			if err != nil {
				return runasRootAmbiguous
			}
			if uid == 0 {
				includesRoot = true
			}
			continue
		}
		if validate.Username(entry) {
			continue
		}
		// User aliases, groups, netgroups, escaped names, and any syntax this
		// verifier does not fully understand can resolve to root at runtime.
		return runasRootAmbiguous
	}
	if includesRoot {
		return runasRootIncluded
	}
	return runasRootExcluded
}

// allAuthenticationMode reports the authentication mode of an exact ALL
// command specification. The first result is true for NOPASSWD and false for
// PASSWD; ok is false when spec is not an exact ALL command specification.
func allAuthenticationMode(spec string) (nopasswd bool, ok bool) {
	for {
		colon := strings.IndexByte(spec, ':')
		if colon < 0 {
			return nopasswd, strings.TrimSpace(spec) == "ALL"
		}
		tag := strings.TrimSpace(spec[:colon])
		switch tag {
		case "NOPASSWD":
			nopasswd = true
		case "PASSWD":
			nopasswd = false
		case "EXEC", "NOEXEC", "FOLLOW", "NOFOLLOW", "SETENV", "NOSETENV",
			"LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL", "NOMAIL",
			"INTERCEPT", "NOINTERCEPT":
			// Other sudo tags do not change password authentication.
		default:
			// The colon belongs to the command or a later comma-separated rule,
			// not to a leading tag sequence. It cannot be our exact ALL grant.
			return false, false
		}
		spec = strings.TrimSpace(spec[colon+1:])
	}
}
