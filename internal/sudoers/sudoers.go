// Package sudoers grants and removes a per-user NOPASSWD sudoers drop-in. A
// grant is written atomically, syntax-checked with visudo, and confirmed to
// actually take effect via `sudo -n -l -U <user>`; any failure removes the file.
package sudoers

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// filePrefix namespaces the drop-in files this tool manages.
const filePrefix = config.ManagedTag + "-"

// Manager writes sudoers drop-ins. Dir and the two external checks are fields so
// tests can point at a temporary directory and inject validators.
type Manager struct {
	Dir      string
	Validate func(path string) error // syntax check (default: visudo -cf)
	Verify   func(user string) error // effective-policy check (default: sudo -n -l -U)
}

// New returns a Manager for the real /etc/sudoers.d using visudo and sudo.
func New() *Manager {
	return &Manager{Dir: "/etc/sudoers.d", Validate: visudoValidate, Verify: verifyNopasswd}
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
	fi, err := os.Lstat(m.Dir)
	if err != nil {
		return fmt.Errorf("sudoers dir: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a safe directory", m.Dir)
	}
	content := []byte(fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", user))
	// Validate a throwaway copy BEFORE the drop-in goes live in sudoers.d, so a
	// syntactically broken file never briefly breaks sudo system-wide.
	if m.Validate != nil {
		tmp, err := os.CreateTemp("", "lta-sudoers-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		_, werr := tmp.Write(content)
		_ = tmp.Close()
		if werr == nil {
			werr = m.Validate(tmpName)
		}
		_ = os.Remove(tmpName)
		if werr != nil {
			return fmt.Errorf("sudoers validation failed: %w", werr)
		}
	}
	path := m.FilePath(user)
	if err := fsutil.WriteRootFile(path, content, 0o440); err != nil {
		return err
	}
	if m.Verify != nil {
		if err := m.Verify(user); err != nil {
			// The drop-in is already live (WriteRootFile succeeded), so the grant is
			// real — back it out. If removal also fails, surface that loudly rather
			// than swallowing it, because the caller must know a NOPASSWD grant may
			// still be on disk and needs manual cleanup.
			if rmErr := os.Remove(path); rmErr != nil {
				return fmt.Errorf("sudo policy did not take effect (%w) and rollback failed: %v; NOPASSWD drop-in may persist at %s", err, rmErr, path)
			}
			return fmt.Errorf("sudo policy did not take effect: %w", err)
		}
	}
	return nil
}

// Remove deletes the drop-in for user (best-effort). It only ever removes a file
// under Dir carrying the managed prefix.
// Remove deletes the managed drop-in for user, if any. A file that is already
// absent is success — the caller wants the grant gone, and it is.
//
// It reports failure because a caller may need to know: an uninstall removes the
// binary only once nothing root-capable is left behind it, and a NOPASSWD:ALL
// file that could not be deleted is exactly that. Silently discarding the error
// let the removal fail and the teardown call it done.
func (m *Manager) Remove(user string) error {
	path := m.FilePath(user)
	if !strings.HasPrefix(filepath.Base(path), filePrefix) {
		// Not ours to touch. Nothing was granted under this name by this tool, so
		// there is nothing to remove and no failure to report.
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove sudo grant %s: %w", path, err)
	}
	return nil
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
	matches, err := filepath.Glob(filepath.Join(m.Dir, filePrefix+"*"))
	if err != nil {
		return nil, err
	}
	var users []string
	for _, path := range matches {
		user := strings.TrimPrefix(filepath.Base(path), filePrefix)
		if user != "" && validate.Username(user) {
			users = append(users, user)
		}
	}
	sort.Strings(users)
	return users, nil
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
func (m *Manager) Orphans(exists func(string) bool) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(m.Dir, filePrefix+"*"))
	if err != nil {
		return nil, err
	}
	var orphans []string
	for _, path := range matches {
		user := strings.TrimPrefix(filepath.Base(path), filePrefix)
		// validate.Username keeps a hand-made file with a strange name from being
		// reported (and later removed) as if this tool had written it.
		if user != "" && validate.Username(user) && !exists(user) {
			orphans = append(orphans, user)
		}
	}
	return orphans, nil
}

// visudoValidate syntax-checks a sudoers file. If visudo is unavailable the
// check is skipped (best-effort).
func visudoValidate(path string) error {
	if _, err := exec.LookPath("visudo"); err != nil {
		return nil
	}
	return exec.Command("visudo", "-cf", path).Run()
}

// verifyNopasswd confirms the effective policy grants user NOPASSWD sudo.
func verifyNopasswd(user string) error {
	out, err := exec.Command("sudo", "-n", "-l", "-U", user).Output()
	if err != nil {
		return err
	}
	if !bytes.Contains(out, []byte("NOPASSWD:")) {
		return fmt.Errorf("effective policy has no NOPASSWD grant")
	}
	return nil
}
