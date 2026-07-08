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

func (m *Manager) filePath(user string) string {
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
	path := m.filePath(user)
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
func (m *Manager) Remove(user string) {
	path := m.filePath(user)
	if strings.HasPrefix(filepath.Base(path), filePrefix) {
		_ = os.Remove(path)
	}
}

// visudoValidate syntax-checks a sudoers file. If visudo is unavailable the
// check is skipped (best-effort, matching the bash tool).
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
