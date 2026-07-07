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
	fi, err := os.Lstat(m.Dir)
	if err != nil {
		return fmt.Errorf("sudoers dir: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a safe directory", m.Dir)
	}
	path := m.filePath(user)
	content := []byte(fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", user))
	if err := fsutil.WriteRootFile(path, content, 0o440); err != nil {
		return err
	}
	if m.Validate != nil {
		if err := m.Validate(path); err != nil {
			_ = os.Remove(path)
			return fmt.Errorf("sudoers validation failed: %w", err)
		}
	}
	if m.Verify != nil {
		if err := m.Verify(user); err != nil {
			_ = os.Remove(path)
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
