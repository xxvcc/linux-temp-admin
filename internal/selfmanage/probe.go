package selfmanage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

// probeVersion writes the (already verified) bytes to a temp file beside the
// install path, executes `<tmp> version`, and returns the validated version.
func (m *Manager) probeVersion(bin []byte) (string, error) {
	dir := filepath.Dir(m.InstallPath)
	// The install dir must be root-owned and not group/world-writable before we
	// write+exec a temp binary in it (a writable dir could let a local user swap
	// the temp between close and exec).
	if err := fsutil.RootSafeDir(dir); err != nil {
		return "", fmt.Errorf("install dir unsafe: %w", err)
	}
	// RootSafeDir and CreateTemp resolve dir separately, and this is the one
	// privileged write+exec in the tree that works by name rather than through a
	// pinned directory fd. Restructuring it to openat/fexecve is a larger change
	// than this warrants, but the gap it leaves — dir being replaced between the
	// safety verdict and the write — is closed by binding the two resolutions to
	// the same inode.
	var before unix.Stat_t
	if err := unix.Lstat(dir, &before); err != nil {
		return "", fmt.Errorf("pin install dir: %w", err)
	}
	f, err := os.CreateTemp(dir, ".lta-upgrade-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	var after unix.Stat_t
	if err := unix.Lstat(dir, &after); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("recheck install dir: %w", err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		_ = f.Close()
		return "", fmt.Errorf("install dir %s was replaced while staging the version probe", dir)
	}
	if _, err := io.Copy(f, bytes.NewReader(bin)); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Chmod(0o700); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	v, err := m.runVersionProbe(tmp)
	if err != nil {
		return "", err
	}
	return v, nil
}

func (m *Manager) runVersionProbe(path string) (string, error) {
	timeout := m.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	maxOutput := m.ProbeMaxOutput
	if maxOutput <= 0 {
		maxOutput = defaultProbeMaxBytes
	}
	// Keep the leader waitable until exceptional completion has terminated its
	// process group. CommandContext alone can reap an exited leader and return
	// WaitDelay while a descendant still holds the output pipe and keeps running.
	// The shared runner also bounds stderr and supplies a minimal environment.
	out, err := executil.Output(path, []string{"version"}, executil.Options{
		Timeout: timeout, MaxOutput: maxOutput,
	})
	if errors.Is(err, context.DeadlineExceeded) {
		return "", fmt.Errorf("version probe timed out after %s", timeout)
	}
	if errors.Is(err, executil.ErrOutputLimit) {
		return "", fmt.Errorf("version probe output exceeds %d bytes", maxOutput)
	}
	if err != nil {
		// Output adds captured stderr to helper failures. Version probes historically
		// discarded stderr; preserve that boundary instead of exposing arbitrary
		// diagnostic contents through upgrade errors and audit logs.
		if errors.Is(err, exec.ErrWaitDelay) {
			return "", exec.ErrWaitDelay
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", exitErr
		}
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return "", pathErr
		}
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return "", execErr
		}
		return "", errors.New("version probe failed")
	}
	v := strings.TrimSpace(string(out))
	if !validate.InstalledVersion(v) {
		return "", fmt.Errorf("binary reported an invalid version: %q", v)
	}
	return v, nil
}
