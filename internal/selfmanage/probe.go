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
	"syscall"
	"time"

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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	cmd.WaitDelay = time.Second
	out := &boundedBuffer{max: maxOutput}
	cmd.Stdout = out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("version probe timed out after %s", timeout)
	}
	if errors.Is(err, errProbeOutputLimit) || errors.Is(out.err, errProbeOutputLimit) {
		return "", fmt.Errorf("version probe output exceeds %d bytes", maxOutput)
	}
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(out.String())
	if !validate.InstalledVersion(v) {
		return "", fmt.Errorf("binary reported an invalid version: %q", v)
	}
	return v, nil
}

var errProbeOutputLimit = errors.New("version probe output limit exceeded")

type boundedBuffer struct {
	buf bytes.Buffer
	max int64
	err error
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.max - int64(b.buf.Len())
	if remaining <= 0 {
		b.err = errProbeOutputLimit
		return 0, b.err
	}
	if int64(len(p)) > remaining {
		n, _ := b.buf.Write(p[:remaining])
		b.err = errProbeOutputLimit
		return n, b.err
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string { return b.buf.String() }
