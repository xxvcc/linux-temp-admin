//go:build integration

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
)

// rootOwnedDir returns a root-owned temp dir. Install writes through
// fsutil.WriteRootFile, which refuses a target directory that is not root-owned
// and then chowns the file to 0:0 -- so these tests cannot run unprivileged.
func rootOwnedDir(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	d := t.TempDir()
	if err := os.Chown(d, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestInstallReportsNoOpWhenAlreadyStable: installing the binary that already sits
// at InstallPath writes nothing, so it must not claim it installed anything -- the
// message and the audit entry would both assert a privileged write that never
// happened.
func TestInstallReportsNoOpWhenAlreadyStable(t *testing.T) {
	dir := rootOwnedDir(t)
	ip := filepath.Join(dir, "linux-temp-admin")
	newApp := func() (*App, *bytes.Buffer) {
		a, out, _ := newTestApp(t, "")
		a.InstallPath = ip
		a.Selfmanage = selfmanage.New(ip, config.MaxUpgradeBytes)
		return a, out
	}

	a1, out1 := newApp()
	if rc := a1.install(nil); rc != 0 {
		t.Fatalf("first install rc=%d", rc)
	}
	if !strings.Contains(out1.String(), "installed the stable command") {
		t.Errorf("first install should report a write: %q", out1.String())
	}
	fi1, err := os.Stat(ip)
	if err != nil {
		t.Fatalf("nothing installed: %v", err)
	}

	// Same bytes at the target: no write, and no "installed" claim.
	a2, out2 := newApp()
	if rc := a2.install(nil); rc != 0 {
		t.Fatalf("second install rc=%d", rc)
	}
	if !strings.Contains(out2.String(), "nothing to install") {
		t.Errorf("second install should report a no-op: %q", out2.String())
	}
	if strings.Contains(out2.String(), "installed the stable command") {
		t.Errorf("second install claimed a write that never happened: %q", out2.String())
	}
	fi2, _ := os.Stat(ip)
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("second install rewrote the target")
	}

	// --force does not change that: the identical-bytes short-circuit precedes it.
	a3, out3 := newApp()
	if rc := a3.install([]string{"--force"}); rc != 0 {
		t.Fatalf("forced install rc=%d", rc)
	}
	if !strings.Contains(out3.String(), "nothing to install") {
		t.Errorf("forced identical install should still be a no-op: %q", out3.String())
	}
}
