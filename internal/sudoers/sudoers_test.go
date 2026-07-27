package sudoers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
)

func writeSudoersCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestAllPropagatesDirectoryReadFailure(t *testing.T) {
	old := readManagedDir
	readManagedDir = func(string) ([]os.DirEntry, error) {
		return nil, errors.New("injected directory I/O failure")
	}
	t.Cleanup(func() { readManagedDir = old })

	if _, err := (&Manager{Dir: t.TempDir()}).All(); err == nil || !strings.Contains(err.Error(), "injected directory I/O failure") {
		t.Fatalf("All error = %v, want directory failure", err)
	}
}

func TestSudoersProbesAreBoundedAndUseCLocale(t *testing.T) {
	old := sudoProbeOptions
	t.Cleanup(func() { sudoProbeOptions = old })

	t.Run("visudo locale", func(t *testing.T) {
		sudoProbeOptions = old
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "visudo", `[ "$LC_ALL:$LANG:$1:$2" = "C:C:-cf:-" ]`)
		t.Setenv("PATH", dir)
		if err := visudoValidate([]byte("alice ALL=(ALL) NOPASSWD:ALL\n")); err != nil {
			t.Fatalf("visudoValidate did not force the C locale: %v", err)
		}
	})

	t.Run("sudo locale and argv", func(t *testing.T) {
		sudoProbeOptions = old
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "sudo", `[ "$LC_ALL:$LANG:$1:$2:$3:$4" = "C:C:-n:-l:-U:alice" ] || exit 9
printf '    (root) NOPASSWD: ALL\n'`)
		t.Setenv("PATH", dir)
		if err := verifyNopasswd("alice"); err != nil {
			t.Fatalf("verifyNopasswd did not force the C locale/expected argv: %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "sudo", `/bin/sleep 30 & wait`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = 50 * time.Millisecond
		sudoProbeOptions = opts
		if err := verifyNopasswd("alice"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("verifyNopasswd error = %v, want timeout", err)
		}
	})

	t.Run("output limit", func(t *testing.T) {
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "visudo", `while :; do printf 0123456789abcdef; done`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = time.Second
		opts.MaxOutput = 64
		sudoProbeOptions = opts
		if err := visudoValidate([]byte("alice ALL=(ALL) NOPASSWD:ALL\n")); !errors.Is(err, executil.ErrOutputLimit) {
			t.Fatalf("visudoValidate error = %v, want output limit", err)
		}
	})
}

func TestRemoveUsesInjectedRemoveFile(t *testing.T) {
	wantErr := errors.New("injected remove failure")
	var removed string
	m := &Manager{
		Dir: t.TempDir(),
		RemoveFile: func(path string) error {
			removed = path
			return wantErr
		},
	}

	err := m.Remove("xxvcc-a1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Remove error = %v, want injected failure", err)
	}
	if removed != m.FilePath("xxvcc-a1") {
		t.Fatalf("removed path = %q, want %q", removed, m.FilePath("xxvcc-a1"))
	}
}

func TestRemoveRejectsInvalidUsernameBeforePathResolution(t *testing.T) {
	const malicious = "x/../../linux-temp-admin-target"

	t.Run("injected remover is not called", func(t *testing.T) {
		called := false
		m := &Manager{
			Dir: t.TempDir(),
			RemoveFile: func(string) error {
				called = true
				return nil
			},
		}
		if err := m.Remove(malicious); err == nil || !strings.Contains(err.Error(), "invalid username") {
			t.Fatalf("Remove error = %v, want invalid username refusal", err)
		}
		if called {
			t.Fatal("RemoveFile was called for an invalid username")
		}
	})

	t.Run("file outside sudoers directory survives", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "sudoers")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(root, "linux-temp-admin-target")
		if err := os.WriteFile(sentinel, []byte("keep\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := (&Manager{Dir: dir}).Remove(malicious); err == nil {
			t.Fatal("Remove accepted a path-traversal username")
		}
		if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep\n" {
			t.Fatalf("outside sentinel changed: content=%q err=%v", got, err)
		}
	})
}

func TestVerifyNopasswdOutputRequiresRootNopasswdAll(t *testing.T) {
	tests := []struct {
		name string
		out  string
		ok   bool
	}{
		{"root", "User alice may run the following commands:\n    (root) NOPASSWD: ALL\n", true},
		{"all runas", "    (ALL : ALL) NOPASSWD: ALL\n", true},
		{"non-root runas", "    (daemon) NOPASSWD: ALL\n", false},
		{"restricted command", "    (root) NOPASSWD: /usr/bin/id\n", false},
		{"password required", "    (root) PASSWD: ALL\n", false},
		{"unrelated nopasswd", "    (daemon) NOPASSWD: /bin/true\n    (root) PASSWD: ALL\n", false},
		{"tag changes before all", "    (root) NOPASSWD: /bin/true, PASSWD: ALL\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyNopasswdOutput([]byte(tt.out))
			if tt.ok && err != nil {
				t.Fatalf("verifyNopasswdOutput rejected full grant: %v", err)
			}
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "root NOPASSWD: ALL")) {
				t.Fatalf("verifyNopasswdOutput error = %v, want precise refusal", err)
			}
		})
	}
}

// TestOrphansFindsGrantsWhoseAccountIsGone pins the M1 fix. An orphaned
// NOPASSWD:ALL drop-in is the most dangerous leftover this tool can produce — it
// re-arms full root the instant its username is reused — so it must be findable.
func TestOrphansFindsGrantsWhoseAccountIsGone(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		filePrefix + "xxvcc-gone",  // ours, account deleted -> orphan
		filePrefix + "xxvcc-alive", // ours, account exists -> not an orphan
		"90-someone-elses-file",    // not ours: never report or remove it
		filePrefix + "BAD NAME",    // ours-looking but not a valid username -> ignore
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x ALL=(ALL) NOPASSWD:ALL\n"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{Dir: dir}
	orphans, err := m.Orphans(func(u string) (bool, error) { return u == "xxvcc-alive", nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 1 || orphans[0] != "xxvcc-gone" {
		t.Fatalf("orphans = %v, want exactly [xxvcc-gone]", orphans)
	}
}

// TestRemoveOnlyTouchesItsOwnFile: the sweep removes by username, so it must
// never reach a file this tool did not write.
func TestRemoveOnlyTouchesItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "90-someone-elses-file")
	if err := os.WriteFile(foreign, []byte("x\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	ours := filepath.Join(dir, filePrefix+"xxvcc-a1")
	if err := os.WriteFile(ours, []byte("x\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: dir}
	m.Remove("xxvcc-a1")
	if _, err := os.Lstat(ours); !os.IsNotExist(err) {
		t.Error("our own drop-in should be gone")
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Error("a file this tool does not own must survive")
	}
}
