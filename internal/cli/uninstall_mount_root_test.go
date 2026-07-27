//go:build integration

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRemoveStateDirRefusesLiveBindMount(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	target := filepath.Join(base, "state")
	for _, path := range []string{source, target} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(source, "must-survive")
	if err := os.WriteFile(sentinel, []byte("unrelated data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("create isolated bind mount: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount test bind: %v", err)
		}
	})

	removeCalled := false
	a := &App{
		StateDir: target,
		RemoveAll: func(string) error {
			removeCalled = true
			return nil
		},
	}
	err := a.removeStateDir(true)
	if err == nil || !strings.Contains(err.Error(), "mountpoint") {
		t.Fatalf("mounted state removal error = %v, want mountpoint refusal", err)
	}
	if removeCalled {
		t.Fatal("mounted state reached recursive removal")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "unrelated data" {
		t.Fatalf("mounted data changed: content=%q err=%v", got, err)
	}
}
