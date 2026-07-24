package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockSerializesIndependentCallers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	first, err := New(path).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func() error, 1)
	errs := make(chan error, 1)
	go func() {
		release, err := New(path).Acquire()
		if err != nil {
			errs <- err
			return
		}
		acquired <- release
	}()

	select {
	case <-acquired:
		t.Fatal("second caller acquired the lifecycle lock while the first held it")
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := first(); err != nil {
		t.Fatal(err)
	}
	select {
	case release := <-acquired:
		if err := release(); err != nil {
			t.Fatal(err)
		}
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("second caller did not acquire the released lifecycle lock")
	}
}

func TestLockRejectsSymlinkAndLooseMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link).Acquire(); err == nil {
		t.Fatal("symlinked lifecycle lock was accepted")
	}

	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := New(loose).Acquire(); err == nil || !strings.Contains(err.Error(), "group/world") {
		t.Fatalf("loose lock error = %v", err)
	}
}
