package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitForOpenFileDescriptors(t *testing.T, path string, want int) {
	t.Helper()
	target, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		open := 0
		for _, entry := range entries {
			fi, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name()))
			if err == nil && os.SameFile(target, fi) {
				open++
			}
		}
		if open >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s has %d open descriptors, want at least %d", path, open, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTryAcquireReportsBusyWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	first, err := New(path).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := first(); err != nil {
			t.Error(err)
		}
	}()

	started := time.Now()
	if release, err := New(path).TryAcquire(); !errors.Is(err, ErrBusy) || release != nil {
		t.Fatalf("TryAcquire while held returned release=%t, err=%v; want release=false, ErrBusy", release != nil, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("TryAcquire blocked for %s", elapsed)
	}
}

func TestSharedLocksDistinguishReadersFromExclusiveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	firstReader, err := New(path).AcquireShared()
	if err != nil {
		t.Fatal(err)
	}
	secondReader, err := New(path).TryAcquireShared()
	if err != nil {
		_ = firstReader()
		t.Fatalf("second shared acquisition failed: %v", err)
	}
	if release, err := New(path).TryAcquire(); !errors.Is(err, ErrBusy) || release != nil {
		_ = secondReader()
		_ = firstReader()
		t.Fatalf("exclusive acquisition with readers returned release=%t, err=%v; want busy", release != nil, err)
	}
	if err := secondReader(); err != nil {
		_ = firstReader()
		t.Fatal(err)
	}
	if err := firstReader(); err != nil {
		t.Fatal(err)
	}

	exclusive, err := New(path).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if release, err := New(path).TryAcquireShared(); !errors.Is(err, ErrBusy) || release != nil {
		_ = exclusive()
		t.Fatalf("shared acquisition with writer returned release=%t, err=%v; want busy", release != nil, err)
	}
	if err := exclusive(); err != nil {
		t.Fatal(err)
	}
}

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
	waitForOpenFileDescriptors(t, path, 2)

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

func TestUninstallMarkerRoundTrip(t *testing.T) {
	l := New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	if stopped, err := l.IsUninstalled(); err != nil || stopped {
		t.Fatalf("initial marker: stopped=%v err=%v", stopped, err)
	}
	if err := l.MarkUninstalled(); err != nil {
		t.Fatal(err)
	}
	if stopped, err := l.IsUninstalled(); err != nil || !stopped {
		t.Fatalf("marked state: stopped=%v err=%v", stopped, err)
	}
	if err := l.ClearUninstalled(); err != nil {
		t.Fatal(err)
	}
	if stopped, err := l.IsUninstalled(); err != nil || stopped {
		t.Fatalf("cleared marker: stopped=%v err=%v", stopped, err)
	}
}

func TestUninstallMarkerRejectsSymlink(t *testing.T) {
	l := New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	if err := os.Symlink("/etc/passwd", l.tombstonePath()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.IsUninstalled(); err == nil {
		t.Fatal("symlink uninstall marker was accepted")
	}
}
