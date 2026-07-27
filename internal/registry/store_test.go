package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadAllRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.tsv")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := (&Store{File: path}).readAll()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a safe regular file") {
			t.Fatalf("FIFO registry error = %v, want special-file refusal", err)
		}
	case <-time.After(time.Second):
		t.Fatal("registry read blocked while opening a FIFO")
	}
}

func TestMissingStoreRemovalAndCompactAreNoOps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	s := &Store{
		Dir:  dir,
		File: filepath.Join(dir, "registry.tsv"),
		Lock: filepath.Join(dir, "registry.lock"),
	}
	if err := s.Remove("xxvcc-a1"); err != nil {
		t.Fatalf("Remove on a fully absent store: %v", err)
	}
	called := false
	removed, err := s.Compact(func(string) (bool, error) {
		called = true
		return false, nil
	})
	if err != nil || removed != 0 || called {
		t.Fatalf("Compact on absent store: removed=%d called=%v err=%v", removed, called, err)
	}
}

func TestExistingRegistryWithoutLockStillFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s := &Store{
		Dir:  dir,
		File: filepath.Join(dir, "registry.tsv"),
		Lock: filepath.Join(dir, "registry.lock"),
	}
	if err := os.WriteFile(s.File, []byte(Header+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("xxvcc-a1"); err == nil {
		t.Fatal("Remove accepted an existing registry whose lock was missing")
	}
}

func TestWriteAllRejectsOutputAboveRegistryLimit(t *testing.T) {
	s := &Store{File: filepath.Join(t.TempDir(), "registry.tsv")}
	rec := Record{Host: strings.Repeat("x", int(maxRegistryBytes))}
	if err := s.writeAll([]Record{rec}); err == nil || !strings.Contains(err.Error(), "registry output exceeds") {
		t.Fatalf("writeAll error = %v, want output-size refusal", err)
	}
	if _, err := os.Lstat(s.File); !os.IsNotExist(err) {
		t.Fatalf("oversized registry write created output: %v", err)
	}
}
