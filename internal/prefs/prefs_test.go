package prefs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func usePrefsFile(t *testing.T, path string) {
	t.Helper()
	old := File
	File = path
	t.Cleanup(func() { File = old })
}

func TestLangReadsBoundedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prefs")
	usePrefsFile(t, path)
	if err := os.WriteFile(path, []byte("other=value\nlang=en\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Lang(); got != "en" {
		t.Fatalf("Lang() = %q, want en", got)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxPrefsBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Lang(); got != "" {
		t.Fatalf("oversized Lang() = %q, want empty", got)
	}
}

func TestLangIgnoresSymlinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("lang=en\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	usePrefsFile(t, link)
	if got := Lang(); got != "" {
		t.Fatalf("symlink Lang() = %q, want empty", got)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	File = fifo
	if got := Lang(); got != "" {
		t.Fatalf("FIFO Lang() = %q, want empty", got)
	}
}
