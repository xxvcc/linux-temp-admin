package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFileAs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if err := AtomicWriteFileAs(p, []byte("hello"), 0o640, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "hello" {
		t.Fatalf("content=%q err=%v", b, err)
	}
	fi, _ := os.Lstat(p)
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", fi.Mode().Perm())
	}
	// no leftover temp files
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("expected 1 file, found %d (temp leak?)", len(ents))
	}
}

func TestAtomicWriteRefusesSymlinkTargetAndDoesNotFollow(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Symlink(secret, target); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFileAs(target, []byte("PWNED"), 0o600, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected refusal to overwrite a symlink target")
	}
	if b, _ := os.ReadFile(secret); string(b) != "ORIGINAL" {
		t.Errorf("symlink was followed: secret content is now %q", b)
	}
	if fi, _ := os.Lstat(target); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("target is no longer a symlink (was replaced through the link)")
	}
}

func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "leaf")
	if err := EnsureDir(p, 0o700, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir wrong: isdir=%v mode=%o err=%v", fi.IsDir(), fi.Mode().Perm(), err)
	}
	// idempotent
	if err := EnsureDir(p, 0o700, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("second EnsureDir: %v", err)
	}
}

func TestEnsureDirRefusesSymlinkLeaf(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(dir, "leaf")
	if err := os.Symlink(real, leaf); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(leaf, 0o700, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected EnsureDir to refuse a symlink leaf")
	}
}
