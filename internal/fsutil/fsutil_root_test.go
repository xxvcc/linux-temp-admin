//go:build integration

package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
}

func ownerOf(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

func TestWriteRootFileHappyPath(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "conf")
	if err := WriteRootFile(p, []byte("policy\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if uid, gid := ownerOf(t, p); uid != 0 || gid != 0 {
		t.Errorf("owner = %d:%d, want 0:0", uid, gid)
	}
	if fi, _ := os.Lstat(p); fi.Mode().Perm() != 0o440 {
		t.Errorf("mode = %o, want 440", fi.Mode().Perm())
	}
}

func TestWriteRootFileRefusesWorldWritableParent(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // world-writable
		t.Fatal(err)
	}
	if err := WriteRootFile(filepath.Join(dir, "conf"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected refusal for a world-writable parent directory")
	}
}

func TestWriteRootFileRefusesSymlinkParent(t *testing.T) {
	requireRoot(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteRootFile(filepath.Join(link, "conf"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected refusal when the parent directory is a symlink")
	}
}

func TestAtomicWriteChownsToRequestedUID(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	const uid, gid = 12345, 12345
	if err := AtomicWriteFileAs(p, []byte("x"), 0o600, uid, gid); err != nil {
		t.Fatal(err)
	}
	if u, g := ownerOf(t, p); u != uid || g != gid {
		t.Errorf("owner = %d:%d, want %d:%d", u, g, uid, gid)
	}
}
