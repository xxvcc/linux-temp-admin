//go:build integration

package sudoers

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func rootDir(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGrantWritesValidatedDropin(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{Dir: dir, Validate: func(string) error { return nil }, Verify: func(string) error { return nil }}
	const user = "xxvcc-a1"
	if err := m.Grant(user); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "linux-temp-admin-"+user)
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || fi.Mode().Perm() != 0o440 {
		t.Errorf("owner=%d mode=%o, want 0 440", st.Uid, fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if want := user + " ALL=(ALL) NOPASSWD:ALL\n"; string(b) != want {
		t.Errorf("content = %q, want %q", b, want)
	}
}

func TestGrantRemovesFileOnValidationFailure(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{Dir: dir, Validate: func(string) error { return fmt.Errorf("bad syntax") }}
	if err := m.Grant("xxvcc-a1"); err == nil {
		t.Fatal("expected Grant to fail on validation error")
	}
	if _, err := os.Lstat(filepath.Join(dir, "linux-temp-admin-xxvcc-a1")); !os.IsNotExist(err) {
		t.Error("drop-in should be removed after a validation failure")
	}
}

func TestGrantRemovesFileOnVerifyFailure(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{Dir: dir, Validate: func(string) error { return nil }, Verify: func(string) error { return fmt.Errorf("not effective") }}
	if err := m.Grant("xxvcc-a1"); err == nil {
		t.Fatal("expected Grant to fail on verify error")
	}
	if _, err := os.Lstat(filepath.Join(dir, "linux-temp-admin-xxvcc-a1")); !os.IsNotExist(err) {
		t.Error("drop-in should be removed after a verify failure")
	}
}

func TestRemove(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{Dir: dir, Validate: func(string) error { return nil }, Verify: func(string) error { return nil }}
	if err := m.Grant("xxvcc-a1"); err != nil {
		t.Fatal(err)
	}
	m.Remove("xxvcc-a1")
	if _, err := os.Lstat(filepath.Join(dir, "linux-temp-admin-xxvcc-a1")); !os.IsNotExist(err) {
		t.Error("Remove should delete the drop-in")
	}
}
