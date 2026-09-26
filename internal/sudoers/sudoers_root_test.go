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
	var validated []byte
	m := &Manager{Dir: dir, Validate: func(content []byte) error {
		validated = append([]byte(nil), content...)
		return nil
	}, Verify: func(string) error { return nil }}
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
	} else if string(validated) != want {
		t.Errorf("validated content = %q, want %q", validated, want)
	}
}

func TestGrantRemovesFileOnValidationFailure(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{Dir: dir, Validate: func([]byte) error { return fmt.Errorf("bad syntax") }}
	if err := m.Grant("xxvcc-a1"); err == nil {
		t.Fatal("expected Grant to fail on validation error")
	}
	if _, err := os.Lstat(filepath.Join(dir, "linux-temp-admin-xxvcc-a1")); !os.IsNotExist(err) {
		t.Error("drop-in should be removed after a validation failure")
	}
}

func TestGrantRemovesFileOnVerifyFailure(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{Dir: dir, Validate: func([]byte) error { return nil }, Verify: func(string) error { return fmt.Errorf("not effective") }}
	if err := m.Grant("xxvcc-a1"); err == nil {
		t.Fatal("expected Grant to fail on verify error")
	}
	if _, err := os.Lstat(filepath.Join(dir, "linux-temp-admin-xxvcc-a1")); !os.IsNotExist(err) {
		t.Error("drop-in should be removed after a verify failure")
	}
}

func TestRemove(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{Dir: dir, Validate: func([]byte) error { return nil }, Verify: func(string) error { return nil }}
	if err := m.Grant("xxvcc-a1"); err != nil {
		t.Fatal(err)
	}
	m.Remove("xxvcc-a1")
	if _, err := os.Lstat(filepath.Join(dir, "linux-temp-admin-xxvcc-a1")); !os.IsNotExist(err) {
		t.Error("Remove should delete the drop-in")
	}
}

// The invariant is an ORDER, not an outcome: the exact bytes are validated before
// anything lands in sudoers.d, so a syntactically broken drop-in never briefly
// breaks sudo for the whole host. The existing failure tests only assert the file
// is absent afterwards, which is equally true of a write-then-validate-then-remove
// implementation — and that implementation is exactly the bug.
func TestGrantValidatesBeforeTheDropInEverExists(t *testing.T) {
	dir := rootDir(t)
	path := filepath.Join(dir, "linux-temp-admin-xxvcc-a1")

	var validatedContent []byte
	var existedAtValidation, existedAtVerification bool
	m := &Manager{
		Dir: dir,
		Validate: func(content []byte) error {
			validatedContent = append([]byte(nil), content...)
			_, err := os.Lstat(path)
			existedAtValidation = err == nil
			return nil
		},
		Verify: func(string) error {
			_, err := os.Lstat(path)
			existedAtVerification = err == nil
			return nil
		},
	}

	if err := m.Grant("xxvcc-a1"); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	if existedAtValidation {
		t.Fatal("the drop-in was already live in sudoers.d when validation ran; a broken file would have been live host-wide first")
	}
	if !existedAtVerification {
		t.Fatal("verification ran before the drop-in was live, so it cannot have confirmed the real policy")
	}
	if want := "xxvcc-a1 ALL=(ALL) NOPASSWD:ALL\n"; string(validatedContent) != want {
		t.Fatalf("validated content = %q, want the exact bytes that go on disk (%q)", validatedContent, want)
	}

	// And the placed file is byte-identical to what was validated.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(validatedContent) {
		t.Fatalf("on-disk content %q differs from the validated bytes %q", onDisk, validatedContent)
	}
}
