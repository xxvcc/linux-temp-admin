//go:build integration

package sshkey

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const testUID, testGID = 12345, 12345

func TestWriteAuthorizedKeys(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	home := t.TempDir()
	if err := os.Chown(home, testUID, testGID); err != nil {
		t.Fatal(err)
	}
	line := []byte("ssh-ed25519 AAAAExample comment\n")
	if err := WriteAuthorizedKeys(home, testUID, testGID, line); err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(home, ".ssh")
	fi, err := os.Lstat(sshDir)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != testUID || fi.Mode().Perm() != 0o700 {
		t.Errorf(".ssh owner=%d mode=%o, want %d 700", st.Uid, fi.Mode().Perm(), testUID)
	}
	authFile := filepath.Join(sshDir, "authorized_keys")
	fi2, err := os.Lstat(authFile)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi2.Sys().(*syscall.Stat_t); st.Uid != testUID || fi2.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys owner=%d mode=%o, want %d 600", st.Uid, fi2.Mode().Perm(), testUID)
	}
	if b, _ := os.ReadFile(authFile); string(b) != string(line) {
		t.Errorf("content = %q, want %q", b, line)
	}
}

func TestWriteAuthorizedKeysRefusesSymlink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	home := t.TempDir()
	if err := os.Chown(home, testUID, testGID); err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, "secret")
	if err := os.WriteFile(secret, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if err := WriteAuthorizedKeys(home, testUID, testGID, []byte("PWNED\n")); err == nil {
		t.Fatal("expected refusal for a symlinked authorized_keys")
	}
	if b, _ := os.ReadFile(secret); string(b) != "ORIGINAL" {
		t.Errorf("symlink was followed: secret = %q", b)
	}
}

func TestWriteAuthorizedKeysRefusesRootOwnedHome(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	home := t.TempDir()
	if err := WriteAuthorizedKeys(home, testUID, testGID, []byte("ssh-ed25519 AAAAExample\n")); err == nil {
		t.Fatal("expected a root-owned home to be refused")
	}
}
