//go:build integration

package sshkey

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

const testUID, testGID = 12345, 12345

func chownTestUserOrSkip(t *testing.T, path string) {
	t.Helper()
	if err := os.Chown(path, testUID, testGID); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
			t.Skipf("test filesystem cannot represent uid %d: %v", testUID, err)
		}
		t.Fatal(err)
	}
}

func TestWriteAuthorizedKeys(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	home := t.TempDir()
	chownTestUserOrSkip(t, home)
	oldSSHSync, oldHomeSync := syncSSHDirectory, syncSSHHomeDirectory
	sshSyncs, homeSyncs := 0, 0
	syncSSHDirectory = func(*os.File) error { sshSyncs++; return nil }
	syncSSHHomeDirectory = func(*os.File) error { homeSyncs++; return nil }
	t.Cleanup(func() { syncSSHDirectory, syncSSHHomeDirectory = oldSSHSync, oldHomeSync })
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
	if sshSyncs != 1 || homeSyncs != 1 {
		t.Fatalf("directory syncs: .ssh=%d home=%d, want 1 each", sshSyncs, homeSyncs)
	}
}

func TestWriteAuthorizedKeysReportsSSHDirectorySyncFailure(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	home := t.TempDir()
	chownTestUserOrSkip(t, home)
	old := syncSSHDirectory
	wantErr := errors.New("forced .ssh sync failure")
	syncSSHDirectory = func(*os.File) error { return wantErr }
	t.Cleanup(func() { syncSSHDirectory = old })

	err := WriteAuthorizedKeys(home, testUID, testGID, []byte("ssh-ed25519 AAAAExample\n"))
	var durability *fsutil.DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) {
		t.Fatalf("WriteAuthorizedKeys error=%v, want DurabilityError", err)
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".ssh", "authorized_keys")); !os.IsNotExist(statErr) {
		t.Fatalf("authorized_keys was written after the directory sync failed: %v", statErr)
	}
}

func TestWriteAuthorizedKeysRefusesSymlink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	home := t.TempDir()
	chownTestUserOrSkip(t, home)
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

func TestWriteAuthorizedKeysDetectsSSHDirectoryReplacement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	home := t.TempDir()
	chownTestUserOrSkip(t, home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	chownTestUserOrSkip(t, sshDir)
	victim := t.TempDir()
	hook := beforeAuthorizedKeysWrite
	beforeAuthorizedKeysWrite = func() {
		if err := os.Rename(sshDir, filepath.Join(home, ".ssh-moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, sshDir); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeAuthorizedKeysWrite = hook })

	err := WriteAuthorizedKeys(home, testUID, testGID, []byte("ssh-ed25519 AAAAExample\n"))
	if err == nil {
		t.Fatal("directory replacement must be detected")
	}
	if _, err := os.Lstat(filepath.Join(victim, "authorized_keys")); !os.IsNotExist(err) {
		t.Fatalf("authorized_keys escaped into replacement directory: %v", err)
	}
}
