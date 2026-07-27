// Package sshkey generates a one-time ed25519 keypair natively (no ssh-keygen
// dependency) and writes the public key into a freshly-created user's
// authorized_keys with the same TOCTOU-safe atomic-rename discipline the bash
// tool used: the destination is never chown/chmod'd by name after the rename, so
// an attacker symlink in the user-owned .ssh directory is never followed.
package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// KeyPair is a generated one-time ed25519 keypair.
type KeyPair struct {
	PrivatePEM    []byte // OpenSSH-format private key (shown once, never stored)
	AuthorizedKey []byte // authorized_keys line, trailing newline included
	Fingerprint   string // "SHA256:..."
}

// GenerateEd25519 creates a new keypair. comment is appended to the
// authorized_keys line (as ssh-keygen -C would).
func GenerateEd25519(comment string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	defer clear(priv)
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	defer clear(block.Bytes)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("wrap public key: %w", err)
	}
	authLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		authLine += " " + comment
	}
	privatePEM := pem.EncodeToMemory(block)
	if privatePEM == nil {
		return nil, fmt.Errorf("encode OpenSSH private key")
	}
	return &KeyPair{
		PrivatePEM:    privatePEM,
		AuthorizedKey: []byte(authLine + "\n"),
		Fingerprint:   ssh.FingerprintSHA256(sshPub),
	}, nil
}

// WriteAuthorizedKeys creates homeDir/.ssh (0700, owned by uid:gid) and writes
// authorizedKey to .ssh/authorized_keys (0600, owned by uid:gid), refusing any
// symlinked component and never following one.
func WriteAuthorizedKeys(homeDir string, uid, gid int, authorizedKey []byte) error {
	if !validate.AccountID(uid) || !validate.AccountID(gid) {
		return fmt.Errorf("refusing non-user uid/gid %d:%d", uid, gid)
	}
	uid64 := int64(uid)
	gid64 := int64(gid)
	if !filepath.IsAbs(homeDir) || filepath.Clean(homeDir) == "/" {
		return fmt.Errorf("home directory %s is not a safe absolute user home", homeDir)
	}
	homeFD, err := unix.Open(homeDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open home directory: %w", err)
	}
	home := os.NewFile(uintptr(homeFD), homeDir)
	defer home.Close()
	var homeStat unix.Stat_t
	if err := unix.Fstat(homeFD, &homeStat); err != nil {
		return fmt.Errorf("stat home directory: %w", err)
	}
	if homeStat.Mode&unix.S_IFMT != unix.S_IFDIR || int64(homeStat.Uid) != uid64 {
		return fmt.Errorf("home directory %s is not a safe account-owned directory", homeDir)
	}

	createdSSHDir := false
	if err := unix.Mkdirat(homeFD, ".ssh", 0o700); err == nil {
		createdSSHDir = true
	} else if err != unix.EEXIST {
		return fmt.Errorf("create .ssh: %w", err)
	}
	sshFD, err := unix.Openat(homeFD, ".ssh", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open .ssh without following links: %w", err)
	}
	sshDir := os.NewFile(uintptr(sshFD), filepath.Join(homeDir, ".ssh"))
	defer sshDir.Close()
	var sshStat unix.Stat_t
	if err := unix.Fstat(sshFD, &sshStat); err != nil {
		return fmt.Errorf("stat .ssh: %w", err)
	}
	if !safeInitialSSHDirectory(sshStat, createdSSHDir, uid64) {
		return fmt.Errorf("%s is not a safe account-owned directory", sshDir.Name())
	}
	if err := sshDir.Chown(uid, gid); err != nil {
		return fmt.Errorf("set .ssh owner: %w", err)
	}
	if err := sshDir.Chmod(0o700); err != nil {
		return fmt.Errorf("set .ssh mode: %w", err)
	}
	if err := unix.Fstat(sshFD, &sshStat); err != nil {
		return fmt.Errorf("verify .ssh metadata: %w", err)
	}
	if int64(sshStat.Uid) != uid64 || int64(sshStat.Gid) != gid64 || sshStat.Mode&0o7777 != 0o700 {
		return fmt.Errorf(".ssh metadata remains unsafe after repair")
	}
	if err := syncSSHDirectory(sshDir); err != nil {
		return &fsutil.DurabilityError{Operation: ".ssh metadata update", Err: err}
	}
	if createdSSHDir {
		if err := syncSSHHomeDirectory(home); err != nil {
			return &fsutil.DurabilityError{Operation: ".ssh directory creation", Err: err}
		}
	}
	if beforeAuthorizedKeysWrite != nil {
		beforeAuthorizedKeysWrite()
	}
	if err := verifyPinnedDirectories(homeDir, homeFD, homeStat, sshFD, sshStat); err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFileAt(sshDir, "authorized_keys", authorizedKey, 0o600, uid, gid); err != nil {
		return fmt.Errorf("write authorized_keys: %w", err)
	}
	return verifyPinnedDirectories(homeDir, homeFD, homeStat, sshFD, sshStat)
}

// beforeAuthorizedKeysWrite is a deterministic race hook for the integration
// test. Production leaves it nil.
var beforeAuthorizedKeysWrite func()

var (
	syncSSHDirectory     = func(dir *os.File) error { return dir.Sync() }
	syncSSHHomeDirectory = func(home *os.File) error { return home.Sync() }
)

func verifyPinnedDirectories(homeDir string, homeFD int, homeStat unix.Stat_t, sshFD int, sshStat unix.Stat_t) error {
	var currentHome unix.Stat_t
	if err := unix.Lstat(homeDir, &currentHome); err != nil {
		return fmt.Errorf("recheck home directory: %w", err)
	}
	if !sameInode(homeStat, currentHome) || currentHome.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("home directory %s was replaced while installing the key", homeDir)
	}
	var currentSSH unix.Stat_t
	if err := unix.Fstatat(homeFD, ".ssh", &currentSSH, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck .ssh: %w", err)
	}
	if !sameInode(sshStat, currentSSH) || currentSSH.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf(".ssh was replaced while installing the key")
	}
	var openSSH unix.Stat_t
	if err := unix.Fstat(sshFD, &openSSH); err != nil {
		return fmt.Errorf("recheck open .ssh: %w", err)
	}
	if !sameInode(sshStat, openSSH) {
		return fmt.Errorf("open .ssh inode changed unexpectedly")
	}
	return nil
}

func sameInode(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func safeInitialSSHDirectory(stat unix.Stat_t, created bool, uid int64) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	if created {
		return stat.Uid == 0
	}
	return int64(stat.Uid) == uid
}
