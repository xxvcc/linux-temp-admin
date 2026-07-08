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
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"golang.org/x/crypto/ssh"
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
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("wrap public key: %w", err)
	}
	authLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		authLine += " " + comment
	}
	return &KeyPair{
		PrivatePEM:    pem.EncodeToMemory(block),
		AuthorizedKey: []byte(authLine + "\n"),
		Fingerprint:   ssh.FingerprintSHA256(sshPub),
	}, nil
}

// WriteAuthorizedKeys creates homeDir/.ssh (0700, owned by uid:gid) and writes
// authorizedKey to .ssh/authorized_keys (0600, owned by uid:gid), refusing any
// symlinked component and never following one.
func WriteAuthorizedKeys(homeDir string, uid, gid int, authorizedKey []byte) error {
	fi, err := os.Lstat(homeDir)
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("home directory %s is not a safe directory", homeDir)
	}
	// The home must belong to the account (or root); refuse to write into a dir
	// owned by anyone else, so a hijacked home can't redirect the key write. Fail
	// closed if ownership can't be determined (mirrors fsutil's stat handling).
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of home directory %s", homeDir)
	}
	if st.Uid != uint32(uid) && st.Uid != 0 {
		return fmt.Errorf("home directory %s is not owned by the account or root", homeDir)
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	if fi, err := os.Lstat(sshDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("%s is not a safe directory", sshDir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := fsutil.EnsureDir(sshDir, 0o700, uid, gid); err != nil {
		return fmt.Errorf("create .ssh: %w", err)
	}
	authFile := filepath.Join(sshDir, "authorized_keys")
	if fi, err := os.Lstat(authFile); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a safe regular file", authFile)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return fsutil.AtomicWriteFileAs(authFile, authorizedKey, 0o600, uid, gid)
}
