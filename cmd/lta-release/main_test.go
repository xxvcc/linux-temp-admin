package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGenerateAndReadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release.key")
	pub, err := generateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := readPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := priv.Public().(ed25519.PublicKey); string(got) != string(pub) {
		t.Fatal("generated public and private key do not match")
	}
	if _, err := generateKey(path); err == nil {
		t.Fatal("key generation must be create-only")
	}
}

func TestReadPrivateKeyRejectsUnsafeMetadata(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("mode 0644 error=%v, want strict-mode rejection", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(path); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error=%v, want rejection", err)
	}
}

func TestReadPrivateKeyRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.key")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(path); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("FIFO error=%v, want non-regular-file rejection", err)
	}
}

func TestPrivateKeyPathRejectsUnsafeAncestor(t *testing.T) {
	root := t.TempDir()
	unsafe := filepath.Join(root, "unsafe")
	dir := filepath.Join(unsafe, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release.key")
	if _, err := generateKey(path); err == nil || !strings.Contains(err.Error(), "writable without the sticky bit") {
		t.Fatalf("unsafe-ancestor keygen error=%v, want rejection", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unsafe-ancestor keygen left a key behind: %v", err)
	}
}

func TestPrivateKeyPathRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(linkDir, "release.key")
	if _, err := generateKey(path); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("symlink-ancestor keygen error=%v, want rejection", err)
	}
}

func TestPrivateKeyPathRejectsSymlinkBeforeCreatingMissingSuffix(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(linkDir, "missing", "keys", "release.key")
	if _, err := generateKey(path); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("symlink-with-missing-suffix keygen error=%v, want refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(realDir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("keygen followed the symlink and created a directory in its target: %v", err)
	}
}

func TestGenerateKeySyncsDirectoryAndCleansUpOnSyncFailure(t *testing.T) {
	dir := t.TempDir()
	oldSync := syncReleaseDirectory
	t.Cleanup(func() { syncReleaseDirectory = oldSync })

	syncs := 0
	syncReleaseDirectory = func(*os.File) error {
		syncs++
		return nil
	}
	first := filepath.Join(dir, "first.key")
	if _, err := generateKey(first); err != nil {
		t.Fatal(err)
	}
	if syncs != 1 {
		t.Fatalf("private-key parent syncs = %d, want 1", syncs)
	}

	wantErr := errors.New("forced directory sync failure")
	syncReleaseDirectory = func(*os.File) error { return wantErr }
	second := filepath.Join(dir, "second.key")
	if _, err := generateKey(second); !errors.Is(err, wantErr) {
		t.Fatalf("directory sync error = %v, want injected failure", err)
	}
	if _, err := os.Lstat(second); !os.IsNotExist(err) {
		t.Fatalf("key survived a failed directory durability check: %v", err)
	}
}

func TestReadPublicKeysStrictKeyring(t *testing.T) {
	dir := t.TempDir()
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(dir, "keys.hex")
	content := "# rotation overlap\n" + hex.EncodeToString(pub1) + "\n" + hex.EncodeToString(pub2) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := readPublicKeys(path)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys=%d err=%v, want two keys", len(keys), err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub1)+"\n"+hex.EncodeToString(pub1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicKeys(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key error=%v, want rejection", err)
	}
}

func TestReadBoundedRegularFileRejectsOversizeAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(regular, 4); err == nil || !strings.Contains(err.Error(), "4-byte limit") {
		t.Fatalf("oversize error=%v, want bounded-read refusal", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(link, 8); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error=%v, want refusal", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(fifo, 8); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("FIFO error=%v, want refusal without blocking", err)
	}
}

func TestAtomicWriteSignatureRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "asset.sig")
	if err := os.Symlink(filepath.Join(dir, "victim"), dest); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteSignature(dest, make([]byte, ed25519.SignatureSize)); err == nil {
		t.Fatal("signature writer must refuse a symlink destination")
	}
}

func TestAtomicWriteSignatureSyncsDirectoryAndReportsCommittedFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "asset.sig")
	signature := make([]byte, ed25519.SignatureSize)
	oldSync := syncReleaseDirectory
	wantErr := errors.New("forced directory sync failure")
	syncReleaseDirectory = func(*os.File) error { return wantErr }
	t.Cleanup(func() { syncReleaseDirectory = oldSync })

	err := atomicWriteSignature(dest, signature)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "committed") {
		t.Fatalf("signature sync error = %v, want committed durability error", err)
	}
	if got, readErr := os.ReadFile(dest); readErr != nil || string(got) != string(signature) {
		t.Fatalf("committed signature content=%x err=%v", got, readErr)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(dest) {
		t.Fatalf("signature write left temporary files: %v", entries)
	}
}
