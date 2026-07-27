// Command lta-release is a small, network-incapable release signing tool. Build
// it once from an audited commit, record its SHA-256 offline, and use that fixed
// binary for every signing ceremony. Never build it from the candidate tag on
// the machine that holds the release private key.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	protocolVersion         = "lta-release-offline-v1"
	maxReleaseBinaryBytes   = int64(64 << 20)
	maxReleaseMetadataBytes = int64(1 << 20)
)

func main() {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		fmt.Fprintln(os.Stderr, "error: disable core dumps:", err)
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "version":
		mustArgs(2)
		fmt.Println(protocolVersion)
	case "keygen":
		mustArgs(3)
		keygen(os.Args[2])
	case "sign":
		mustArgs(4)
		sign(os.Args[2], os.Args[3])
	case "pubkey":
		mustArgs(3)
		printPublicKey(os.Args[2])
	case "verify":
		mustArgs(5)
		verify(os.Args[2], os.Args[3], os.Args[4])
	case "pem":
		mustArgs(3)
		writePEMKeyring(os.Args[2])
	default:
		usage()
	}
}

func printPublicKey(privFile string) {
	priv := loadPriv(privFile)
	defer clear(priv)
	fmt.Println(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lta-release version | keygen <privkey-out> | sign <privkey> <file> | pubkey <privkey> | verify <keyring-hex> <file> <sig> | pem <keyring-hex>")
	os.Exit(2)
}

func mustArgs(n int) {
	if len(os.Args) != n {
		usage()
	}
}

func keygen(privOut string) {
	pub, err := generateKey(privOut)
	check(err)
	fmt.Fprintf(os.Stderr, "private key written to %s (keep offline)\n", privOut)
	fmt.Fprintln(os.Stderr, "add this public key as one line in internal/selfmanage/release_pubkey.hex:")
	fmt.Println(hex.EncodeToString(pub))
}

func generateKey(privOut string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(priv)
	dirPath, name, err := splitOwnedTarget(privOut)
	if err != nil {
		return nil, err
	}
	dir, err := openOwnedDir(dirPath, true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	// Create-only plus O_EXCL rejects both overwrite and a planted leaf symlink.
	f, err := openFileAt(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = unix.Unlinkat(int(dir.Fd()), name, 0)
			_ = syncReleaseDirectory(dir)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return nil, err
	}
	if _, err = hex.NewEncoder(f).Write(priv); err != nil {
		return nil, err
	}
	if _, err = f.Write([]byte{'\n'}); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := syncReleaseDirectory(dir); err != nil {
		return nil, fmt.Errorf("sync private-key directory: %w", err)
	}
	complete = true
	return pub, nil
}

func sign(privFile, file string) {
	priv := loadPriv(privFile)
	defer clear(priv)
	data, err := readBoundedRegularFile(file, maxReleaseBinaryBytes)
	check(err)
	dest := file + ".sig"
	check(atomicWriteSignature(dest, ed25519.Sign(priv, data)))
	fmt.Fprintf(os.Stderr, "wrote %s\n", dest)
}

func atomicWriteSignature(dest string, signature []byte) error {
	dirPath, name, err := splitOwnedTarget(dest)
	if err != nil {
		return err
	}
	dir, err := openOwnedDir(dirPath, false)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := regularOrAbsentAt(dir, name); err != nil {
		return err
	}
	tmp, tmpName, err := createTempFileAt(dir, ".lta-signature-")
	if err != nil {
		return err
	}
	renamed := false
	cleanup := func() {
		_ = tmp.Close()
		if !renamed {
			_ = unix.Unlinkat(int(dir.Fd()), tmpName, 0)
		}
	}
	defer cleanup()
	if _, err := tmp.Write(signature); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := regularOrAbsentAt(dir, name); err != nil {
		return err
	}
	if err := unix.Renameat(int(dir.Fd()), tmpName, int(dir.Fd()), name); err != nil {
		return err
	}
	renamed = true
	if err := syncReleaseDirectory(dir); err != nil {
		return fmt.Errorf("signature %s committed but directory sync failed: %w", dest, err)
	}
	return nil
}

func verify(keyringFile, file, sigFile string) {
	keys, err := readPublicKeys(keyringFile)
	check(err)
	data, err := readBoundedRegularFile(file, maxReleaseBinaryBytes)
	check(err)
	sig, err := readBoundedRegularFile(sigFile, ed25519.SignatureSize)
	check(err)
	if len(sig) != ed25519.SignatureSize {
		fmt.Fprintf(os.Stderr, "invalid signature length: %d (want %d)\n", len(sig), ed25519.SignatureSize)
		os.Exit(1)
	}
	for _, key := range keys {
		if ed25519.Verify(key, data, sig) {
			fmt.Fprintf(os.Stderr, "ok: %s verifies against %s\n", file, keyringFile)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "SIGNATURE INVALID: %s\n", file)
	os.Exit(1)
}

func readPublicKeys(file string) ([]ed25519.PublicKey, error) {
	b, err := readBoundedRegularFile(file, maxReleaseMetadataBytes)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	seen := make(map[string]struct{})
	for lineNo, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := hex.DecodeString(line)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key at %s:%d", file, lineNo+1)
		}
		id := string(raw)
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate ed25519 public key at %s:%d", file, lineNo+1)
		}
		seen[id] = struct{}{}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no ed25519 public keys in %s", file)
	}
	return keys, nil
}

func readBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, fmt.Errorf("invalid read limit %d", maxBytes)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s is not a regular non-symlink file", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular non-symlink file", path)
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	return b, nil
}

func writePEMKeyring(file string) {
	keys, err := readPublicKeys(file)
	check(err)
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(key)
		check(err)
		check(pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
}

func loadPriv(file string) ed25519.PrivateKey {
	key, err := readPrivateKey(file)
	check(err)
	return key
}

func readPrivateKey(file string) (ed25519.PrivateKey, error) {
	dirPath, name, err := splitOwnedTarget(file)
	if err != nil {
		return nil, err
	}
	dir, err := openOwnedDir(dirPath, false)
	if err != nil {
		return nil, fmt.Errorf("unsafe private-key directory: %w", err)
	}
	defer dir.Close()
	f, err := openFileAt(dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("private key %s is not a regular non-symlink file", file)
		}
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("private key %s is not a regular non-symlink file", file)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("cannot stat private key %s", file)
	}
	if int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("private key %s is owned by uid %d, want current uid %d", file, st.Uid, os.Geteuid())
	}
	special := os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if fi.Mode().Perm() != 0o600 || fi.Mode()&special != 0 {
		return nil, fmt.Errorf("private key %s mode is %v, want exactly 0600", file, fi.Mode())
	}
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		return nil, err
	}
	if len(b) > 1024 {
		return nil, fmt.Errorf("private key %s is too large", file)
	}
	defer clear(b)
	encoded := bytes.TrimSpace(b)
	raw := make([]byte, hex.DecodedLen(len(encoded)))
	n, err := hex.Decode(raw, encoded)
	if err != nil {
		clear(raw)
		return nil, err
	}
	raw = raw[:n]
	if len(raw) != ed25519.PrivateKeySize {
		clear(raw)
		return nil, fmt.Errorf("invalid private key length: %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

var syncReleaseDirectory = func(dir *os.File) error { return dir.Sync() }

func splitOwnedTarget(path string) (dir, name string, err error) {
	if path == "" || strings.HasSuffix(path, string(filepath.Separator)) {
		return "", "", fmt.Errorf("unsafe empty target name in %q", path)
	}
	name = filepath.Base(path)
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return "", "", fmt.Errorf("unsafe target name %q", name)
	}
	return filepath.Dir(path), name, nil
}

// openOwnedDir traverses from / on pinned directory descriptors. In create mode
// it mkdirs missing components only after every existing ancestor has passed the
// ownership/mode policy, so a symlink can never redirect even a directory-creation
// side effect. The returned descriptor pins the final directory for later openat.
func openOwnedDir(dir string, create bool) (*os.File, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	clean := filepath.Clean(absDir)
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("open directory traversal root")
	}
	if clean == string(filepath.Separator) {
		if err := validateOwnedDirectoryFD(clean, current, true); err != nil {
			_ = current.Close()
			return nil, err
		}
		return current, nil
	}
	if err := validateOwnedDirectoryFD(string(filepath.Separator), current, false); err != nil {
		_ = current.Close()
		return nil, err
	}

	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	currentPath := string(filepath.Separator)
	for i, part := range parts {
		currentPath = filepath.Join(currentPath, part)
		created := false
		childFD, openErr := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			mkdirErr := unix.Mkdirat(int(current.Fd()), part, 0o700)
			if mkdirErr == nil {
				created = true
			} else if !errors.Is(mkdirErr, unix.EEXIST) {
				_ = current.Close()
				return nil, fmt.Errorf("create directory component %s: %w", currentPath, mkdirErr)
			}
			childFD, openErr = unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, fmt.Errorf("%s is not a real directory", currentPath)
			}
			return nil, openErr
		}
		child := os.NewFile(uintptr(childFD), currentPath)
		if child == nil {
			_ = unix.Close(childFD)
			_ = current.Close()
			return nil, fmt.Errorf("open directory component %s", currentPath)
		}
		leaf := i == len(parts)-1
		if err := validateOwnedDirectoryFD(currentPath, child, leaf); err != nil {
			_ = child.Close()
			_ = current.Close()
			return nil, err
		}
		if created {
			if err := child.Chmod(0o700); err != nil {
				_ = child.Close()
				_ = current.Close()
				return nil, err
			}
			if err := syncReleaseDirectory(child); err != nil {
				_ = child.Close()
				_ = current.Close()
				return nil, fmt.Errorf("sync created directory %s: %w", currentPath, err)
			}
			if err := syncReleaseDirectory(current); err != nil {
				_ = child.Close()
				_ = current.Close()
				return nil, fmt.Errorf("sync parent after creating %s: %w", currentPath, err)
			}
		}
		if err := current.Close(); err != nil {
			_ = child.Close()
			return nil, err
		}
		current = child
	}
	return current, nil
}

func validateOwnedDirectoryFD(path string, dir *os.File, leaf bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a real directory", path)
	}
	uid := int(stat.Uid)
	perm := os.FileMode(stat.Mode & 0o777)
	if leaf {
		if uid != os.Geteuid() {
			return fmt.Errorf("%s is not owned by current uid %d", path, os.Geteuid())
		}
		if perm&0o022 != 0 {
			return fmt.Errorf("%s is group/world writable (mode %o)", path, perm)
		}
		return nil
	}
	if uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("ancestor %s is owned by unexpected uid %d", path, uid)
	}
	if perm&0o022 != 0 && stat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("ancestor %s is writable without the sticky bit (mode %o)", path, perm)
	}
	return nil
}

func openFileAt(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name))
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open %s", name)
	}
	return f, nil
}

func regularOrAbsentAt(dir *os.File, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a regular non-symlink file", filepath.Join(dir.Name(), name))
	}
	return nil
}

func createTempFileAt(dir *os.File, prefix string) (*os.File, string, error) {
	for range 128 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(nonce[:])
		f, err := openFileAt(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return f, name, err
	}
	return nil, "", fmt.Errorf("cannot allocate a unique temporary signature file")
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
