// Package fsutil provides atomic, symlink-safe file and directory writes for
// privileged (root-owned) paths. Ownership and mode are set on file descriptors
// (fchown/fchmod), and the destination is never chown/chmod'd by name after the
// final rename, so an attacker-planted symlink at the target is never followed.
package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

// notWritableByGroupOther is the mask for group/other write bits.
const notWritableByGroupOther = 0o022

// DurabilityError means a filesystem mutation became visible but syncing the
// parent directory failed. Callers must not retry as though nothing happened:
// they need to inspect, roll back, or otherwise reconcile the committed change.
type DurabilityError struct {
	Operation string
	Err       error
}

func (e *DurabilityError) Error() string {
	op := e.Operation
	if op == "" {
		op = "filesystem mutation"
	}
	return fmt.Sprintf("%s committed but parent directory sync failed: %v", op, e.Err)
}

func (e *DurabilityError) Unwrap() error { return e.Err }

// RootSafeDir verifies path is a real directory (not a symlink), owned by root,
// and not group/world writable.
func RootSafeDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return checkRootOwnedNotWritable(path, fi)
}

// RootSafeFile verifies path is a regular file (not a symlink), owned by root,
// not group/world writable, and carries no set-id/sticky special bits. A managed
// executable must never become a privilege-escalation entry point merely because
// its content and owner otherwise look safe.
func RootSafeFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if special := fi.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky); special != 0 {
		return fmt.Errorf("%s has unsafe special mode bits (%v)", path, special)
	}
	return checkRootOwnedNotWritable(path, fi)
}

func checkRootOwnedNotWritable(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot stat %s", path)
	}
	if st.Uid != 0 || st.Gid != 0 {
		return fmt.Errorf("%s is not owned by root:root (owner %d:%d)", path, st.Uid, st.Gid)
	}
	if fi.Mode().Perm()&notWritableByGroupOther != 0 {
		return fmt.Errorf("%s is group/world writable (mode %o)", path, fi.Mode().Perm())
	}
	return nil
}

// EnsureDir creates path (and parents) component by component, refusing symlinks
// anywhere in the path. A newly created directory is synced before its parent
// directory entry, and the leaf is synced after ownership/mode repair.
func EnsureDir(path string, mode os.FileMode, uid, gid int) error {
	if path == "" {
		return fmt.Errorf("empty directory path")
	}
	if !validate.KernelID(uid) || !validate.KernelID(gid) {
		return fmt.Errorf("invalid directory owner %d:%d", uid, gid)
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return fmt.Errorf("refusing to change broad directory %q", path)
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("unsafe directory component %q in %s", part, path)
		}
	}

	start := "."
	if filepath.IsAbs(clean) {
		start = string(filepath.Separator)
	}
	rootFD, err := unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open directory traversal root %s: %w", start, err)
	}
	parent := os.NewFile(uintptr(rootFD), start)
	defer func() { _ = parent.Close() }()

	for i, part := range parts {
		created := false
		childFD, openErr := unix.Openat(int(parent.Fd()), part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr == unix.ENOENT {
			if mkdirErr := unix.Mkdirat(int(parent.Fd()), part, uint32(mode.Perm())); mkdirErr == nil {
				created = true
			} else if mkdirErr != unix.EEXIST {
				return fmt.Errorf("create directory component %s: %w", part, mkdirErr)
			}
			childFD, openErr = unix.Openat(int(parent.Fd()), part,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			return fmt.Errorf("open directory component %s without following links: %w", part, openErr)
		}
		child := os.NewFile(uintptr(childFD), filepath.Join(parent.Name(), part))
		last := i == len(parts)-1
		if last {
			if err := child.Chown(uid, gid); err != nil {
				_ = child.Close()
				return fmt.Errorf("set directory owner for %s: %w", path, err)
			}
			if err := child.Chmod(mode); err != nil {
				_ = child.Close()
				return fmt.Errorf("set directory mode for %s: %w", path, err)
			}
		}
		if created || last {
			if err := syncDirectory(child); err != nil {
				_ = child.Close()
				return &DurabilityError{Operation: "directory metadata update", Err: err}
			}
		}
		if created {
			if err := syncDirectory(parent); err != nil {
				_ = child.Close()
				return &DurabilityError{Operation: "mkdir", Err: err}
			}
		}
		if err := parent.Close(); err != nil {
			_ = child.Close()
			return fmt.Errorf("close directory component: %w", err)
		}
		parent = child
	}
	return nil
}

// WriteRootFile atomically writes a root:root file at path with mode. The parent
// directory must be root-safe and the target, if it exists, must be a regular
// non-symlink file.
func WriteRootFile(path string, content []byte, mode os.FileMode) error {
	dirPath := filepath.Dir(path)
	dir, err := os.OpenFile(dirPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open target directory %s: %w", dirPath, err)
	}
	defer dir.Close()
	if afterRootDirOpen != nil {
		afterRootDirOpen()
	}
	if err := rootSafeDirectoryFD(dirPath, dir); err != nil {
		return fmt.Errorf("unsafe target directory: %w", err)
	}
	return AtomicWriteFileAt(dir, filepath.Base(path), content, mode, 0, 0)
}

// afterRootDirOpen is a deterministic path-swap hook used by the integration
// test. Production leaves it nil.
var afterRootDirOpen func()

func rootSafeDirectoryFD(path string, dir *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a directory", path)
	}
	if stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("%s is not owned by root:root (owner %d:%d)", path, stat.Uid, stat.Gid)
	}
	if stat.Mode&notWritableByGroupOther != 0 {
		return fmt.Errorf("%s is group/world writable (mode %o)", path, stat.Mode&0o7777)
	}
	return nil
}

// AtomicWriteFileAs writes content to path atomically: the parent directory is
// pinned by fd, a temp file is created there with openat(O_EXCL), its owner/mode
// are set on the fd, and renameat replaces the re-checked target.
// The destination is never chown/chmod'd by name afterward (rename preserves the
// temp's owner/mode), so an attacker symlink at the target is never followed.
// The caller is responsible for the parent directory's safety policy.
func AtomicWriteFileAs(path string, content []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	dirFile, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open parent directory %s: %w", dir, err)
	}
	defer dirFile.Close()
	return AtomicWriteFileAt(dirFile, filepath.Base(path), content, mode, uid, gid)
}

// syncDirectory is indirected so a unit test can prove that a successful rename
// is followed by the directory fsync needed to make the new name durable.
var syncDirectory = func(dir *os.File) error { return dir.Sync() }

// AtomicWriteFileAt atomically writes a single file relative to an already-open
// directory. openat/renameat keep every operation bound to the same directory
// inode even if an attacker renames or replaces its pathname concurrently.
func AtomicWriteFileAt(dir *os.File, name string, content []byte, mode os.FileMode, uid, gid int) error {
	if dir == nil {
		return fmt.Errorf("nil target directory")
	}
	if !validate.KernelID(uid) || !validate.KernelID(gid) {
		return fmt.Errorf("invalid file owner %d:%d", uid, gid)
	}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsRune(name, os.PathSeparator) {
		return fmt.Errorf("unsafe target name %q", name)
	}
	var dirStat unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &dirStat); err != nil {
		return fmt.Errorf("stat target directory: %w", err)
	}
	if dirStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("target fd is not a directory")
	}
	if err := requireRegularOrAbsentAt(int(dir.Fd()), name); err != nil {
		return err
	}

	tmpName, tmp, err := createTempAt(dir, name)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = unix.Unlinkat(int(dir.Fd()), tmpName, 0)
		}
	}()
	for written := 0; written < len(content); {
		n, err := tmp.Write(content[written:])
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write to temporary file")
		}
	}
	if err := tmp.Chown(uid, gid); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := requireRegularOrAbsentAt(int(dir.Fd()), name); err != nil {
		return err
	}
	if err := unix.Renameat(int(dir.Fd()), tmpName, int(dir.Fd()), name); err != nil {
		return err
	}
	cleanup = false
	if err := syncDirectory(dir); err != nil {
		return &DurabilityError{Operation: "rename", Err: err}
	}
	return nil
}

// RemoveFile unlinks one non-directory entry relative to a pinned parent
// directory and syncs that directory before returning success. It never follows
// a symlink at either the parent or target. An absent target is already removed
// and is therefore success.
func RemoveFile(path string) error {
	dirPath := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "" || name == "." || name == ".." || filepath.Clean(path) == dirPath {
		return fmt.Errorf("unsafe removal path %q", path)
	}
	dir, err := os.OpenFile(dirPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open parent directory %s: %w", dirPath, err)
	}
	defer dir.Close()

	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("stat removal target %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		return fmt.Errorf("refusing to unlink directory %s", path)
	}
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("unlink %s: %w", path, err)
	}
	if err := syncDirectory(dir); err != nil {
		return &DurabilityError{Operation: "unlink", Err: err}
	}
	return nil
}

func createTempAt(dir *os.File, target string) (string, *os.File, error) {
	for i := 0; i < 128; i++ {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", nil, fmt.Errorf("generate temporary filename: %w", err)
		}
		name := "." + target + "." + hex.EncodeToString(suffix[:])
		fd, err := unix.Openat(int(dir.Fd()), name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == unix.EEXIST {
			continue
		}
		if err != nil {
			return "", nil, fmt.Errorf("create temporary file: %w", err)
		}
		return name, os.NewFile(uintptr(fd), name), nil
	}
	return "", nil, fmt.Errorf("could not allocate a unique temporary file")
}

func requireRegularOrAbsentAt(dirFD int, name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a safe regular file; refusing", name)
	}
	return nil
}
