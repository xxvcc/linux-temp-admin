// Package fsutil provides atomic, symlink-safe file and directory writes for
// privileged (root-owned) paths, replacing the bash tool's `install -d`/
// `safe_write_root_file` logic. Ownership and mode are set on file descriptors
// (fchown/fchmod), and the destination is never chown/chmod'd by name after the
// final rename, so an attacker-planted symlink at the target is never followed.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// notWritableByGroupOther is the mask for group/other write bits.
const notWritableByGroupOther = 0o022

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
// and not group/world writable.
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
	return checkRootOwnedNotWritable(path, fi)
}

func checkRootOwnedNotWritable(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot stat %s", path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s is not owned by root (uid %d)", path, st.Uid)
	}
	if fi.Mode().Perm()&notWritableByGroupOther != 0 {
		return fmt.Errorf("%s is group/world writable (mode %o)", path, fi.Mode().Perm())
	}
	return nil
}

// EnsureDir creates path (and parents) if needed and sets its owner/mode, all
// while refusing to follow a symlink at the leaf. Safe to call repeatedly.
func EnsureDir(path string, mode os.FileMode, uid, gid int) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing", path)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	// Reopen the leaf with O_NOFOLLOW so a swapped-in symlink can't redirect the
	// chown/chmod; operate on the fd.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("reopen dir %s: %w", path, err)
	}
	defer f.Close()
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	return f.Chmod(mode)
}

// WriteRootFile atomically writes a root:root file at path with mode. The parent
// directory must be root-safe and the target, if it exists, must be a regular
// non-symlink file.
func WriteRootFile(path string, content []byte, mode os.FileMode) error {
	if err := RootSafeDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("unsafe target directory: %w", err)
	}
	if err := requireRegularOrAbsent(path); err != nil {
		return err
	}
	return AtomicWriteFileAs(path, content, mode, 0, 0)
}

// AtomicWriteFileAs writes content to path atomically: a temp file is created in
// the same directory (O_EXCL via CreateTemp), its owner/mode are set on the fd,
// the target is re-checked for symlink safety, then the temp is renamed over it.
// The destination is never chown/chmod'd by name afterward (rename preserves the
// temp's owner/mode), so an attacker symlink at the target is never followed.
// The caller is responsible for the parent directory's safety policy.
func AtomicWriteFileAs(path string, content []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(e error) error {
		tmp.Close()
		os.Remove(tmpName)
		return e
	}
	if _, err := tmp.Write(content); err != nil {
		return fail(err)
	}
	if err := tmp.Chown(uid, gid); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := requireRegularOrAbsent(path); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// requireRegularOrAbsent errors if path exists as a symlink or non-regular file.
func requireRegularOrAbsent(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a safe regular file; refusing", path)
	}
	return nil
}
