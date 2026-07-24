// Package lifecycle serializes privileged account and installation mutations.
package lifecycle

import (
	"fmt"
	"os"
	"syscall"
)

// Lock is an advisory process lock. Path must live outside removable application
// state so uninstall cannot unlink a held lock and let another process lock a new
// inode at the same pathname.
type Lock struct {
	Path string
}

// New returns a lifecycle lock at path.
func New(path string) *Lock { return &Lock{Path: path} }

// Acquire blocks until the lifecycle lock is held. The returned release function
// must be called exactly once.
func (l *Lock) Acquire() (func() error, error) {
	if l == nil || l.Path == "" {
		return func() error { return nil }, nil
	}
	f, err := os.OpenFile(l.Path, os.O_RDWR|os.O_CREATE|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lifecycle lock: %w", err)
	}
	fail := func(err error) (func() error, error) {
		_ = f.Close()
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat lifecycle lock: %w", err))
	}
	if !fi.Mode().IsRegular() {
		return fail(fmt.Errorf("lifecycle lock %s is not a regular file", l.Path))
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fail(fmt.Errorf("lifecycle lock %s is not owned by effective uid %d", l.Path, os.Geteuid()))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fail(fmt.Errorf("lifecycle lock %s is group/world accessible (mode %o)", l.Path, fi.Mode().Perm()))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fail(fmt.Errorf("flock lifecycle: %w", err))
	}
	released := false
	return func() error {
		if released {
			return fmt.Errorf("lifecycle lock released more than once")
		}
		released = true
		unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closeErr := f.Close()
		if unlockErr != nil {
			return fmt.Errorf("unlock lifecycle: %w", unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close lifecycle lock: %w", closeErr)
		}
		return nil
	}, nil
}
