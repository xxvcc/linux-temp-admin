// Package lifecycle serializes privileged account and installation mutations.
package lifecycle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

// ErrBusy is returned by TryAcquire when another process owns the lifecycle
// lock. Callers that cannot safely queue behind an in-flight mutation can use it
// to abandon that operation without changing the host.
var ErrBusy = errors.New("lifecycle lock is busy")

// Lock is an advisory process lock. Path must live outside removable application
// state so uninstall cannot unlink a held lock and let another process lock a new
// inode at the same pathname.
type Lock struct {
	Path string
}

// New returns a lifecycle lock at path.
func New(path string) *Lock { return &Lock{Path: path} }

const tombstoneContent = "uninstalled-v1\n"

func (l *Lock) tombstonePath() string { return l.Path + ".uninstalled" }

// Acquire blocks until the lifecycle lock is held. The returned release function
// must be called exactly once.
func (l *Lock) Acquire() (func() error, error) {
	return l.acquire(syscall.LOCK_EX)
}

// AcquireShared blocks until a shared lifecycle lock is held. It is used by
// operations that may run one at a time under a separate global lock but must all
// finish before an exclusive same-object replacement begins.
func (l *Lock) AcquireShared() (func() error, error) {
	return l.acquire(syscall.LOCK_SH)
}

// TryAcquire acquires the lifecycle lock without waiting. It returns ErrBusy
// when another process owns the lock; every other validation and I/O error is
// reported exactly as Acquire reports it.
func (l *Lock) TryAcquire() (func() error, error) {
	return l.acquire(syscall.LOCK_EX | syscall.LOCK_NB)
}

// TryAcquireShared acquires a shared lifecycle lock without waiting.
func (l *Lock) TryAcquireShared() (func() error, error) {
	return l.acquire(syscall.LOCK_SH | syscall.LOCK_NB)
}

func (l *Lock) acquire(operation int) (func() error, error) {
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
	if err := syscall.Flock(int(f.Fd()), operation); err != nil {
		if operation&syscall.LOCK_NB != 0 && (errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)) {
			return fail(ErrBusy)
		}
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

// MarkUninstalled records that a completed teardown owns the lifecycle. It must
// be called while the lock is held, after accounts and grants are gone but before
// removable state or the stable binary is removed. The marker lives beside the
// lock, outside removable application state, so a crash cannot leave state gone
// without stopping already-running processes when they later acquire the lock.
func (l *Lock) MarkUninstalled() error {
	if l == nil || l.Path == "" {
		return nil
	}
	return fsutil.AtomicWriteFileAs(l.tombstonePath(), []byte(tombstoneContent), 0o600, os.Geteuid(), os.Getegid())
}

// IsUninstalled validates and reads the marker. Unsafe marker metadata is an
// error, not "installed": a caller must fail closed rather than let an attacker
// bypass the lifecycle gate with a malformed file.
func (l *Lock) IsUninstalled() (bool, error) {
	if l == nil || l.Path == "" {
		return false, nil
	}
	path := l.tombstonePath()
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("open uninstall marker: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("stat uninstall marker: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid() || fi.Mode().Perm() != 0o600 {
		return false, fmt.Errorf("uninstall marker %s has unsafe metadata", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(len(tombstoneContent)+1)))
	if err != nil {
		return false, fmt.Errorf("read uninstall marker: %w", err)
	}
	if !bytes.Equal(b, []byte(tombstoneContent)) {
		return false, fmt.Errorf("uninstall marker %s has invalid content", path)
	}
	return true, nil
}

// ClearUninstalled re-enables mutations after an explicit successful install.
// It must be called while the lifecycle lock is held.
func (l *Lock) ClearUninstalled() error {
	if l == nil || l.Path == "" {
		return nil
	}
	return fsutil.RemoveFile(l.tombstonePath())
}
