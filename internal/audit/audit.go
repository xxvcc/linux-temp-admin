// Package audit attempts to append a root-owned record of each privileged
// mutating operation (account create/delete, sudo grant, install/uninstall/
// upgrade) to a log file. Each completed entry is one JSON object per line and
// records when, who (the invoking user under sudo, plus the effective uid), what,
// the target, and the result — giving an operator-attributable trail.
//
// The log lives in a root-owned 0700 directory and is written 0600 with
// O_NOFOLLOW, so an unprivileged local user can neither read nor redirect it.
// Note: a root-level compromise can still tamper with an on-host log; forwarding
// to a remote collector (out of scope here) is what makes it tamper-evident.
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"golang.org/x/sys/unix"
)

const (
	maxAuditRecordBytes = 64 << 10
	maxAuditLogBytes    = int64(64 << 20)
)

// Event is a single auditable operation, supplied by the caller.
type Event struct {
	Action string            // e.g. "account.create", "account.delete", "upgrade"
	Target string            // the affected username (empty for self-management)
	Result string            // "ok" or "fail"
	Detail string            // freeform note or error summary
	Fields map[string]string // optional structured params (host, sudo, auto, ...)
}

// record is the on-disk JSON shape.
type record struct {
	Time   string            `json:"time"`
	PID    int               `json:"pid"`
	Actor  string            `json:"actor"`
	UID    int               `json:"uid"`
	Action string            `json:"action"`
	Target string            `json:"target,omitempty"`
	Result string            `json:"result"`
	Detail string            `json:"detail,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Logger appends events to File, which must be a direct child of the absolute
// Dir. Fields are injectable so tests can point the complete layout at a
// temporary directory and supply a fixed clock/actor.
type Logger struct {
	Dir   string
	File  string
	Now   func() time.Time
	Actor func() (actor string, uid int)

	// write and sync are failure-injection hooks. Production leaves them nil.
	write func(*os.File, []byte) (int, error)
	sync  func(*os.File) error
}

// Default returns a Logger writing to the configured audit-log path.
func Default() *Logger {
	return &Logger{Dir: config.AuditLogDir, File: config.AuditLogFile, Now: time.Now, Actor: realActor}
}

// realActor names the human behind the operation: the pre-sudo user when run via
// sudo, otherwise "root" (a direct-root run carries no further identity). The
// effective uid is reported alongside.
func realActor() (string, int) {
	euid := os.Geteuid()
	if su := os.Getenv("SUDO_USER"); su != "" {
		return su, euid
	}
	return "root", euid
}

// Log appends one event. It is best-effort from the caller's perspective (it
// returns any error so the caller can warn). New writers serialize with flock;
// a failed write is truncated back to its locked starting size and the completed
// line is synced before success. After a crash, the next writer truncates an
// incomplete tail back to the last newline before appending, preserving JSONL
// framing. A concurrent writer from an older build that does not honor the lock
// can still violate this protocol. A nil/empty-path Logger is a no-op, which
// disables auditing (e.g. in tests).
func (l *Logger) Log(ev Event) error {
	if l == nil || l.Dir == "" || l.File == "" {
		return nil
	}
	if err := l.validateLayout(); err != nil {
		return err
	}
	if err := fsutil.EnsureDir(l.Dir, 0o700, 0, 0); err != nil {
		return fmt.Errorf("audit dir: %w", err)
	}
	if err := fsutil.RootSafeDir(l.Dir); err != nil {
		return fmt.Errorf("audit dir unsafe: %w", err)
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	actor, uid := "root", os.Geteuid()
	if l.Actor != nil {
		actor, uid = l.Actor()
	}
	result := ev.Result
	if result == "" {
		result = "ok"
	}
	line, err := json.Marshal(record{
		Time:   now().UTC().Format(time.RFC3339),
		PID:    os.Getpid(),
		Actor:  actor,
		UID:    uid,
		Action: ev.Action,
		Target: ev.Target,
		Result: result,
		Detail: ev.Detail,
		Fields: ev.Fields,
	})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if len(line) > maxAuditRecordBytes {
		return fmt.Errorf("audit record exceeds %d bytes", maxAuditRecordBytes)
	}
	// Open the append-oriented log without following a symlink planted at the path.
	// Existing logs are repaired to the required metadata through the descriptor
	// and then re-checked before any event is written.
	f, _, err := openAuditFile(l.File)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock audit log: %w", err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat locked audit log: %w", err)
	}
	if fi.Size() > maxAuditLogBytes {
		return fmt.Errorf("audit log reached its %d-byte limit; archive or rotate it before retrying", maxAuditLogBytes)
	}
	start, err := l.repairIncompleteTail(f, fi.Size())
	if err != nil {
		return fmt.Errorf("repair incomplete audit record: %w", err)
	}
	if start < 0 || start > maxAuditLogBytes-int64(len(line)) {
		return fmt.Errorf("audit log reached its %d-byte limit; archive or rotate it before retrying", maxAuditLogBytes)
	}
	write := l.write
	if write == nil {
		write = func(f *os.File, p []byte) (int, error) { return f.Write(p) }
	}
	if err := writeAll(f, line, write); err != nil {
		rollbackErr := f.Truncate(start)
		if rollbackErr == nil {
			rollbackErr = l.syncFile(f)
		}
		return errors.Join(fmt.Errorf("append audit record: %w", err), wrapIfErr("roll back partial audit record", rollbackErr))
	}
	if err := l.syncFile(f); err != nil {
		// The line is complete and visible, but its durability is unknown. Do not
		// truncate it: a failed sync gives no guarantee that a rollback could be made
		// durable either, and a complete possibly-durable record is the safer state.
		return fmt.Errorf("sync audit record: %w", err)
	}
	// Sync the parent even for an existing path. It may be the visible result of a
	// previous append whose new-file directory sync failed; retrying only the file
	// sync would otherwise report success without finishing that durability step.
	if err := syncAuditDirectory(filepath.Dir(l.File)); err != nil {
		return fmt.Errorf("sync audit log directory: %w", err)
	}
	return nil
}

func (l *Logger) validateLayout() error {
	dir := filepath.Clean(l.Dir)
	file := filepath.Clean(l.File)
	if !filepath.IsAbs(l.Dir) || dir != l.Dir || dir == string(filepath.Separator) {
		return fmt.Errorf("unsafe audit directory %q", l.Dir)
	}
	if !filepath.IsAbs(l.File) || file != l.File || filepath.Dir(file) != dir || file == dir {
		return fmt.Errorf("audit file %q must be a direct child of %s", l.File, dir)
	}
	return nil
}

func (l *Logger) repairIncompleteTail(f *os.File, size int64) (int64, error) {
	if size <= 0 {
		return size, nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], size-1); err != nil {
		return 0, err
	}
	if last[0] == '\n' {
		return size, nil
	}

	const blockSize = 64 << 10
	buf := make([]byte, blockSize)
	newSize := int64(0)
	for end := size; end > 0; {
		start := end - int64(len(buf))
		if start < 0 {
			start = 0
		}
		want := int(end - start)
		n, err := f.ReadAt(buf[:want], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if n != want {
			return 0, io.ErrUnexpectedEOF
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			newSize = start + int64(i) + 1
			break
		}
		end = start
	}
	if err := f.Truncate(newSize); err != nil {
		return 0, err
	}
	if err := l.syncFile(f); err != nil {
		return 0, err
	}
	return newSize, nil
}

func (l *Logger) syncFile(f *os.File) error {
	if l.sync != nil {
		return l.sync(f)
	}
	return f.Sync()
}

func writeAll(f *os.File, line []byte, write func(*os.File, []byte) (int, error)) error {
	for written := 0; written < len(line); {
		n, err := write(f, line[written:])
		if n < 0 || n > len(line)-written {
			return fmt.Errorf("invalid write count %d", n)
		}
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func wrapIfErr(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

var syncAuditDirectory = func(path string) error {
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func openAuditFile(path string) (*os.File, bool, error) {
	var before *syscall.Stat_t
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return nil, false, fmt.Errorf("%s is not a safe regular file", path)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, false, fmt.Errorf("cannot determine inode of %s", path)
		}
		if st.Nlink != 1 {
			return nil, false, fmt.Errorf("%s has %d hard links; refusing to mutate a shared inode", path, st.Nlink)
		}
		copy := *st
		before = &copy
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	created := before == nil
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, false, err
	}
	fail := func(err error) (*os.File, bool, error) {
		_ = f.Close()
		return nil, false, err
	}
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !fi.Mode().IsRegular() {
		return fail(fmt.Errorf("%s is not a regular file", path))
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fail(fmt.Errorf("cannot determine owner of %s", path))
	}
	if st.Nlink != 1 {
		return fail(fmt.Errorf("%s has %d hard links; refusing to mutate a shared inode", path, st.Nlink))
	}
	if before != nil && (before.Dev != st.Dev || before.Ino != st.Ino) {
		return fail(fmt.Errorf("%s was replaced while opening it", path))
	}
	if err := f.Chown(0, 0); err != nil {
		return fail(fmt.Errorf("repair owner of %s: %w", path, err))
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("repair mode of %s: %w", path, err))
	}
	fi, err = f.Stat()
	if err != nil {
		return fail(err)
	}
	st, ok = fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || st.Nlink != 1 || st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != 0o600 {
		return fail(fmt.Errorf("%s metadata remains unsafe after repair", path))
	}
	return f, created, nil
}
