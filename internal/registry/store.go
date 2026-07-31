package registry

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

const maxRegistryBytes = int64(16 << 20)

// Store is the flock-guarded, root-owned registry of managed accounts. Dir must
// be absolute; File and Lock must be distinct direct children. Paths are fields
// so tests can point the complete layout at a temporary directory.
type Store struct {
	Dir  string
	File string
	Lock string
}

// Default returns a Store using the configured registry paths.
func Default() *Store {
	return &Store{Dir: config.RegistryDir, File: config.RegistryFile, Lock: config.RegistryLockFile}
}

// Init creates the registry directory (0700 root), the registry file (with the
// schema header if new), and the lock file, refusing any symlinked component.
func (s *Store) Init() error {
	if err := s.validateLayout(); err != nil {
		return err
	}
	if fi, err := os.Lstat(s.Dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("registry dir %s is a symlink", s.Dir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("registry path %s is not a directory", s.Dir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := fsutil.EnsureDir(s.Dir, 0o700, 0, 0); err != nil {
		return err
	}
	dir, err := os.OpenFile(s.Dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open registry dir: %w", err)
	}
	defer dir.Close()
	if err := requireRootDirFD(s.Dir, dir, 0o700); err != nil {
		return fmt.Errorf("registry dir unsafe: %w", err)
	}

	// The lock must be created in place. An atomic-write helper would rename a
	// different inode over the pathname, allowing concurrent first-time Init calls
	// to lock different files and enter the critical section together.
	lock, err := openOrCreateLockAt(dir, filepath.Base(s.Lock), s.Lock)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := requireRegularFD(s.Lock, lock); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock registry: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	if err := repairRootFileFD(s.Lock, lock); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return &fsutil.DurabilityError{Operation: "registry lock directory entry", Err: err}
	}

	// Upgrade deployed registries only while holding their lock. New writes use a
	// v4 header that older binaries reject, preventing them from dropping the
	// deletion recovery phase during a delayed rewrite.
	if err := ensureFile(s.File, []byte(Header+"\n")); err != nil {
		return err
	}
	recs, header, err := s.readAllWithHeader()
	if err != nil {
		return err
	}
	if header == legacyHeaderV2 || header == legacyHeaderV3 {
		return s.writeAll(recs)
	}
	return nil
}

func (s *Store) validateLayout() error {
	if s == nil {
		return fmt.Errorf("nil registry store")
	}
	dir := filepath.Clean(s.Dir)
	if s.Dir == "" || !filepath.IsAbs(s.Dir) || dir != s.Dir || dir == string(filepath.Separator) {
		return fmt.Errorf("unsafe registry directory %q", s.Dir)
	}
	for label, path := range map[string]string{"file": s.File, "lock": s.Lock} {
		clean := filepath.Clean(path)
		if path == "" || !filepath.IsAbs(path) || clean != path || filepath.Dir(clean) != dir || clean == dir {
			return fmt.Errorf("registry %s %q must be a direct child of %s", label, path, dir)
		}
	}
	if s.File == s.Lock {
		return fmt.Errorf("registry file and lock must be different paths")
	}
	return nil
}

func openOrCreateLockAt(dir *os.File, name, path string) (*os.File, error) {
	if dir == nil || name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, fmt.Errorf("unsafe registry lock name %q", name)
	}
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open or create registry lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open or create registry lock: invalid file descriptor")
	}
	return f, nil
}

func ensureFile(path string, initial []byte) error {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return fsutil.WriteRootFile(path, initial, 0o600)
		}
		return err
	}
	defer f.Close()
	return repairRootFileFD(path, f)
}

func repairRootFileFD(path string, f *os.File) error {
	if err := requireRegularFD(path, f); err != nil {
		return err
	}
	if err := f.Chown(0, 0); err != nil {
		return fmt.Errorf("repair owner of %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("repair mode of %s: %w", path, err)
	}
	if err := syncRegistryFile(f); err != nil {
		return &fsutil.DurabilityError{Operation: "registry metadata repair", Err: err}
	}
	return requireRootFileFD(path, f, 0o600)
}

var syncRegistryFile = func(f *os.File) error { return f.Sync() }

// withLock runs fn while holding an exclusive advisory lock on the lock file.
func (s *Store) withLock(fn func() error) error {
	f, err := os.OpenFile(s.Lock, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open registry lock: %w", err)
	}
	defer f.Close()
	if err := requireRootFileFD(s.Lock, f, 0o600); err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock registry: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// readAll reads and parses the registry (unlocked; reads see a consistent inode
// even across a concurrent atomic rewrite). Missing file yields no records.
func (s *Store) readAll() ([]Record, error) {
	recs, _, err := s.readAllWithHeader()
	return recs, err
}

func (s *Store) readAllWithHeader() ([]Record, string, error) {
	f, err := os.OpenFile(s.File, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	defer f.Close()
	if err := requireRootFileFD(s.File, f, 0o600); err != nil {
		return nil, "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRegistryBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(b)) > maxRegistryBytes {
		return nil, "", fmt.Errorf("registry exceeds %d bytes", maxRegistryBytes)
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || (lines[0] != Header && lines[0] != legacyHeaderV3 && lines[0] != legacyHeaderV2) {
		return nil, "", fmt.Errorf("registry header is missing or unsupported")
	}
	header := lines[0]
	var recs []Record
	seenUsers := make(map[string]int)
	for i, line := range lines[1:] {
		lineNumber := i + 2
		if line == Header || line == legacyHeaderV3 || line == legacyHeaderV2 {
			return nil, "", fmt.Errorf("registry line %d: duplicate schema header", lineNumber)
		}
		var r Record
		var ok bool
		var err error
		switch header {
		case Header:
			r, ok, err = ParseLine(line)
		case legacyHeaderV3:
			r, ok, err = parseLegacyV3Line(line)
		case legacyHeaderV2:
			r, ok, err = parseLegacyV2Line(line)
		}
		if err != nil {
			return nil, "", fmt.Errorf("registry line %d: %w", lineNumber, err)
		}
		if ok {
			if firstLine, exists := seenUsers[r.User]; exists {
				return nil, "", fmt.Errorf("registry line %d: duplicate username %q (first seen on line %d)", lineNumber, r.User, firstLine)
			}
			seenUsers[r.User] = lineNumber
			recs = append(recs, r)
		}
	}
	return recs, header, nil
}

func requireRegularFD(path string, f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a safe regular file", path)
	}
	return nil
}

func requireRootDirFD(path string, f *os.File, mode os.FileMode) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("%s metadata is unsafe: owner %d:%d mode %o, want root:root %o",
			path, st.Uid, st.Gid, fi.Mode().Perm(), mode.Perm())
	}
	return nil
}

func requireRootFileFD(path string, f *os.File, mode os.FileMode) error {
	if err := requireRegularFD(path, f); err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("%s metadata is unsafe: owner %d:%d mode %o, want root:root %o",
			path, st.Uid, st.Gid, fi.Mode().Perm(), mode.Perm())
	}
	return nil
}

// writeAll atomically rewrites the registry from recs (header + one line each).
func (s *Store) writeAll(recs []Record) error {
	var b strings.Builder
	b.WriteString(Header)
	b.WriteByte('\n')
	for _, r := range recs {
		row := r.TSV()
		remaining := maxRegistryBytes - int64(b.Len())
		if remaining < 1 || int64(len(row)) > remaining-1 {
			return fmt.Errorf("registry output exceeds %d bytes", maxRegistryBytes)
		}
		b.WriteString(row)
		b.WriteByte('\n')
	}
	return fsutil.WriteRootFile(s.File, []byte(b.String()), 0o600)
}

// Record upserts an ordinary creation/active record. A deletion recovery row is
// immutable through this general API: callers must use BeginDeletion and
// FinishDeletionRecovery so a new invite or routine update cannot erase the only
// durable authority for post-userdel cleanup.
func (s *Store) Record(rec Record) error {
	if _, ok, err := ParseLine(rec.TSV()); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("record did not produce a data row")
		}
		return fmt.Errorf("invalid registry record: %w", err)
	}
	if rec.DeletionStarted {
		return fmt.Errorf("deletion-started state requires BeginDeletion")
	}
	return s.withLock(func() error {
		recs, err := s.readAll()
		if err != nil {
			return err
		}
		out := recs[:0:0]
		for _, r := range recs {
			if r.User == rec.User {
				if r.DeletionStarted {
					return fmt.Errorf("registry record for %s is in deletion recovery", rec.User)
				}
				continue
			}
			out = append(out, r)
		}
		out = append(out, rec)
		return s.writeAll(out)
	})
}

// BeginDeletion durably enters the phase before controlled mail/Home cleanup and
// userdel. A non-empty generation can only mark an existing, completed
// identity-bound row with the same user, UID, and generation. An empty generation
// requests a UID-only recovery witness: an existing legacy row is converted, an
// unregistered name is inserted, and a rollback-pending row is deliberately
// stripped of pending and generation authority. Repeating the exact same
// transition is harmless.
func (s *Store) BeginDeletion(user string, uid int, generation string) error {
	if err := validateDeletionIdentity(user, uid, generation); err != nil {
		return err
	}
	return s.withLock(func() error {
		recs, err := s.readAll()
		if err != nil {
			return err
		}
		out, changed, err := beginDeletionRecords(recs, user, uid, generation)
		if err != nil || !changed {
			return err
		}
		return s.writeAll(out)
	})
}

func validateDeletionIdentity(user string, uid int, generation string) error {
	if !validate.Username(user) || !validate.AccountID(uid) ||
		(generation != "" && !validate.Generation(generation)) {
		return fmt.Errorf("invalid deletion identity")
	}
	return nil
}

// beginDeletionRecords contains the state transition independently of filesystem
// ownership and locking. The Store method above supplies both; keeping the
// transition pure makes every identity mismatch testable without root.
func beginDeletionRecords(recs []Record, user string, uid int, generation string) ([]Record, bool, error) {
	if err := validateDeletionIdentity(user, uid, generation); err != nil {
		return nil, false, err
	}
	out := append([]Record(nil), recs...)
	for i := range out {
		if out[i].User != user {
			continue
		}
		current := out[i]
		if current.DeletionStarted {
			boundMatches := generation != "" && current.IdentityBound && current.Generation == generation
			uidOnlyMatches := generation == "" && !current.IdentityBound && current.Generation == ""
			if current.UID != uid || (!boundMatches && !uidOnlyMatches) {
				return nil, false, fmt.Errorf("registry deletion recovery identity changed")
			}
			return out, false, nil
		}

		if generation != "" {
			if current.Pending || !current.IdentityBound || current.UID != uid || current.Generation != generation {
				return nil, false, fmt.Errorf("registry identity changed before deletion")
			}
			current.DeletionStarted = true
		} else {
			// A completed bound row must not be silently weakened. Pending rollback
			// is the exception: after the caller has authorized userdel it becomes a
			// recovery-only witness, so a crash cannot turn that pending intent into
			// unattended live-account deletion authority.
			if current.IdentityBound && !current.Pending {
				return nil, false, fmt.Errorf("identity-bound registry row requires its generation")
			}
			if current.UID != 0 && current.UID != uid {
				return nil, false, fmt.Errorf("registry UID changed before deletion")
			}
			current.UID = uid
			current.Generation = ""
			current.IdentityBound = false
			current.Pending = false
			current.DeletionStarted = true
		}
		if _, ok, err := ParseLine(current.TSV()); err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("deletion transition did not produce a data row")
			}
			return nil, false, fmt.Errorf("invalid deletion transition: %w", err)
		}
		out[i] = current
		return out, true, nil
	}

	if generation != "" {
		return nil, false, fmt.Errorf("registry identity disappeared before deletion")
	}
	recovery := Record{User: user, UID: uid, DeletionStarted: true}
	if _, ok, err := ParseLine(recovery.TSV()); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("deletion transition did not produce a data row")
		}
		return nil, false, fmt.Errorf("invalid deletion transition: %w", err)
	}
	return append(out, recovery), true, nil
}

// FinishDeletionRecovery removes only the exact row whose deletion phase was
// durably started. Every row is bound by user+UID; an identity-bound row also
// requires its exact generation, while a UID-only row requires generation to be
// empty. Absence is an idempotent success and a different same-name row is never
// removed.
func (s *Store) FinishDeletionRecovery(user string, uid int, generation string) error {
	if err := validateDeletionIdentity(user, uid, generation); err != nil {
		return fmt.Errorf("invalid deletion recovery identity: %w", err)
	}
	absent, err := s.completelyAbsent()
	if err != nil {
		return err
	}
	if absent {
		return nil
	}
	return s.withLock(func() error {
		recs, err := s.readAll()
		if err != nil {
			return err
		}
		out, changed, err := finishDeletionRecoveryRecords(recs, user, uid, generation)
		if err != nil || !changed {
			return err
		}
		return s.writeAll(out)
	})
}

func finishDeletionRecoveryRecords(recs []Record, user string, uid int, generation string) ([]Record, bool, error) {
	if err := validateDeletionIdentity(user, uid, generation); err != nil {
		return nil, false, fmt.Errorf("invalid deletion recovery identity: %w", err)
	}
	out := make([]Record, 0, len(recs))
	for i, r := range recs {
		if r.User != user {
			out = append(out, r)
			continue
		}
		boundMatches := generation != "" && r.IdentityBound && r.Generation == generation
		uidOnlyMatches := generation == "" && !r.IdentityBound && r.Generation == ""
		if !r.DeletionStarted || r.UID != uid || (!boundMatches && !uidOnlyMatches) {
			return nil, false, fmt.Errorf("registry deletion recovery identity changed")
		}
		return append(out, recs[i+1:]...), true, nil
	}
	return append([]Record(nil), recs...), false, nil
}

// Remove deletes an ordinary entry for user (no error if absent). Recovery rows
// require FinishDeletionRecovery and cannot be discarded by name alone.
func (s *Store) Remove(user string) error {
	absent, err := s.completelyAbsent()
	if err != nil {
		return err
	}
	if absent {
		return nil
	}
	return s.withLock(func() error {
		recs, err := s.readAll()
		if err != nil {
			return err
		}
		out := recs[:0:0]
		removed := false
		for _, r := range recs {
			if r.User == user {
				if r.DeletionStarted {
					return fmt.Errorf("registry record for %s is in deletion recovery", user)
				}
				removed = true
				continue
			}
			out = append(out, r)
		}
		if !removed {
			return nil
		}
		return s.writeAll(out)
	})
}

// Contains reports whether user has a registry entry.
func (s *Store) Contains(user string) (bool, error) {
	recs, err := s.readAll()
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if r.User == user {
			return true, nil
		}
	}
	return false, nil
}

// List returns all records.
func (s *Store) List() ([]Record, error) { return s.readAll() }

// Lookup returns user's record. found is false when the account has no entry.
// Callers that need more than one field of a record (revoke needs the recorded
// UID, the auto-revoke unit, and registration all at once) should use this
// rather than several single-field lookups, so every field they act on comes
// from one consistent read of the file.
func (s *Store) Lookup(user string) (rec Record, found bool, err error) {
	recs, err := s.readAll()
	if err != nil {
		return Record{}, false, err
	}
	for _, r := range recs {
		if r.User == user {
			return r, true, nil
		}
	}
	return Record{}, false, nil
}

// UnitFor returns the recorded auto-revoke unit for user (empty if none/absent).
func (s *Store) UnitFor(user string) (string, error) {
	recs, err := s.readAll()
	if err != nil {
		return "", err
	}
	for _, r := range recs {
		if r.User == user {
			return r.AutoUnit, nil
		}
	}
	return "", nil
}

// Compact removes ordinary entries whose account no longer exists, deciding
// under one held lock so a concurrent recreate cannot lose its fresh entry.
// Deletion recovery rows are retained without calling keep: that row is the
// authority needed to finish post-userdel cleanup. Callers must not re-enter
// Store methods from the callback. Returns the number pruned.
func (s *Store) Compact(keep func(Record) (bool, error)) (int, error) {
	absent, err := s.completelyAbsent()
	if err != nil {
		return 0, err
	}
	if absent {
		return 0, nil
	}
	removed := 0
	err = s.withLock(func() error {
		recs, err := s.readAll()
		if err != nil {
			return err
		}
		out := recs[:0:0]
		for _, r := range recs {
			if r.DeletionStarted {
				out = append(out, r)
				continue
			}
			live, err := keep(r)
			if err != nil {
				return err
			}
			if live {
				out = append(out, r)
			} else {
				removed++
			}
		}
		if removed == 0 {
			return nil
		}
		return s.writeAll(out)
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// completelyAbsent recognizes only a fully absent store. A missing data file
// paired with an existing lock is a valid empty store; an existing data file
// without its lock is damaged and must still fail in withLock.
func (s *Store) completelyAbsent() (bool, error) {
	for _, path := range []string{s.File, s.Lock} {
		if _, err := os.Lstat(path); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	return true, nil
}
