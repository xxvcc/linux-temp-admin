package registry

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

const maxRegistryBytes = int64(16 << 20)

// Store is the flock-guarded, root-owned registry of managed accounts. Paths are
// fields so tests can point them at a temporary directory.
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
	if err := fsutil.RootSafeDir(s.Dir); err != nil {
		return fmt.Errorf("registry dir unsafe: %w", err)
	}
	if err := ensureFile(s.File, []byte(Header+"\n")); err != nil {
		return err
	}
	if err := ensureFile(s.Lock, nil); err != nil {
		return err
	}
	// Upgrade a deployed v2 registry only while holding its lock. New writes use a
	// v3 header that old binaries reject, preventing them from dropping UID,
	// generation, or pending state during a delayed rewrite.
	return s.withLock(func() error {
		recs, header, err := s.readAllWithHeader()
		if err != nil {
			return err
		}
		if header == legacyHeaderV2 {
			return s.writeAll(recs)
		}
		return nil
	})
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
	if len(lines) == 0 || (lines[0] != Header && lines[0] != legacyHeaderV2) {
		return nil, "", fmt.Errorf("registry header is missing or unsupported")
	}
	header := lines[0]
	var recs []Record
	seenUsers := make(map[string]int)
	for i, line := range lines[1:] {
		lineNumber := i + 2
		if line == Header || line == legacyHeaderV2 {
			return nil, "", fmt.Errorf("registry line %d: duplicate schema header", lineNumber)
		}
		var r Record
		var ok bool
		var err error
		if header == Header {
			r, ok, err = ParseLine(line)
		} else {
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

// Record upserts rec (replacing any existing entry for the same user).
func (s *Store) Record(rec Record) error {
	if _, ok, err := ParseLine(rec.TSV()); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("record did not produce a data row")
		}
		return fmt.Errorf("invalid registry record: %w", err)
	}
	return s.withLock(func() error {
		recs, err := s.readAll()
		if err != nil {
			return err
		}
		out := recs[:0:0]
		for _, r := range recs {
			if r.User != rec.User {
				out = append(out, r)
			}
		}
		out = append(out, rec)
		return s.writeAll(out)
	})
}

// Remove deletes the entry for user (no error if absent).
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

// Compact removes entries whose account no longer exists, deciding under a single
// held lock (re-checking existence inside it) so a concurrent recreate cannot
// lose its fresh entry. exists reports whether an account is still present.
// Returns the number of entries pruned.
func (s *Store) Compact(exists func(user string) (bool, error)) (int, error) {
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
			live, err := exists(r.User)
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
