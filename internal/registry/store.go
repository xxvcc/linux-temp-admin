package registry

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

// Store is the flock-guarded, root-owned registry of managed accounts. Paths are
// fields so tests can point them at a temporary directory.
type Store struct {
	Dir  string
	File string
	Lock string
}

// Default returns a Store using the configured v2 registry paths.
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
	return ensureFile(s.Lock, nil)
}

func ensureFile(path string, initial []byte) error {
	fi, err := os.Lstat(path)
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a safe regular file", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return fsutil.WriteRootFile(path, initial, 0o600)
}

// withLock runs fn while holding an exclusive advisory lock on the lock file.
func (s *Store) withLock(fn func() error) error {
	f, err := os.OpenFile(s.Lock, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open registry lock: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock registry: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// readAll reads and parses the registry (unlocked; reads see a consistent inode
// even across a concurrent atomic rewrite). Missing file yields no records.
func (s *Store) readAll() ([]Record, error) {
	if fi, err := os.Lstat(s.File); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("registry file %s is unsafe", s.File)
		}
	} else if os.IsNotExist(err) {
		return nil, nil
	} else {
		return nil, err
	}
	b, err := os.ReadFile(s.File)
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, line := range strings.Split(string(b), "\n") {
		if r, ok := ParseLine(line); ok {
			recs = append(recs, r)
		}
	}
	return recs, nil
}

// writeAll atomically rewrites the registry from recs (header + one line each).
func (s *Store) writeAll(recs []Record) error {
	var b strings.Builder
	b.WriteString(Header)
	b.WriteByte('\n')
	for _, r := range recs {
		b.WriteString(r.TSV())
		b.WriteByte('\n')
	}
	return fsutil.WriteRootFile(s.File, []byte(b.String()), 0o600)
}

// Record upserts rec (replacing any existing entry for the same user).
func (s *Store) Record(rec Record) error {
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
func (s *Store) Compact(exists func(user string) bool) (int, error) {
	removed := 0
	err := s.withLock(func() error {
		recs, err := s.readAll()
		if err != nil {
			return err
		}
		out := recs[:0:0]
		for _, r := range recs {
			if exists(r.User) {
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
