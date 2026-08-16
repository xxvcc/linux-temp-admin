package registry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

const (
	identitySequenceHeader = "# linux-temp-admin identity sequence v1"
	maxSequenceBytes       = int64(4 << 10)
)

// ErrIdentitySequenceMissing identifies the one sequence-integrity failure an
// operator can repair by supplying an independently established high-water
// mark. Corrupt, unsafe, and merely unreadable sequence files do not match this
// error and must never be overwritten by the repair path.
var ErrIdentitySequenceMissing = errors.New("identity sequence is missing")

// IdentitySequenceInfo is the operator-visible result of a successful explicit
// sequence repair. SafeAfter is the exact UTC deadline committed to disk.
type IdentitySequenceInfo struct {
	Highest   int
	SafeAfter time.Time
}

type identitySequence struct {
	highest   int
	safeAfter time.Time
}

func identitySequenceBytes(sequence identitySequence) []byte {
	safeAfter := "none"
	if !sequence.safeAfter.IsZero() {
		safeAfter = sequence.safeAfter.UTC().Format(time.RFC3339)
	}
	return []byte(fmt.Sprintf("%s\nhighest\t%d\nsafe-after\t%s\n", identitySequenceHeader, sequence.highest, safeAfter))
}

func ceilUTCSecond(t time.Time) time.Time {
	t = t.UTC()
	if t.Nanosecond() == 0 {
		return t
	}
	return t.Truncate(time.Second).Add(time.Second)
}

// ensureIdentitySequence creates or advances the durable allocation high-water
// mark. allowCreate is false after a v5 header has become visible: absence then
// means retired identity history was lost and must fail closed.
func (s *Store) ensureIdentitySequence(seed int, allowCreate bool, safeAfter time.Time) error {
	if seed < 0 || !validate.KernelID(seed) {
		return fmt.Errorf("invalid identity sequence seed %d", seed)
	}
	if !safeAfter.IsZero() {
		safeAfter = ceilUTCSecond(safeAfter)
	}
	path := s.sequencePath()
	sequence, err := readIdentitySequence(path)
	if os.IsNotExist(err) {
		if !allowCreate {
			return fmt.Errorf("%w: %s is missing for a v5 registry", ErrIdentitySequenceMissing, path)
		}
		return fsutil.WriteRootFile(path, identitySequenceBytes(identitySequence{highest: seed, safeAfter: safeAfter}), 0o600)
	}
	if err != nil {
		return err
	}
	changed := false
	if sequence.highest < seed {
		sequence.highest = seed
		changed = true
	}
	if sequence.safeAfter.Before(safeAfter) {
		sequence.safeAfter = safeAfter
		changed = true
	}
	if !changed {
		return nil
	}
	return fsutil.WriteRootFile(path, identitySequenceBytes(sequence), 0o600)
}

func (s *Store) requireIdentitySequence() (identitySequence, error) {
	path := s.sequencePath()
	sequence, err := readIdentitySequence(path)
	if os.IsNotExist(err) {
		return identitySequence{}, fmt.Errorf("%w: %s is missing for a v5 registry", ErrIdentitySequenceMissing, path)
	}
	if err != nil {
		return identitySequence{}, err
	}
	return sequence, nil
}

func (s *Store) requireIdentitySequenceCovering(recs []Record) (identitySequence, error) {
	sequence, err := s.requireIdentitySequence()
	if err != nil {
		return identitySequence{}, err
	}
	if highest := highestRecordedUID(recs); sequence.highest < highest {
		return identitySequence{}, fmt.Errorf("identity sequence high-water mark %d is below recorded UID %d", sequence.highest, highest)
	}
	return sequence, nil
}

// CheckIntegrity validates the registry/identity-sequence relationship without
// creating, repairing, or rewriting either file. A legacy registry may
// legitimately predate the sequence; once a v5 header is visible the sequence
// is mandatory, valid, and at least as high as every UID still in the registry.
func (s *Store) CheckIntegrity() error {
	if err := s.validateLayout(); err != nil {
		return err
	}
	recs, header, err := s.readAllWithHeader()
	if err != nil {
		return err
	}
	path := s.sequencePath()
	if header != Header {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
	}
	_, err = s.requireIdentitySequenceCovering(recs)
	if err != nil {
		return fmt.Errorf("identity sequence integrity: %w", err)
	}
	return nil
}

// RepairMissingIdentitySequence recreates only a genuinely absent sequence for
// an otherwise valid v5 registry. highWater must be independently established
// by the operator and cover every UID retained in the registry. The first new
// allocation remains isolated for one full daemon polling interval. Existing
// sequence objects, including corrupt files and symlinks, are never replaced.
func (s *Store) RepairMissingIdentitySequence(highWater int) (IdentitySequenceInfo, error) {
	if err := s.validateLayout(); err != nil {
		return IdentitySequenceInfo{}, err
	}
	if !validate.KernelID(highWater) {
		return IdentitySequenceInfo{}, fmt.Errorf("invalid identity sequence high-water mark %d", highWater)
	}
	var repaired IdentitySequenceInfo
	err := s.withLock(func() error {
		recs, header, err := s.readAllWithHeader()
		if err != nil {
			return err
		}
		if header != Header {
			return fmt.Errorf("identity sequence repair requires an existing valid v5 registry")
		}
		if recorded := highestRecordedUID(recs); highWater < recorded {
			return fmt.Errorf("identity sequence high-water mark %d is below recorded UID %d", highWater, recorded)
		}
		path := s.sequencePath()
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("identity sequence %s already exists; refusing to overwrite it", path)
		} else if !os.IsNotExist(err) {
			return err
		}
		safeAfter := ceilUTCSecond(s.now().Add(time.Duration(config.IdentityQuarantineSeconds) * time.Second))
		if err := writeRootFileExclusive(path, identitySequenceBytes(identitySequence{
			highest: highWater, safeAfter: safeAfter,
		}), 0o600); err != nil {
			return err
		}
		repaired = IdentitySequenceInfo{Highest: highWater, SafeAfter: safeAfter}
		return nil
	})
	if err != nil {
		return IdentitySequenceInfo{}, err
	}
	return repaired, nil
}

var writeIdentitySequenceStaging = fsutil.AtomicWriteFileAt

var syncIdentitySequenceDirectory = func(dir *os.File) error { return dir.Sync() }

// writeRootFileExclusive publishes a complete root-owned file with linkat, whose
// no-replace semantics close the check/write race without ever exposing partial
// contents at the destination name.
func writeRootFileExclusive(path string, content []byte, mode os.FileMode) (retErr error) {
	dirPath := filepath.Dir(path)
	dir, err := os.OpenFile(dirPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open identity sequence directory: %w", err)
	}
	defer dir.Close()
	if err := requireRootDirFD(dirPath, dir, 0o700); err != nil {
		return fmt.Errorf("identity sequence directory unsafe: %w", err)
	}
	name := filepath.Base(path)
	var stat unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return fmt.Errorf("identity sequence %s already exists; refusing to overwrite it", path)
	} else if err != unix.ENOENT {
		return fmt.Errorf("inspect identity sequence: %w", err)
	}

	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fmt.Errorf("generate identity sequence temporary name: %w", err)
	}
	tempName := "." + name + ".repair-" + hex.EncodeToString(token[:])
	tempPresent := true
	defer func() {
		if !tempPresent {
			return
		}
		if err := unix.Unlinkat(int(dir.Fd()), tempName, 0); err != nil {
			if err != unix.ENOENT {
				retErr = errors.Join(retErr, fmt.Errorf("remove identity sequence temporary link: %w", err))
			}
			return
		}
		tempPresent = false
		if err := syncIdentitySequenceDirectory(dir); err != nil {
			retErr = errors.Join(retErr, &fsutil.DurabilityError{
				Operation: "identity sequence temporary link cleanup", Err: err,
			})
		}
	}()
	if err := writeIdentitySequenceStaging(dir, tempName, content, mode, 0, 0); err != nil {
		return err
	}
	if err := unix.Linkat(int(dir.Fd()), tempName, int(dir.Fd()), name, 0); err != nil {
		if err == unix.EEXIST {
			return fmt.Errorf("identity sequence %s already exists; refusing to overwrite it", path)
		}
		return fmt.Errorf("publish identity sequence: %w", err)
	}
	if err := syncIdentitySequenceDirectory(dir); err != nil {
		return &fsutil.DurabilityError{Operation: "identity sequence directory entry", Err: err}
	}
	if err := unix.Unlinkat(int(dir.Fd()), tempName, 0); err != nil {
		return fmt.Errorf("remove identity sequence temporary link: %w", err)
	}
	tempPresent = false
	if err := syncIdentitySequenceDirectory(dir); err != nil {
		return &fsutil.DurabilityError{Operation: "identity sequence temporary link cleanup", Err: err}
	}
	return verifyRootFileContent(path, content, mode)
}

func verifyRootFileContent(path string, expected []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("reopen identity sequence: %w", err)
	}
	defer f.Close()
	if err := requireRootFileFD(path, f, mode); err != nil {
		return fmt.Errorf("verify identity sequence metadata: %w", err)
	}
	got, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	if err != nil {
		return fmt.Errorf("read back identity sequence: %w", err)
	}
	if !bytes.Equal(got, expected) {
		return fmt.Errorf("identity sequence readback did not match the committed content")
	}
	return nil
}

func readIdentitySequence(path string) (identitySequence, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return identitySequence{}, err
	}
	defer f.Close()
	if err := requireRootFileFD(path, f, 0o600); err != nil {
		return identitySequence{}, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSequenceBytes+1))
	if err != nil {
		return identitySequence{}, err
	}
	if int64(len(b)) > maxSequenceBytes {
		return identitySequence{}, fmt.Errorf("identity sequence exceeds %d bytes", maxSequenceBytes)
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) != 4 || lines[0] != identitySequenceHeader || lines[3] != "" {
		return identitySequence{}, fmt.Errorf("identity sequence is malformed")
	}
	highestFields := strings.Split(lines[1], "\t")
	safeFields := strings.Split(lines[2], "\t")
	if len(highestFields) != 2 || highestFields[0] != "highest" || len(safeFields) != 2 || safeFields[0] != "safe-after" {
		return identitySequence{}, fmt.Errorf("identity sequence is malformed")
	}
	highest, err := strconv.Atoi(highestFields[1])
	if err != nil || !validate.KernelID(highest) {
		return identitySequence{}, fmt.Errorf("identity sequence has invalid high-water mark %q", highestFields[1])
	}
	var safeAfter time.Time
	if safeFields[1] != "none" {
		safeAfter, err = time.Parse(time.RFC3339, safeFields[1])
		if err != nil || safeAfter.Location() != time.UTC {
			return identitySequence{}, fmt.Errorf("identity sequence has invalid isolation deadline %q", safeFields[1])
		}
	}
	return identitySequence{highest: highest, safeAfter: safeAfter}, nil
}

// ReserveIdentity durably burns and returns a UID/GID pair. minimum is the
// first currently-free local account ID and maximum is the configured upper
// bound shared by UID and GID allocation. The write commits before useradd, so
// a crash can waste an ID but can never make a later invite reuse it.
func (s *Store) ReserveIdentity(minimum, maximum int) (reserved int, isolated bool, err error) {
	if !validate.AccountID(minimum) || !validate.AccountID(maximum) || minimum > maximum {
		return 0, false, fmt.Errorf("invalid identity allocation range %d..%d", minimum, maximum)
	}
	err = s.withLock(func() error {
		recs, header, err := s.readAllWithHeader()
		if err != nil {
			return err
		}
		if header != Header {
			return fmt.Errorf("identity reservation requires an existing valid v5 registry")
		}
		sequence, err := s.requireIdentitySequenceCovering(recs)
		if err != nil {
			return err
		}
		candidate := sequence.highest + 1
		if candidate < minimum {
			candidate = minimum
		}
		if candidate > maximum || !validate.AccountID(candidate) {
			return fmt.Errorf("monotonic UID/GID range %d..%d is exhausted", minimum, maximum)
		}
		sequence.highest = candidate
		if err := fsutil.WriteRootFile(s.sequencePath(), identitySequenceBytes(sequence), 0o600); err != nil {
			return err
		}
		reserved = candidate
		isolated = sequence.safeAfter.IsZero() || !s.now().Before(sequence.safeAfter)
		return nil
	})
	return reserved, isolated, err
}
