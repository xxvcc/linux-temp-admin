package registry

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

const (
	identitySequenceHeader = "# linux-temp-admin identity sequence v1"
	maxSequenceBytes       = int64(4 << 10)
)

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

// ensureIdentitySequence creates or advances the durable allocation high-water
// mark. allowCreate is false after a v5 header has become visible: absence then
// means retired identity history was lost and must fail closed.
func (s *Store) ensureIdentitySequence(seed int, allowCreate bool, safeAfter time.Time) error {
	if seed < 0 || !validate.KernelID(seed) {
		return fmt.Errorf("invalid identity sequence seed %d", seed)
	}
	if !safeAfter.IsZero() {
		safeAfter = safeAfter.UTC().Truncate(time.Second)
	}
	path := s.sequencePath()
	sequence, err := readIdentitySequence(path)
	if os.IsNotExist(err) {
		if !allowCreate {
			return fmt.Errorf("identity sequence %s is missing for a v5 registry", path)
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
		sequence, err := readIdentitySequence(s.sequencePath())
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
