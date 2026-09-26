package registry

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadAllRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.tsv")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := (&Store{File: path}).readAll()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a safe regular file") {
			t.Fatalf("FIFO registry error = %v, want special-file refusal", err)
		}
	case <-time.After(time.Second):
		t.Fatal("registry read blocked while opening a FIFO")
	}
}

func TestMissingStoreRemovalAndCompactAreNoOps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	s := &Store{
		Dir:  dir,
		File: filepath.Join(dir, "registry.tsv"),
		Lock: filepath.Join(dir, "registry.lock"),
	}
	if err := s.Remove("xxvcc-a1"); err != nil {
		t.Fatalf("Remove on a fully absent store: %v", err)
	}
	called := false
	removed, err := s.Compact(func(Record) (bool, error) {
		called = true
		return false, nil
	})
	if err != nil || removed != 0 || called {
		t.Fatalf("Compact on absent store: removed=%d called=%v err=%v", removed, called, err)
	}
	if err := s.FinishDeletionRecovery("xxvcc-a1", 1001, ""); err != nil {
		t.Fatalf("FinishDeletionRecovery on a fully absent store: %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("idempotent absent-store operations created state: %v", err)
	}
}

func TestExistingRegistryWithoutLockStillFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s := &Store{
		Dir:  dir,
		File: filepath.Join(dir, "registry.tsv"),
		Lock: filepath.Join(dir, "registry.lock"),
	}
	if err := os.WriteFile(s.File, []byte(Header+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("xxvcc-a1"); err == nil {
		t.Fatal("Remove accepted an existing registry whose lock was missing")
	}
}

func TestWriteAllRejectsOutputAboveRegistryLimit(t *testing.T) {
	s := &Store{File: filepath.Join(t.TempDir(), "registry.tsv")}
	rec := Record{Host: strings.Repeat("x", int(maxRegistryBytes))}
	if err := s.writeAll([]Record{rec}); err == nil || !strings.Contains(err.Error(), "registry output exceeds") {
		t.Fatalf("writeAll error = %v, want output-size refusal", err)
	}
	if _, err := os.Lstat(s.File); !os.IsNotExist(err) {
		t.Fatalf("oversized registry write created output: %v", err)
	}
}

func TestWriteAllFailsClosedWithoutAValidIdentitySequence(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root-owned sequence validation requires root")
	}
	dir := t.TempDir()
	s := &Store{
		Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock"),
	}
	original := []byte(Header + "\n")
	if err := os.WriteFile(s.File, original, 0o600); err != nil {
		t.Fatal(err)
	}
	recs := []Record{{User: "xxvcc-defensive", Port: 22, UID: 1777}}

	err := s.writeAll(recs)
	if !errors.Is(err, ErrIdentitySequenceMissing) {
		t.Fatalf("writeAll without sequence error = %v, want ErrIdentitySequenceMissing", err)
	}
	if got, readErr := os.ReadFile(s.File); readErr != nil || string(got) != string(original) {
		t.Fatalf("missing-sequence refusal changed registry: bytes=%q err=%v", got, readErr)
	}

	sequencePath := s.sequencePath()
	corrupt := []byte("not an identity sequence\n")
	if err := os.WriteFile(sequencePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	err = s.writeAll(recs)
	if err == nil || errors.Is(err, ErrIdentitySequenceMissing) {
		t.Fatalf("writeAll with corrupt sequence error = %v", err)
	}
	if got, readErr := os.ReadFile(s.File); readErr != nil || string(got) != string(original) {
		t.Fatalf("corrupt-sequence refusal changed registry: bytes=%q err=%v", got, readErr)
	}
	if got, readErr := os.ReadFile(sequencePath); readErr != nil || string(got) != string(corrupt) {
		t.Fatalf("corrupt sequence was overwritten: bytes=%q err=%v", got, readErr)
	}

	if err := os.WriteFile(sequencePath, identitySequenceBytes(identitySequence{}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.writeAll(recs); err == nil || !strings.Contains(err.Error(), "below recorded UID") {
		t.Fatalf("writeAll with too-low valid sequence error = %v", err)
	}
	sequence, err := readIdentitySequence(sequencePath)
	if err != nil || sequence.highest != 0 {
		t.Fatalf("defensive refusal changed sequence = %+v err=%v", sequence, err)
	}
	if err := os.WriteFile(sequencePath, identitySequenceBytes(identitySequence{highest: 1777}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.writeAll(recs); err != nil {
		t.Fatalf("writeAll with covering sequence: %v", err)
	}
}

func TestValidateLayoutRequiresDedicatedSiblingPaths(t *testing.T) {
	dir := t.TempDir()
	valid := &Store{
		Dir:  dir,
		File: filepath.Join(dir, "registry.tsv"),
		Lock: filepath.Join(dir, "registry.lock"),
	}
	if err := valid.validateLayout(); err != nil {
		t.Fatalf("valid registry layout rejected: %v", err)
	}

	for name, mutate := range map[string]func(*Store){
		"relative directory": func(s *Store) { s.Dir = "relative" },
		"file outside":       func(s *Store) { s.File = filepath.Join(filepath.Dir(dir), "outside.tsv") },
		"lock outside":       func(s *Store) { s.Lock = filepath.Join(filepath.Dir(dir), "outside.lock") },
		"nested file":        func(s *Store) { s.File = filepath.Join(dir, "nested", "registry.tsv") },
		"same path":          func(s *Store) { s.Lock = s.File },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			mutate(&candidate)
			if err := candidate.validateLayout(); err == nil {
				t.Fatal("unsafe registry layout was accepted")
			}
		})
	}
}

func TestBeginDeletionRecordsSupportsBoundAndUIDOnlyRecovery(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name       string
		in         []Record
		user       string
		generation string
		check      func(*testing.T, []Record)
	}{
		{
			name: "generation bound",
			in: []Record{{
				User: "xxvcc-bound", Port: 22, UID: 1001,
				Generation: generation, IdentityBound: true,
			}},
			user: "xxvcc-bound", generation: generation,
			check: func(t *testing.T, got []Record) {
				if len(got) != 1 || !got[0].DeletionStarted || !got[0].IdentityBound ||
					got[0].Generation != generation || got[0].UID != 1001 || got[0].Pending {
					t.Fatalf("bound transition = %+v", got)
				}
			},
		},
		{
			name: "registered legacy",
			in: []Record{{
				User: "xxvcc-legacy", Port: 2222, UID: 1001,
				Generation: generation, AutoUnit: "legacy.timer",
			}},
			user: "xxvcc-legacy",
			check: func(t *testing.T, got []Record) {
				if len(got) != 1 || !got[0].DeletionStarted || got[0].IdentityBound ||
					got[0].Generation != "" || got[0].Pending || got[0].UID != 1001 ||
					got[0].Port != 2222 || got[0].AutoUnit != "legacy.timer" {
					t.Fatalf("legacy transition = %+v", got)
				}
			},
		},
		{
			name: "unregistered",
			user: "xxvcc-unregistered",
			check: func(t *testing.T, got []Record) {
				want := Record{User: "xxvcc-unregistered", UID: 1001, DeletionStarted: true}
				if !reflect.DeepEqual(got, []Record{want}) {
					t.Fatalf("unregistered transition = %+v, want %+v", got, want)
				}
			},
		},
		{
			name: "pending rollback becomes recovery only",
			in: []Record{{
				User: "xxvcc-pending", Port: 22, Generation: generation,
				IdentityBound: true, SequentialID: true, Pending: true,
			}},
			user: "xxvcc-pending",
			check: func(t *testing.T, got []Record) {
				if len(got) != 1 || !got[0].DeletionStarted || got[0].Pending ||
					got[0].IdentityBound || !got[0].SequentialID || got[0].Generation != "" || got[0].UID != 1001 {
					t.Fatalf("pending rollback transition = %+v", got)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, changed, err := beginDeletionRecords(test.in, test.user, 1001, test.generation)
			if err != nil || !changed {
				t.Fatalf("beginDeletionRecords changed=%v err=%v", changed, err)
			}
			test.check(t, got)
			again, changed, err := beginDeletionRecords(got, test.user, 1001, test.generation)
			if err != nil || changed || !reflect.DeepEqual(again, got) {
				t.Fatalf("idempotent begin changed=%v got=%+v err=%v", changed, again, err)
			}
		})
	}
}

func TestBeginDeletionRecordsRejectsIdentityMismatchWithoutMutation(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	const otherGeneration = "fedcba9876543210fedcba9876543210"
	tests := []struct {
		name       string
		recs       []Record
		user       string
		uid        int
		generation string
	}{
		{
			name: "bound row cannot be downgraded",
			recs: []Record{{User: "xxvcc-a1", Port: 22, UID: 1001, Generation: generation, IdentityBound: true}},
			user: "xxvcc-a1", uid: 1001,
		},
		{
			name: "wrong bound generation",
			recs: []Record{{User: "xxvcc-a1", Port: 22, UID: 1001, Generation: generation, IdentityBound: true}},
			user: "xxvcc-a1", uid: 1001, generation: otherGeneration,
		},
		{
			name: "bound identity missing",
			user: "xxvcc-a1", uid: 1001, generation: generation,
		},
		{
			name: "legacy UID mismatch",
			recs: []Record{{User: "xxvcc-a1", Port: 22, UID: 1002}},
			user: "xxvcc-a1", uid: 1001,
		},
		{
			name: "invalid UID",
			user: "xxvcc-a1", uid: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := append([]Record(nil), test.recs...)
			if _, _, err := beginDeletionRecords(test.recs, test.user, test.uid, test.generation); err == nil {
				t.Fatal("mismatched deletion transition was accepted")
			}
			if !reflect.DeepEqual(test.recs, before) {
				t.Fatalf("failed transition mutated input: got %+v want %+v", test.recs, before)
			}
		})
	}
}

func TestFinishDeletionRecoveryRecordsRequiresExactModeAndIdentity(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	bound := Record{
		User: "xxvcc-bound", Port: 22, UID: 1001, Generation: generation,
		IdentityBound: true, DeletionStarted: true,
	}
	uidOnly := Record{User: "xxvcc-uid", UID: 1002, DeletionStarted: true}
	recs := []Record{bound, uidOnly}

	for _, test := range []struct {
		name       string
		user       string
		uid        int
		generation string
	}{
		{name: "bound without generation", user: bound.User, uid: bound.UID},
		{name: "bound wrong UID", user: bound.User, uid: bound.UID + 1, generation: generation},
		{name: "uid-only with generation", user: uidOnly.User, uid: uidOnly.UID, generation: generation},
		{name: "uid-only wrong UID", user: uidOnly.User, uid: uidOnly.UID + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := finishDeletionRecoveryRecords(recs, test.user, test.uid, test.generation); err == nil {
				t.Fatal("mismatched recovery completion was accepted")
			}
		})
	}

	afterBound, changed, err := finishDeletionRecoveryRecords(recs, bound.User, bound.UID, generation)
	if err != nil || !changed || !reflect.DeepEqual(afterBound, []Record{uidOnly}) {
		t.Fatalf("finish bound = changed %v records %+v err %v", changed, afterBound, err)
	}
	afterUID, changed, err := finishDeletionRecoveryRecords(recs, uidOnly.User, uidOnly.UID, "")
	if err != nil || !changed || !reflect.DeepEqual(afterUID, []Record{bound}) {
		t.Fatalf("finish UID-only = changed %v records %+v err %v", changed, afterUID, err)
	}
	missing, changed, err := finishDeletionRecoveryRecords(recs, "xxvcc-missing", 1003, "")
	if err != nil || changed || !reflect.DeepEqual(missing, recs) {
		t.Fatalf("idempotent missing finish = changed %v records %+v err %v", changed, missing, err)
	}
}

// A registry migrated from the released nine-column v2 format carries no UID
// column, so its sequence is seeded with highest 0 and only a real isolation
// deadline. Treating "highest > 0" as the sole proof of prior use meant losing
// the data file on exactly those hosts reported a clean bill of health.
func TestRegistryLossIsDetectedFromAnyEvidenceOfPriorUse(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root-owned registry and sequence metadata require root")
	}
	newDir := func(t *testing.T) *Store {
		t.Helper()
		dir := t.TempDir()
		return &Store{
			Dir:      dir,
			File:     filepath.Join(dir, "registry.tsv"),
			Lock:     filepath.Join(dir, "registry.lock"),
			Sequence: filepath.Join(dir, "identity-sequence"),
			Now:      func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
		}
	}
	writeSequence := func(t *testing.T, s *Store, body string) {
		t.Helper()
		if err := os.WriteFile(s.sequencePath(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name     string
		sequence string
		wantLost bool
		wantHigh int
	}{
		{
			name:     "migrated v2 registry: no UID column, but a real isolation deadline",
			sequence: "# linux-temp-admin identity sequence v1\nhighest\t0\nsafe-after\t2026-08-01T12:01:05Z\n",
			wantLost: true,
		},
		{
			name:     "ordinary v5 host with allocations",
			sequence: "# linux-temp-admin identity sequence v1\nhighest\t1500\nsafe-after\tnone\n",
			wantLost: true,
			wantHigh: 1500,
		},
		{
			name:     "genuinely fresh install",
			sequence: "# linux-temp-admin identity sequence v1\nhighest\t0\nsafe-after\tnone\n",
			wantLost: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDir(t)
			writeSequence(t, s, tc.sequence)
			highest, lost, err := s.InspectRegistryLoss()
			if err != nil {
				t.Fatal(err)
			}
			if lost != tc.wantLost || highest != tc.wantHigh {
				t.Fatalf("InspectRegistryLoss() = %d, %v; want %d, %v", highest, lost, tc.wantHigh, tc.wantLost)
			}
		})
	}

	t.Run("an existing data file is never reported as lost", func(t *testing.T) {
		s := newDir(t)
		writeSequence(t, s, "# linux-temp-admin identity sequence v1\nhighest\t1500\nsafe-after\tnone\n")
		if err := os.WriteFile(s.File, []byte(Header+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, lost, err := s.InspectRegistryLoss(); err != nil || lost {
			t.Fatalf("InspectRegistryLoss() with a present registry = %v, %v; want not lost", lost, err)
		}
	})

	t.Run("no sequence at all is a fresh or uninstalled host", func(t *testing.T) {
		s := newDir(t)
		if _, lost, err := s.InspectRegistryLoss(); err != nil || lost {
			t.Fatalf("InspectRegistryLoss() with no sequence = %v, %v; want not lost", lost, err)
		}
	})
}

// The read cap is the only thing between an oversized registry file and a silent
// partial read, and Record's refusal is what keeps deletion-recovery witnesses
// exclusive to BeginDeletion. Neither had a test.
func TestReadCapAndRecoveryRowRefusalAreEnforced(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root-owned registry metadata requires root")
	}
	newStore := func(t *testing.T) *Store {
		t.Helper()
		dir := t.TempDir()
		return &Store{
			Dir:      dir,
			File:     filepath.Join(dir, "registry.tsv"),
			Lock:     filepath.Join(dir, "registry.lock"),
			Sequence: filepath.Join(dir, "identity-sequence"),
			Now:      func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
		}
	}

	t.Run("a registry above the read cap fails closed instead of truncating", func(t *testing.T) {
		s := newStore(t)
		f, err := os.OpenFile(s.File, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(Header + "\n"); err != nil {
			t.Fatal(err)
		}
		// One byte past the cap is enough; the reader must not report the rows it
		// did manage to read as the whole registry.
		if err := f.Truncate(maxRegistryBytes + 1); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		_, _, err = s.readAllWithHeader()
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("readAllWithHeader on an oversized registry = %v, want a size refusal", err)
		}
	})

	t.Run("Record refuses to create a deletion-recovery row", func(t *testing.T) {
		s := newStore(t)
		err := s.Record(Record{
			User: "xxvcc-a1", Port: 22, UID: 1500,
			DeletionStarted: true,
		})
		if err == nil || !strings.Contains(err.Error(), "BeginDeletion") {
			t.Fatalf("Record(DeletionStarted) = %v, want it routed to BeginDeletion", err)
		}
		// It must be refused before any lock or file is touched: a recovery witness
		// that Record could mint is a deletion authorization nobody proved.
		if _, statErr := os.Lstat(s.File); !os.IsNotExist(statErr) {
			t.Fatalf("Record created registry state before refusing: %v", statErr)
		}
	})
}

// The sequence is monotonic in both dimensions. Inverting either comparison left
// the whole registry suite green while handing out a retired UID, or erasing an
// active isolation deadline.
func TestIdentitySequenceNeverMovesBackwards(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("writing a root-owned identity sequence requires root")
	}
	dir := t.TempDir()
	s := &Store{
		Dir:      dir,
		File:     filepath.Join(dir, "registry.tsv"),
		Lock:     filepath.Join(dir, "registry.lock"),
		Sequence: filepath.Join(dir, "identity-sequence"),
		Now:      func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
	}
	safeAfter := time.Date(2026, 8, 1, 12, 1, 5, 0, time.UTC)
	if err := s.ensureIdentitySequence(5000, true, safeAfter); err != nil {
		t.Fatal(err)
	}
	read := func(t *testing.T) identitySequence {
		t.Helper()
		seq, err := readIdentitySequence(s.sequencePath())
		if err != nil {
			t.Fatal(err)
		}
		return seq
	}

	t.Run("a lower seed does not lower the high-water mark", func(t *testing.T) {
		if err := s.ensureIdentitySequence(1000, false, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if got := read(t); got.highest != 5000 {
			t.Fatalf("highest = %d after seeding 1000, want it held at 5000", got.highest)
		}
	})

	t.Run("a zero safe-after does not erase an active isolation deadline", func(t *testing.T) {
		if err := s.ensureIdentitySequence(0, false, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if got := read(t); !got.safeAfter.Equal(safeAfter) {
			t.Fatalf("safe-after = %v, want the active deadline %v preserved", got.safeAfter, safeAfter)
		}
	})

	t.Run("an earlier safe-after does not shorten the isolation window", func(t *testing.T) {
		if err := s.ensureIdentitySequence(0, false, safeAfter.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got := read(t); !got.safeAfter.Equal(safeAfter) {
			t.Fatalf("safe-after = %v, want the later deadline %v kept", got.safeAfter, safeAfter)
		}
	})

	t.Run("higher values still advance both", func(t *testing.T) {
		later := safeAfter.Add(time.Hour)
		if err := s.ensureIdentitySequence(6000, false, later); err != nil {
			t.Fatal(err)
		}
		got := read(t)
		if got.highest != 6000 || !got.safeAfter.Equal(later) {
			t.Fatalf("sequence = highest %d safe-after %v, want 6000 and %v", got.highest, got.safeAfter, later)
		}
	})
}
