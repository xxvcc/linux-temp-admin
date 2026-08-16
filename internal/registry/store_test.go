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
					got[0].IdentityBound || got[0].SequentialID || got[0].Generation != "" || got[0].UID != 1001 {
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
