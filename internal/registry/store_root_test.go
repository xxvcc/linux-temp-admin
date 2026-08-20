//go:build integration

package registry_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/registry"
)

func newStore(t *testing.T) *registry.Store {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &registry.Store{
		Dir:  dir,
		File: filepath.Join(dir, "registry.tsv"),
		Lock: filepath.Join(dir, "registry.lock"),
		Now:  func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
}

func reserveThrough(t *testing.T, s *registry.Store, highest int) {
	t.Helper()
	got, _, err := s.ReserveIdentity(highest, highest)
	if err != nil || got != highest {
		t.Fatalf("reserve identity through %d: got=%d err=%v", highest, got, err)
	}
}

func newRawRegistryStore(t *testing.T, header string, rows ...string) *registry.Store {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &registry.Store{
		Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock"),
		Now: func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
	}
	body := header + "\n"
	if len(rows) > 0 {
		body += strings.Join(rows, "\n") + "\n"
	}
	if err := os.WriteFile(s.File, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func legacyMutationRow(version int, user string, uid int, generation string, pending, bound, deletion bool) string {
	fields := []string{
		user, "2026-07-07 12:00:00 UTC", "2026-07-08 12:00:00 UTC",
		"yes", "203.0.113.5", "22", "SHA256:legacy", "yes", "legacy.timer",
		strconv.Itoa(uid), generation,
	}
	if version >= 3 {
		fields = append(fields, map[bool]string{true: "yes", false: "no"}[pending])
		fields = append(fields, map[bool]string{true: "yes", false: "no"}[bound])
	}
	if version >= 4 {
		fields = append(fields, map[bool]string{true: "yes", false: "no"}[deletion])
	}
	return strings.Join(fields, "\t")
}

func TestInitRepairsExistingRegistryFileAndLockMetadata(t *testing.T) {
	s := newStore(t)
	for _, path := range []string{s.File, s.Lock} {
		if err := os.Chown(path, 12345, 12345); err != nil {
			t.Logf("cannot create non-root owner fixture for %s: %v", path, err)
		}
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init repair: %v", err)
	}
	for _, path := range []string{s.File, s.Lock} {
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if !fi.Mode().IsRegular() || st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s type=%v owner=%d:%d mode=%o, want regular root:root 0600", path, fi.Mode(), st.Uid, st.Gid, fi.Mode().Perm())
		}
	}
}

func TestConcurrentFirstInitUsesOneRegistryAndLock(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := filepath.Join(t.TempDir(), "registry")
	s := &registry.Store{
		Dir:  dir,
		File: filepath.Join(dir, "registry.tsv"),
		Lock: filepath.Join(dir, "registry.lock"),
	}

	const workers = 32
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.Init()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Init: %v", err)
		}
	}
	recs, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("new registry contains records: %+v", recs)
	}
	b, err := os.ReadFile(s.File)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != registry.Header+"\n" {
		t.Fatalf("concurrent Init registry = %q, want one schema header", b)
	}
}

func TestInitMigratesV2RegistryToV5UnderLock(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 500_000_000, time.UTC)
	s := &registry.Store{Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock"), Now: func() time.Time { return now }}
	v2row := strings.Join([]string{
		"xxvcc-v2", "2026-07-07 12:00:00 UTC", "2026-07-08 12:00:00 UTC",
		"yes", "203.0.113.5", "22", "SHA256:abc", "yes", "unit.timer",
		"1001", "0123456789abcdef0123456789abcdef",
	}, "\t")
	if err := os.WriteFile(s.File, []byte("# linux-temp-admin registry v2\n"+v2row+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.File)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), registry.Header+"\n") {
		t.Fatalf("registry was not migrated to v5: %q", b)
	}
	recs, err := s.List()
	if err != nil || len(recs) != 1 || recs[0].UID != 1001 || recs[0].Pending || recs[0].IdentityBound {
		t.Fatalf("migrated records=%+v err=%v", recs, err)
	}
	sequence, err := os.ReadFile(filepath.Join(dir, "identity-sequence"))
	if err != nil || !strings.Contains(string(sequence), "highest\t1001\n") ||
		!strings.Contains(string(sequence), "safe-after\t2026-08-01T12:01:06Z\n") {
		t.Fatalf("migrated identity sequence = %q err=%v", sequence, err)
	}
}

func TestInitMigratesReleasedV3RowsToV5(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := &registry.Store{Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock"), Now: func() time.Time { return now }}
	const generation = "0123456789abcdef0123456789abcdef"
	active := strings.Join([]string{
		"xxvcc-v3a", "2026-07-07 12:00:00 UTC", "2026-07-08 12:00:00 UTC",
		"yes", "203.0.113.5", "22", "SHA256:active", "yes", "active.timer",
		"1001", generation, "no", "yes",
	}, "\t")
	pending := strings.Join([]string{
		"xxvcc-v3p", "2026-07-07 13:00:00 UTC", "2026-07-08 13:00:00 UTC",
		"no", "203.0.113.6", "2222", "SHA256:pending", "no", "",
		"0", generation, "yes", "yes",
	}, "\t")
	if err := os.WriteFile(s.File, []byte("# linux-temp-admin registry v3\n"+active+"\n"+pending+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.File)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), registry.Header+"\n") {
		t.Fatalf("registry was not migrated to v5: %q", b)
	}
	recs, err := s.List()
	if err != nil || len(recs) != 2 {
		t.Fatalf("migrated records=%+v err=%v", recs, err)
	}
	if recs[0].User != "xxvcc-v3a" || recs[0].UID != 1001 || recs[0].Generation != generation ||
		recs[0].Pending || !recs[0].IdentityBound || recs[0].DeletionStarted || recs[0].AutoUnit != "active.timer" {
		t.Fatalf("active v3 row changed during migration: %+v", recs[0])
	}
	if recs[1].User != "xxvcc-v3p" || recs[1].UID != 0 || recs[1].Generation != generation ||
		!recs[1].Pending || !recs[1].IdentityBound || recs[1].DeletionStarted || recs[1].Port != 2222 {
		t.Fatalf("pending v3 row changed during migration: %+v", recs[1])
	}
}

func TestInitMigratesReleasedV4RowsBeforePublishingV5Header(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := &registry.Store{Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock"), Now: func() time.Time { return now }}
	const generation = "0123456789abcdef0123456789abcdef"
	row := strings.Join([]string{
		"xxvcc-v4", "2026-07-07 12:00:00 UTC", "2026-07-08 12:00:00 UTC",
		"yes", "203.0.113.5", "22", "SHA256:active", "yes", "active.timer",
		"1777", generation, "no", "yes", "no",
	}, "\t")
	if err := os.WriteFile(s.File, []byte("# linux-temp-admin registry v4\n"+row+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	sequence, err := os.ReadFile(filepath.Join(dir, "identity-sequence"))
	if err != nil || !strings.Contains(string(sequence), "highest\t1777\n") ||
		!strings.Contains(string(sequence), "safe-after\t2026-08-01T12:01:05Z\n") {
		t.Fatalf("v4 migration sequence = %q err=%v", sequence, err)
	}
	b, err := os.ReadFile(s.File)
	if err != nil || !strings.HasPrefix(string(b), registry.Header+"\n") {
		t.Fatalf("v4 migration registry = %q err=%v", b, err)
	}
}

func TestV5RegistryRequiresItsDurableIdentitySequence(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &registry.Store{Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock")}
	if err := os.WriteFile(s.File, []byte(registry.Header+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err == nil || !strings.Contains(err.Error(), "identity sequence") {
		t.Fatalf("Init without v5 identity sequence error = %v", err)
	}
}

func TestReserveIdentityIsMonotonicAndFailsClosedAtLimit(t *testing.T) {
	s := newStore(t)
	for want := 1000; want <= 1002; want++ {
		got, isolated, err := s.ReserveIdentity(1000, 1002)
		if err != nil || got != want || !isolated {
			t.Fatalf("reserve #%d = %d isolated=%v err=%v", want-999, got, isolated, err)
		}
	}
	if _, _, err := s.ReserveIdentity(1000, 1002); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exhausted sequence error = %v", err)
	}
}

func TestReserveIdentityRevalidatesV5RegistryAndSequenceUnderLock(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	rec := registry.Record{
		User: "xxvcc-reserve-guard", Port: 22, UID: 1777,
		Generation: generation, IdentityBound: true,
	}
	validSequence := []byte("# linux-temp-admin identity sequence v1\nhighest\t1777\nsafe-after\tnone\n")
	lowSequence := []byte("# linux-temp-admin identity sequence v1\nhighest\t1000\nsafe-after\tnone\n")
	corruptSequence := []byte("not an identity sequence\n")

	tests := []struct {
		name           string
		header         string
		rows           []string
		sequence       []byte
		removeRegistry bool
		wantMissing    bool
		wantError      string
	}{
		{name: "missing sequence", header: registry.Header, rows: []string{rec.TSV()}, wantMissing: true},
		{name: "corrupt sequence", header: registry.Header, rows: []string{rec.TSV()}, sequence: corruptSequence},
		{name: "sequence below recorded UID", header: registry.Header, rows: []string{rec.TSV()}, sequence: lowSequence, wantError: "below recorded UID"},
		{name: "legacy registry", header: "# linux-temp-admin registry v4", rows: []string{
			legacyMutationRow(4, rec.User, rec.UID, generation, false, true, false),
		}, sequence: validSequence, wantError: "requires an existing valid v5 registry"},
		{name: "unsupported registry header", header: "# linux-temp-admin registry v99", sequence: validSequence, wantError: "header is missing or unsupported"},
		{name: "missing registry", header: registry.Header, sequence: validSequence, removeRegistry: true, wantError: "requires an existing valid v5 registry"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newRawRegistryStore(t, tc.header, tc.rows...)
			sequencePath := filepath.Join(s.Dir, "identity-sequence")
			if tc.sequence != nil {
				if err := os.WriteFile(sequencePath, tc.sequence, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.removeRegistry {
				if err := os.Remove(s.File); err != nil {
					t.Fatal(err)
				}
			}
			registryBefore, registryBeforeErr := os.ReadFile(s.File)
			sequenceBefore, sequenceBeforeErr := os.ReadFile(sequencePath)

			_, _, err := s.ReserveIdentity(1000, 3000)
			if err == nil {
				t.Fatal("ReserveIdentity accepted inconsistent registry/sequence state")
			}
			if errors.Is(err, registry.ErrIdentitySequenceMissing) != tc.wantMissing {
				t.Fatalf("ReserveIdentity error = %v, missing sentinel=%v", err, errors.Is(err, registry.ErrIdentitySequenceMissing))
			}
			if tc.wantError != "" && !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("ReserveIdentity error = %v, want %q", err, tc.wantError)
			}

			registryAfter, registryAfterErr := os.ReadFile(s.File)
			registryErrorChanged := (registryBeforeErr == nil) != (registryAfterErr == nil) ||
				(registryBeforeErr != nil && (!os.IsNotExist(registryBeforeErr) || !os.IsNotExist(registryAfterErr)))
			if registryErrorChanged || string(registryAfter) != string(registryBefore) {
				t.Fatalf("refused reservation changed registry: before=%q/%v after=%q/%v", registryBefore, registryBeforeErr, registryAfter, registryAfterErr)
			}
			sequenceAfter, sequenceAfterErr := os.ReadFile(sequencePath)
			sequenceErrorChanged := (sequenceBeforeErr == nil) != (sequenceAfterErr == nil) ||
				(sequenceBeforeErr != nil && (!os.IsNotExist(sequenceBeforeErr) || !os.IsNotExist(sequenceAfterErr)))
			if sequenceErrorChanged || string(sequenceAfter) != string(sequenceBefore) {
				t.Fatalf("refused reservation changed sequence: before=%q/%v after=%q/%v", sequenceBefore, sequenceBeforeErr, sequenceAfter, sequenceAfterErr)
			}
		})
	}
}

func TestMigratedIdentitySequenceRequiresOneIsolationWindow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 500_000_000, time.UTC)
	s := &registry.Store{
		Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock"),
		Now: func() time.Time { return now },
	}
	if err := os.WriteFile(s.File, []byte("# linux-temp-admin registry v4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	if got, isolated, err := s.ReserveIdentity(1000, 1002); err != nil || got != 1000 || isolated {
		t.Fatalf("first migrated reserve = %d isolated=%v err=%v", got, isolated, err)
	}
	now = time.Date(2026, 8, 1, 12, 1, 6, 0, time.UTC)
	if got, isolated, err := s.ReserveIdentity(1000, 1002); err != nil || got != 1001 || !isolated {
		t.Fatalf("post-isolation reserve = %d isolated=%v err=%v", got, isolated, err)
	}
	sequence, err := os.ReadFile(filepath.Join(dir, "identity-sequence"))
	if err != nil || !strings.Contains(string(sequence), "safe-after\t2026-08-01T12:01:06Z\n") {
		t.Fatalf("isolation deadline was not preserved: %q err=%v", sequence, err)
	}
}

func TestBeginQuarantineBindsCompletedAndPendingGenerations(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	deadline := time.Date(2026, 8, 1, 12, 2, 0, 0, time.UTC)
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("pending=%v", pending), func(t *testing.T) {
			s := newStore(t)
			name := "xxvcc-bound"
			uid := 1001
			recordedUID := uid
			if pending {
				name = "xxvcc-pending"
				recordedUID = 0
			}
			reserveThrough(t, s, uid)
			rec := registry.Record{
				User: name, Port: 22, UID: recordedUID, Generation: generation,
				IdentityBound: true, Pending: pending,
			}
			if err := s.Record(rec); err != nil {
				t.Fatal(err)
			}
			unit := "linux-temp-admin-v2-quarantine-" + name
			if err := s.BeginQuarantine(name, uid, generation, deadline, unit); err != nil {
				t.Fatal(err)
			}
			got, found, err := s.Lookup(name)
			if err != nil || !found || !got.DeletionStarted || got.UID != uid || got.Pending != pending ||
				got.QuarantineUntil != deadline.Format(time.RFC3339) || got.QuarantineUnit != unit {
				t.Fatalf("quarantine transition = found=%v rec=%+v err=%v", found, got, err)
			}
			if err := s.BeginQuarantine(name, uid, generation, deadline, unit); err != nil {
				t.Fatalf("idempotent BeginQuarantine: %v", err)
			}
		})
	}
}

func TestIdentitySequenceRejectsUnsafeOrCorruptFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, path string)
	}{
		{name: "symlink", make: func(t *testing.T, path string) {
			if err := os.Symlink("/etc/passwd", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed", make: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("not a sequence\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			path := filepath.Join(s.Dir, "identity-sequence")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			tc.make(t, path)
			if _, _, err := s.ReserveIdentity(1000, 2000); err == nil {
				t.Fatal("unsafe identity sequence was accepted")
			}
		})
	}
}

func TestInitRejectsExistingNonRegularRegistryFiles(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &registry.Store{Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock")}
	if err := os.Mkdir(s.File, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err == nil {
		t.Fatal("Init accepted a directory in place of the registry file")
	}
}

func TestInitRejectsRegistryFileOutsideDedicatedDirectoryWithoutMutation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	want := []byte("do not touch\n")
	if err := os.WriteFile(victim, want, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &registry.Store{Dir: dir, File: victim, Lock: filepath.Join(dir, "registry.lock")}
	if err := s.Init(); err == nil {
		t.Fatal("Init accepted a registry file outside its dedicated directory")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("outside file content changed: %q", got)
	}
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("outside file mode changed to %o", fi.Mode().Perm())
	}
}

func TestStoreRecordUpsertRemove(t *testing.T) {
	s := newStore(t)
	rec := registry.Record{User: "xxvcc-a1", Host: "h", Port: 22, Sudo: true, AutoRevoke: true, AutoUnit: "u"}
	if err := s.Record(rec); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Contains("xxvcc-a1"); !ok {
		t.Fatal("Contains should be true after Record")
	}
	// Upsert: same user, updated fields -> still one record.
	rec.Host = "h2"
	if err := s.Record(rec); err != nil {
		t.Fatal(err)
	}
	recs, _ := s.List()
	if len(recs) != 1 {
		t.Fatalf("upsert produced %d records, want 1", len(recs))
	}
	if recs[0].Host != "h2" {
		t.Errorf("upsert did not update: host=%q", recs[0].Host)
	}
	if u, _ := s.UnitFor("xxvcc-a1"); u != "u" {
		t.Errorf("UnitFor = %q, want u", u)
	}
	if err := s.Remove("xxvcc-a1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Contains("xxvcc-a1"); ok {
		t.Error("Contains should be false after Remove")
	}
}

func TestStoreCompact(t *testing.T) {
	s := newStore(t)
	for _, u := range []string{"xxvcc-live", "xxvcc-gone"} {
		if err := s.Record(registry.Record{User: u, Port: 22}); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := s.Compact(func(rec registry.Record) (bool, error) { return rec.User == "xxvcc-live", nil })
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("Compact removed %d, want 1", removed)
	}
	if ok, _ := s.Contains("xxvcc-gone"); ok {
		t.Error("gone user should be pruned")
	}
	if ok, _ := s.Contains("xxvcc-live"); !ok {
		t.Error("live user should survive")
	}
}

func TestDeletionRecoveryStateIsProtected(t *testing.T) {
	s := newStore(t)
	reserveThrough(t, s, 1001)
	const generation = "0123456789abcdef0123456789abcdef"
	recovery := registry.Record{
		User: "xxvcc-recovery", Port: 22, UID: 1001, Generation: generation, IdentityBound: true,
	}
	stale := registry.Record{User: "xxvcc-stale", Port: 22}
	if err := s.Record(recovery); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(stale); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginDeletion(recovery.User, recovery.UID, recovery.Generation); err != nil {
		t.Fatal(err)
	}

	if err := s.Record(recovery); err == nil {
		t.Fatal("Record cleared a deletion recovery phase")
	}
	if err := s.Remove(recovery.User); err == nil {
		t.Fatal("Remove discarded a deletion recovery phase")
	}
	callbackUsers := []string{}
	removed, err := s.Compact(func(rec registry.Record) (bool, error) {
		callbackUsers = append(callbackUsers, rec.User)
		return false, nil
	})
	if err != nil || removed != 1 {
		t.Fatalf("Compact removed=%d err=%v", removed, err)
	}
	if strings.Join(callbackUsers, ",") != stale.User {
		t.Fatalf("Compact callback users = %v, want only ordinary stale row", callbackUsers)
	}
	if err := s.FinishDeletionRecovery(recovery.User, recovery.UID+1, recovery.Generation); err == nil {
		t.Fatal("FinishDeletionRecovery accepted the wrong UID")
	}
	if rec, found, err := s.Lookup(recovery.User); err != nil || !found || !rec.DeletionStarted {
		t.Fatalf("failed transition changed recovery row: found=%v rec=%+v err=%v", found, rec, err)
	}
	if err := s.FinishDeletionRecovery(recovery.User, recovery.UID, recovery.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishDeletionRecovery(recovery.User, recovery.UID, recovery.Generation); err != nil {
		t.Fatalf("idempotent finish: %v", err)
	}
}

func TestUIDOnlyDeletionRecoveryStateIsProtected(t *testing.T) {
	s := newStore(t)
	reserveThrough(t, s, 1001)
	const (
		user  = "xxvcc-uid-only"
		stale = "xxvcc-stale"
		uid   = 1001
	)
	if err := s.BeginDeletion(user, uid, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(registry.Record{User: user, Port: 22, UID: uid}); err == nil {
		t.Fatal("Record cleared a UID-only deletion recovery phase")
	}
	if err := s.Remove(user); err == nil {
		t.Fatal("Remove discarded a UID-only deletion recovery phase")
	}
	if err := s.Record(registry.Record{User: stale, Port: 22}); err != nil {
		t.Fatal(err)
	}
	callbackUsers := []string{}
	removed, err := s.Compact(func(rec registry.Record) (bool, error) {
		callbackUsers = append(callbackUsers, rec.User)
		return false, nil
	})
	if err != nil || removed != 1 {
		t.Fatalf("Compact removed=%d err=%v", removed, err)
	}
	if strings.Join(callbackUsers, ",") != stale {
		t.Fatalf("Compact callback users = %v, want only ordinary stale row", callbackUsers)
	}
	want := registry.Record{User: user, UID: uid, DeletionStarted: true}
	if got, found, err := s.Lookup(user); err != nil || !found || got != want {
		t.Fatalf("UID-only recovery changed: found=%v rec=%+v err=%v", found, got, err)
	}
	if err := s.FinishDeletionRecovery(user, uid, ""); err != nil {
		t.Fatal(err)
	}
}

func TestBeginDeletionConvertsPendingRollbackToUIDOnlyRecovery(t *testing.T) {
	s := newStore(t)
	reserveThrough(t, s, 1001)
	const generation = "0123456789abcdef0123456789abcdef"
	rec := registry.Record{
		User: "xxvcc-pending", Port: 22, UID: 1001, Generation: generation,
		IdentityBound: true, SequentialID: true, Pending: true,
	}
	if err := s.Record(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginDeletion(rec.User, 1001, ""); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Lookup(rec.User)
	if err != nil || !found || got.UID != 1001 || got.Pending || got.IdentityBound ||
		got.Generation != "" || !got.DeletionStarted || !got.SequentialID {
		t.Fatalf("pending deletion state: found=%v rec=%+v err=%v", found, got, err)
	}
	if err := s.BeginDeletion(rec.User, 1001, ""); err != nil {
		t.Fatalf("idempotent begin: %v", err)
	}
}

func TestStorePersistsLegacyAndUnregisteredUIDOnlyRecovery(t *testing.T) {
	s := newStore(t)
	reserveThrough(t, s, 1002)
	legacy := registry.Record{
		User: "xxvcc-legacy", Port: 22, UID: 1001,
		Generation: "0123456789abcdef0123456789abcdef", AutoUnit: "legacy.timer",
	}
	if err := s.Record(legacy); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginDeletion(legacy.User, legacy.UID, ""); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Lookup(legacy.User)
	if err != nil || !found || !got.DeletionStarted || got.IdentityBound || got.Pending ||
		got.Generation != "" || got.UID != legacy.UID || got.AutoUnit != legacy.AutoUnit {
		t.Fatalf("legacy recovery row: found=%v rec=%+v err=%v", found, got, err)
	}

	const unregistered = "xxvcc-unregistered"
	if err := s.BeginDeletion(unregistered, 1002, ""); err != nil {
		t.Fatal(err)
	}
	got, found, err = s.Lookup(unregistered)
	if err != nil || !found || got != (registry.Record{User: unregistered, UID: 1002, DeletionStarted: true}) {
		t.Fatalf("unregistered recovery row: found=%v rec=%+v err=%v", found, got, err)
	}
	if err := s.FinishDeletionRecovery(unregistered, 1002, legacy.Generation); err == nil {
		t.Fatal("UID-only recovery accepted a generation")
	}
	if err := s.FinishDeletionRecovery(unregistered, 1002, ""); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Lookup(unregistered); err != nil || found {
		t.Fatalf("finished unregistered recovery still present: found=%v err=%v", found, err)
	}
}

func TestStoreConcurrentRecord(t *testing.T) {
	s := newStore(t)
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.Record(registry.Record{User: fmt.Sprintf("xxvcc-%03d", i), Port: 22}); err != nil {
				t.Errorf("Record %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	recs, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != n {
		t.Errorf("got %d records after %d concurrent writes, want %d", len(recs), n, n)
	}
}

func TestStoreRejectsCorruptRegistry(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(s.File, []byte(registry.Header+"\ninvalid\trow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("a corrupt record must make the registry unreadable")
	}
	if err := os.WriteFile(s.File, []byte("# wrong schema\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("an unsupported registry header must be rejected")
	}
	if err := os.WriteFile(s.File, []byte(registry.Header+"\n# corrupted row\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("a non-header # line must be reported as corruption")
	}
	rec := registry.Record{User: "xxvcc-duplicate", Port: 22}.TSV()
	for name, body := range map[string]string{
		"duplicate username": registry.Header + "\n" + rec + "\n" + rec + "\n",
		"duplicate header":   registry.Header + "\n" + registry.Header + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(s.File, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.List(); err == nil {
				t.Fatalf("registry accepted %s", name)
			}
		})
	}
}

func TestStoreRejectsInvalidRecordBeforeWriting(t *testing.T) {
	s := newStore(t)
	if err := s.Record(registry.Record{User: "not a valid username", Port: 22}); err == nil {
		t.Fatal("Record accepted an invalid username")
	}
	recs, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Errorf("invalid Record poisoned the registry: %v", recs)
	}
}

func TestLegacyMutationsCommitSequenceBeforePublishingV5(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	type mutationCase struct {
		version int
		kind    string
		user    string
	}
	var tests []mutationCase
	for _, version := range []int{2, 3, 4} {
		tests = append(tests,
			mutationCase{version: version, kind: "remove", user: fmt.Sprintf("xxvcc-v%d-rm", version)},
			mutationCase{version: version, kind: "compact", user: fmt.Sprintf("xxvcc-v%d-cp", version)},
			mutationCase{version: version, kind: "begin-deletion", user: fmt.Sprintf("xxvcc-v%d-bd", version)},
		)
	}
	for _, version := range []int{3, 4} {
		tests = append(tests, mutationCase{version: version, kind: "begin-quarantine", user: fmt.Sprintf("xxvcc-v%d-bq", version)})
	}
	tests = append(tests, mutationCase{version: 4, kind: "finish-recovery", user: "xxvcc-v4-fr"})

	for _, tc := range tests {
		t.Run(fmt.Sprintf("v%d/%s", tc.version, tc.kind), func(t *testing.T) {
			header := fmt.Sprintf("# linux-temp-admin registry v%d", tc.version)
			bound := tc.version >= 3
			deletionStarted := tc.kind == "finish-recovery"
			row := legacyMutationRow(tc.version, tc.user, 1777, generation, false, bound, deletionStarted)
			s := newRawRegistryStore(t, header, row)

			var err error
			switch tc.kind {
			case "remove":
				err = s.Remove(tc.user)
			case "compact":
				var removed int
				removed, err = s.Compact(func(registry.Record) (bool, error) { return false, nil })
				if err == nil && removed != 1 {
					err = fmt.Errorf("removed %d records, want 1", removed)
				}
			case "begin-deletion":
				boundGeneration := ""
				if bound {
					boundGeneration = generation
				}
				err = s.BeginDeletion(tc.user, 1777, boundGeneration)
			case "begin-quarantine":
				deadline := time.Date(2026, 8, 1, 12, 2, 0, 0, time.UTC)
				err = s.BeginQuarantine(tc.user, 1777, generation, deadline, "linux-temp-admin-v2-quarantine-"+tc.user)
			case "finish-recovery":
				err = s.FinishDeletionRecovery(tc.user, 1777, generation)
			default:
				t.Fatalf("unknown mutation kind %q", tc.kind)
			}
			if err != nil {
				t.Fatalf("legacy mutation: %v", err)
			}

			registryBytes, err := os.ReadFile(s.File)
			if err != nil || !strings.HasPrefix(string(registryBytes), registry.Header+"\n") {
				t.Fatalf("registry was not published as v5: bytes=%q err=%v", registryBytes, err)
			}
			sequencePath := filepath.Join(s.Dir, "identity-sequence")
			sequenceBytes, err := os.ReadFile(sequencePath)
			if err != nil || !strings.Contains(string(sequenceBytes), "highest\t1777\n") ||
				!strings.Contains(string(sequenceBytes), "safe-after\t2026-08-01T12:01:05Z\n") {
				t.Fatalf("legacy mutation sequence = %q err=%v", sequenceBytes, err)
			}
			if err := s.CheckIntegrity(); err != nil {
				t.Fatalf("migrated registry integrity: %v", err)
			}
			recs, err := s.List()
			if err != nil {
				t.Fatal(err)
			}
			switch tc.kind {
			case "remove", "compact", "finish-recovery":
				if len(recs) != 0 {
					t.Fatalf("completed mutation retained records: %+v", recs)
				}
			case "begin-deletion":
				if len(recs) != 1 || !recs[0].DeletionStarted || recs[0].UID != 1777 {
					t.Fatalf("deletion transition = %+v", recs)
				}
				if bound != recs[0].IdentityBound {
					t.Fatalf("deletion identity binding changed: %+v", recs[0])
				}
			case "begin-quarantine":
				if len(recs) != 1 || !recs[0].DeletionStarted ||
					recs[0].QuarantineUntil != "2026-08-01T12:02:00Z" ||
					recs[0].QuarantineUnit != "linux-temp-admin-v2-quarantine-"+tc.user {
					t.Fatalf("quarantine transition = %+v", recs)
				}
			}
		})
	}
}

func TestV5MutationsFailClosedWhenSequenceIsMissingOrCorrupt(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	rec := registry.Record{
		User: "xxvcc-v5-bound", Port: 22, UID: 1777, Generation: generation, IdentityBound: true,
	}
	deadline := time.Date(2026, 8, 1, 12, 2, 0, 0, time.UTC)
	mutations := []struct {
		name string
		run  func(*registry.Store) error
	}{
		{name: "record", run: func(s *registry.Store) error { return s.Record(rec) }},
		{name: "begin deletion", run: func(s *registry.Store) error {
			return s.BeginDeletion(rec.User, rec.UID, generation)
		}},
		{name: "begin quarantine", run: func(s *registry.Store) error {
			return s.BeginQuarantine(rec.User, rec.UID, generation, deadline, "linux-temp-admin-v2-quarantine-"+rec.User)
		}},
		{name: "finish absent recovery", run: func(s *registry.Store) error {
			return s.FinishDeletionRecovery("xxvcc-v5-absent", rec.UID, generation)
		}},
		{name: "remove absent", run: func(s *registry.Store) error { return s.Remove("xxvcc-v5-absent") }},
		{name: "compact no-op", run: func(s *registry.Store) error {
			_, err := s.Compact(func(registry.Record) (bool, error) { return true, nil })
			return err
		}},
	}
	for _, state := range []string{"missing", "corrupt", "low"} {
		for _, mutation := range mutations {
			t.Run(state+"/"+mutation.name, func(t *testing.T) {
				s := newRawRegistryStore(t, registry.Header, rec.TSV())
				sequencePath := filepath.Join(s.Dir, "identity-sequence")
				badSequence := []byte("corrupt sequence\n")
				if state == "low" {
					badSequence = []byte("# linux-temp-admin identity sequence v1\nhighest\t1000\nsafe-after\tnone\n")
				}
				if state == "corrupt" {
					if err := os.WriteFile(sequencePath, badSequence, 0o600); err != nil {
						t.Fatal(err)
					}
				} else if state == "low" {
					if err := os.WriteFile(sequencePath, badSequence, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.ReadFile(s.File)
				if err != nil {
					t.Fatal(err)
				}
				err = mutation.run(s)
				if err == nil {
					t.Fatal("mutation accepted invalid v5 sequence state")
				}
				if (state == "missing") != errors.Is(err, registry.ErrIdentitySequenceMissing) {
					t.Fatalf("mutation error = %v, missing sentinel match=%v", err, errors.Is(err, registry.ErrIdentitySequenceMissing))
				}
				after, readErr := os.ReadFile(s.File)
				if readErr != nil || string(after) != string(before) {
					t.Fatalf("refused mutation changed registry: bytes=%q err=%v", after, readErr)
				}
				if state == "missing" {
					if _, statErr := os.Lstat(sequencePath); !os.IsNotExist(statErr) {
						t.Fatalf("refused mutation created sequence: %v", statErr)
					}
				} else if got, readErr := os.ReadFile(sequencePath); readErr != nil || string(got) != string(badSequence) {
					t.Fatalf("refused mutation changed invalid sequence: bytes=%q err=%v", got, readErr)
				}
			})
		}
	}
}

func TestCheckIntegrityAndExplicitMissingSequenceRepair(t *testing.T) {
	s := newStore(t)
	reserveThrough(t, s, 1777)
	if err := s.Record(registry.Record{User: "xxvcc-repair", Port: 22, UID: 1777}); err != nil {
		t.Fatal(err)
	}
	sequencePath := filepath.Join(s.Dir, "identity-sequence")
	if err := os.Remove(sequencePath); err != nil {
		t.Fatal(err)
	}
	registryBefore, err := os.ReadFile(s.File)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckIntegrity(); !errors.Is(err, registry.ErrIdentitySequenceMissing) {
		t.Fatalf("CheckIntegrity missing error = %v", err)
	}
	if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
		t.Fatalf("CheckIntegrity mutated missing sequence: %v", err)
	}
	if _, err := s.RepairMissingIdentitySequence(1776); err == nil || !strings.Contains(err.Error(), "below recorded UID") {
		t.Fatalf("too-low repair error = %v", err)
	}
	if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
		t.Fatalf("too-low repair created sequence: %v", err)
	}
	info, err := s.RepairMissingIdentitySequence(2000)
	if err != nil {
		t.Fatalf("repair missing sequence: %v", err)
	}
	if info.Highest != 2000 || !info.SafeAfter.Equal(time.Date(2026, 8, 1, 12, 1, 5, 0, time.UTC)) {
		t.Fatalf("repair info = %+v", info)
	}
	wantSequence := "# linux-temp-admin identity sequence v1\nhighest\t2000\nsafe-after\t2026-08-01T12:01:05Z\n"
	sequenceBytes, err := os.ReadFile(sequencePath)
	if err != nil || string(sequenceBytes) != wantSequence {
		t.Fatalf("repaired sequence = %q err=%v", sequenceBytes, err)
	}
	fi, err := os.Stat(sequencePath)
	if err != nil {
		t.Fatal(err)
	}
	stat := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		t.Fatalf("repaired sequence type=%v owner=%d:%d mode=%o links=%d", fi.Mode(), stat.Uid, stat.Gid, fi.Mode().Perm(), stat.Nlink)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".identity-sequence.repair-") {
			t.Fatalf("repair left temporary link %q", entry.Name())
		}
	}
	if err := s.CheckIntegrity(); err != nil {
		t.Fatalf("repaired integrity: %v", err)
	}
	registryAfter, err := os.ReadFile(s.File)
	if err != nil || string(registryAfter) != string(registryBefore) {
		t.Fatalf("repair changed registry: bytes=%q err=%v", registryAfter, err)
	}
	if _, err := s.RepairMissingIdentitySequence(3000); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("existing sequence repair error = %v", err)
	}
	if got, err := os.ReadFile(sequencePath); err != nil || string(got) != wantSequence {
		t.Fatalf("existing sequence was overwritten: bytes=%q err=%v", got, err)
	}

	if err := os.Remove(sequencePath); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("not a sequence\n")
	if err := os.WriteFile(sequencePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckIntegrity(); err == nil || errors.Is(err, registry.ErrIdentitySequenceMissing) {
		t.Fatalf("corrupt integrity error = %v", err)
	}
	if _, err := s.RepairMissingIdentitySequence(3000); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("corrupt sequence repair error = %v", err)
	}
	if got, err := os.ReadFile(sequencePath); err != nil || string(got) != string(corrupt) {
		t.Fatalf("corrupt sequence was overwritten: bytes=%q err=%v", got, err)
	}

	if err := os.Remove(sequencePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", sequencePath); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RepairMissingIdentitySequence(3000); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("symlink sequence repair error = %v", err)
	}
	fi, err = os.Lstat(sequencePath)
	if err != nil {
		t.Fatalf("stat sequence symlink after refused repair: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("sequence symlink was replaced: mode=%v", fi.Mode())
	}
}

func TestIntegrityCheckLeavesLegacyStateReadOnlyAndRepairRefusesIt(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	s := newRawRegistryStore(t, "# linux-temp-admin registry v4",
		legacyMutationRow(4, "xxvcc-v4-read", 1777, generation, false, true, false))
	before, err := os.ReadFile(s.File)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckIntegrity(); err != nil {
		t.Fatalf("legacy integrity check: %v", err)
	}
	sequencePath := filepath.Join(s.Dir, "identity-sequence")
	if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
		t.Fatalf("legacy integrity check created sequence: %v", err)
	}
	if _, err := s.RepairMissingIdentitySequence(1777); err == nil || !strings.Contains(err.Error(), "requires an existing valid v5") {
		t.Fatalf("legacy repair error = %v", err)
	}
	if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
		t.Fatalf("legacy repair created sequence: %v", err)
	}
	after, err := os.ReadFile(s.File)
	if err != nil || string(after) != string(before) {
		t.Fatalf("read-only legacy checks changed registry: bytes=%q err=%v", after, err)
	}
}

func TestConcurrentMissingSequenceRepairPublishesExactlyOnce(t *testing.T) {
	s := newStore(t)
	sequencePath := filepath.Join(s.Dir, "identity-sequence")
	if err := os.Remove(sequencePath); err != nil {
		t.Fatal(err)
	}
	type result struct {
		info registry.IdentitySequenceInfo
		err  error
	}
	const workers = 16
	start := make(chan struct{})
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(highWater int) {
			defer wg.Done()
			<-start
			info, err := s.RepairMissingIdentitySequence(highWater)
			results <- result{info: info, err: err}
		}(1000 + i)
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	var committed registry.IdentitySequenceInfo
	for result := range results {
		if result.err == nil {
			successes++
			committed = result.info
			continue
		}
		if !strings.Contains(result.err.Error(), "refusing to overwrite") {
			t.Fatalf("concurrent repair error = %v", result.err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent repairs succeeded %d times, want exactly one", successes)
	}
	sequenceBytes, err := os.ReadFile(sequencePath)
	if err != nil || !strings.Contains(string(sequenceBytes), fmt.Sprintf("highest\t%d\n", committed.Highest)) ||
		!strings.Contains(string(sequenceBytes), "safe-after\t2026-08-01T12:01:05Z\n") {
		t.Fatalf("concurrently repaired sequence = %q committed=%+v err=%v", sequenceBytes, committed, err)
	}
	if err := s.CheckIntegrity(); err != nil {
		t.Fatalf("concurrently repaired integrity: %v", err)
	}
}

func TestMissingSequenceRepairRequiresAValidRegistryAndHighWater(t *testing.T) {
	s := newRawRegistryStore(t, registry.Header, "invalid\trow")
	sequencePath := filepath.Join(s.Dir, "identity-sequence")
	if _, err := s.RepairMissingIdentitySequence(2000); err == nil || !strings.Contains(err.Error(), "registry line") {
		t.Fatalf("malformed-registry repair error = %v", err)
	}
	if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
		t.Fatalf("malformed-registry repair created sequence: %v", err)
	}
	if _, err := s.RepairMissingIdentitySequence(-1); err == nil || !strings.Contains(err.Error(), "invalid identity sequence high-water") {
		t.Fatalf("invalid-high-water repair error = %v", err)
	}
	if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
		t.Fatalf("invalid-high-water repair created sequence: %v", err)
	}
}

func TestBeginDeletionAdvancesSequenceForFirstUIDOnlyWitness(t *testing.T) {
	const (
		targetUID  = 1777
		generation = "0123456789abcdef0123456789abcdef"
	)
	for _, pending := range []bool{false, true} {
		name := "unregistered"
		if pending {
			name = "pending-uid-zero"
		}
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			reserveThrough(t, s, 1000)
			userName := "xxvcc-first-uid"
			if pending {
				userName = "xxvcc-pending-zero"
				if err := s.Record(registry.Record{
					User: userName, Port: 22, Generation: generation,
					Pending: true, IdentityBound: true,
				}); err != nil {
					t.Fatal(err)
				}
			}

			if err := s.BeginDeletion(userName, targetUID, ""); err != nil {
				t.Fatalf("BeginDeletion UID-only witness: %v", err)
			}
			sequenceBytes, err := os.ReadFile(filepath.Join(s.Dir, "identity-sequence"))
			if err != nil || !strings.Contains(string(sequenceBytes), "highest\t1777\n") ||
				!strings.Contains(string(sequenceBytes), "safe-after\tnone\n") {
				t.Fatalf("advanced sequence = %q err=%v", sequenceBytes, err)
			}
			rec, found, err := s.Lookup(userName)
			if err != nil || !found || rec.UID != targetUID || !rec.DeletionStarted ||
				rec.Pending || rec.IdentityBound || rec.SequentialID || rec.Generation != "" {
				t.Fatalf("UID-only recovery = found=%v rec=%+v err=%v", found, rec, err)
			}
			next, isolated, err := s.ReserveIdentity(1000, targetUID+1)
			if err != nil || next != targetUID+1 || !isolated {
				t.Fatalf("post-recovery reservation = %d isolated=%v err=%v", next, isolated, err)
			}
		})
	}
}

func TestBeginDeletionMigratesNineFieldRowAndBurnsRecoveredUID(t *testing.T) {
	const (
		userName = "xxvcc-nine-field"
		uid      = 1777
	)
	nineFieldRow := strings.Join([]string{
		userName, "2026-07-07 12:00:00 UTC", "2026-07-08 12:00:00 UTC",
		"yes", "203.0.113.5", "22", "SHA256:legacy", "yes", "legacy.timer",
	}, "\t")
	s := newRawRegistryStore(t, "# linux-temp-admin registry v2", nineFieldRow)
	sequencePath := filepath.Join(s.Dir, "identity-sequence")
	if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
		t.Fatalf("nine-field fixture unexpectedly has a sequence: %v", err)
	}

	if err := s.BeginDeletion(userName, uid, ""); err != nil {
		t.Fatalf("BeginDeletion nine-field row: %v", err)
	}
	registryBytes, err := os.ReadFile(s.File)
	if err != nil || !strings.HasPrefix(string(registryBytes), registry.Header+"\n") {
		t.Fatalf("nine-field registry was not migrated: bytes=%q err=%v", registryBytes, err)
	}
	sequenceBytes, err := os.ReadFile(sequencePath)
	if err != nil || !strings.Contains(string(sequenceBytes), "highest\t1777\n") ||
		!strings.Contains(string(sequenceBytes), "safe-after\t2026-08-01T12:01:05Z\n") {
		t.Fatalf("nine-field migration sequence = %q err=%v", sequenceBytes, err)
	}
	rec, found, err := s.Lookup(userName)
	if err != nil || !found || rec.UID != uid || !rec.DeletionStarted ||
		rec.IdentityBound || rec.Generation != "" || rec.AutoUnit != "legacy.timer" {
		t.Fatalf("migrated nine-field recovery = found=%v rec=%+v err=%v", found, rec, err)
	}
	next, isolated, err := s.ReserveIdentity(1000, uid+1)
	if err != nil || next != uid+1 || isolated {
		t.Fatalf("post-migration reservation = %d isolated=%v err=%v", next, isolated, err)
	}
}

func TestBeginDeletionUIDOnlyAdvanceRejectsInvalidSequenceState(t *testing.T) {
	const uid = 1777
	for _, state := range []string{"missing", "corrupt", "below-recorded-uid"} {
		t.Run(state, func(t *testing.T) {
			userName := "xxvcc-invalid-seq"
			var rows []string
			if state == "below-recorded-uid" {
				rows = append(rows, registry.Record{User: userName, Port: 22, UID: uid}.TSV())
			}
			s := newRawRegistryStore(t, registry.Header, rows...)
			sequencePath := filepath.Join(s.Dir, "identity-sequence")
			var sequenceBefore []byte
			switch state {
			case "corrupt":
				sequenceBefore = []byte("not an identity sequence\n")
			case "below-recorded-uid":
				sequenceBefore = []byte("# linux-temp-admin identity sequence v1\nhighest\t1000\nsafe-after\tnone\n")
			}
			if sequenceBefore != nil {
				if err := os.WriteFile(sequencePath, sequenceBefore, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			registryBefore, err := os.ReadFile(s.File)
			if err != nil {
				t.Fatal(err)
			}

			err = s.BeginDeletion(userName, uid, "")
			if err == nil {
				t.Fatal("BeginDeletion accepted invalid sequence state")
			}
			if (state == "missing") != errors.Is(err, registry.ErrIdentitySequenceMissing) {
				t.Fatalf("BeginDeletion error = %v, missing sentinel match=%v", err, errors.Is(err, registry.ErrIdentitySequenceMissing))
			}
			if state == "below-recorded-uid" && !strings.Contains(err.Error(), "below recorded UID") {
				t.Fatalf("low-sequence error = %v", err)
			}
			registryAfter, readErr := os.ReadFile(s.File)
			if readErr != nil || string(registryAfter) != string(registryBefore) {
				t.Fatalf("refused BeginDeletion changed registry: bytes=%q err=%v", registryAfter, readErr)
			}
			if state == "missing" {
				if _, statErr := os.Lstat(sequencePath); !os.IsNotExist(statErr) {
					t.Fatalf("refused BeginDeletion created sequence: %v", statErr)
				}
			} else if sequenceAfter, readErr := os.ReadFile(sequencePath); readErr != nil ||
				string(sequenceAfter) != string(sequenceBefore) {
				t.Fatalf("refused BeginDeletion changed sequence: bytes=%q err=%v", sequenceAfter, readErr)
			}
		})
	}
}
