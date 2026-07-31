//go:build integration

package registry_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

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
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
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

func TestInitMigratesV2RegistryToV4UnderLock(t *testing.T) {
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
		t.Fatalf("registry was not migrated to v4: %q", b)
	}
	recs, err := s.List()
	if err != nil || len(recs) != 1 || recs[0].UID != 1001 || recs[0].Pending || recs[0].IdentityBound {
		t.Fatalf("migrated records=%+v err=%v", recs, err)
	}
}

func TestInitMigratesReleasedV3RowsToV4(t *testing.T) {
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
		t.Fatalf("registry was not migrated to v4: %q", b)
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
	const generation = "0123456789abcdef0123456789abcdef"
	rec := registry.Record{
		User: "xxvcc-pending", Port: 22, Generation: generation, IdentityBound: true, Pending: true,
	}
	if err := s.Record(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginDeletion(rec.User, 1001, ""); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Lookup(rec.User)
	if err != nil || !found || got.UID != 1001 || got.Pending || got.IdentityBound ||
		got.Generation != "" || !got.DeletionStarted {
		t.Fatalf("pending deletion state: found=%v rec=%+v err=%v", found, got, err)
	}
	if err := s.BeginDeletion(rec.User, 1001, ""); err != nil {
		t.Fatalf("idempotent begin: %v", err)
	}
}

func TestStorePersistsLegacyAndUnregisteredUIDOnlyRecovery(t *testing.T) {
	s := newStore(t)
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
