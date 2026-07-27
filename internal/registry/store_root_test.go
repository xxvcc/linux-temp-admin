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

func TestInitMigratesV2RegistryToV3UnderLock(t *testing.T) {
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
		t.Fatalf("registry was not migrated to v3: %q", b)
	}
	recs, err := s.List()
	if err != nil || len(recs) != 1 || recs[0].UID != 1001 || recs[0].Pending || recs[0].IdentityBound {
		t.Fatalf("migrated records=%+v err=%v", recs, err)
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
	removed, err := s.Compact(func(user string) (bool, error) { return user == "xxvcc-live", nil })
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
