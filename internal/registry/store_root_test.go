//go:build integration

package registry_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
	removed, err := s.Compact(func(user string) bool { return user == "xxvcc-live" })
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
