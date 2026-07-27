//go:build integration

package registry

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

func TestEnsureFileSyncsRepairedMetadataAndReportsFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "registry.tsv")
	if err := os.WriteFile(path, []byte(Header+"\n"), 0o666); err != nil {
		t.Fatal(err)
	}

	old := syncRegistryFile
	t.Cleanup(func() { syncRegistryFile = old })
	calls := 0
	syncRegistryFile = func(*os.File) error {
		calls++
		return nil
	}
	if err := ensureFile(path, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("registry metadata sync calls=%d, want 1", calls)
	}

	wantErr := errors.New("forced registry metadata sync failure")
	syncRegistryFile = func(*os.File) error { return wantErr }
	err := ensureFile(path, nil)
	var durability *fsutil.DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "registry metadata repair" {
		t.Fatalf("ensureFile error=%v, want registry metadata DurabilityError", err)
	}
	fi, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("metadata repair target is missing: %v", statErr)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("metadata repair mode=%v, want 0600", fi.Mode())
	}
	if st := fiStat(t, path); st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("metadata repair owner=%d:%d, want root:root", st.Uid, st.Gid)
	}
}

func fiStat(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}
