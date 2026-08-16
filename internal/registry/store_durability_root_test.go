//go:build integration

package registry

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestOpenOrCreateLockAtUsesOneStableInode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dirFile.Close()

	path := filepath.Join(dir, "registry.lock")
	first, err := openOrCreateLockAt(dirFile, filepath.Base(path), path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openOrCreateLockAt(dirFile, filepath.Base(path), path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	firstStat := fiStatFD(t, first)
	secondStat := fiStatFD(t, second)
	if firstStat.Dev != secondStat.Dev || firstStat.Ino != secondStat.Ino {
		t.Fatalf("concurrent lock opens resolved to different inodes: first=%d:%d second=%d:%d",
			firstStat.Dev, firstStat.Ino, secondStat.Dev, secondStat.Ino)
	}
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("lock first fd: %v", err)
	}
	defer func() { _ = syscall.Flock(int(first.Fd()), syscall.LOCK_UN) }()
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("second fd did not contend on the same lock inode: %v", err)
	}
}

func TestExclusiveSequenceWriteCleansVisibleStagingAfterDurabilityFailure(t *testing.T) {
	dir, path := newRootSequenceTestDir(t)
	content := []byte(identitySequenceHeader + "\nhighest\t2000\nsafe-after\tnone\n")
	wantErr := errors.New("forced staging durability failure")
	original := writeIdentitySequenceStaging
	writeIdentitySequenceStaging = func(dir *os.File, name string, content []byte, mode os.FileMode, uid, gid int) error {
		if err := original(dir, name, content, mode, uid, gid); err != nil {
			return err
		}
		return &fsutil.DurabilityError{Operation: "injected staging rename", Err: wantErr}
	}
	t.Cleanup(func() { writeIdentitySequenceStaging = original })

	err := writeRootFileExclusive(path, content, 0o600)
	var durability *fsutil.DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) {
		t.Fatalf("exclusive write error=%v, want staging DurabilityError", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("staging failure published the final sequence: %v", err)
	}
	assertNoSequenceRepairTemps(t, dir)
}

func TestExclusiveSequenceWriteCleansTempAfterPublishedEntrySyncFailure(t *testing.T) {
	dir, path := newRootSequenceTestDir(t)
	content := []byte(identitySequenceHeader + "\nhighest\t2001\nsafe-after\tnone\n")
	wantErr := errors.New("forced published entry sync failure")
	original := syncIdentitySequenceDirectory
	calls := 0
	syncIdentitySequenceDirectory = func(dir *os.File) error {
		calls++
		if calls == 1 {
			return wantErr
		}
		return dir.Sync()
	}
	t.Cleanup(func() { syncIdentitySequenceDirectory = original })

	err := writeRootFileExclusive(path, content, 0o600)
	var durability *fsutil.DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "identity sequence directory entry" {
		t.Fatalf("exclusive write error=%v, want published-entry DurabilityError", err)
	}
	if calls != 2 {
		t.Fatalf("directory sync calls=%d, want failed publish sync plus successful cleanup sync", calls)
	}
	assertCommittedSequenceFile(t, path, content)
	assertNoSequenceRepairTemps(t, dir)
	if err := writeRootFileExclusive(path, []byte("replacement"), 0o600); err == nil {
		t.Fatal("retry overwrote a sequence made visible before a durability error")
	}
	assertCommittedSequenceFile(t, path, content)
}

func TestExclusiveSequenceWriteReportsTemporaryLinkCleanupSyncFailure(t *testing.T) {
	dir, path := newRootSequenceTestDir(t)
	content := []byte(identitySequenceHeader + "\nhighest\t2002\nsafe-after\tnone\n")
	wantErr := errors.New("forced temporary link cleanup sync failure")
	original := syncIdentitySequenceDirectory
	calls := 0
	syncIdentitySequenceDirectory = func(dir *os.File) error {
		calls++
		if calls == 2 {
			return wantErr
		}
		return dir.Sync()
	}
	t.Cleanup(func() { syncIdentitySequenceDirectory = original })

	err := writeRootFileExclusive(path, content, 0o600)
	var durability *fsutil.DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "identity sequence temporary link cleanup" {
		t.Fatalf("exclusive write error=%v, want cleanup DurabilityError", err)
	}
	if calls != 2 {
		t.Fatalf("directory sync calls=%d, want publish and cleanup sync", calls)
	}
	assertCommittedSequenceFile(t, path, content)
	assertNoSequenceRepairTemps(t, dir)
}

func newRootSequenceTestDir(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, "identity-sequence")
}

func assertNoSequenceRepairTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".identity-sequence.repair-") {
			t.Fatalf("exclusive sequence write left temporary link %q", entry.Name())
		}
	}
}

func assertCommittedSequenceFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("committed sequence=%q err=%v, want %q", got, err, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		t.Fatalf("committed sequence type=%v owner=%d:%d mode=%o links=%d", fi.Mode(), stat.Uid, stat.Gid, fi.Mode().Perm(), stat.Nlink)
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

func fiStatFD(t *testing.T, f *os.File) *syscall.Stat_t {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}
