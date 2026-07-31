package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAtomicWriteFileAs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if err := AtomicWriteFileAs(p, []byte("hello"), 0o640, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "hello" {
		t.Fatalf("content=%q err=%v", b, err)
	}
	fi, _ := os.Lstat(p)
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", fi.Mode().Perm())
	}
	// no leftover temp files
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("expected 1 file, found %d (temp leak?)", len(ents))
	}
}

func TestOwnershipMutationsRejectChownSentinel(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot represent the reserved uint32 chown sentinel")
	}
	reservedKernelID := uint64(^uint32(0))
	reserved := int(reservedKernelID)
	dir := t.TempDir()
	if err := EnsureDir(filepath.Join(dir, "child"), 0o700, reserved, 1); err == nil {
		t.Fatal("EnsureDir accepted chown's all-ones uid sentinel")
	}
	if _, err := os.Lstat(filepath.Join(dir, "child")); !os.IsNotExist(err) {
		t.Fatalf("EnsureDir mutated the filesystem before rejecting the uid: %v", err)
	}
	if err := AtomicWriteFileAs(filepath.Join(dir, "file"), []byte("x"), 0o600, 1, reserved); err == nil {
		t.Fatal("AtomicWriteFileAs accepted chown's all-ones gid sentinel")
	}
	if _, err := os.Lstat(filepath.Join(dir, "file")); !os.IsNotExist(err) {
		t.Fatalf("AtomicWriteFileAs wrote before rejecting the gid: %v", err)
	}
}

func TestAtomicWriteReportsPostRenameSyncFailureAsCommitted(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state")
	wantErr := errors.New("forced directory sync failure")
	old := syncDirectory
	syncDirectory = func(*os.File) error { return wantErr }
	t.Cleanup(func() { syncDirectory = old })

	err := AtomicWriteFileAs(target, []byte("committed"), 0o600, os.Getuid(), os.Getgid())
	var committed *DurabilityError
	if !errors.As(err, &committed) || !errors.Is(err, wantErr) {
		t.Fatalf("AtomicWriteFileAs error = %v, want committed DurabilityError", err)
	}
	if b, readErr := os.ReadFile(target); readErr != nil || string(b) != "committed" {
		t.Fatalf("post-rename target=%q err=%v", b, readErr)
	}
}

func TestAtomicWriteFileAsSyncsParentAfterRename(t *testing.T) {
	dir := t.TempDir()
	old := syncDirectory
	called := 0
	syncDirectory = func(*os.File) error {
		called++
		return nil
	}
	t.Cleanup(func() { syncDirectory = old })
	if err := AtomicWriteFileAs(filepath.Join(dir, "state"), []byte("durable"), 0o600, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("parent directory sync calls = %d, want 1 after rename", called)
	}
}

func TestRemoveFileSyncsParentAndDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret", target); err != nil {
		t.Fatal(err)
	}
	old := syncDirectory
	called := 0
	syncDirectory = func(*os.File) error {
		called++
		return nil
	}
	t.Cleanup(func() { syncDirectory = old })

	if err := RemoveFile(target); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("parent directory sync calls = %d, want 1", called)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("symlink target name survived: %v", err)
	}
	if b, err := os.ReadFile(secret); err != nil || string(b) != "keep" {
		t.Fatalf("symlink destination changed: content=%q err=%v", b, err)
	}
}

func TestRemoveFileRetrySyncsParentAfterCommittedSyncFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("forced unlink sync failure")
	old := syncDirectory
	syncs := 0
	syncDirectory = func(*os.File) error {
		syncs++
		if syncs == 1 {
			return wantErr
		}
		return nil
	}
	t.Cleanup(func() { syncDirectory = old })

	err := RemoveFile(target)
	var committed *DurabilityError
	if !errors.As(err, &committed) || !errors.Is(err, wantErr) || committed.Operation != "unlink" {
		t.Fatalf("RemoveFile error = %v, want committed unlink DurabilityError", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("unlink was not committed: %v", err)
	}
	if err := RemoveFile(target); err != nil {
		t.Fatalf("RemoveFile retry after visible unlink: %v", err)
	}
	if syncs != 2 {
		t.Fatalf("parent directory sync calls = %d, want failed unlink sync plus absent-target retry sync", syncs)
	}
}

func TestRemoveFileAbsentTargetReportsParentSyncFailure(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("forced absent-target sync failure")
	old := syncDirectory
	syncDirectory = func(*os.File) error { return wantErr }
	t.Cleanup(func() { syncDirectory = old })

	err := RemoveFile(filepath.Join(dir, "absent"))
	var durability *DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "unlink" {
		t.Fatalf("RemoveFile absent-target error = %v, want unlink DurabilityError", err)
	}
}

func TestRemoveFileSyncsParentWhenTargetDisappearsBeforeUnlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldUnlinkFileAt := unlinkFileAt
	unlinkFileAt = func(dirfd int, path string, flags int) error {
		if err := oldUnlinkFileAt(dirfd, path, flags); err != nil {
			return err
		}
		return unix.ENOENT
	}
	t.Cleanup(func() { unlinkFileAt = oldUnlinkFileAt })

	oldSync := syncDirectory
	syncs := 0
	syncDirectory = func(*os.File) error {
		syncs++
		return nil
	}
	t.Cleanup(func() { syncDirectory = oldSync })

	if err := RemoveFile(target); err != nil {
		t.Fatalf("RemoveFile after concurrent disappearance: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("target still exists after simulated unlink race: %v", err)
	}
	if syncs != 1 {
		t.Fatalf("parent directory sync calls = %d, want 1 after unlink race", syncs)
	}
}

func TestRemoveFileRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveFile(child); err == nil {
		t.Fatal("RemoveFile accepted a directory")
	}
}

func TestRemoveFileMissingParentIsSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone", "file")
	if err := RemoveFile(path); err != nil {
		t.Fatalf("already-absent path returned error: %v", err)
	}
}

func TestAtomicWriteFileAtPinsDirectoryFD(t *testing.T) {
	base := t.TempDir()
	dirPath := filepath.Join(base, "dir")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	moved := filepath.Join(base, "moved")
	if err := os.Rename(dirPath, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFileAt(dir, "authorized_keys", []byte("key\n"), 0o600, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dirPath, "authorized_keys")); !os.IsNotExist(err) {
		t.Fatalf("write escaped into replacement directory: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(moved, "authorized_keys")); err != nil || string(b) != "key\n" {
		t.Fatalf("pinned-directory content=%q err=%v", b, err)
	}
}

func TestAtomicWriteFileAtRefusesUnsafeNameAndSymlink(t *testing.T) {
	dirPath := t.TempDir()
	dir, err := os.Open(dirPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for _, name := range []string{"", ".", "../escape", "nested/file"} {
		if err := AtomicWriteFileAt(dir, name, []byte("x"), 0o600, os.Getuid(), os.Getgid()); err == nil {
			t.Errorf("AtomicWriteFileAt accepted unsafe name %q", name)
		}
	}
	secret := filepath.Join(dirPath, "secret")
	if err := os.WriteFile(secret, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret", filepath.Join(dirPath, "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFileAt(dir, "authorized_keys", []byte("changed"), 0o600, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("AtomicWriteFileAt accepted a symlink destination")
	}
	if b, _ := os.ReadFile(secret); string(b) != "original" {
		t.Fatalf("symlink target was modified: %q", b)
	}
}

func TestAtomicWriteRefusesSymlinkTargetAndDoesNotFollow(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Symlink(secret, target); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFileAs(target, []byte("PWNED"), 0o600, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected refusal to overwrite a symlink target")
	}
	if b, _ := os.ReadFile(secret); string(b) != "ORIGINAL" {
		t.Errorf("symlink was followed: secret content is now %q", b)
	}
	if fi, _ := os.Lstat(target); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("target is no longer a symlink (was replaced through the link)")
	}
}

func TestRootSafeFileRejectsSpecialModeBits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, bit := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		if err := os.Chmod(path, 0o755|bit); err != nil {
			t.Fatal(err)
		}
		if err := RootSafeFile(path); err == nil || !strings.Contains(err.Error(), "special mode bits") {
			t.Fatalf("RootSafeFile with mode bit %v error = %v, want special-bit refusal", bit, err)
		}
	}
}

func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "leaf")
	old := syncDirectory
	syncs := 0
	syncDirectory = func(*os.File) error {
		syncs++
		return nil
	}
	t.Cleanup(func() { syncDirectory = old })
	if err := EnsureDir(p, 0o700, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if syncs != 6 {
		t.Fatalf("new nested directory sync calls=%d, want existing-prefix inode+parent repair plus child+parent for both components", syncs)
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir wrong: isdir=%v mode=%o err=%v", fi.IsDir(), fi.Mode().Perm(), err)
	}
	// idempotent
	if err := EnsureDir(p, 0o700, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("second EnsureDir: %v", err)
	}
	if syncs != 8 {
		t.Fatalf("existing leaf durability sync calls=%d, want leaf and parent added on retry", syncs)
	}
}

func TestEnsureDirRepairsEveryNewSuffixDespiteRestrictiveUmask(t *testing.T) {
	base := t.TempDir()
	existing := filepath.Join(base, "existing")
	if err := os.Mkdir(existing, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(existing, 0o711); err != nil {
		t.Fatal(err)
	}
	var existingBefore unix.Stat_t
	if err := unix.Stat(existing, &existingBefore); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(existing, "middle", "leaf")
	wantUID, wantGID := os.Getuid(), os.Getgid()
	if os.Geteuid() == 0 {
		wantUID, wantGID = 12345, 12346
	}

	oldUmask := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(oldUmask) })
	if err := EnsureDir(target, 0o755, wantUID, wantGID); err != nil {
		t.Fatal(err)
	}

	existingInfo, err := os.Lstat(existing)
	if err != nil {
		t.Fatal(err)
	}
	var existingAfter unix.Stat_t
	if err := unix.Stat(existing, &existingAfter); err != nil {
		t.Fatal(err)
	}
	if existingInfo.Mode().Perm() != 0o711 || existingAfter.Uid != existingBefore.Uid || existingAfter.Gid != existingBefore.Gid {
		t.Fatalf("existing prefix metadata changed: mode=%o owner %d:%d, want 711 %d:%d",
			existingInfo.Mode().Perm(), existingAfter.Uid, existingAfter.Gid, existingBefore.Uid, existingBefore.Gid)
	}
	for _, want := range []struct {
		path     string
		uid, gid int
	}{
		{path: filepath.Join(existing, "middle"), uid: os.Geteuid(), gid: os.Getegid()},
		{path: target, uid: wantUID, gid: wantGID},
	} {
		fi, err := os.Lstat(want.path)
		if err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(want.path, &st); err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o755 || int(st.Uid) != want.uid || int(st.Gid) != want.gid {
			t.Fatalf("new directory %s metadata = mode %o owner %d:%d, want 755 %d:%d",
				want.path, fi.Mode().Perm(), st.Uid, st.Gid, want.uid, want.gid)
		}
	}
}

func TestEnsureDirRefusesSymlinkLeaf(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(dir, "leaf")
	if err := os.Symlink(real, leaf); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(leaf, 0o700, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected EnsureDir to refuse a symlink leaf")
	}
}

func TestEnsureDirRefusesSymlinkIntermediateComponent(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(filepath.Join(link, "leaf"), 0o700, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected EnsureDir to refuse a symlink in an intermediate component")
	}
	if _, err := os.Lstat(filepath.Join(real, "leaf")); !os.IsNotExist(err) {
		t.Fatalf("EnsureDir followed the intermediate symlink: %v", err)
	}
}

func TestEnsureDirRejectsRelativeAndTraversalPathsBeforeMutation(t *testing.T) {
	working := t.TempDir()
	t.Chdir(working)
	if err := EnsureDir("relative/child", 0o700, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("EnsureDir accepted a relative path")
	}
	if _, err := os.Lstat(filepath.Join(working, "relative")); !os.IsNotExist(err) {
		t.Fatalf("relative path was mutated before refusal: %v", err)
	}

	dir := t.TempDir()
	escaped := filepath.Join(dir, "escaped")
	path := dir + string(filepath.Separator) + "missing" + string(filepath.Separator) + ".." + string(filepath.Separator) + "escaped"
	if err := EnsureDir(path, 0o700, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("EnsureDir accepted an absolute path containing ..")
	}
	if _, err := os.Lstat(escaped); !os.IsNotExist(err) {
		t.Fatalf("traversal path was mutated before refusal: %v", err)
	}
}

func TestEnsureDirReportsVisibleDirectoryOnSyncFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "new")
	wantErr := errors.New("forced directory sync failure")
	old := syncDirectory
	syncs := 0
	syncDirectory = func(*os.File) error {
		syncs++
		if syncs == 3 {
			return wantErr
		}
		return nil
	}
	t.Cleanup(func() { syncDirectory = old })

	err := EnsureDir(p, 0o700, os.Getuid(), os.Getgid())
	var durability *DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) {
		t.Fatalf("EnsureDir error=%v, want DurabilityError", err)
	}
	if fi, statErr := os.Lstat(p); statErr != nil || !fi.IsDir() {
		t.Fatalf("created directory is not visible: info=%v err=%v", fi, statErr)
	}
}

func TestEnsureDirRetrySyncsVisibleIntermediateParentEntry(t *testing.T) {
	base := t.TempDir()
	visible := filepath.Join(base, "visible")
	target := filepath.Join(visible, "leaf")
	wantErr := errors.New("forced visible-mkdir parent sync failure")
	old := syncDirectory
	failed := false
	baseSyncs := 0
	var retrySyncs []string
	inRetry := false
	syncDirectory = func(dir *os.File) error {
		if inRetry {
			retrySyncs = append(retrySyncs, dir.Name())
		}
		if dir.Name() == base {
			baseSyncs++
			if !failed && baseSyncs == 2 {
				failed = true
				return wantErr
			}
		}
		return nil
	}
	t.Cleanup(func() { syncDirectory = old })

	err := EnsureDir(target, 0o700, os.Getuid(), os.Getgid())
	var durability *DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "mkdir" {
		t.Fatalf("first EnsureDir error = %v, want mkdir DurabilityError", err)
	}
	if fi, statErr := os.Lstat(visible); statErr != nil || !fi.IsDir() {
		t.Fatalf("intermediate directory is not visible after failed parent sync: info=%v err=%v", fi, statErr)
	}
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Fatalf("first EnsureDir continued after failed parent sync: %v", statErr)
	}

	inRetry = true
	if err := EnsureDir(target, 0o700, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("EnsureDir retry: %v", err)
	}
	if len(retrySyncs) < 2 || retrySyncs[0] != visible || retrySyncs[1] != base {
		t.Fatalf("retry syncs = %v, want visible inode %s then parent %s before extending it", retrySyncs, visible, base)
	}
}

func TestEnsureDirRetryAfterVisibleDirectorySyncFailurePreservesSyncOrder(t *testing.T) {
	base := t.TempDir()
	visible := filepath.Join(base, "visible")
	target := filepath.Join(visible, "leaf")
	wantErr := errors.New("forced visible-directory sync failure")
	old := syncDirectory
	failed := false
	inRetry := false
	var retrySyncs []string
	syncDirectory = func(dir *os.File) error {
		if inRetry {
			retrySyncs = append(retrySyncs, dir.Name())
		}
		if !failed && dir.Name() == visible {
			failed = true
			return wantErr
		}
		return nil
	}
	t.Cleanup(func() { syncDirectory = old })

	err := EnsureDir(target, 0o700, os.Getuid(), os.Getgid())
	var durability *DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "directory metadata update" {
		t.Fatalf("first EnsureDir error = %v, want directory metadata DurabilityError", err)
	}
	if fi, statErr := os.Lstat(visible); statErr != nil || !fi.IsDir() {
		t.Fatalf("intermediate directory is not visible after its failed sync: info=%v err=%v", fi, statErr)
	}
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Fatalf("first EnsureDir continued after child sync failure: %v", statErr)
	}

	inRetry = true
	if err := EnsureDir(target, 0o700, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("EnsureDir retry: %v", err)
	}
	if len(retrySyncs) < 2 || retrySyncs[0] != visible || retrySyncs[1] != base {
		t.Fatalf("retry syncs = %v, want failed visible inode %s before parent %s", retrySyncs, visible, base)
	}
}
