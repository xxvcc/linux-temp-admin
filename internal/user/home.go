package user

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/mountinfo"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

var managedHomeRoot = "/home"

func managedHome(name string) string { return filepath.Join(managedHomeRoot, name) }

var (
	syncCreatedHomeMetadata = func(home *os.File) error { return home.Sync() }
	syncCreatedHomeParent   = func(parent *os.File) error { return parent.Sync() }
)

// DefaultHome is the dedicated home path used for every newly created account.
func DefaultHome(name string) (string, error) {
	if !validate.Username(name) {
		return "", fmt.Errorf("invalid username %q", name)
	}
	return managedHome(name), nil
}

func (m *Manager) removeManagedHome(expected Passwd) error {
	remove := m.RemoveManagedHome
	if remove == nil {
		remove = removeManagedHome
	}
	return remove(expected)
}

func validateHomeRemoval(expected Passwd) error {
	if !isManagedHome(expected.Name, expected.Home) {
		return fmt.Errorf("account home %q is not a dedicated managed path", expected.Home)
	}
	if err := fsutil.RootSafeDir(managedHomeRoot); err != nil {
		return fmt.Errorf("managed home parent is unsafe: %w", err)
	}
	fi, err := os.Lstat(expected.Home)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect account home %s: %w", expected.Home, err)
	}
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("account home %s is not a real directory", expected.Home)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int64(st.Uid) != int64(expected.UID) || int64(st.Gid) != int64(expected.GID) {
			return fmt.Errorf("account home %s owner does not match uid/gid %d:%d", expected.Home, expected.UID, expected.GID)
		}
	}
	if err := refuseMountsUnder(expected.Home); err != nil {
		return err
	}
	return nil
}

func isManagedHome(name, home string) bool {
	return validate.Username(name) && home == managedHome(name)
}

func prepareManagedHome(name string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	if err := fsutil.RootSafeDir(managedHomeRoot); err != nil {
		return fmt.Errorf("managed home parent is unsafe: %w", err)
	}
	home := managedHome(name)
	if _, err := os.Lstat(home); err == nil {
		return fmt.Errorf("managed home %s already exists", home)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect managed home %s: %w", home, err)
	}
	return nil
}

// createManagedHome creates an empty deterministic Home only after the account's
// selected UID has been proved idle. It never copies /etc/skel: a host-local
// skeleton can contain authorized_keys or other authentication material that is
// inappropriate for a one-time account. All mutation is relative to a pinned,
// root-owned parent directory and metadata is applied through the opened fd.
func createManagedHome(expected Passwd) error {
	if !validate.Username(expected.Name) || !validate.AccountID(expected.UID) ||
		!validate.AccountID(expected.GID) || expected.Home != managedHome(expected.Name) {
		return fmt.Errorf("invalid managed account identity for Home creation")
	}
	parentFD, err := unix.Open(managedHomeRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open managed home parent %s: %w", managedHomeRoot, err)
	}
	parent := os.NewFile(uintptr(parentFD), managedHomeRoot)
	defer parent.Close()

	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return fmt.Errorf("stat managed home parent: %w", err)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Gid != 0 || parentStat.Mode&0o022 != 0 {
		return fmt.Errorf("managed home parent is not a root-owned non-writable directory")
	}
	var namedParent unix.Stat_t
	if err := unix.Lstat(managedHomeRoot, &namedParent); err != nil {
		return fmt.Errorf("recheck managed home parent: %w", err)
	}
	if namedParent.Dev != parentStat.Dev || namedParent.Ino != parentStat.Ino || namedParent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home parent was replaced during account creation")
	}

	if err := unix.Mkdirat(parentFD, expected.Name, 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("managed home %s already exists", expected.Home)
		}
		return fmt.Errorf("create managed home %s: %w", expected.Home, err)
	}
	homeFD, err := unix.Openat(parentFD, expected.Name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open newly created managed home: %w", err)
	}
	home := os.NewFile(uintptr(homeFD), expected.Home)
	defer home.Close()

	var initial unix.Stat_t
	if err := unix.Fstat(homeFD, &initial); err != nil {
		return fmt.Errorf("stat newly created managed home: %w", err)
	}
	if initial.Mode&unix.S_IFMT != unix.S_IFDIR || initial.Uid != 0 || initial.Gid != 0 {
		return fmt.Errorf("new managed home did not begin as a root-owned directory")
	}
	if err := home.Chown(expected.UID, expected.GID); err != nil {
		return fmt.Errorf("set managed home owner: %w", err)
	}
	if err := home.Chmod(0o700); err != nil {
		return fmt.Errorf("set managed home mode: %w", err)
	}
	if err := syncCreatedHomeMetadata(home); err != nil {
		return &fsutil.DurabilityError{Operation: "managed home metadata update", Err: err}
	}
	if err := syncCreatedHomeParent(parent); err != nil {
		return &fsutil.DurabilityError{Operation: "managed home creation", Err: err}
	}

	var final, namedHome, finalParent unix.Stat_t
	if err := unix.Fstat(homeFD, &final); err != nil {
		return fmt.Errorf("verify managed home metadata: %w", err)
	}
	if final.Mode&unix.S_IFMT != unix.S_IFDIR || int64(final.Uid) != int64(expected.UID) ||
		int64(final.Gid) != int64(expected.GID) || final.Mode&0o7777 != 0o700 {
		return fmt.Errorf("managed home metadata remains unsafe after creation")
	}
	if err := unix.Fstatat(parentFD, expected.Name, &namedHome, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck managed home entry: %w", err)
	}
	if namedHome.Dev != final.Dev || namedHome.Ino != final.Ino || namedHome.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home was replaced during account creation")
	}
	if err := unix.Lstat(managedHomeRoot, &finalParent); err != nil {
		return fmt.Errorf("final recheck of managed home parent: %w", err)
	}
	if finalParent.Dev != parentStat.Dev || finalParent.Ino != parentStat.Ino || finalParent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home parent was replaced during account creation")
	}
	return nil
}

func validateCreatedHome(expected Passwd) error {
	if !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) {
		return fmt.Errorf("invalid account owner %d:%d", expected.UID, expected.GID)
	}
	if err := validateHomeRemoval(expected); err != nil {
		return err
	}
	if _, err := os.Lstat(expected.Home); os.IsNotExist(err) {
		return fmt.Errorf("account home %s was not created", expected.Home)
	} else if err != nil {
		return fmt.Errorf("inspect account home %s: %w", expected.Home, err)
	}
	return nil
}

func removeManagedHome(expected Passwd) error {
	if err := validateHomeRemoval(expected); err != nil {
		return fmt.Errorf("refusing managed home cleanup: %w", err)
	}
	if err := removeHomeTree(expected); err != nil {
		return fmt.Errorf("remove managed home %s: %w", expected.Home, err)
	}
	return nil
}

var syncRemovalDirectory = func(dir *os.File) error { return dir.Sync() }

func syncRemovalParent(dir *os.File, operation string) error {
	if err := syncRemovalDirectory(dir); err != nil {
		return &fsutil.DurabilityError{Operation: operation, Err: err}
	}
	return nil
}

const (
	maxManagedHomeEntries     = 100_000
	maxManagedHomeDepth       = 128
	managedHomeRemovalTimeout = 2 * time.Minute
	managedHomeReadBatch      = 128
)

type homeRemovalBudget struct {
	remaining int
	maxDepth  int
	deadline  time.Time
	now       func() time.Time
	device    uint64
}

func (b *homeRemovalBudget) check(path string, depth int) error {
	now := b.now
	if now == nil {
		now = time.Now
	}
	if !now().Before(b.deadline) {
		return fmt.Errorf("managed home cleanup exceeded its time limit at %s", path)
	}
	if depth > b.maxDepth {
		return fmt.Errorf("managed home cleanup exceeded its depth limit at %s", path)
	}
	return nil
}

func (b *homeRemovalBudget) consume(path string, depth int) error {
	if err := b.check(path, depth); err != nil {
		return err
	}
	if b.remaining <= 0 {
		return fmt.Errorf("managed home cleanup exceeded its entry limit at %s", path)
	}
	b.remaining--
	return nil
}

// removeHomeTreeBounded removes a managed Home through directory-relative file
// descriptors. It never follows a symlink and checks fixed entry/depth limits and
// a cooperative deadline between filesystem calls. The deadline cannot interrupt
// one blocked call. A limit failure may leave a partially cleaned tree; callers
// retain the disabled account and registry witness, so a later retry can continue
// without freeing the UID or username.
func removeHomeTreeBounded(expected Passwd) error {
	budget := &homeRemovalBudget{
		remaining: maxManagedHomeEntries,
		maxDepth:  maxManagedHomeDepth,
		deadline:  time.Now().Add(managedHomeRemovalTimeout),
	}
	return removeHomeTreeWithin(expected, budget)
}

func removeHomeTreeWithin(expected Passwd, budget *homeRemovalBudget) error {
	if budget == nil || budget.remaining <= 0 || budget.maxDepth < 0 || budget.deadline.IsZero() {
		return fmt.Errorf("invalid managed home cleanup budget")
	}
	if !isManagedHome(expected.Name, expected.Home) || !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) {
		return fmt.Errorf("invalid expected account identity for managed home cleanup")
	}
	parentPath := filepath.Dir(expected.Home)
	if parentPath != managedHomeRoot || filepath.Base(expected.Home) != expected.Name {
		return fmt.Errorf("managed home %q is not directly beneath %q", expected.Home, managedHomeRoot)
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open managed home parent %s: %w", parentPath, err)
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	if parent == nil {
		_ = unix.Close(parentFD)
		return fmt.Errorf("adopt managed home parent descriptor")
	}
	defer parent.Close()

	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return fmt.Errorf("stat managed home parent %s: %w", parentPath, err)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Gid != 0 || parentStat.Mode&0o022 != 0 {
		return fmt.Errorf("managed home parent %s is not a root-owned, non-writable directory", parentPath)
	}
	if err := refuseMountsUnder(expected.Home); err != nil {
		return err
	}

	var rootStat unix.Stat_t
	err = unix.Fstatat(parentFD, expected.Name, &rootStat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		// A previous attempt may have removed the root but failed to sync /home.
		// Confirm the already-visible absence durably before account deletion.
		return syncRemovalParent(parent, "managed home absence confirmation")
	}
	if err != nil {
		return fmt.Errorf("inspect managed home %s: %w", expected.Home, err)
	}
	if rootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home %s is not a real directory", expected.Home)
	}
	if int64(rootStat.Uid) != int64(expected.UID) || int64(rootStat.Gid) != int64(expected.GID) {
		return fmt.Errorf("managed home %s owner does not match uid/gid %d:%d", expected.Home, expected.UID, expected.GID)
	}
	budget.device = uint64(rootStat.Dev)
	if err := removeHomeEntryAt(parentFD, expected.Name, expected.Home, 0, rootStat, budget); err != nil {
		return err
	}
	return syncRemovalParent(parent, "managed home removal")
}

func removeHomeEntryAt(parentFD int, name, displayPath string, depth int, inspected unix.Stat_t, budget *homeRemovalBudget) error {
	if err := budget.consume(displayPath, depth); err != nil {
		return err
	}
	if uint64(inspected.Dev) != budget.device {
		return fmt.Errorf("refusing managed home cleanup across a filesystem boundary at %s", displayPath)
	}
	if inspected.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(parentFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove managed home entry %s: %w", displayPath, err)
		}
		return nil
	}

	dirFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open managed home directory %s: %w", displayPath, err)
	}
	dir := os.NewFile(uintptr(dirFD), displayPath)
	if dir == nil {
		_ = unix.Close(dirFD)
		return fmt.Errorf("adopt managed home directory descriptor for %s", displayPath)
	}

	var opened unix.Stat_t
	if err := unix.Fstat(dirFD, &opened); err != nil {
		_ = dir.Close()
		return fmt.Errorf("stat opened managed home directory %s: %w", displayPath, err)
	}
	if opened.Dev != inspected.Dev || opened.Ino != inspected.Ino {
		_ = dir.Close()
		return fmt.Errorf("managed home directory changed while opening %s", displayPath)
	}

	for {
		if err := budget.check(displayPath, depth); err != nil {
			_ = dir.Close()
			return err
		}
		entries, readErr := dir.ReadDir(managedHomeReadBatch)
		for _, entry := range entries {
			childName := entry.Name()
			if childName == "" || childName == "." || childName == ".." || filepath.Base(childName) != childName {
				_ = dir.Close()
				return fmt.Errorf("unsafe managed home entry name %q under %s", childName, displayPath)
			}
			var childStat unix.Stat_t
			if err := unix.Fstatat(dirFD, childName, &childStat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				_ = dir.Close()
				return fmt.Errorf("inspect managed home entry %s: %w", filepath.Join(displayPath, childName), err)
			}
			if err := removeHomeEntryAt(dirFD, childName, filepath.Join(displayPath, childName), depth+1, childStat, budget); err != nil {
				_ = dir.Close()
				return err
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = dir.Close()
			return fmt.Errorf("read managed home directory %s: %w", displayPath, readErr)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if len(entries) == 0 {
			_ = dir.Close()
			return fmt.Errorf("read managed home directory %s made no progress", displayPath)
		}
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close managed home directory %s: %w", displayPath, err)
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove managed home directory %s: %w", displayPath, err)
	}
	return nil
}

var (
	refuseMountsUnder = mountinfo.RefuseUnder
	removeHomeTree    = removeHomeTreeBounded
)
