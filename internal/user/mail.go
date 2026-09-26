package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

func (m *Manager) removeManagedMail(expected Passwd) error {
	remove := m.RemoveManagedMail
	if remove == nil {
		remove = removeManagedMail
	}
	return remove(expected)
}

// ClearManagedMailExpected removes a same-name spool only while the complete
// live passwd entry still matches expected. It is used during account creation,
// before credentials are installed, so a reused UID cannot inherit old mail.
func (m *Manager) ClearManagedMailExpected(name string, expected Passwd) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) ||
		!validate.AccountID(expected.GID) || !isManagedHome(name, expected.Home) || expected.Shell == "" {
		return fmt.Errorf("invalid expected account identity for mail cleanup")
	}
	if err := m.verifyExpectedIdentity(name, expected, "before managed mail cleanup"); err != nil {
		return fmt.Errorf("verify account before managed mail cleanup: %w", err)
	}
	if err := m.removeManagedMail(expected); err != nil {
		return err
	}
	if err := m.verifyExpectedIdentity(name, expected, "after managed mail cleanup"); err != nil {
		return fmt.Errorf("verify account after managed mail cleanup: %w", err)
	}
	return nil
}

// ReconcileManagedMailAfterDeletion retries the final mail-only sweep after a
// deletion whose intent was durably recorded while the account still existed.
// The caller owns that authorization decision. This method independently requires
// the name to remain absent before and after cleanup; it never touches Home.
func (m *Manager) ReconcileManagedMailAfterDeletion(name string, uid int) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if !validate.AccountID(uid) {
		return fmt.Errorf("invalid expected account UID for post-deletion mail cleanup")
	}
	absent, err := m.deletionState(name, nil, nil)
	if err != nil {
		return fmt.Errorf("verify account absence before managed mail cleanup: %w", err)
	}
	if !absent {
		return fmt.Errorf("account %s exists; refusing post-deletion mail cleanup", name)
	}
	if err := m.removeManagedMail(Passwd{Name: name, UID: uid}); err != nil {
		return err
	}
	absent, err = m.deletionState(name, nil, nil)
	if err != nil {
		return fmt.Errorf("verify account absence after managed mail cleanup: %w", err)
	}
	if !absent {
		return fmt.Errorf("account %s reappeared during post-deletion mail cleanup", name)
	}
	return nil
}

var managedMailRoots = []string{"/var/mail", "/var/spool/mail"}

// unlinkManagedMailAt is indirected so a unit test can force the stat/unlink
// disappearance race without relying on scheduler timing.
var unlinkManagedMailAt = unix.Unlinkat

func syncAndConfirmManagedMailAbsent(dir *os.File, root, name, operation string) error {
	if err := syncRemovalParent(dir, operation); err != nil {
		return err
	}
	var spool unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &spool, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err == nil {
			return fmt.Errorf("managed mail spool %s/%s reappeared during cleanup", root, name)
		}
		return fmt.Errorf("verify managed mail spool absence after directory sync %s/%s: %w", root, name, err)
	}
	return nil
}

// removeManagedMail removes only a conventional single-file system mailbox
// still owned by the captured account UID. Account helpers are intentionally
// invoked without recursive-home flags, so this preserves the mail-spool part of
// userdel -r without delegating Home traversal to a name-scoped helper.
func removeManagedMail(expected Passwd) error {
	if !validate.Username(expected.Name) || !validate.AccountID(expected.UID) {
		return fmt.Errorf("invalid expected account identity for mail cleanup")
	}
	return visitManagedMailRoots(func(root string) error {
		return removeManagedMailAt(root, expected)
	})
}

// validateManagedMailRoots checks directory metadata before useradd. The real
// cleanup opens and validates each root again while the selected UID is bound.
func validateManagedMailRoots() error {
	return visitManagedMailRoots(func(root string) error {
		dir, err := openManagedMailRoot(root)
		if err != nil {
			return err
		}
		return closeManagedMailRoot(dir, root)
	})
}

func visitManagedMailRoots(visit func(string) error) error {
	allowed := make(map[string]bool, len(managedMailRoots))
	for _, root := range managedMailRoots {
		clean := filepath.Clean(root)
		if root == "" || !filepath.IsAbs(root) || clean != root || clean == string(filepath.Separator) {
			return fmt.Errorf("unsafe managed mail root %q", root)
		}
		allowed[clean] = true
	}
	seen := make(map[string]bool, len(managedMailRoots))
	for _, root := range managedMailRoots {
		if _, err := os.Lstat(root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return fmt.Errorf("inspect managed mail root %s: %w", root, err)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return fmt.Errorf("resolve managed mail root %s: %w", root, err)
		}
		resolved = filepath.Clean(resolved)
		if !allowed[resolved] {
			return fmt.Errorf("managed mail root %s resolves outside the accepted spool directories", root)
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		if err := visit(resolved); err != nil {
			return err
		}
	}
	return nil
}

func openManagedMailRoot(root string) (*os.File, error) {
	dir, err := os.OpenFile(root, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open managed mail root %s: %w", root, err)
	}
	fi, err := dir.Stat()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("stat managed mail root %s: %w", root, err),
			closeManagedMailRoot(dir, root),
		)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	mode := fi.Mode()
	worldWritableWithoutSticky := mode.Perm()&0o002 != 0 && mode&os.ModeSticky == 0
	if !ok || !fi.IsDir() || st.Uid != 0 || mode&os.ModeSetuid != 0 || worldWritableWithoutSticky {
		return nil, errors.Join(
			fmt.Errorf("managed mail root %s is not a safe root-owned directory (world-writable roots require sticky protection and setuid is forbidden)", root),
			closeManagedMailRoot(dir, root),
		)
	}
	return dir, nil
}

func closeManagedMailRoot(dir *os.File, root string) error {
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close managed mail root %s: %w", root, err)
	}
	return nil
}

func removeManagedMailAt(root string, expected Passwd) (returnErr error) {
	dir, err := openManagedMailRoot(root)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeManagedMailRoot(dir, root))
	}()

	var spool unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), expected.Name, &spool, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		// This can be a retry after unlink succeeded but the previous directory sync
		// failed. Re-sync the observed absence before allowing the UID to be released.
		return syncAndConfirmManagedMailAbsent(dir, root, expected.Name, "managed mail spool absence confirmation")
	}
	if err != nil {
		return fmt.Errorf("inspect managed mail spool %s/%s: %w", root, expected.Name, err)
	}
	if spool.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("managed mail spool %s/%s is not a regular file", root, expected.Name)
	}
	if int64(spool.Uid) != int64(expected.UID) {
		return fmt.Errorf("managed mail spool %s/%s owner does not match uid %d", root, expected.Name, expected.UID)
	}
	if err := unlinkManagedMailAt(int(dir.Fd()), expected.Name, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return syncAndConfirmManagedMailAbsent(dir, root, expected.Name, "managed mail spool absence confirmation")
		}
		return fmt.Errorf("remove managed mail spool %s/%s: %w", root, expected.Name, err)
	}
	if err := unix.Fstatat(int(dir.Fd()), expected.Name, &spool, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err == nil {
			return fmt.Errorf("managed mail spool %s/%s reappeared during cleanup", root, expected.Name)
		}
		return fmt.Errorf("verify managed mail spool removal %s/%s: %w", root, expected.Name, err)
	}
	return syncAndConfirmManagedMailAbsent(dir, root, expected.Name, "managed mail spool removal")
}
