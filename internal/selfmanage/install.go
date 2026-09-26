package selfmanage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"github.com/xxvcc/linux-temp-admin/internal/version"
)

// ErrNotInstalled reports that InstallPath has no directory entry. Callers use
// it to distinguish a repairable missing command from an unsafe or unreadable
// installed command.
var ErrNotInstalled = errors.New("stable command is not installed")

// Install atomically writes srcBytes to InstallPath as a root-owned 0755 binary.
// It reports whether it actually wrote: a byte-identical target is left alone and
// returns (false, nil). If the target differs and force is false, it refuses.
func (m *Manager) Install(srcBytes []byte, force bool) (installed bool, err error) {
	if err := ensureInstallDir(filepath.Dir(m.InstallPath)); err != nil {
		return false, err
	}
	fi, statErr := m.lstat(m.InstallPath)
	if statErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%s is a symlink; refusing", m.InstallPath)
		}
		if fi.Mode().IsRegular() {
			same, rerr := sameInstalledBytes(m.InstallPath, srcBytes)
			if rerr == nil && same {
				if installedFileMetadataSafe(fi) {
					return false, nil // byte-identical and already root:root 0755
				}
				// Identical bytes do not make an attacker-writable or set-id binary
				// safe. Rewrite atomically to normalize all metadata, even without
				// --force: no content replacement has been requested.
				if err := m.writeRootFile(srcBytes); err != nil {
					return mutationResult(err)
				}
				return true, nil
			}
			if !force {
				// Fail closed: never replace an existing binary without --force, even
				// if it could not be read back for the identical-bytes comparison.
				if rerr != nil {
					return false, fmt.Errorf("%s exists but could not be read (%v); use --force to replace", m.InstallPath, rerr)
				}
				return false, fmt.Errorf("%s already exists and differs; use --force to replace", m.InstallPath)
			}
		} else if !force {
			return false, fmt.Errorf("%s exists and is not a regular file; use --force to replace", m.InstallPath)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect existing install target: %w", statErr)
	}
	if err := m.writeRootFile(srcBytes); err != nil {
		return mutationResult(err)
	}
	return true, nil
}

func (m *Manager) lstat(path string) (os.FileInfo, error) {
	if m.Lstat != nil {
		return m.Lstat(path)
	}
	return os.Lstat(path)
}

func ensureInstallDir(dir string) error {
	if err := fsutil.RootSafeDir(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unsafe target directory: %w", err)
	}
	if err := fsutil.EnsureDir(dir, 0o755, 0, 0); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	if err := fsutil.RootSafeDir(dir); err != nil {
		return fmt.Errorf("unsafe target directory after creation: %w", err)
	}
	return nil
}

func sameInstalledBytes(path string, expected []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() != int64(len(expected)) {
		return false, nil
	}
	actual, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	if err != nil {
		return false, err
	}
	return bytes.Equal(actual, expected), nil
}

func (m *Manager) writeRootFile(content []byte) error {
	if m.WriteRootFile != nil {
		return m.WriteRootFile(m.InstallPath, content, 0o755)
	}
	return fsutil.WriteRootFile(m.InstallPath, content, 0o755)
}

// mutationResult preserves the crucial distinction exposed by DurabilityError:
// the new inode is already visible even though its parent-directory fsync failed.
func mutationResult(err error) (bool, error) {
	var durability *fsutil.DurabilityError
	return errors.As(err, &durability), err
}

func installedFileMetadataSafe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return false
	}
	special := os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return fi.Mode().IsRegular() && fi.Mode().Perm() == 0o755 && fi.Mode()&special == 0
}

// Uninstall removes the stable command. Unless force is set, the target must be a
// safe root-owned regular file.
func (m *Manager) Uninstall(force bool) error {
	if _, err := os.Lstat(m.InstallPath); os.IsNotExist(err) {
		return nil
	}
	if !force {
		if err := fsutil.RootSafeFile(m.InstallPath); err != nil {
			return fmt.Errorf("refusing to remove an unsafe path: %w", err)
		}
	}
	if m.RemoveFile != nil {
		return m.RemoveFile(m.InstallPath)
	}
	return fsutil.RemoveFile(m.InstallPath)
}

// UpgradeResult records the installed state observed at commit time and whether
// the command was visibly replaced. Replaced remains true if directory syncing
// fails after replacement, so an interactive caller can retire its old process.
type UpgradeResult struct {
	// PreviousVersion is empty when no command was installed, or "unknown" when
	// an existing command could not be identified.
	PreviousVersion string
	// Version is the resulting version after replacement or a successful no-op.
	// It remains empty when an error prevented a visible replacement.
	Version  string
	Replaced bool
}

// ApplyUpgrade re-reads the installed command at commit time, applies the
// downgrade policy to that current state, and atomically installs candidate.
// A same/newer installed command produces a successful result with Replaced
// false. A visible but not known durable replacement returns both its result
// and the durability error; failure alone does not mean nothing changed.
func (m *Manager) ApplyUpgrade(candidate *UpgradeCandidate, force bool) (UpgradeResult, error) {
	var result UpgradeResult
	if candidate == nil || len(candidate.bin) == 0 ||
		(candidate.signedVersion != "" && !validate.ReleaseVersion(candidate.signedVersion)) ||
		(candidate.expected != "" && !validate.ReleaseVersion(candidate.expected)) {
		return result, fmt.Errorf("invalid prepared upgrade candidate")
	}
	if current, err := m.InstalledVersion(); err == nil {
		result.PreviousVersion = current
	} else if !errors.Is(err, ErrNotInstalled) {
		result.PreviousVersion = "unknown"
		if !force {
			return result, fmt.Errorf("read installed version: %w", err)
		}
	}
	if !force {
		if candidate.signedVersion == "" {
			return result, fmt.Errorf("signed candidate has no static release-version witness; use --force only after independently confirming the historical binary")
		}
		if result.PreviousVersion != "" && !version.Greater(candidate.signedVersion, result.PreviousVersion) {
			result.Version = result.PreviousVersion
			return result, nil // same/newer install; candidate was not executed
		}
	}
	probedVersion, err := m.probeVersion(candidate.bin)
	if err != nil {
		return result, fmt.Errorf("read downloaded version: %w", err)
	}
	if candidate.signedVersion != "" && probedVersion != candidate.signedVersion {
		return result, fmt.Errorf("candidate version %q does not match signed release-version witness %q", probedVersion, candidate.signedVersion)
	}
	if candidate.expected != "" && probedVersion != candidate.expected {
		return result, fmt.Errorf("signed candidate version %q does not match selected release %q", probedVersion, candidate.expected)
	}
	result.Replaced, err = m.Install(candidate.bin, true)
	if result.Replaced {
		result.Version = probedVersion
	}
	if err != nil {
		if result.Replaced {
			return result, fmt.Errorf("installed command was replaced but durability is unknown: %w", err)
		}
		return result, err
	}
	// Install also returns false for identical, already-safe bytes. This is a
	// known no-op, not an unverified or failed installation.
	result.Version = probedVersion
	return result, nil
}

// InstalledVersion safely executes `<InstallPath> version` under the same
// timeout, output cap, process-group cancellation, and WaitDelay used for a
// downloaded candidate.
func (m *Manager) InstalledVersion() (string, error) {
	if _, err := os.Lstat(m.InstallPath); err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotInstalled
		}
		return "", err
	}
	if err := fsutil.RootSafeFile(m.InstallPath); err != nil {
		return "", fmt.Errorf("installed command is unsafe: %w", err)
	}
	v, err := m.runVersionProbe(m.InstallPath)
	if err != nil {
		return "", fmt.Errorf("probe installed command: %w", err)
	}
	return v, nil
}
