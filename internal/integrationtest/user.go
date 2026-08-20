//go:build integration

// Package integrationtest contains destructive test helpers that are compiled
// only for the explicitly requested root integration suite.
package integrationtest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	runUserdel = func(args ...string) ([]byte, error) {
		return exec.Command("userdel", args...).CombinedOutput()
	}
	runGroupdel = func(args ...string) ([]byte, error) {
		return exec.Command("groupdel", args...).CombinedOutput()
	}
	lookupSystemUser          = user.Lookup
	lookupSystemGroup         = user.LookupGroup // retained as a narrow test adapter
	inspectLocalGroupDatabase = inspectLocalGroupDatabaseFiles
	groupDatabasePath         = "/etc/group"
	gshadowDatabasePath       = "/etc/gshadow"
)

const maxLocalGroupDatabaseBytes = 64 << 20

type localGroupArtifacts struct {
	group          bool
	gshadow        bool
	gshadowPresent bool
}

// CleanupUser is the reporting post-test cleanup for a disposable account and
// its same-name private group. Missing entries are expected; unresolved removal
// failures fail the test without aborting its remaining cleanup stack.
func CleanupUser(t interface {
	Helper()
	Errorf(string, ...any)
}, name string, force bool) {
	t.Helper()
	if err := removeUser(name, force); err != nil {
		t.Errorf("%v", err)
	}
}

// RequireUserAbsent is the strict pre-test counterpart of CleanupUser. It stops
// the test before any mutation if a stale account or private group cannot be
// removed.
func RequireUserAbsent(t interface {
	Helper()
	Fatalf(string, ...any)
}, name string, force bool) {
	t.Helper()
	if err := removeUser(name, force); err != nil {
		t.Fatalf("%v", err)
	}
}

func removeUser(name string, force bool) error {
	args := []string{"-r"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, "--", name)
	out, removeErr := runUserdel(args...)
	if err := confirmUserAbsent(name); err != nil {
		if removeErr != nil {
			return fmt.Errorf("cleanup integration user %q: userdel failed: %v%s; %w",
				name, removeErr, commandDiagnostic(out), err)
		}
		return fmt.Errorf("cleanup integration user %q: userdel reported success but %w", name, err)
	}
	if err := removeSameNameGroup(name); err != nil {
		return err
	}
	if err := confirmUserAbsent(name); err != nil {
		return fmt.Errorf("cleanup integration user %q: account reappeared during private-group cleanup: %w", name, err)
	}
	return nil
}

func confirmUserAbsent(name string) error {
	if _, err := lookupSystemUser(name); err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return nil
		}
		return fmt.Errorf("cannot verify account absence: %w", err)
	}
	return fmt.Errorf("account still exists")
}

func removeSameNameGroup(name string) error {
	state, inspectErr := inspectLocalGroupDatabase(name)
	if inspectErr != nil {
		return fmt.Errorf("cleanup integration group %q: cannot verify group/gshadow absence: %v", name, inspectErr)
	}
	if !state.group && !state.gshadow {
		return nil
	}
	if !state.group {
		return fmt.Errorf("cleanup integration group %q: orphaned gshadow entry remains without a local group", name)
	}
	out, removeErr := runGroupdel("--", name)
	state, inspectErr = inspectLocalGroupDatabase(name)
	if inspectErr != nil {
		if removeErr != nil {
			return fmt.Errorf("cleanup integration group %q: groupdel failed: %v%s; cannot verify group/gshadow absence: %v",
				name, removeErr, commandDiagnostic(out), inspectErr)
		}
		return fmt.Errorf("cleanup integration group %q: groupdel reported success but group/gshadow absence cannot be verified: %v",
			name, inspectErr)
	}
	if !state.group && !state.gshadow {
		return nil
	}
	if removeErr != nil {
		return fmt.Errorf("cleanup integration group %q: groupdel failed while group/gshadow residue still exists: %v%s",
			name, removeErr, commandDiagnostic(out))
	}
	return fmt.Errorf("cleanup integration group %q: groupdel reported success but group/gshadow residue still exists", name)
}

func inspectLocalGroupDatabaseFiles(name string) (localGroupArtifacts, error) {
	groupData, err := readBoundedDatabase(groupDatabasePath, false)
	if err != nil {
		return localGroupArtifacts{}, fmt.Errorf("read group database: %w", err)
	}
	groupFound, err := databaseHasName(groupData, name, true)
	if err != nil {
		return localGroupArtifacts{}, fmt.Errorf("parse group database: %w", err)
	}
	gshadowData, err := readBoundedDatabase(gshadowDatabasePath, true)
	if errors.Is(err, os.ErrNotExist) {
		return localGroupArtifacts{group: groupFound}, nil
	}
	if err != nil {
		return localGroupArtifacts{}, fmt.Errorf("read gshadow database: %w", err)
	}
	gshadowFound, err := databaseHasName(gshadowData, name, false)
	if err != nil {
		return localGroupArtifacts{}, fmt.Errorf("parse gshadow database: %w", err)
	}
	return localGroupArtifacts{group: groupFound, gshadow: gshadowFound, gshadowPresent: true}, nil
}

func readBoundedDatabase(path string, optional bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if optional && errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxLocalGroupDatabaseBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxLocalGroupDatabaseBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLocalGroupDatabaseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxLocalGroupDatabaseBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxLocalGroupDatabaseBytes)
	}
	return data, nil
}

func databaseHasName(data []byte, name string, parseGID bool) (bool, error) {
	seen := make(map[string]bool)
	found := false
	for lineNumber, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 || parts[0] == "" {
			return false, fmt.Errorf("malformed entry at line %d", lineNumber+1)
		}
		if seen[parts[0]] {
			return false, fmt.Errorf("duplicate entry for %s", parts[0])
		}
		seen[parts[0]] = true
		if parseGID {
			gid, err := strconv.ParseUint(parts[2], 10, 32)
			if err != nil || gid == 1<<32-1 {
				return false, fmt.Errorf("malformed GID at line %d", lineNumber+1)
			}
		}
		if parts[0] == name {
			found = true
		}
	}
	return found, nil
}

func commandDiagnostic(out []byte) string {
	diagnostic := strings.TrimSpace(string(out))
	if diagnostic == "" {
		return ""
	}
	return fmt.Sprintf(": %s", diagnostic)
}
