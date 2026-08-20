package user

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

var (
	gshadowPath = "/etc/gshadow"
	subuidPath  = "/etc/subuid"
	subgidPath  = "/etc/subgid"
)

const (
	maxLocalGShadowBytes = 64 << 20
	maxLocalSubIDBytes   = 64 << 20
)

// preflightSequentialAccountCreation refuses to let useradd inherit account
// database residue from an older generation. The reserved ID is above the
// allocation high-water mark, so any same-name or same-ID group is unexpected.
func (m *Manager) preflightSequentialAccountCreation(name string, reservedID int) error {
	if m.Runner == nil || !m.Runner.Look("groupdel") {
		return fmt.Errorf("groupdel is required for sequential account creation")
	}
	present, err := m.inspectPrivateGroup(name, reservedID, false)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("same-name private group %s already exists before account creation", name)
	}
	return m.ensureSubordinateIDsAbsent(name)
}

// preflightPrivateGroupRemoval proves that the same-name, same-GID private
// group created by useradd -U still has its original empty shape. The account
// remains alive during this check, so its own primary-GID reference is allowed;
// every other reference fails closed.
func (m *Manager) preflightPrivateGroupRemoval(expected Passwd) error {
	if m.Runner == nil || !m.Runner.Look("groupdel") {
		return fmt.Errorf("groupdel is required to remove the managed private group %s", expected.Name)
	}
	if expected.UID != expected.GID {
		return fmt.Errorf("sequential account identity %s is not a UID/GID pair", expected.Name)
	}
	present, err := m.inspectPrivateGroup(expected.Name, expected.GID, true)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("managed private group %s is missing before account deletion", expected.Name)
	}
	return nil
}

// ReconcileAccountDatabaseAfterDeletion removes a proven private-group residue
// and verifies that shadow's userdel did not leave subordinate-ID assignments.
// A deletion-recovery row may authorize the group only when its SequentialID bit
// proves that the recorded UID was also the private GID.
func (m *Manager) ReconcileAccountDatabaseAfterDeletion(name string, gid int, removePrivateGroup bool) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if removePrivateGroup && !validate.AccountID(gid) {
		return fmt.Errorf("invalid expected private-group GID %d", gid)
	}
	absent, err := m.deletionState(name, nil, nil)
	if err != nil {
		return fmt.Errorf("verify account absence before account-database reconciliation: %w", err)
	}
	if !absent {
		return fmt.Errorf("account %s exists; refusing account-database reconciliation", name)
	}
	groupErr := m.reconcilePrivateGroupAfterDeletion(name, gid, removePrivateGroup)
	subIDErr := m.ensureSubordinateIDsAbsent(name)
	absent, stateErr := m.deletionState(name, nil, nil)
	if stateErr != nil {
		stateErr = fmt.Errorf("verify account absence after account-database reconciliation: %w", stateErr)
	} else if !absent {
		stateErr = fmt.Errorf("account %s reappeared during account-database reconciliation", name)
	}
	return errors.Join(groupErr, subIDErr, stateErr)
}

// VerifyAccountDatabaseAfterExternalDeletion proves that an account removed
// outside this deletion transaction left no database artifact that only its old
// registry row can identify. It never invokes groupdel: without a durable
// deletion-started witness, an exact-looking group is still not deletion
// authority and must be handled by an operator.
func (m *Manager) VerifyAccountDatabaseAfterExternalDeletion(name string, gid int, sequentialID bool) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if sequentialID && !validate.AccountID(gid) {
		return fmt.Errorf("invalid expected private-group GID %d", gid)
	}
	absent, err := m.deletionState(name, nil, nil)
	if err != nil {
		return fmt.Errorf("verify account absence before account-database inspection: %w", err)
	}
	if !absent {
		return fmt.Errorf("account %s exists; refusing absent-account database inspection", name)
	}
	var present bool
	var groupErr error
	if sequentialID {
		present, groupErr = m.inspectPrivateGroup(name, gid, false)
	} else {
		present, groupErr = m.inspectSameNameGroup(name)
	}
	if groupErr == nil && present {
		if sequentialID {
			groupErr = fmt.Errorf("managed private group %s remains after external account deletion; remove it with shadow tools, then retry", name)
		} else {
			groupErr = fmt.Errorf("same-name group %s remains after external account deletion, but the registry does not prove its GID; remove it manually, then retry", name)
		}
	}
	subIDErr := m.ensureSubordinateIDsAbsent(name)
	absent, stateErr := m.deletionState(name, nil, nil)
	if stateErr != nil {
		stateErr = fmt.Errorf("verify account absence after account-database inspection: %w", stateErr)
	} else if !absent {
		stateErr = fmt.Errorf("account %s reappeared during account-database inspection", name)
	}
	return errors.Join(groupErr, subIDErr, stateErr)
}

func (m *Manager) reconcilePrivateGroupAfterDeletion(name string, gid int, authorized bool) error {
	if !authorized {
		present, err := m.inspectSameNameGroup(name)
		if err != nil || !present {
			return err
		}
		return fmt.Errorf("same-name group %s remains after account deletion, but the recovery record does not prove its GID", name)
	}
	present, err := m.inspectPrivateGroup(name, gid, false)
	if err != nil || !present {
		return err
	}
	if m.Runner == nil || !m.Runner.Look("groupdel") {
		return fmt.Errorf("groupdel is required to remove the managed private group %s", name)
	}
	absent, err := m.deletionState(name, nil, nil)
	if err != nil {
		return fmt.Errorf("recheck account absence before groupdel: %w", err)
	}
	if !absent {
		return fmt.Errorf("account %s reappeared before groupdel", name)
	}
	present, err = m.inspectPrivateGroup(name, gid, false)
	if err != nil || !present {
		return err
	}
	runErr := m.Runner.Run("groupdel", "--", name)
	present, stateErr := m.inspectPrivateGroup(name, gid, false)
	if stateErr != nil {
		stateErr = fmt.Errorf("verify groupdel removed %s: %w", name, stateErr)
	}
	absent, absenceErr := m.deletionState(name, nil, nil)
	if absenceErr != nil {
		absenceErr = fmt.Errorf("verify account absence after groupdel: %w", absenceErr)
	} else if !absent {
		absenceErr = fmt.Errorf("account %s reappeared during groupdel", name)
	}
	if stateErr != nil || absenceErr != nil {
		return errors.Join(runErr, stateErr, absenceErr)
	}
	if present {
		if runErr != nil {
			return runErr
		}
		return fmt.Errorf("groupdel reported success but private group %s still exists", name)
	}
	if runErr != nil {
		return fmt.Errorf("groupdel removed the private group but reported incomplete cleanup: %w", runErr)
	}
	return absenceErr
}

func (m *Manager) inspectPrivateGroup(name string, expectedGID int, allowPrimaryUser bool) (bool, error) {
	if m.InspectPrivateGroupState != nil {
		return m.InspectPrivateGroupState(name, expectedGID, allowPrimaryUser)
	}
	return inspectPrivateGroup(name, expectedGID, allowPrimaryUser)
}

func (m *Manager) inspectSameNameGroup(name string) (bool, error) {
	if m.InspectSameNameGroupState != nil {
		return m.InspectSameNameGroupState(name)
	}
	return inspectSameNameGroup(name)
}

func (m *Manager) ensureSubordinateIDsAbsent(name string) error {
	if m.CheckSubordinateIDsAbsent != nil {
		return m.CheckSubordinateIDsAbsent(name)
	}
	return ensureSubordinateIDsAbsent(name)
}

// inspectPrivateGroup accepts only the shape created by useradd -U: one local
// group with the expected name/GID, disabled group and gshadow passwords, no
// explicit members or administrators, and no other local account or group
// sharing its primary GID.
func inspectPrivateGroup(name string, expectedGID int, allowPrimaryUser bool) (bool, error) {
	groups, err := readPasswdDatabase(groupPath, maxLocalGroupBytes)
	if err != nil {
		return false, fmt.Errorf("read group database: %w", err)
	}
	seenNames := make(map[string]bool)
	found := false
	for lineNumber, line := range strings.Split(string(groups), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 || parts[0] == "" {
			return false, fmt.Errorf("malformed group entry at line %d", lineNumber+1)
		}
		if seenNames[parts[0]] {
			return false, fmt.Errorf("duplicate group entries for %s", parts[0])
		}
		seenNames[parts[0]] = true
		gid, parseErr := strconv.Atoi(parts[2])
		if parseErr != nil || !validate.KernelID(gid) {
			return false, fmt.Errorf("malformed group GID at line %d", lineNumber+1)
		}
		if gid == expectedGID && parts[0] != name {
			return false, fmt.Errorf("group %s also uses expected private GID %d", parts[0], expectedGID)
		}
		if parts[0] != name {
			continue
		}
		if gid != expectedGID {
			return false, fmt.Errorf("same-name group %s has GID %d, want %d", name, gid, expectedGID)
		}
		password := parts[1]
		if password != "x" && password != "*" && !strings.HasPrefix(password, "!") {
			return false, fmt.Errorf("managed private group %s has a /etc/group password field that is not explicitly locked", name)
		}
		if parts[3] != "" {
			return false, fmt.Errorf("managed private group %s has explicit members", name)
		}
		found = true
	}

	gshadowFound, gshadowExists, err := inspectPrivateGShadow(name)
	if err != nil {
		return false, err
	}
	if !found && gshadowFound {
		return false, fmt.Errorf("orphaned gshadow entry remains for group %s", name)
	}
	if found && gshadowExists && !gshadowFound {
		return false, fmt.Errorf("group %s has no matching gshadow entry", name)
	}
	if !found {
		return false, nil
	}

	passwd, err := readPasswdDatabase(passwdPath, maxLocalPasswdBytes)
	if err != nil {
		return false, fmt.Errorf("read passwd database for private-group removal: %w", err)
	}
	seenUsers := make(map[string]bool)
	for lineNumber, line := range strings.Split(string(passwd), "\n") {
		if line == "" {
			continue
		}
		pw, parseErr := parsePasswdEntry(line)
		if parseErr != nil {
			return false, fmt.Errorf("scan passwd primary groups at line %d: %w", lineNumber+1, parseErr)
		}
		if seenUsers[pw.Name] {
			return false, fmt.Errorf("duplicate passwd entries for %s", pw.Name)
		}
		seenUsers[pw.Name] = true
		if pw.GID == expectedGID && (!allowPrimaryUser || pw.Name != name) {
			return false, fmt.Errorf("account %s still uses managed private GID %d as its primary group", pw.Name, expectedGID)
		}
	}
	return true, nil
}

// inspectSameNameGroup is the non-authorizing counterpart used for old records.
// It proves only absence; a present group is never mutated without SequentialID.
func inspectSameNameGroup(name string) (bool, error) {
	groups, err := readPasswdDatabase(groupPath, maxLocalGroupBytes)
	if err != nil {
		return false, fmt.Errorf("read group database: %w", err)
	}
	seen := make(map[string]bool)
	found := false
	for lineNumber, line := range strings.Split(string(groups), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 || parts[0] == "" {
			return false, fmt.Errorf("malformed group entry at line %d", lineNumber+1)
		}
		if seen[parts[0]] {
			return false, fmt.Errorf("duplicate group entries for %s", parts[0])
		}
		seen[parts[0]] = true
		gid, parseErr := strconv.Atoi(parts[2])
		if parseErr != nil || !validate.KernelID(gid) {
			return false, fmt.Errorf("malformed group GID at line %d", lineNumber+1)
		}
		if parts[0] == name {
			found = true
		}
	}
	gshadowFound, gshadowExists, err := inspectPrivateGShadow(name)
	if err != nil {
		return false, err
	}
	if !found && gshadowFound {
		return false, fmt.Errorf("orphaned gshadow entry remains for group %s", name)
	}
	if found && gshadowExists && !gshadowFound {
		return false, fmt.Errorf("group %s has no matching gshadow entry", name)
	}
	return found, nil
}

func inspectPrivateGShadow(name string) (found, exists bool, err error) {
	data, err := readPasswdDatabase(gshadowPath, maxLocalGShadowBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read gshadow database: %w", err)
	}
	seen := make(map[string]bool)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 || parts[0] == "" {
			return false, true, fmt.Errorf("malformed gshadow entry at line %d", lineNumber+1)
		}
		if seen[parts[0]] {
			return false, true, fmt.Errorf("duplicate gshadow entries for %s", parts[0])
		}
		seen[parts[0]] = true
		if parts[0] != name {
			continue
		}
		password := parts[1]
		if password != "" && password != "*" && !strings.HasPrefix(password, "!") {
			return false, true, fmt.Errorf("managed private group %s has an enabled gshadow password", name)
		}
		if parts[2] != "" || parts[3] != "" {
			return false, true, fmt.Errorf("managed private group %s has gshadow administrators or members", name)
		}
		found = true
	}
	return found, true, nil
}

func ensureSubordinateIDsAbsent(name string) error {
	var errs []error
	for _, database := range []struct {
		label string
		path  string
	}{
		{label: "subuid", path: subuidPath},
		{label: "subgid", path: subgidPath},
	} {
		data, err := readPasswdDatabase(database.path, maxLocalSubIDBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s database: %w", database.label, err))
			continue
		}
		for lineNumber, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) != 3 || parts[0] == "" {
				errs = append(errs, fmt.Errorf("malformed %s entry at line %d", database.label, lineNumber+1))
				break
			}
			start, startErr := strconv.ParseUint(parts[1], 10, 32)
			count, countErr := strconv.ParseUint(parts[2], 10, 32)
			if startErr != nil || countErr != nil || count == 0 || start+count-1 > 1<<32-1 {
				errs = append(errs, fmt.Errorf("malformed %s range at line %d", database.label, lineNumber+1))
				break
			}
			if parts[0] == name {
				errs = append(errs, fmt.Errorf("%s assignment remains for deleted account %s", database.label, name))
				break
			}
		}
	}
	return errors.Join(errs...)
}
