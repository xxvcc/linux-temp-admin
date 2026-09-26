package user

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// CreatePendingIdentityWithID creates the pending account with an explicitly
// reserved UID/GID pair. -U makes the private group deterministic; the complete
// passwd snapshot is rejected unless both numeric identities equal reservedID.
// Home remains absent until the caller drains inherited work and calls
// CreateManagedHomeExpected with the returned identity.
func (m *Manager) CreatePendingIdentityWithID(name, shell, generation string, reservedID int) (Passwd, error) {
	if !validate.AccountID(reservedID) {
		return Passwd{}, fmt.Errorf("%w: invalid reserved UID/GID %d", ErrAccountCreationNotStarted, reservedID)
	}
	gecos, err := pendingGECOSForGeneration(generation)
	if err != nil {
		return Passwd{}, fmt.Errorf("%w: %w", ErrAccountCreationNotStarted, err)
	}
	if err := validateMutationName(name); err != nil {
		return Passwd{}, fmt.Errorf("%w: %w", ErrAccountCreationNotStarted, err)
	}
	if err := m.preflightSequentialAccountCreation(name, reservedID); err != nil {
		return Passwd{}, fmt.Errorf("%w: validate account databases before account creation: %w", ErrAccountCreationNotStarted, err)
	}
	validateMailRoots := m.ValidateManagedMailRoots
	if validateMailRoots == nil {
		validateMailRoots = validateManagedMailRoots
	}
	// Mail-root metadata does not depend on the UID selected by useradd. Reject a
	// persistently unsafe layout before creating a pending account, then repeat the
	// same validation while doing the UID-bound cleanup below to close path races.
	if err := validateMailRoots(); err != nil {
		return Passwd{}, fmt.Errorf("%w: validate managed mail roots before account creation: %w", ErrAccountCreationNotStarted, err)
	}
	home := managedHome(name)
	prepare := m.PrepareManagedHome
	if prepare == nil {
		prepare = prepareManagedHome
	}
	if err := prepare(name); err != nil {
		return Passwd{}, fmt.Errorf("%w: prepare managed home: %w", ErrAccountCreationNotStarted, err)
	}
	if !m.Runner.Look("useradd") {
		return Passwd{}, fmt.Errorf("%w: useradd not available", ErrAccountCreationNotStarted)
	}
	// Create only the account database entry here. The expired date and locked
	// hash are part of the same useradd transaction, so the pending name never
	// depends on a later chage/usermod call for its initial login gate. -M also
	// prevents /etc/skel (including any locally provisioned SSH credential) from
	// being copied before the selected UID has been proved idle.
	// Pin the private-group allocator to the same already-reserved number:
	// login.defs gaps or concurrent administration can otherwise make -U's
	// usual UID==GID choice unreliable. The post-create check remains authoritative.
	id := strconv.Itoa(reservedID)
	args := []string{"-M", "-d", home, "-s", shell, "-c", gecos,
		"-e", expiredDate, "-p", initialLockedPasswordHash,
		"-U", "-u", id, "-K", "GID_MIN=" + id, "-K", "GID_MAX=" + id, name}
	err = m.Runner.Run("useradd", args...)
	if err != nil {
		pw, exists, lookupErr := m.lookup(name)
		if lookupErr != nil {
			return Passwd{}, errors.Join(err, fmt.Errorf("inspect account after failed useradd: %w", lookupErr))
		}
		if !exists {
			// The helper ran and may have committed a private group or subordinate-ID
			// assignment before failing. The caller's durable SequentialID intent must
			// remain available for absent-account reconciliation.
			return Passwd{}, fmt.Errorf("useradd failed after account creation started, but no passwd entry exists: %w", err)
		}
		return pw, fmt.Errorf("useradd reported failure after creating an account: %w", err)
	}

	// Even a reserved UID may be held by a process left behind after an
	// out-of-band deletion. Check all four Linux credential UIDs before creating a
	// UID-owned Home or allowing the caller to use the account. If the check is inconclusive or finds a residual process, retain
	// the expired, password-locked pending account without a Home: deleting it would
	// free the reused UID while that process still carries it.
	pw, ok, lookupErr := m.lookup(name)
	if lookupErr != nil {
		return Passwd{}, errors.Join(
			fmt.Errorf("look up newly created account: %w", lookupErr),
			fmt.Errorf("newly created account %s was retained without a verified identity", name),
		)
	}
	if !ok {
		return Passwd{}, fmt.Errorf("newly created account %s is absent from the local account database", name)
	}
	if !validate.AccountID(pw.UID) || !validate.AccountID(pw.GID) {
		return Passwd{}, errors.Join(
			fmt.Errorf("newly created account %s has no safe local UID/GID", name),
			fmt.Errorf("account was retained for manual recovery because identity %d:%d is unsafe", pw.UID, pw.GID),
		)
	}
	if pw.UID != reservedID || pw.GID != reservedID {
		return pw, fmt.Errorf("newly created account received identity %d:%d, want reserved %d:%d; account retained for rollback or manual recovery",
			pw.UID, pw.GID, reservedID, reservedID)
	}
	if pw.Name != name || pw.Home != home || pw.Shell != shell || pw.GECOS != gecos {
		// Return the snapshot that was actually read, exactly as the reserved-identity
		// mismatch above does. It is the last complete identity this call proved, and
		// discarding it left the caller with a zero Passwd whose first rollback check
		// fails, so a benign distro quirk in one field turned into an account that
		// could only ever be recovered by hand. The rollback path re-verifies the
		// generation marker and every name-scoped grant before it may delete anything.
		return pw, fmt.Errorf("newly created account identity does not match the requested name, home, shell, and marker; account retained for rollback or manual recovery")
	}
	pids, scanErr := processesForUID(pw.UID)
	if scanErr != nil {
		return Passwd{}, fmt.Errorf("scan processes before using UID %d: %w; account retained to keep the UID occupied", pw.UID, scanErr)
	}
	if len(pids) != 0 {
		return Passwd{}, fmt.Errorf("refusing reused UID %d: residual processes %v already carry it; account retained to keep the UID occupied", pw.UID, pids)
	}
	// A previous account generation can leave a same-name mail spool behind even
	// when its Home is gone. The newly selected UID may be the same, so clear that
	// artifact while this identity is still expired, password-locked, and has no
	// credential. A different owner or special file fails closed and retains the
	// pending account to keep the name and UID occupied.
	if err := m.ClearManagedMailExpected(name, pw); err != nil {
		return pw, fmt.Errorf("clear mail spool before using account identity: %w; account retained for rollback or manual recovery", err)
	}
	return pw, nil
}

// CreateManagedHomeExpected creates and validates an empty Home only while the
// complete passwd identity captured at useradd still exists unchanged. Invite
// calls this after draining inherited deferred work, so an old account generation
// has no writable Home during that drain.
func (m *Manager) CreateManagedHomeExpected(name string, expected Passwd) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) ||
		!validate.AccountID(expected.GID) || expected.Home != managedHome(name) ||
		expected.Shell == "" ||
		(!hasManagedGenerationMarker(expected) && !hasPendingGenerationMarker(expected)) {
		return fmt.Errorf("invalid expected account identity for managed Home creation")
	}
	if err := m.verifyExpectedIdentity(name, expected, "before managed Home creation"); err != nil {
		return err
	}
	createHome := m.CreateManagedHome
	if createHome == nil {
		createHome = createManagedHome
	}
	createErr := createHome(expected)
	identityErr := m.verifyExpectedIdentity(name, expected, "during managed Home creation")
	if createErr != nil || identityErr != nil {
		if createErr != nil {
			createErr = fmt.Errorf("create empty managed account Home: %w", createErr)
		}
		return errors.Join(createErr, identityErr)
	}
	inspect := m.ValidateManagedHome
	if inspect == nil {
		inspect = validateCreatedHome
	}
	inspectErr := inspect(expected)
	identityErr = m.verifyExpectedIdentity(name, expected, "during managed Home validation")
	if inspectErr != nil || identityErr != nil {
		if inspectErr != nil {
			inspectErr = fmt.Errorf("validate newly created account Home: %w", inspectErr)
		}
		return errors.Join(inspectErr, identityErr)
	}
	return nil
}

// MarkManaged changes a pending account to the exact managed marker only after
// its numeric UID has been durably recorded. usermod is a required dependency
// for both invite and fail-closed revoke, so there is no weaker fallback here.
func (m *Manager) MarkManaged(name, generation string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	gecos, err := ManagedGECOSForGeneration(generation)
	if err != nil {
		return err
	}
	if !m.Runner.Look("usermod") {
		return fmt.Errorf("usermod not available")
	}
	return m.Runner.Run("usermod", "-c", gecos, name)
}

// MarkManagedExpected changes only the pending identity captured at creation and
// verifies the complete passwd entry afterward. The underlying usermod remains a
// name-scoped system helper, so these checks detect and contain replacement; they
// cannot make the helper itself an atomic compare-and-swap.
func (m *Manager) MarkManagedExpected(name, generation string, expected Passwd) (Passwd, error) {
	pending, err := pendingGECOSForGeneration(generation)
	if err != nil {
		return Passwd{}, err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) || expected.Home != managedHome(name) || expected.Shell == "" || expected.GECOS != pending {
		return Passwd{}, fmt.Errorf("invalid pending account identity for %q", name)
	}
	if err := m.verifyExpectedIdentity(name, expected, "before marking it managed"); err != nil {
		return Passwd{}, fmt.Errorf("verify pending account before marking managed: %w", err)
	}
	if err := m.MarkManaged(name, generation); err != nil {
		return Passwd{}, err
	}
	current, exists, err := m.lookup(name)
	if err != nil {
		return Passwd{}, fmt.Errorf("verify managed account marker: %w", err)
	}
	want := expected
	want.GECOS, err = ManagedGECOSForGeneration(generation)
	if err != nil {
		return Passwd{}, err
	}
	if !exists || current != want {
		return Passwd{}, fmt.Errorf("account identity changed while marking it managed")
	}
	return current, nil
}
