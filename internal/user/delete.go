package user

import (
	"errors"
	"fmt"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// DeleteExpected removes name only while its stable passwd identity still
// matches expected. A protected trailing witness permits user-changeable
// GECOS/shell fields to move; old identities retain byte-for-byte comparison.
// The caller has already disabled login and reached an initial
// cron/at/process fixed point. beforeDelete is mandatory and runs after controlled
// Home/mail cleanup, so the caller can repeat its scheduled-work and process checks
// while the UID is still bound. The manager then revalidates that binding and
// repeats owner-checked Home cleanup before the name-scoped account helper. System
// helpers are invoked without recursive Home/mail options. In particular, userdel
// must not receive -f: on shadow-utils that flag
// may delete the same-name group even while another account still uses it as a
// primary group. Distro deluser and arbitrary BusyBox builds are not fallbacks:
// their configuration and compiled account-database semantics cannot be proven
// equivalent to shadow-utils userdel.
func (m *Manager) DeleteExpected(name string, expected Passwd, beforeDelete func() error) error {
	return m.deleteExpected(name, expected, beforeDelete, SameAccountIdentity, false)
}

// DeleteExpectedSequential is DeleteExpected plus cleanup of the private group
// proven by a durable SequentialID registry witness.
func (m *Manager) DeleteExpectedSequential(name string, expected Passwd, beforeDelete func() error) error {
	return m.deleteExpected(name, expected, beforeDelete, SameAccountIdentity, true)
}

// DeleteExpectedExact is the pre-activation rollback counterpart of
// DeleteExpected. It requires the complete passwd snapshot to remain unchanged,
// even for a current trailing-witness identity that cannot yet be used by the
// invitee. Once login activation has been attempted, callers must use
// DeleteExpected because the helper may have taken effect before reporting an
// error and a live invitee must not be able to hold rollback open with chfn/chsh.
func (m *Manager) DeleteExpectedExact(name string, expected Passwd, beforeDelete func() error) error {
	return m.deleteExpected(name, expected, beforeDelete, func(expected, current Passwd) bool {
		return expected == current
	}, false)
}

// DeleteExpectedExactSequential is the pre-activation counterpart that also
// carries the durable SequentialID authority for private-group cleanup.
func (m *Manager) DeleteExpectedExactSequential(name string, expected Passwd, beforeDelete func() error) error {
	return m.deleteExpected(name, expected, beforeDelete, func(expected, current Passwd) bool {
		return expected == current
	}, true)
}

func (m *Manager) deleteExpected(name string, expected Passwd, beforeDelete func() error, identityMatches func(Passwd, Passwd) bool, removePrivateGroup bool) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) || !isManagedHome(name, expected.Home) {
		return fmt.Errorf("invalid expected account identity for %q", name)
	}
	if beforeDelete == nil {
		return fmt.Errorf("final account quiescence check is not configured")
	}
	if removePrivateGroup && expected.UID != expected.GID {
		return fmt.Errorf("invalid sequential account identity for %q", name)
	}
	return m.delete(name, &expected, beforeDelete, identityMatches, removePrivateGroup)
}

func (m *Manager) delete(name string, expected *Passwd, beforeDelete func() error, identityMatches func(Passwd, Passwd) bool, removePrivateGroup bool) error {
	absent, err := m.deletionState(name, expected, identityMatches)
	if err != nil {
		return fmt.Errorf("verify account identity before deletion: %w", err)
	}
	if absent {
		// Once passwd no longer binds the name and UID, the captured snapshot cannot
		// authorize recursive Home removal: Linux may already have reused the UID and
		// a replacement could have populated the deterministic path. Mail cleanup is
		// narrower and independently owner-checked, so it remains recoverable. Sweep
		// twice around an absence recheck to catch an in-flight delivery without ever
		// touching Home, jobs, processes, or an account helper.
		for sweep := 1; sweep <= 2; sweep++ {
			if err := m.removeManagedMail(*expected); err != nil {
				return err
			}
			absent, err = m.deletionState(name, expected, identityMatches)
			if err != nil {
				return fmt.Errorf("verify account remained absent after artifact cleanup sweep %d: %w", sweep, err)
			}
			if !absent {
				return fmt.Errorf("account %s reappeared during artifact cleanup sweep %d", name, sweep)
			}
		}
		return m.ReconcileAccountDatabaseAfterDeletion(name, expected.UID, expected.GID, removePrivateGroup)
	}
	if !m.Runner.Look("userdel") {
		return fmt.Errorf("userdel not available")
	}
	if removePrivateGroup {
		if err := m.preflightPrivateGroupRemoval(*expected); err != nil {
			return fmt.Errorf("validate managed private group before account deletion: %w", err)
		}
	}
	// Keep the account and registry witness if artifact cleanup cannot be proved
	// safe. Once a helper removes the passwd entry, a later retry no longer has the
	// complete snapshot needed to validate an orphaned mail spool or home.
	if err := m.removeManagedMail(*expected); err != nil {
		return err
	}
	if err := m.removeManagedHome(*expected); err != nil {
		return err
	}
	if err := beforeDelete(); err != nil {
		return fmt.Errorf("final account quiescence check before userdel: %w", err)
	}
	// The final process/job pass can race with a service that recreates Home after
	// the first sweep. Recheck the passwd binding before authorizing another
	// recursive owner-checked cleanup; after userdel, UID reuse makes that unsafe.
	absentAfterQuiescence, err := m.deletionState(name, expected, identityMatches)
	if err != nil {
		return fmt.Errorf("verify account after final quiescence: %w", err)
	}
	if !absentAfterQuiescence {
		if err := m.removeManagedHome(*expected); err != nil {
			return fmt.Errorf("final managed Home cleanup after account quiescence: %w", err)
		}
	}
	absent, err = m.deletionState(name, expected, identityMatches)
	if err != nil {
		return fmt.Errorf("verify account before userdel: %w", err)
	}
	if absent {
		if err := m.removeManagedMail(*expected); err != nil {
			return fmt.Errorf("final managed mail cleanup after account disappearance: %w", err)
		}
		absent, err = m.deletionState(name, expected, identityMatches)
		if err != nil {
			return fmt.Errorf("verify account remained absent after account disappearance: %w", err)
		}
		if !absent {
			return fmt.Errorf("account %s reappeared during final managed mail cleanup", name)
		}
		return m.ReconcileAccountDatabaseAfterDeletion(name, expected.UID, expected.GID, removePrivateGroup)
	}
	if removePrivateGroup {
		// The artifact cleanup and final job drain above can be long. Repeat the
		// complete group proof immediately before userdel, whose distro policy may
		// otherwise remove a same-name group implicitly.
		if err := m.preflightPrivateGroupRemoval(*expected); err != nil {
			return fmt.Errorf("revalidate managed private group before userdel: %w", err)
		}
	}
	runErr := m.Runner.Run("userdel", "--", name)
	absent, stateErr := m.deletionState(name, expected, identityMatches)
	if stateErr != nil {
		return errors.Join(runErr, fmt.Errorf("verify userdel removed %s: %w", name, stateErr))
	}
	if absent {
		// Mail can be recreated while the account still exists and controlled Home
		// cleanup is in progress. Once the helper has made the account absent, sweep
		// one final time before reporting success or releasing the registry witness.
		mailErr := m.removeManagedMail(*expected)
		stillAbsent, finalStateErr := m.deletionState(name, expected, identityMatches)
		if finalStateErr == nil && !stillAbsent {
			finalStateErr = fmt.Errorf("account %s reappeared during final managed mail cleanup", name)
		}
		accountDBErr := m.ReconcileAccountDatabaseAfterDeletion(name, expected.UID, expected.GID, removePrivateGroup)
		if runErr != nil {
			return errors.Join(
				fmt.Errorf("userdel removed the account but reported incomplete cleanup: %w", runErr),
				mailErr,
				finalStateErr,
				accountDBErr)
		}
		if finalErr := errors.Join(mailErr, finalStateErr, accountDBErr); finalErr != nil {
			return fmt.Errorf("final cleanup after userdel: %w", finalErr)
		}
		return nil
	}
	if runErr != nil {
		runErr = fmt.Errorf("userdel: %w", runErr)
	} else {
		runErr = fmt.Errorf("userdel reported success but account %s still exists", name)
	}
	return errors.Join(runErr, fmt.Errorf("account %s still exists after userdel", name))
}

func (m *Manager) deletionState(name string, expected *Passwd, identityMatches func(Passwd, Passwd) bool) (absent bool, err error) {
	current, exists, err := m.lookup(name)
	if err != nil {
		return false, err
	}
	if !exists {
		nameInUse := m.NameInUse
		if nameInUse == nil {
			nameInUse = NameInUse
		}
		inUse, err := nameInUse(name)
		if err != nil {
			return false, fmt.Errorf("confirm account absence through NSS: %w", err)
		}
		if inUse {
			return false, fmt.Errorf("account name %s remains present through NSS after local account disappearance", name)
		}
		return true, nil
	}
	if expected != nil && (identityMatches == nil || !identityMatches(*expected, current)) {
		return false, fmt.Errorf("account identity changed during deletion; refusing a name-scoped fallback")
	}
	return false, nil
}
