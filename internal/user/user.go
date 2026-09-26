// Package user manages the lifecycle of temporary local accounts: creating,
// locking, expiring, and deleting them, plus the protection checks that keep the
// tool from ever touching a system or real account. Account mutations shell out
// to the distro's shadow tools (useradd/usermod/chage/userdel) via an injectable
// runner, so argv is unit-testable; passwd
// lookups and process termination are done natively (no getent/pkill).
package user

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
)

var (
	// ErrAccountCreationNotStarted marks failures that happened before useradd was
	// invoked. A transaction may release its creation-intent witness for this
	// class after independently confirming that the account name is still absent.
	ErrAccountCreationNotStarted = errors.New("account creation was not started")
	nssCommandOptions            = executil.Options{
		Timeout:   10 * time.Second,
		MaxOutput: 256 << 10,
		ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
	}
	accountCommandOptions = executil.Options{
		Timeout:   2 * time.Minute,
		MaxOutput: 1 << 20,
		ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
	}
)

// Runner executes account-management commands; injectable for tests.
type Runner interface {
	Run(name string, args ...string) error
	// RunInput is Run with data on the command's stdin. It exists so a secret
	// (a password) is handed to chpasswd through a pipe and never as an argv
	// element, which every process on the host can read out of /proc.
	RunInput(stdin string, name string, args ...string) error
	Look(name string) bool
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) error {
	out, err := executil.CombinedOutput(name, args, accountCommandOptions)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execRunner) RunInput(stdin string, name string, args ...string) error {
	opts := accountCommandOptions
	opts.Stdin = strings.NewReader(stdin)
	err := executil.Run(name, args, opts)
	if err != nil {
		// A malicious or broken helper can echo stdin to either output stream. Do
		// not include any child output in this error: stdin holds the password.
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func (execRunner) Look(name string) bool { _, err := exec.LookPath(name); return err == nil }

// Manager performs account mutations via its Runner.
type Manager struct {
	Runner                    Runner
	LookupUser                func(string) (Passwd, bool, error)
	NameInUse                 func(string) (bool, error)
	InspectPrivateGroupState  func(string, int, bool) (bool, error)
	InspectSameNameGroupState func(string) (bool, error)
	CheckSubordinateIDsAbsent func(string, int) error
	ValidateManagedMailRoots  func() error
	PrepareManagedHome        func(string) error
	CreateManagedHome         func(Passwd) error
	ValidateManagedHome       func(Passwd) error
	RemoveManagedMail         func(Passwd) error
	RemoveManagedHome         func(Passwd) error
}

// New returns a Manager using real command execution.
func New() *Manager {
	return &Manager{
		Runner:                   execRunner{},
		LookupUser:               Lookup,
		NameInUse:                NameInUse,
		ValidateManagedMailRoots: validateManagedMailRoots,
		PrepareManagedHome:       prepareManagedHome,
		CreateManagedHome:        createManagedHome,
		ValidateManagedHome:      validateCreatedHome,
		RemoveManagedMail:        removeManagedMail,
		RemoveManagedHome:        removeManagedHome,
	}
}

// keyOnlyPasswordHash is deliberately not a valid crypt(3) result. Traditional
// DES crypt output is exactly 13 bytes, while modern Linux schemes start with
// '$' (or '_' for BSD extended DES). No password can reproduce this longer,
// unmarked value. Unlike a shadow value beginning with '!' or '*', it also does
// not make OpenSSH on Alpine reject the entire account before public-key auth.
const keyOnlyPasswordHash = "linux-temp-admin-key-only-password-disabled"

// DisablePasswordForKeyLogin makes password authentication impossible without
// marking the whole account locked. This distinction is required on OpenSSH
// builds that reject a shadow-locked account even when its authorized key is
// valid (notably Alpine's default configuration).
func (m *Manager) DisablePasswordForKeyLogin(name string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("usermod", "-p", keyOnlyPasswordHash, name)
}

// LockPassword locks name during revocation. Revoke also expires the account,
// so rejecting every authentication method is intentional here.
func (m *Manager) LockPassword(name string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("usermod", "-L", name)
}

// SetPassword sets name's login password, for the --password-login invite on a
// host whose sshd will not take a key. The password goes to chpasswd on stdin,
// never in argv, so it cannot be read out of the process table.
func (m *Manager) SetPassword(name string, password []byte) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if !m.Runner.Look("chpasswd") {
		return fmt.Errorf("chpasswd not available")
	}
	if bytes.ContainsAny(password, ":\n") {
		// chpasswd's line format is user:password — a colon or newline would split
		// the record and set a different password than the one we printed.
		return fmt.Errorf("refusing a password containing ':' or a newline")
	}
	// Build the chpasswd line in a buffer this function owns and clear it before
	// returning. RunInput still takes a string, so one copy remains beyond reach;
	// zeroing what can be zeroed is the difference between one unclearable copy
	// and four.
	line := make([]byte, 0, len(name)+len(password)+2)
	line = append(line, name...)
	line = append(line, ':')
	line = append(line, password...)
	line = append(line, '\n')
	defer clear(line)
	return m.Runner.RunInput(string(line), "chpasswd")
}

// SetExpiry sets the account expiry date (YYYY-MM-DD) via chage.
func (m *Manager) SetExpiry(name, date string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("chage", "-E", date, name)
}

// ClearExpiry restores a permanent account after the credential-less safety
// drain temporarily expired it. chage documents -1 as "never expires"; using a
// dedicated method keeps that sentinel out of ordinary date-setting call sites.
func (m *Manager) ClearExpiry(name string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("chage", "-E", "-1", name)
}

// expiredDate is a date safely in the past; chage -E it to make an account
// expired as of now.
//
// It must not be the epoch itself. chage stores this field as days since
// 1970-01-01, so -E 1970-01-01 writes a literal 0, and shadow(5) says of that
// value: "The value 0 should not be used as it is interpreted as either an
// account with no expiration, or as an expiration on Jan 1, 1970." shadow's own
// isexpired() takes the first reading — it requires sp_expire > 0 before it will
// call an account expired — so the epoch would leave the account unexpired on
// the very path DisableLogin relies on. That gate is the one that stops a
// public-key login; the password lock does not. One day past the epoch is still
// unambiguously in the past and encodes as 1.
//
// Passing a literal "0" as the argument would be wrong for a second, unrelated
// reason: chage's numeric form is days-since-epoch and reads ambiguously next to
// -E -1 ("never"). Avoiding that is what the previous value was reaching for; it
// simply moved the same ambiguity one layer down, into the stored field.
const expiredDate = "1970-01-02"

// initialLockedPasswordHash is passed to useradd as an encrypted hash. It is not
// a valid crypt(3) result, and the leading '!' has the conventional shadow meaning
// of a locked password. Account expiry remains the authentication-method-neutral
// gate; this value independently closes password authentication at creation.
const initialLockedPasswordHash = "!"

// DisableLogin shuts the account's door before revoke starts taking it apart:
// it expires the account (chage), which sshd and PAM both refuse regardless of
// how the invitee authenticates, and locks the password for good measure.
//
// This must happen BEFORE processes are killed and the account is deleted.
// Without it the account stays reachable throughout the revoke, so an invitee
// reconnecting in a loop can land a session in the window between the kill and
// the delete — which used to be enough to make userdel fail and leave the
// account alive. Expiry is the effective gate for a key-based account: locking
// the password alone would not stop a public-key login.
//
// Both steps are attempted and their errors are returned. Destructive callers
// must stop before process termination or deletion unless both doors were shut.
//
// Both steps are ATTEMPTED even if the first fails. They guard different auth
// vectors — expiry stops a key login, the lock stops a password login — so
// returning on the expiry error would skip the password lock, dropping a
// mitigation that might still have succeeded (chage missing does not imply
// usermod missing). The errors are joined so the caller sees every door that
// could not be shut, not just the first.
func (m *Manager) DisableLogin(name string) error {
	return errors.Join(m.SetExpiry(name, expiredDate), m.LockPassword(name))
}
