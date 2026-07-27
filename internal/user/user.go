// Package user manages the lifecycle of temporary local accounts: creating,
// locking, expiring, and deleting them, plus the protection checks that keep the
// tool from ever touching a system or real account. Account mutations shell out
// to the distro's user tools (useradd/usermod/chage/userdel or the BusyBox
// adduser/deluser) via an injectable runner, so argv is unit-testable; passwd
// lookups and process termination are done natively (no getent/pkill).
package user

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

// passwdPath is the account database; overridable in tests.
var passwdPath = "/etc/passwd"

const maxLocalPasswdBytes = 64 << 20

var (
	nssCommandOptions = executil.Options{
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

// Passwd is one /etc/passwd entry.
type Passwd struct {
	Name  string
	UID   int
	GID   int
	GECOS string
	Home  string
	Shell string
}

// Lookup returns the passwd entry for name (local accounts only; no NSS).
// A caller must distinguish a confirmed absence from an unreadable or malformed
// account database; destructive lifecycle operations fail closed on err.
func Lookup(name string) (Passwd, bool, error) {
	// Read the complete bounded file, not a bufio.Scanner: a scanner ignores a
	// mid-file read error and stops early, which would make an account later in the
	// file look absent. Lookup backs destructive existence checks, so partial or
	// oversized input must fail closed rather than masquerade as EOF.
	data, err := readPasswdDatabase(passwdPath, maxLocalPasswdBytes)
	if err != nil {
		return Passwd{}, false, fmt.Errorf("read passwd database: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 7 || parts[0] != name {
			continue
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil || !validate.KernelID(uid) || !validate.KernelID(gid) {
			return Passwd{}, false, fmt.Errorf("malformed passwd entry for %s", name)
		}
		return Passwd{Name: parts[0], UID: uid, GID: gid, GECOS: parts[4], Home: parts[5], Shell: parts[6]}, true, nil
	}
	return Passwd{}, false, nil
}

func readPasswdDatabase(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	return b, nil
}

// Exists reports whether name is a local account.
func Exists(name string) (bool, error) {
	_, ok, err := Lookup(name)
	return ok, err
}

// NameInUse reports whether either the local passwd database or the host's NSS
// resolver knows name. Account ownership still comes only from /etc/passwd, but
// invite must not create a local account that shadows an LDAP/SSSD identity.
func NameInUse(name string) (bool, error) {
	if !validate.Username(name) {
		return false, fmt.Errorf("refusing NSS query for invalid username %q", name)
	}
	local, err := Exists(name)
	if err != nil || local {
		return local, err
	}
	out, err := executil.CombinedOutput("id", []string{"-u", "--", name}, nssCommandOptions)
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && idReportsUnknownUser(name, out) {
		return false, nil
	}
	diagnostic := strings.TrimSpace(string(out))
	if diagnostic == "" {
		return false, fmt.Errorf("query NSS identity %s: %w", name, err)
	}
	return false, fmt.Errorf("query NSS identity %s: %w: %s", name, err, diagnostic)
}

// idReportsUnknownUser recognizes only the C-locale diagnostics emitted for a
// confirmed miss by the implementations on supported systems: GNU coreutils on
// glibc, GNU coreutils on Alpine/musl (which appends EINVAL), and BusyBox on
// Alpine. Other nonzero exits may be an NSS/LDAP/SSSD failure and must not
// authorize creation of a shadowing account.
func idReportsUnknownUser(name string, out []byte) bool {
	diagnostic := strings.TrimSpace(string(out))
	return diagnostic == fmt.Sprintf("id: '%s': no such user", name) ||
		diagnostic == fmt.Sprintf("id: '%s': no such user: Invalid argument", name) ||
		diagnostic == "id: unknown user "+name
}

// Groups returns pw's group names: its primary group, plus every group that
// lists it as a member. This is exactly the set sshd evaluates AllowGroups and
// DenyGroups against, so an invite can tell whether a whitelist would admit the
// account it is about to create.
func Groups(pw Passwd) ([]string, error) {
	// Use the system identity resolver rather than parsing /etc/group: sshd also
	// consults NSS, so LDAP/SSSD memberships must participate in DenyGroups.
	out, err := executil.Output("id", []string{"-Gn", pw.Name}, nssCommandOptions)
	if err != nil {
		return nil, fmt.Errorf("resolve groups for %s: %w", pw.Name, err)
	}
	groups := strings.Fields(string(out))
	if len(groups) == 0 {
		return nil, fmt.Errorf("identity resolver returned no groups for %s", pw.Name)
	}
	return groups, nil
}

// IsManaged reports whether name's GECOS carries a syntactically exact legacy or
// generation-bound marker written by this tool. Identity-sensitive callers must
// additionally match the generation stored in the registry.
func IsManaged(name string) (bool, error) {
	pw, ok, err := Lookup(name)
	return ok && IsManagedEntry(pw), err
}

// IsManagedEntry recognizes both deployed fixed markers and well-formed dynamic
// markers. It is suitable for display and explicitly confirmed recovery only;
// registry-backed identity decisions must use MatchesManagedGeneration.
func IsManagedEntry(pw Passwd) bool {
	name := gecosFullName(pw.GECOS)
	if name == config.ManagedGECOS {
		return true
	}
	generation, found := strings.CutPrefix(name, config.ManagedGenerationGECOSPrefix)
	return found && validate.Generation(generation)
}

// IsLegacyManagedEntry reports whether pw has the fixed marker used by released
// versions that could not bind the passwd entry to a registry generation.
func IsLegacyManagedEntry(pw Passwd) bool {
	return gecosFullName(pw.GECOS) == config.ManagedGECOS
}

// MatchesManagedGeneration requires the exact dynamic marker for generation.
// Matching only the username, UID, and legacy marker is unsafe because all three
// can be reproduced after an out-of-band account deletion and recreation.
func MatchesManagedGeneration(pw Passwd, generation string) bool {
	return validate.Generation(generation) &&
		gecosFullName(pw.GECOS) == config.ManagedGenerationGECOSPrefix+generation
}

// ManagedGECOSForGeneration returns the exact completed marker for generation.
func ManagedGECOSForGeneration(generation string) (string, error) {
	if !validate.Generation(generation) {
		return "", fmt.Errorf("invalid account generation %q", generation)
	}
	return config.ManagedGenerationGECOSPrefix + generation, nil
}

func pendingGECOSForGeneration(generation string) (string, error) {
	if !validate.Generation(generation) {
		return "", fmt.Errorf("invalid account generation %q", generation)
	}
	return config.PendingGenerationGECOSPrefix + generation, nil
}

// gecosFullName returns the first comma-separated GECOS subfield. Account tools
// may pad the remaining office/phone fields with commas.
func gecosFullName(gecos string) string {
	name := gecos
	if i := strings.IndexByte(gecos, ','); i >= 0 {
		name = gecos[:i]
	}
	return name
}

// protectedNames are never deletable regardless of registration.
var protectedNames = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true, "list": true,
	"irc": true, "gnats": true, "nobody": true, "dbus": true, "sshd": true, "polkitd": true,
}

// IsReservedName reports whether name falls in a namespace the tool must never
// touch based on its shape alone — a well-known system account name or the
// reserved "systemd-" prefix — independent of any /etc/passwd lookup. It is the
// single source of truth shared by both sides: the revoke path refuses to delete
// these, and the create path (invite) refuses to create them, so the tool can
// never mint an account it would later be unable to revoke.
func IsReservedName(name string) bool {
	return protectedNames[name] || strings.HasPrefix(name, "systemd-")
}

// IsProtectedRevokeTarget reports whether deleting name must be refused.
// registered says whether the tool's registry lists it, and recordedUID is the
// UID the registry recorded when it created the account (0 = not recorded, i.e.
// a row from a build before that field existed).
//
// A reserved (system/systemd-) name or a UID-0 account is always protected; a
// system-range UID (<1000) is protected unless it is a registered, managed temp
// account; a real UID>=1000 account is protected unless it can be proven to be
// one the tool made — so a real account that merely reuses the name of a
// since-deleted temp account is never touched, even if a stale registry entry
// still names it.
//
// A current managed GECOS marker proves the account is in this tool's namespace.
// A recorded UID is a contradiction detector, not a sufficient witness: Linux
// can reuse the same UID after an out-of-band deletion and recreation. If the
// recorded and current UIDs differ, deletion is refused; if they match, the
// marker is still required.
//
// An account that escalates itself to UID 0 stays protected: never auto-delete a
// root account. The caller is expected to report that tamper rather than retry —
// see UIDTampered.
func IsProtectedRevokeTarget(name string, registered bool, recordedUID int, recordedGeneration string, allowLegacy bool) (bool, error) {
	pw, ok, err := Lookup(name)
	if err != nil {
		return true, err
	}
	return IsProtectedRevokeEntry(name, pw, ok, registered, recordedUID, recordedGeneration, allowLegacy), nil
}

// IsProtectedRevokeEntry applies the revoke policy to one already-read passwd
// snapshot. Destructive callers must not splice the UID from one lookup together
// with the marker or name from another lookup while an account is being replaced.
func IsProtectedRevokeEntry(name string, pw Passwd, exists, registered bool, recordedUID int, recordedGeneration string, allowLegacy bool) bool {
	if IsReservedName(name) {
		return true
	}
	if !exists {
		return !registered
	}
	if pw.UID == 0 {
		return true
	}
	if registered {
		if recordedUID < 1 || pw.UID != recordedUID {
			return true
		}
	}
	managed := IsManagedEntry(pw)
	if registered {
		managed = MatchesManagedGeneration(pw, recordedGeneration) || (allowLegacy && IsLegacyManagedEntry(pw))
	}
	if pw.UID < 1000 {
		return !(registered && managed)
	}
	// UIDs are reusable. Even a matching recorded UID cannot prove that this is the
	// same account generation after an out-of-band deletion and recreation. Require
	// the per-account marker as well; ambiguity is safer to leave for an operator.
	return !managed
}

// UIDTampered reports whether name's current UID differs from the one the
// registry recorded at creation — the signature of an account that rewrote its
// own /etc/passwd entry (most dangerously to UID 0, which makes it permanently
// root and permanently protected). It is advisory: the caller reports it so the
// operator knows automatic revocation cannot proceed and why. Returns false when
// nothing was recorded (an older row) or the account is gone.
func UIDTampered(name string, recordedUID int) (current int, tampered bool, err error) {
	if recordedUID <= 0 {
		return 0, false, nil
	}
	pw, ok, err := Lookup(name)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, nil
	}
	return pw.UID, pw.UID != recordedUID, nil
}

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
type Manager struct{ Runner Runner }

// New returns a Manager using real command execution.
func New() *Manager { return &Manager{Runner: execRunner{}} }

// Create makes a new account with a generation-bound managed GECOS tag. Invite uses
// CreatePending instead so an older binary cannot mistake a pre-UID-registration
// account for a completed managed identity.
func (m *Manager) Create(name, shell, generation string) error {
	gecos, err := ManagedGECOSForGeneration(generation)
	if err != nil {
		return err
	}
	return m.create(name, shell, gecos)
}

// CreatePending makes an account whose GECOS is intentionally not the managed
// marker. The caller must persist the selected UID and then call MarkManaged
// before granting credentials or policy.
func (m *Manager) CreatePending(name, shell, generation string) error {
	gecos, err := pendingGECOSForGeneration(generation)
	if err != nil {
		return err
	}
	return m.create(name, shell, gecos)
}

func (m *Manager) create(name, shell, gecos string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	var err error
	switch {
	case m.Runner.Look("useradd"):
		err = m.Runner.Run("useradd", "-m", "-s", shell, "-c", gecos, name)
	case m.Runner.Look("adduser"):
		err = m.Runner.Run("adduser", "-D", "-s", shell, "-g", gecos, name)
	default:
		return fmt.Errorf("no useradd/adduser available")
	}
	if err != nil {
		return err
	}

	// useradd/adduser choose a numeric UID automatically. A process left behind
	// after an out-of-band deletion may still carry that number; giving it to the
	// new account would immediately give the process ownership of the new home and
	// any later sudo/key material. Check all four Linux credential UIDs before the
	// caller is allowed to use the account, and roll the just-created account back
	// whenever the check cannot prove the UID is idle.
	pw, ok, lookupErr := Lookup(name)
	if lookupErr != nil {
		return m.rollbackCreate(name, fmt.Errorf("look up newly created account: %w", lookupErr))
	}
	if !ok || pw.UID < 1 {
		return m.rollbackCreate(name, fmt.Errorf("newly created account %s has no safe local UID", name))
	}
	pids, scanErr := processesForUID(pw.UID)
	if scanErr != nil {
		return m.rollbackCreate(name, fmt.Errorf("scan processes before using UID %d: %w", pw.UID, scanErr))
	}
	if len(pids) != 0 {
		return m.rollbackCreate(name, fmt.Errorf("refusing reused UID %d: residual processes %v already carry it", pw.UID, pids))
	}
	return nil
}

// MarkManaged changes a pending account to the exact managed marker only after
// its numeric UID has been durably recorded. usermod is a required dependency
// for both invite and fail-closed revoke, so there is no weaker fallback here.
func (m *Manager) MarkManaged(name, generation string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
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

func (m *Manager) rollbackCreate(name string, cause error) error {
	if err := m.Delete(name); err != nil {
		return errors.Join(cause, fmt.Errorf("rollback newly created account %s: %w", name, err))
	}
	return cause
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
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	return m.Runner.Run("usermod", "-p", keyOnlyPasswordHash, name)
}

// LockPassword locks name during revocation. Revoke also expires the account,
// so rejecting every authentication method is intentional here.
func (m *Manager) LockPassword(name string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	return m.Runner.Run("usermod", "-L", name)
}

// SetPassword sets name's login password, for the --password-login invite on a
// host whose sshd will not take a key. The password goes to chpasswd on stdin,
// never in argv, so it cannot be read out of the process table.
func (m *Manager) SetPassword(name, password string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	if !m.Runner.Look("chpasswd") {
		return fmt.Errorf("chpasswd not available")
	}
	if strings.ContainsAny(password, ":\n") {
		// chpasswd's line format is user:password — a colon or newline would split
		// the record and set a different password than the one we printed.
		return fmt.Errorf("refusing a password containing ':' or a newline")
	}
	return m.Runner.RunInput(name+":"+password+"\n", "chpasswd")
}

// SetExpiry sets the account expiry date (YYYY-MM-DD) via chage.
func (m *Manager) SetExpiry(name, date string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	return m.Runner.Run("chage", "-E", date, name)
}

// expiredDate is a date safely in the past; chage -E it to make an account
// expired as of now. A literal date is used rather than "0" because chage's
// numeric form is days-since-epoch and reads ambiguously next to -E -1 ("never").
const expiredDate = "1970-01-01"

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

// Delete removes the account and its home directory.
//
// userdel gets -f. Without it, shadow's userdel exits 8 ("user currently logged
// in") whenever a session exists — so an invitee who simply reconnects in a loop
// could make every revoke fail. The caller disables the login before reaching
// here, which closes that race at the source; -f closes what is left of it, and
// makes the delete succeed against a stale utmp entry too. Deleting an account
// out from under a live session is exactly what a revoke is asking for.
func (m *Manager) Delete(name string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	var delErr error
	if m.Runner.Look("deluser") {
		if delErr = m.Runner.Run("deluser", "--remove-home", name); delErr == nil {
			absent, err := accountConfirmedAbsent(name)
			if err != nil {
				return fmt.Errorf("verify deluser removed %s: %w", name, err)
			}
			if absent {
				return nil
			}
			delErr = fmt.Errorf("deluser reported success but account %s still exists", name)
		}
	}
	if m.Runner.Look("userdel") {
		if err := m.Runner.Run("userdel", "-r", "-f", "--", name); err != nil {
			return errors.Join(delErr, fmt.Errorf("userdel: %w", err))
		}
		absent, err := accountConfirmedAbsent(name)
		if err != nil {
			return fmt.Errorf("verify userdel removed %s: %w", name, err)
		}
		if !absent {
			return errors.Join(delErr, fmt.Errorf("userdel reported success but account %s still exists", name))
		}
		return nil
	}
	// deluser ran and failed but there is no userdel to fall back to: return the
	// REAL deluser error, not a generic "no tool available". On BusyBox (deluser,
	// no userdel) the true cause — a live session, say — was being hidden behind a
	// false "the tool is missing" that sent the operator debugging the wrong thing.
	if delErr != nil {
		return fmt.Errorf("deluser: %w", delErr)
	}
	return fmt.Errorf("no userdel/deluser available")
}

func accountConfirmedAbsent(name string) (bool, error) {
	exists, err := Exists(name)
	if err != nil {
		return false, err
	}
	return !exists, nil
}

var (
	procRoot        = "/proc"
	pidfdOpen       = unix.PidfdOpen
	pidfdSendSignal = unix.PidfdSendSignal
	closeFD         = unix.Close
	terminateSleep  = time.Sleep
)

// terminateSweeps bounds the SIGKILL retry loop. A handful of passes clears any
// realistic fork loop; the bound keeps a process that cannot be killed at all (an
// uninterruptible-sleep task) from spinning here forever while holding up revoke.
const terminateSweeps = 5

// CheckPidfd verifies that this kernel and sandbox allow pidfd operations. The
// revoke path relies on pidfds so a PID reused between inspection and signalling
// can never redirect a root-issued signal at an unrelated process.
func CheckPidfd() error {
	fd, err := pidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd is unavailable (Linux 5.3+ and permission from the process sandbox are required): %w", err)
	}
	signalErr := pidfdSendSignal(fd, 0, nil, 0)
	closeErr := closeFD(fd)
	var errs []error
	if signalErr != nil {
		errs = append(errs, fmt.Errorf("pidfd signalling is unavailable (permission from the process sandbox is required): %w", signalErr))
	}
	if closeErr != nil {
		errs = append(errs, fmt.Errorf("close pidfd capability probe: %w", closeErr))
	}
	return errors.Join(errs...)
}

// TerminateProcesses signals SIGTERM then, after a grace period, SIGKILL to every
// process owned by uid. It no-ops for a non-positive uid (never root/all). Done
// natively via /proc (no pkill dependency).
//
// The SIGKILL pass repeats until a scan finds nothing left (or the bound is hit),
// because one snapshot-then-signal pass loses to a process that is actively
// forking: a child created after the scan is never in the list, and would survive
// the revoke as an orphan owned by a uid that is about to be recycled. Re-scanning
// after each kill closes that window — each pass strictly shrinks the survivors,
// since a killed parent cannot fork again.
func TerminateProcesses(uid int) error {
	if uid < 1 {
		return nil
	}
	if !validate.AccountID(uid) {
		return fmt.Errorf("refusing invalid Linux UID %d", uid)
	}
	var errs []error
	pids, err := signalUID(unix.SIGTERM, uid)
	if err != nil {
		errs = append(errs, fmt.Errorf("signal UID %d processes with SIGTERM: %w", uid, err))
	}
	if len(pids) != 0 {
		terminateSleep(2 * time.Second)
	}
	for i := 0; i < terminateSweeps; i++ {
		pids, err = signalUID(unix.SIGKILL, uid)
		if err != nil {
			errs = append(errs, fmt.Errorf("signal UID %d processes with SIGKILL: %w", uid, err))
		}
		if len(pids) == 0 {
			return errors.Join(errs...)
		}
		terminateSleep(100 * time.Millisecond)
	}
	survivors, err := processesForUID(uid)
	if err != nil {
		errs = append(errs, fmt.Errorf("final scan for UID %d: %w", uid, err))
	} else if len(survivors) != 0 {
		errs = append(errs, fmt.Errorf("UID %d still has surviving processes %v after SIGKILL", uid, survivors))
	}
	return errors.Join(errs...)
}

// signalUID first filters by credentials, then opens a pidfd and rechecks those
// credentials before signalling through the descriptor. The first filter avoids
// requiring pidfd access to every unrelated host process; the second check plus
// the pidfd means PID reuse can never redirect a signal at an unrelated process.
func signalUID(sig unix.Signal, uid int) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", procRoot, err)
	}
	var signalled []int
	var errs []error
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		status, uidErr := readProcStatus(pid)
		if uidErr != nil {
			if !errors.Is(uidErr, os.ErrNotExist) && !errors.Is(uidErr, unix.ESRCH) {
				errs = append(errs, fmt.Errorf("read credentials for pid %d: %w", pid, uidErr))
			}
			continue
		}
		if status.inactive || !containsUID(status.uids, uid) {
			continue
		}
		fd, err := pidfdOpen(pid, 0)
		if err == unix.ESRCH || err == unix.ENOENT {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("open pidfd for pid %d: %w", pid, err))
			continue
		}
		status, uidErr = readProcStatus(pid)
		if uidErr != nil {
			_ = closeFD(fd)
			if !errors.Is(uidErr, os.ErrNotExist) && !errors.Is(uidErr, unix.ESRCH) {
				errs = append(errs, fmt.Errorf("read credentials for pid %d: %w", pid, uidErr))
			}
			continue
		}
		// Zombies and already-dead tasks cannot execute, fork, or retain a usable
		// credential. They are reaped only by their parent (or init), so repeatedly
		// SIGKILLing them would make every revoke fail forever without improving
		// isolation.
		if status.inactive || !containsUID(status.uids, uid) {
			_ = closeFD(fd)
			continue
		}
		signalErr := pidfdSendSignal(fd, sig, nil, 0)
		closeErr := closeFD(fd)
		if signalErr == nil {
			signalled = append(signalled, pid)
		} else if signalErr != unix.ESRCH {
			errs = append(errs, fmt.Errorf("signal pid %d: %w", pid, signalErr))
		}
		if closeErr != nil {
			errs = append(errs, fmt.Errorf("close pidfd for pid %d: %w", pid, closeErr))
		}
	}
	sort.Ints(signalled)
	return signalled, errors.Join(errs...)
}

func processesForUID(uid int) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", procRoot, err)
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := readProcStatus(pid)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read credentials for pid %d: %w", pid, err)
		}
		if !status.inactive && containsUID(status.uids, uid) {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

func containsUID(uids [4]int, uid int) bool {
	for _, candidate := range uids {
		if candidate == uid {
			return true
		}
	}
	return false
}

type processStatus struct {
	uids     [4]int
	inactive bool
}

// readProcStatus returns Linux's real, effective, saved-set, and filesystem
// UIDs and whether the task is already a zombie/dead process awaiting reaping.
func readProcStatus(pid int) (processStatus, error) {
	// Whole-file read: a scanner that errored before the Uid: line would drop this
	// pid from the SIGKILL sweep silently. /proc/<pid>/status is tiny.
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return processStatus{}, err
	}
	var status processStatus
	foundUID := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "State:"):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return processStatus{}, fmt.Errorf("malformed State line")
			}
			status.inactive = fields[1] == "Z" || fields[1] == "X"
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			if len(fields) != 5 {
				return processStatus{}, fmt.Errorf("malformed Uid line")
			}
			for i := range status.uids {
				parsed, err := strconv.Atoi(fields[i+1])
				if err != nil || !validate.KernelID(parsed) {
					return processStatus{}, fmt.Errorf("malformed Uid value %q", fields[i+1])
				}
				status.uids[i] = parsed
			}
			foundUID = true
		}
	}
	if !foundUID {
		return processStatus{}, fmt.Errorf("status has no Uid line")
	}
	return status, nil
}
