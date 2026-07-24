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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
)

// passwdPath is the account database; overridable in tests.
var passwdPath = "/etc/passwd"

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
	// os.ReadFile, not a bufio.Scanner: a scanner ignores a mid-file read error and
	// stops early, which would make an account later in the file look absent — and
	// Lookup backs user.Exists, which the teardown trusts as ground truth. ReadFile
	// either returns the whole file or an error, so a partial read can never
	// masquerade as EOF or as a missing account.
	data, err := os.ReadFile(passwdPath)
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
		if err1 != nil || err2 != nil {
			return Passwd{}, false, fmt.Errorf("malformed passwd entry for %s", name)
		}
		return Passwd{Name: parts[0], UID: uid, GID: gid, GECOS: parts[4], Home: parts[5], Shell: parts[6]}, true, nil
	}
	return Passwd{}, false, nil
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
	local, err := Exists(name)
	if err != nil || local {
		return local, err
	}
	err = exec.Command("id", "-u", name).Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, fmt.Errorf("query NSS identity %s: %w", name, err)
}

// Groups returns pw's group names: its primary group, plus every group that
// lists it as a member. This is exactly the set sshd evaluates AllowGroups and
// DenyGroups against, so an invite can tell whether a whitelist would admit the
// account it is about to create.
func Groups(pw Passwd) ([]string, error) {
	// Use the system identity resolver rather than parsing /etc/group: sshd also
	// consults NSS, so LDAP/SSSD memberships must participate in DenyGroups.
	out, err := exec.Command("id", "-Gn", pw.Name).Output()
	if err != nil {
		return nil, fmt.Errorf("resolve groups for %s: %w", pw.Name, err)
	}
	groups := strings.Fields(string(out))
	if len(groups) == 0 {
		return nil, fmt.Errorf("identity resolver returned no groups for %s", pw.Name)
	}
	return groups, nil
}

// IsManaged reports whether name's GECOS carries the exact managed tag this tool
// sets — an exact match on the GECOS full-name subfield, not a bare substring, so
// a self-set partial GECOS cannot pose as managed.
func IsManaged(name string) (bool, error) {
	pw, ok, err := Lookup(name)
	return ok && hasManagedGECOS(pw.GECOS), err
}

// hasManagedGECOS reports whether a GECOS value is exactly the managed tag. It
// compares the first comma-separated subfield (the "full name"), because some
// account tools (and chfn) pad GECOS with trailing commas for the empty
// office/phone subfields; a plain substring match would let any GECOS that merely
// contains the tag pose as managed.
func hasManagedGECOS(gecos string) bool {
	name := gecos
	if i := strings.IndexByte(gecos, ','); i >= 0 {
		name = gecos[:i]
	}
	return name == config.ManagedGECOS
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
func IsProtectedRevokeTarget(name string, registered bool, recordedUID int) (bool, error) {
	if IsReservedName(name) {
		return true, nil
	}
	pw, ok, err := Lookup(name)
	if err != nil {
		return true, err
	}
	if !ok {
		return !registered, nil
	}
	if pw.UID == 0 {
		return true, nil
	}
	if registered && recordedUID > 0 {
		if pw.UID != recordedUID {
			return true, nil
		}
	}
	managed := hasManagedGECOS(pw.GECOS)
	if pw.UID < 1000 {
		return !(registered && managed), nil
	}
	// UIDs are reusable. Even a matching recorded UID cannot prove that this is the
	// same account generation after an out-of-band deletion and recreation. Require
	// the per-account marker as well; ambiguity is safer to leave for an operator.
	return !managed, nil
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
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execRunner) RunInput(stdin string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// The error text must never carry stdin back out: it holds the password.
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execRunner) Look(name string) bool { _, err := exec.LookPath(name); return err == nil }

// Manager performs account mutations via its Runner.
type Manager struct{ Runner Runner }

// New returns a Manager using real command execution.
func New() *Manager { return &Manager{Runner: execRunner{}} }

// Create makes a new account with a home directory, the given login shell, and
// the managed GECOS tag, using useradd or (BusyBox) adduser.
func (m *Manager) Create(name, shell string) error {
	switch {
	case m.Runner.Look("useradd"):
		return m.Runner.Run("useradd", "-m", "-s", shell, "-c", config.ManagedGECOS, name)
	case m.Runner.Look("adduser"):
		return m.Runner.Run("adduser", "-D", "-s", shell, "-g", config.ManagedGECOS, name)
	default:
		return fmt.Errorf("no useradd/adduser available")
	}
}

// LockPassword disables password login for name.
func (m *Manager) LockPassword(name string) error { return m.Runner.Run("usermod", "-L", name) }

// SetPassword sets name's login password, for the --password-login invite on a
// host whose sshd will not take a key. The password goes to chpasswd on stdin,
// never in argv, so it cannot be read out of the process table.
func (m *Manager) SetPassword(name, password string) error {
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
func (m *Manager) SetExpiry(name, date string) error { return m.Runner.Run("chage", "-E", date, name) }

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
// Both steps are best-effort in the sense that the caller continues to the
// delete either way, but their errors are returned so the caller can say the
// door could not be shut.
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
	var delErr error
	if m.Runner.Look("deluser") {
		if delErr = m.Runner.Run("deluser", "--remove-home", name); delErr == nil {
			return nil
		}
	}
	if m.Runner.Look("userdel") {
		return m.Runner.Run("userdel", "-r", "-f", "--", name)
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

// kill is syscall.Kill, indirected so a test can observe which pids would be
// signalled without signalling anything. A test that called the real syscall to
// prove the uid guard holds would kill every root process if the guard broke.
var kill = syscall.Kill

// terminateSweeps bounds the SIGKILL retry loop. A handful of passes clears any
// realistic fork loop; the bound keeps a process that cannot be killed at all (an
// uninterruptible-sleep task) from spinning here forever while holding up revoke.
const terminateSweeps = 5

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
func TerminateProcesses(uid int) {
	if uid < 1 {
		return
	}
	signalUID(syscall.SIGTERM, uid)
	time.Sleep(2 * time.Second)
	for i := 0; i < terminateSweeps; i++ {
		if n := signalUID(syscall.SIGKILL, uid); n == 0 {
			return
		}
	}
}

// signalUID sends sig to every process owned by uid and returns how many it
// signalled, so a caller can tell an empty sweep from a productive one.
func signalUID(sig syscall.Signal, uid int) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	signalled := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		ruid, euid, ok := procUIDs(pid)
		if !ok {
			continue
		}
		if ruid == uid || euid == uid {
			if kill(pid, sig) == nil {
				signalled++
			}
		}
	}
	return signalled
}

// procUIDs returns the real and effective UID from /proc/<pid>/status.
func procUIDs(pid int) (ruid, euid int, ok bool) {
	// Whole-file read: a scanner that errored before the Uid: line would drop this
	// pid from the SIGKILL sweep silently. /proc/<pid>/status is tiny.
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return 0, 0, false
		}
		r, err1 := strconv.Atoi(fields[1])
		e, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return r, e, true
	}
	return 0, 0, false
}
