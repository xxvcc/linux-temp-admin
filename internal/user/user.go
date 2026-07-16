// Package user manages the lifecycle of temporary local accounts: creating,
// locking, expiring, and deleting them, plus the protection checks that keep the
// tool from ever touching a system or real account. Account mutations shell out
// to the distro's user tools (useradd/usermod/chage/userdel or the BusyBox
// adduser/deluser) via an injectable runner, so argv is unit-testable; passwd
// lookups and process termination are done natively (no getent/pkill).
package user

import (
	"bufio"
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
func Lookup(name string) (Passwd, bool) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return Passwd{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 || parts[0] != name {
			continue
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil {
			return Passwd{}, false
		}
		return Passwd{Name: parts[0], UID: uid, GID: gid, GECOS: parts[4], Home: parts[5], Shell: parts[6]}, true
	}
	return Passwd{}, false
}

// Exists reports whether name is a local account.
func Exists(name string) bool { _, ok := Lookup(name); return ok }

// groupPath is the group database; overridable in tests.
var groupPath = "/etc/group"

// Groups returns pw's group names: its primary group, plus every group that
// lists it as a member. This is exactly the set sshd evaluates AllowGroups and
// DenyGroups against, so an invite can tell whether a whitelist would admit the
// account it is about to create.
func Groups(pw Passwd) []string {
	f, err := os.Open(groupPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var primary string
	var extra []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// name:passwd:gid:member,member,...
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 4 {
			continue
		}
		if gid, err := strconv.Atoi(parts[2]); err == nil && gid == pw.GID {
			primary = parts[0]
			continue
		}
		for _, m := range strings.Split(parts[3], ",") {
			if m == pw.Name {
				extra = append(extra, parts[0])
				break
			}
		}
	}
	// The primary group comes first: it is the one a grant names when it has to
	// satisfy an AllowGroups whitelist.
	if primary == "" {
		return extra
	}
	return append([]string{primary}, extra...)
}

// IsManaged reports whether name's GECOS carries the exact managed tag this tool
// sets — an exact match on the GECOS full-name subfield, not a bare substring, so
// a self-set partial GECOS cannot pose as managed.
func IsManaged(name string) bool {
	pw, ok := Lookup(name)
	return ok && hasManagedGECOS(pw.GECOS)
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
// "Proven to be ours" has two independent witnesses, and either suffices:
//
//   - The recorded UID still matches the account's current UID. This is the
//     stronger witness: it was fixed at creation, before the invitee had any
//     access, and it cannot be forged by the account itself the way GECOS can
//     (an invitee with the granted NOPASSWD sudo — or plain chfn where
//     CHFN_RESTRICT permits — can erase the marker and, without this, make its
//     own account permanently unrevocable). It stays reuse-proof because a
//     recreated account under the same name draws a fresh UID.
//   - The managed GECOS marker. Still honoured, because rows written before the
//     UID was recorded carry no UID, and those accounts must remain revocable.
//
// An account that escalates itself to UID 0 stays protected: never auto-delete a
// root account. The caller is expected to report that tamper rather than retry —
// see UIDTampered.
func IsProtectedRevokeTarget(name string, registered bool, recordedUID int) bool {
	if IsReservedName(name) {
		return true
	}
	pw, ok := Lookup(name)
	if !ok {
		// Unresolvable: protect unless the registry vouches for it.
		return !registered
	}
	if pw.UID == 0 {
		return true
	}
	// The registry recorded this exact UID for this exact name at creation: this
	// account is provably the one the tool made, whatever its GECOS says now.
	if registered && recordedUID > 0 && pw.UID == recordedUID {
		return false
	}
	managed := hasManagedGECOS(pw.GECOS)
	if pw.UID < 1000 {
		return !(registered && managed)
	}
	// A registry entry is name-keyed and can outlive the account it named (stale
	// entries are pruned only by an explicit `cleanup-expired --compact`), so a reused
	// username could inherit a stale entry that wrongly vouches for a real account. The
	// managed GECOS marker, by contrast, is per-account and reuse-proof, so it — not
	// `registered` — is what makes a real-UID account safe to delete.
	return !managed
}

// UIDTampered reports whether name's current UID differs from the one the
// registry recorded at creation — the signature of an account that rewrote its
// own /etc/passwd entry (most dangerously to UID 0, which makes it permanently
// root and permanently protected). It is advisory: the caller reports it so the
// operator knows automatic revocation cannot proceed and why. Returns false when
// nothing was recorded (an older row) or the account is gone.
func UIDTampered(name string, recordedUID int) (current int, tampered bool) {
	if recordedUID <= 0 {
		return 0, false
	}
	pw, ok := Lookup(name)
	if !ok {
		return 0, false
	}
	return pw.UID, pw.UID != recordedUID
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
func (m *Manager) DisableLogin(name string) error {
	if err := m.SetExpiry(name, expiredDate); err != nil {
		return err
	}
	return m.LockPassword(name)
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
	if m.Runner.Look("deluser") {
		if err := m.Runner.Run("deluser", "--remove-home", name); err == nil {
			return nil
		}
	}
	if m.Runner.Look("userdel") {
		return m.Runner.Run("userdel", "-r", "-f", "--", name)
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
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
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
