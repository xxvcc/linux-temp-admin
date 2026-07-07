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

// IsManaged reports whether name's GECOS carries the exact managed tag this tool
// sets — not a bare substring, so a self-set partial GECOS cannot pose as managed.
func IsManaged(name string) bool {
	pw, ok := Lookup(name)
	return ok && strings.Contains(pw.GECOS, config.ManagedGECOS)
}

// protectedNames are never deletable regardless of registration.
var protectedNames = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true, "list": true,
	"irc": true, "gnats": true, "nobody": true, "dbus": true, "sshd": true, "polkitd": true,
}

// IsProtectedRevokeTarget reports whether deleting name must be refused. registered
// says whether the tool's registry lists it. A UID-0 or blocklisted account is
// always protected; a system-range UID (<1000) is protected unless it is a
// registered, managed temp account; a real UID>=1000 account that is neither
// registered nor managed is protected (almost certainly a human/service account).
func IsProtectedRevokeTarget(name string, registered bool) bool {
	if protectedNames[name] || strings.HasPrefix(name, "systemd-") {
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
	managed := strings.Contains(pw.GECOS, config.ManagedGECOS)
	if pw.UID < 1000 {
		return !(registered && managed)
	}
	return !registered && !managed
}

// Runner executes account-management commands; injectable for tests.
type Runner interface {
	Run(name string, args ...string) error
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

// SetExpiry sets the account expiry date (YYYY-MM-DD) via chage.
func (m *Manager) SetExpiry(name, date string) error { return m.Runner.Run("chage", "-E", date, name) }

// Delete removes the account and its home directory.
func (m *Manager) Delete(name string) error {
	if m.Runner.Look("deluser") {
		if err := m.Runner.Run("deluser", "--remove-home", name); err == nil {
			return nil
		}
	}
	if m.Runner.Look("userdel") {
		return m.Runner.Run("userdel", "-r", "--", name)
	}
	return fmt.Errorf("no userdel/deluser available")
}

// TerminateProcesses signals SIGTERM then, after a grace period, SIGKILL to every
// process owned by uid. It no-ops for a non-positive uid (never root/all). Done
// natively via /proc (no pkill dependency).
func TerminateProcesses(uid int) {
	if uid < 1 {
		return
	}
	signalUID(syscall.SIGTERM, uid)
	time.Sleep(2 * time.Second)
	signalUID(syscall.SIGKILL, uid)
}

func signalUID(sig syscall.Signal, uid int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
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
			_ = syscall.Kill(pid, sig)
		}
	}
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
