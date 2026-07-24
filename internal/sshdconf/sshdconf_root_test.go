//go:build integration

package sshdconf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
)

func rootDir(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// blocked is a host that refuses public-key logins; fixed is the same host once
// the drop-in is in place.
const (
	blocked = "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n"
	fixed   = "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
)

// okManager is a Manager whose external steps all succeed, counting reloads.
func okManager(t *testing.T, reloads *int) *Manager {
	return &Manager{
		Dir:       rootDir(t),
		Validate:  func() error { return nil },
		Effective: func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(fixed), nil },
		Reload:    func() error { *reloads++; return nil },
	}
}

func TestGrantWritesProvesAndReloads(t *testing.T) {
	reloads := 0
	m := okManager(t, &reloads)
	res, err := m.Grant(acct, []string{acct}, report(blocked))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !res.Reloaded {
		t.Error("Reloaded = false although the reload succeeded")
	}
	fi, err := os.Lstat(res.Path)
	if err != nil {
		t.Fatalf("drop-in not written: %v", err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		t.Errorf("drop-in is group/world writable (mode %o): anyone could rewrite sshd policy", fi.Mode().Perm())
	}
	if reloads != 1 {
		t.Errorf("reloads = %d, want exactly 1", reloads)
	}
	if err := m.Remove(acct); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(res.Path); !os.IsNotExist(err) {
		t.Error("Remove left the drop-in behind")
	}
	if reloads != 2 {
		t.Errorf("reloads = %d, want a reload after the removal too", reloads)
	}
}

func TestRemoveNeverReloadsOntoABrokenConfig(t *testing.T) {
	// THE 3am SCENARIO. An operator edits /etc/ssh/sshd_config at 14:00, leaves a
	// typo, and never reloads: the running sshd is still serving its old, good
	// in-memory config, so nothing looks wrong. At 03:00 the auto-revoke timer runs
	// `revoke --user X --yes`, which lands here. A reload re-execs sshd against
	// what is on disk -- so an ungated reload would be the thing that finally takes
	// SSH off a remote production box, unattended.
	//
	// The removal itself must still happen (our file is gone), but sshd must NOT be
	// asked to re-read a configuration that somebody else already broke.
	reloads := 0
	m := okManager(t, &reloads)
	res, err := m.Grant(acct, []string{acct}, report(blocked))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	reloads = 0
	m.Validate = func() error { return fmt.Errorf("/etc/ssh/sshd_config: line 42: Bad configuration option: Prot0col") }

	err = m.Remove(acct)
	if err == nil {
		t.Fatal("Remove must report that it refused to reload onto an invalid config")
	}
	if reloads != 0 {
		t.Fatalf("Remove reloaded sshd %d time(s) onto a config sshd itself rejects — this is how a remote host loses SSH", reloads)
	}
	// The exception is still gone: a live loosening of policy must not survive just
	// because somebody else's typo is in the way.
	if _, err := os.Lstat(res.Path); !os.IsNotExist(err) {
		t.Error("Remove left the sshd exception on disk")
	}
}

func TestGrantKeepsTheFileButDoesNotClaimVerifiedWhenNothingCouldBeReloaded(t *testing.T) {
	// No init system took the reload and no live sshd could be signalled. The file
	// is correct on disk (a socket-activated sshd will read it on the next
	// connection), so it stays -- but the running daemon, if there is one, never saw
	// it, so the caller must not go on to print a "verified" invite.
	reloads := 0
	m := okManager(t, &reloads)
	m.Reload = func() error { return ErrNoReloadMechanism }

	res, err := m.Grant(acct, []string{acct}, report(blocked))
	if err != nil {
		t.Fatalf("Grant must not fail when there is simply no sshd to reload: %v", err)
	}
	if res.Reloaded {
		t.Error("Reloaded = true although nothing was reloaded — this is what stamps a false 'verified' on an invite")
	}
	if _, err := os.Lstat(res.Path); err != nil {
		t.Errorf("the proved drop-in should be kept: %v", err)
	}
	// Remove tolerates the same sentinel: there is nothing to reload on the way out
	// either, and that is not a failure.
	if err := m.Remove(acct); err != nil {
		t.Errorf("Remove: %v", err)
	}
}

func TestGrantRollsBackWhenTheFixDoesNotTakeEffect(t *testing.T) {
	reloads := 0
	m := okManager(t, &reloads)
	// The file landed on disk but sshd still refuses the key — the shape of a host
	// whose sshd_config has no `Include` line, so drop-ins are never read.
	m.Effective = func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(blocked), nil }

	if _, err := m.Grant(acct, []string{acct}, report(blocked)); err == nil {
		t.Fatal("Grant must fail when the drop-in provably did not take effect")
	}
	if ents, _ := os.ReadDir(m.Dir); len(ents) != 0 {
		t.Errorf("a failed grant left files behind: %v", ents)
	}
	if reloads != 0 {
		t.Errorf("a grant that never proved itself reloaded sshd %d time(s)", reloads)
	}
}

func TestGrantRefusesToTouchAnAlreadyBrokenConfig(t *testing.T) {
	// If `sshd -t` already fails before we write anything, the fault is not ours and
	// the host is one reload away from losing sshd. Do not add to it, and do not
	// blame our own file for someone else's typo.
	reloads := 0
	m := okManager(t, &reloads)
	m.Validate = func() error { return fmt.Errorf("Bad configuration option: Prot0col") }

	if _, err := m.Grant(acct, []string{acct}, report(blocked)); err == nil {
		t.Fatal("Grant must refuse when the host's sshd config is already invalid")
	}
	if ents, _ := os.ReadDir(m.Dir); len(ents) != 0 {
		t.Errorf("Grant wrote into an already-broken config: %v", ents)
	}
	if reloads != 0 {
		t.Errorf("Grant reloaded sshd %d time(s) onto an already-broken config", reloads)
	}
}

func TestGrantRollsBackWhenSSHDRejectsTheConfigItProduced(t *testing.T) {
	reloads := 0
	m := okManager(t, &reloads)
	calls := 0
	// Valid before the write, rejected after it: our own file is the bad one.
	m.Validate = func() error {
		calls++
		if calls == 1 {
			return nil
		}
		return fmt.Errorf("Bad configuration option: PubkeyAcceptedAlgorithms")
	}

	if _, err := m.Grant(acct, []string{acct}, report(blocked)); err == nil {
		t.Fatal("Grant must fail when sshd rejects the configuration it produced")
	}
	if ents, _ := os.ReadDir(m.Dir); len(ents) != 0 {
		t.Errorf("a syntactically bad drop-in was left in place: %v", ents)
	}
	if reloads != 0 {
		t.Errorf("reloaded sshd %d time(s) onto a rejected configuration", reloads)
	}
}

func TestGrantRollsBackWhenTheReloadFails(t *testing.T) {
	reloads := 0
	m := okManager(t, &reloads)
	m.Reload = func() error { return fmt.Errorf("systemctl: Job for ssh.service failed") }

	if _, err := m.Grant(acct, []string{acct}, report(blocked)); err == nil {
		t.Fatal("Grant must fail when sshd cannot be reloaded: the invite would not work yet")
	}
	if ents, _ := os.ReadDir(m.Dir); len(ents) != 0 {
		t.Errorf("a grant whose reload failed left the drop-in behind: %v", ents)
	}
}

func TestGrantReportsRollbackRemovalFailure(t *testing.T) {
	reloads := 0
	m := okManager(t, &reloads)
	m.Effective = func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(blocked), nil }
	m.RemoveFile = func(string) error { return fmt.Errorf("filesystem is read-only") }

	_, err := m.Grant(acct, []string{acct}, report(blocked))
	if err == nil || !strings.Contains(err.Error(), "remove failed sshd drop-in") {
		t.Fatalf("Grant error = %v, want the rollback removal failure", err)
	}
	if _, statErr := os.Lstat(m.FilePath(acct)); statErr != nil {
		t.Fatalf("fixture did not leave the unremovable drop-in behind: %v", statErr)
	}
}

func TestRemoveOnlyEverTouchesItsOwnFile(t *testing.T) {
	reloads := 0
	m := okManager(t, &reloads)
	// A file that is not ours must survive a Remove aimed at a similar name.
	foreign := filepath.Join(m.Dir, "99-cloud-init.conf")
	if err := os.WriteFile(foreign, []byte("PasswordAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(acct); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Error("Remove deleted a drop-in this tool does not own")
	}
}

func TestGrantSucceedsDespiteAnUnverifiableAllowUsers(t *testing.T) {
	// The false diagnosis regression: a host with `PubkeyAuthentication no` plus a
	// routine `AllowUsers *@10.0.0.0/8` ("SSH only from the VPN"). The Match User
	// drop-in genuinely makes pubkey auth work, but the address-qualified AllowUsers
	// can never be evaluated, so the report is OK() yet not Certain(). Grant's proof
	// must accept it (the blockers it lifted are gone) rather than roll back a
	// working file and blame a missing Include.
	reloads := 0
	m := okManager(t, &reloads)
	// After the drop-in, sshd accepts the key but the address-qualified AllowUsers
	// still stands -- exactly what the real host reports.
	m.Effective = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nallowusers *@10.0.0.0/8\n"), nil
	}
	rep := sysinfo.CheckKeyLogin(
		sysinfo.ParseSSHD("pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\nallowusers *@10.0.0.0/8\n"),
		acct, []string{acct})
	if rep.OK() {
		t.Fatal("precondition: the pre-grant report should still show the pubkey blocker")
	}
	res, err := m.Grant(acct, []string{acct}, rep)
	if err != nil {
		t.Fatalf("Grant must accept a drop-in that lifted its blockers even when an address-qualified AllowUsers remains unverifiable: %v", err)
	}
	if _, err := os.Lstat(res.Path); err != nil {
		t.Errorf("the working drop-in was rolled back: %v", err)
	}
}
