package sshdconf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"golang.org/x/sys/unix"
)

const acct = "xxvcc-a1b2c3"

func writeSSHDCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFakeSSHDProcess(t *testing.T, procRoot string, pid int, listener bool, bootSeconds int64, startTicks uint64) {
	t.Helper()
	procDir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte("sshd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmdline := "sshd: test [priv]\x00"
	if listener {
		cmdline = "sshd: /usr/sbin/sshd -D [listener]\x00"
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte(cmdline), 0o600); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = "1"
	fields[2] = strconv.Itoa(pid)
	fields[3] = strconv.Itoa(pid)
	fields[19] = strconv.FormatUint(startTicks, 10)
	processStat := strconv.Itoa(pid) + " (sshd) " + strings.Join(fields, " ") + "\n"
	if err := os.WriteFile(filepath.Join(procDir, "stat"), []byte(processStat), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "stat"), []byte("cpu 1 2 3 4\nbtime "+strconv.FormatInt(bootSeconds, 10)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHDHelpersAreBoundedAndUseCLocale(t *testing.T) {
	oldCheck, oldReload := sshdCheckOptions, sshdReloadOptions
	oldPIDFiles := sshdPIDFiles
	t.Cleanup(func() {
		sshdCheckOptions, sshdReloadOptions = oldCheck, oldReload
		sshdPIDFiles = oldPIDFiles
	})

	t.Run("syntax locale", func(t *testing.T) {
		sshdCheckOptions = oldCheck
		dir := t.TempDir()
		writeSSHDCommand(t, dir, "sshd", `[ "$LC_ALL:$LANG:$1" = "C:C:-t" ]`)
		t.Setenv("PATH", dir)
		if err := sshdSyntaxCheck(); err != nil {
			t.Fatalf("sshdSyntaxCheck did not force the C locale/expected argv: %v", err)
		}
	})

	t.Run("syntax timeout", func(t *testing.T) {
		dir := t.TempDir()
		writeSSHDCommand(t, dir, "sshd", `/bin/sleep 30 & wait`)
		t.Setenv("PATH", dir)
		opts := oldCheck
		opts.Timeout = 50 * time.Millisecond
		sshdCheckOptions = opts
		if err := sshdSyntaxCheck(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("sshdSyntaxCheck error = %v, want timeout", err)
		}
	})

	t.Run("syntax output limit", func(t *testing.T) {
		dir := t.TempDir()
		writeSSHDCommand(t, dir, "sshd", `while :; do printf 0123456789abcdef; done`)
		t.Setenv("PATH", dir)
		opts := oldCheck
		opts.Timeout = time.Second
		opts.MaxOutput = 64
		sshdCheckOptions = opts
		if err := sshdSyntaxCheck(); !errors.Is(err, executil.ErrOutputLimit) {
			t.Fatalf("sshdSyntaxCheck error = %v, want output limit", err)
		}
	})

	t.Run("reload locale", func(t *testing.T) {
		sshdReloadOptions = oldReload
		dir := t.TempDir()
		writeSSHDCommand(t, dir, "systemctl", `[ "$LC_ALL:$LANG:$1:$2" = "C:C:reload:sshd" ]`)
		t.Setenv("PATH", dir)
		if err := reload(); err != nil {
			t.Fatalf("reload did not force the C locale/expected argv: %v", err)
		}
	})

	t.Run("reload timeout is bounded", func(t *testing.T) {
		dir := t.TempDir()
		writeSSHDCommand(t, dir, "systemctl", `/bin/sleep 30 & wait`)
		t.Setenv("PATH", dir)
		opts := oldReload
		opts.Timeout = 50 * time.Millisecond
		sshdReloadOptions = opts
		sshdPIDFiles = nil
		start := time.Now()
		err := reload()
		if !errors.Is(err, ErrNoReloadMechanism) || time.Since(start) > 2*time.Second {
			t.Fatalf("reload error = %v after %s, want bounded fallback", err, time.Since(start))
		}
	})
}

func TestSignalSSHDUsesPidfd(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "sshd.pid")
	if err := os.WriteFile(pidFile, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	procRoot := filepath.Join(root, "proc")
	writeFakeSSHDProcess(t, procRoot, 42, true, 1, 100)
	oldFiles, oldOwner, oldProcessUID, oldProc := sshdPIDFiles, sshdPIDOwnerUID, sshdProcessUID, sshdProcRoot
	oldOpen, oldSend, oldClose := pidfdOpen, pidfdSendSignal, closeFD
	sshdPIDFiles = []string{pidFile}
	sshdPIDOwnerUID = uint32(os.Geteuid())
	sshdProcessUID = uint32(os.Geteuid())
	sshdProcRoot = procRoot
	opened := 0
	pidfdOpen = func(pid, flags int) (int, error) {
		opened++
		if pid != 42 || flags != 0 {
			t.Fatalf("PidfdOpen(%d, %d)", pid, flags)
		}
		return 99, nil
	}
	pidfdSendSignal = func(fd int, sig unix.Signal, _ *unix.Siginfo, flags int) error {
		if fd != 99 || sig != unix.SIGHUP || flags != 0 {
			t.Fatalf("PidfdSendSignal(%d, %v, flags=%d)", fd, sig, flags)
		}
		return nil
	}
	closed := 0
	closeFD = func(fd int) error { closed++; return nil }
	t.Cleanup(func() {
		sshdPIDFiles, sshdPIDOwnerUID, sshdProcessUID, sshdProcRoot = oldFiles, oldOwner, oldProcessUID, oldProc
		pidfdOpen, pidfdSendSignal, closeFD = oldOpen, oldSend, oldClose
	})
	if err := signalSSHDMaster(); err != nil {
		t.Fatal(err)
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("pidfd opened=%d closed=%d, want 1/1", opened, closed)
	}
}

func TestSignalSSHDPropagatesPidfdFailure(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "sshd.pid")
	if err := os.WriteFile(pidFile, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	procRoot := filepath.Join(root, "proc")
	writeFakeSSHDProcess(t, procRoot, 42, true, 1, 100)
	oldFiles, oldOwner, oldProcessUID, oldProc, oldOpen := sshdPIDFiles, sshdPIDOwnerUID, sshdProcessUID, sshdProcRoot, pidfdOpen
	sshdPIDFiles = []string{pidFile}
	sshdPIDOwnerUID = uint32(os.Geteuid())
	sshdProcessUID = uint32(os.Geteuid())
	sshdProcRoot = procRoot
	pidfdOpen = func(int, int) (int, error) { return -1, syscall.EPERM }
	t.Cleanup(func() {
		sshdPIDFiles, sshdPIDOwnerUID, sshdProcessUID, sshdProcRoot, pidfdOpen = oldFiles, oldOwner, oldProcessUID, oldProc, oldOpen
	})
	if err := signalSSHDMaster(); err == nil || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("signalSSHDMaster error = %v, want pidfd EPERM", err)
	}
}

func TestReadSSHDMasterPIDRejectsSpecialAndUnsafeFilesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	oldOwner := sshdPIDOwnerUID
	sshdPIDOwnerUID = uint32(os.Geteuid())
	t.Cleanup(func() { sshdPIDOwnerUID = oldOwner })

	valid := filepath.Join(dir, "valid.pid")
	if err := os.WriteFile(valid, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pid, _, err := readSSHDMasterPID(valid); err != nil || pid != 42 {
		t.Fatalf("valid pid = %d, %v; want 42", pid, err)
	}

	link := filepath.Join(dir, "link.pid")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSSHDMasterPID(link); err == nil {
		t.Fatal("symlinked pid file was accepted")
	}

	fifo := filepath.Join(dir, "fifo.pid")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := readSSHDMasterPID(fifo); err == nil {
		t.Fatal("FIFO pid file was accepted")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("FIFO pid file blocked for %s", elapsed)
	}

	oversized := filepath.Join(dir, "oversized.pid")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("1", int(maxSSHDMasterPIDBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSSHDMasterPID(oversized); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized pid error = %v, want bounded-read refusal", err)
	}

	unsafeMode := filepath.Join(dir, "writable.pid")
	if err := os.WriteFile(unsafeMode, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeMode, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSSHDMasterPID(unsafeMode); err == nil || !strings.Contains(err.Error(), "unsafe metadata") {
		t.Fatalf("writable pid error = %v, want metadata refusal", err)
	}

	sshdPIDOwnerUID++
	if _, _, err := readSSHDMasterPID(valid); err == nil || !strings.Contains(err.Error(), "unsafe metadata") {
		t.Fatalf("foreign-owned pid error = %v, want metadata refusal", err)
	}
}

func TestSSHDMasterIdentityRejectsStalePIDAndSessionChild(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	const (
		pid         = 42
		bootSeconds = int64(1_000)
		startTicks  = uint64(250) // process start = 1002.5, exposed as Unix second 1002
	)
	oldRoot, oldUID := sshdProcRoot, sshdProcessUID
	sshdProcRoot = procRoot
	sshdProcessUID = uint32(os.Geteuid())
	t.Cleanup(func() { sshdProcRoot, sshdProcessUID = oldRoot, oldUID })

	writeFakeSSHDProcess(t, procRoot, pid, true, bootSeconds, startTicks)
	if isSSHDMaster(pid, time.Unix(1_001, 999_999_999)) {
		t.Fatal("listener was accepted through a pid file from an older process generation")
	}
	if !isSSHDMaster(pid, time.Unix(1_002, 500_000_000)) {
		t.Fatal("current-generation root sshd listener was rejected")
	}

	writeFakeSSHDProcess(t, procRoot, pid, false, bootSeconds, startTicks)
	if isSSHDMaster(pid, time.Unix(1_003, 0)) {
		t.Fatal("sshd session/priv child was accepted as the reload master")
	}
}

func TestSignalSSHDDoesNotHUPStalePIDReuse(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "sshd.pid")
	if err := os.WriteFile(pidFile, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The pid file predates the process that currently occupies PID 42.
	if err := os.Chtimes(pidFile, time.Unix(1_001, 0), time.Unix(1_001, 0)); err != nil {
		t.Fatal(err)
	}
	procRoot := filepath.Join(root, "proc")
	writeFakeSSHDProcess(t, procRoot, 42, true, 1_000, 250)

	oldFiles, oldPIDOwner, oldProcessUID, oldProc := sshdPIDFiles, sshdPIDOwnerUID, sshdProcessUID, sshdProcRoot
	oldOpen, oldSend, oldClose := pidfdOpen, pidfdSendSignal, closeFD
	sshdPIDFiles = []string{pidFile}
	sshdPIDOwnerUID = uint32(os.Geteuid())
	sshdProcessUID = uint32(os.Geteuid())
	sshdProcRoot = procRoot
	pidfdOpen = func(int, int) (int, error) { return 99, nil }
	sent := 0
	pidfdSendSignal = func(int, unix.Signal, *unix.Siginfo, int) error {
		sent++
		return nil
	}
	closed := 0
	closeFD = func(int) error { closed++; return nil }
	t.Cleanup(func() {
		sshdPIDFiles, sshdPIDOwnerUID, sshdProcessUID, sshdProcRoot = oldFiles, oldPIDOwner, oldProcessUID, oldProc
		pidfdOpen, pidfdSendSignal, closeFD = oldOpen, oldSend, oldClose
	})

	if err := signalSSHDMaster(); !errors.Is(err, ErrNoReloadMechanism) {
		t.Fatalf("stale pid fallback error = %v, want no reload mechanism", err)
	}
	if sent != 0 || closed != 1 {
		t.Fatalf("stale pid sent=%d closed=%d, want no signal and one close", sent, closed)
	}
}

// report builds a LoginReport carrying exactly the given blockers, the way
// CheckKeyLogin would.
func report(config string) sysinfo.LoginReport {
	return sysinfo.CheckKeyLogin(sysinfo.ParseSSHD(config), acct, []string{acct})
}

func TestDropInIsScopedToTheAccount(t *testing.T) {
	body, err := dropIn(acct, []string{acct}, report("pubkeyauthentication no\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "Match User "+acct+"\n") {
		t.Errorf("no Match block for the account:\n%s", got)
	}
	if !strings.HasSuffix(got, "Match all\n") {
		t.Errorf("drop-in does not restore global scope for later Include files:\n%s", got)
	}
	// Every directive must sit inside the Match block. A single line above it
	// would silently become global policy for every account on the host -- the one
	// outcome this whole design exists to prevent.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	seenMatch := false
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "#"):
		case strings.HasPrefix(ln, "Match "):
			seenMatch = true
		case strings.TrimSpace(ln) == "":
		default:
			if !seenMatch {
				t.Errorf("directive outside the Match block (it would be global): %q", ln)
			}
			if !strings.HasPrefix(ln, "    ") {
				t.Errorf("directive is not indented into the Match block: %q", ln)
			}
		}
	}
}

func TestWithLockFailsClosed(t *testing.T) {
	called := false
	m := &Manager{Lock: filepath.Join(t.TempDir(), "missing", "sshd.lock")}
	if err := m.withLock(func() error { called = true; return nil }); err == nil {
		t.Fatal("withLock ignored a lock-open failure")
	}
	if called {
		t.Fatal("withLock ran the sshd transaction without acquiring its lock")
	}
}

func TestWithLockRejectsUnsafeMetadata(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "sshd.lock")
	if err := os.WriteFile(lock, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lock, 0o666); err != nil {
		t.Fatal(err)
	}
	called := false
	m := &Manager{Lock: lock}
	if err := m.withLock(func() error { called = true; return nil }); err == nil {
		t.Fatal("withLock accepted a group/world-writable lock")
	}
	if called {
		t.Fatal("withLock ran the sshd transaction with an unsafe lock")
	}
}

func TestDropInLiftsOnlyWhatBlocks(t *testing.T) {
	tests := []struct {
		name   string
		config string
		groups []string
		want   []string
		absent []string
	}{
		{
			name:   "only the pubkey switch",
			config: "pubkeyauthentication no\n",
			want:   []string{"PubkeyAuthentication yes"},
			// Nothing was wrong with the key file's location, so the drop-in must not
			// pin it: an operator reading this file should see only what it had to fix.
			absent: []string{"AuthorizedKeysFile", "AuthenticationMethods", "AllowUsers", "AllowGroups"},
		},
		{
			name:   "a redirected authorized_keys",
			config: "pubkeyauthentication yes\nauthorizedkeysfile /etc/ssh/keys/%u\n",
			want:   []string{"AuthorizedKeysFile .ssh/authorized_keys"},
			absent: []string{"PubkeyAuthentication"},
		},
		{
			name:   "a second factor the locked account can never supply",
			config: "pubkeyauthentication yes\nauthenticationmethods publickey,password\n",
			want:   []string{"AuthenticationMethods publickey"},
		},
		{
			// NEVER `+ssh-ed25519`: OpenSSH's leading `+` appends to its COMPILED-IN
			// default set, not to the operator's list, and a Match block does not
			// inherit the global value. On the only hosts where this fires -- the ones
			// that deliberately narrowed the algorithm set -- `+` would hand the account
			// sshd's whole default set. Re-state the effective list and append ed25519.
			name:   "a crypto policy without ed25519",
			config: "pubkeyauthentication yes\npubkeyacceptedalgorithms rsa-sha2-512\n",
			want:   []string{"PubkeyAcceptedAlgorithms rsa-sha2-512,ssh-ed25519"},
			absent: []string{"+ssh-ed25519"},
		},
		{
			// sshd renamed the directive in 8.5; the 8.5 spelling is a fatal
			// "Bad configuration option" on the 8.2/8.4 releases that still support
			// Include. Write back the name this host's own sshd used.
			name:   "a pre-8.5 sshd's spelling of the same directive",
			config: "pubkeyauthentication yes\npubkeyacceptedkeytypes rsa-sha2-512\n",
			want:   []string{"PubkeyAcceptedKeyTypes rsa-sha2-512,ssh-ed25519"},
			absent: []string{"PubkeyAcceptedAlgorithms"},
		},
		{
			name:   "a user whitelist",
			config: "pubkeyauthentication yes\nallowusers alice\n",
			want:   []string{"AllowUsers " + acct},
		},
		{
			// The whitelist is satisfied by naming the account's own primary group,
			// never by adding it to one of the admin's existing groups -- that would
			// hand it whatever else that group carries.
			name:   "a group whitelist",
			config: "pubkeyauthentication yes\nallowgroups wheel\n",
			groups: []string{acct, "extra"},
			want:   []string{"AllowGroups " + acct},
			absent: []string{"wheel"},
		},
		{
			name:   "everything at once",
			config: "pubkeyauthentication no\nauthorizedkeysfile none\nauthenticationmethods publickey,password\nallowusers alice\n",
			want: []string{"PubkeyAuthentication yes", "AuthorizedKeysFile .ssh/authorized_keys",
				"AuthenticationMethods publickey", "AllowUsers " + acct},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			groups := tc.groups
			if groups == nil {
				groups = []string{acct}
			}
			body, err := dropIn(acct, groups, report(tc.config))
			if err != nil {
				t.Fatal(err)
			}
			got := string(body)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("drop-in missing %q:\n%s", w, got)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(got, a) {
					t.Errorf("drop-in carries %q, which nothing was blocking on:\n%s", a, got)
				}
			}
		})
	}
}

func TestGrantRefusesWhatItCannotFix(t *testing.T) {
	m := &Manager{Dir: t.TempDir()}
	// An explicit deny is a decision, not an omission. Writing a Match block would
	// not lift it anyway, so the grant must refuse rather than leave a useless
	// file behind and print an invite that cannot be used.
	rep := report("pubkeyauthentication yes\ndenyusers " + acct + "\n")
	if _, err := m.Grant(acct, []string{acct}, rep); err == nil {
		t.Fatal("Grant must refuse a policy it cannot lift for one account")
	}
	if _, err := m.Grant(acct, []string{acct}, report("pubkeyauthentication yes\n")); err == nil {
		t.Error("Grant must refuse when nothing is blocking: it would write a pointless file")
	}
}

func TestGrantAndRemoveRefuseInvalidNames(t *testing.T) {
	m := &Manager{Dir: t.TempDir()}
	// Defense in depth: a name that escaped validation must never reach a
	// `Match User` line or a file path.
	for _, bad := range []string{"root; rm -rf /", "../../etc/passwd", "a b", ""} {
		if _, err := m.Grant(bad, nil, report("pubkeyauthentication no\n")); err == nil {
			t.Errorf("Grant accepted an invalid username %q", bad)
		}
		if err := m.Remove(bad); err == nil {
			t.Errorf("Remove accepted an invalid username %q", bad)
		}
	}
}

func TestRemoveWithNoDropIn(t *testing.T) {
	// revoke calls this for every account, including the ones that never needed an
	// sshd exception. It must be a silent no-op -- and must neither validate nor
	// reload sshd.
	validations := 0
	reloads := 0
	m := &Manager{
		Dir:      t.TempDir(),
		Validate: func() error { validations++; return nil },
		Reload:   func() error { reloads++; return nil },
	}
	if err := m.Remove(acct); err != nil {
		t.Fatalf("Remove on an account with no drop-in: %v", err)
	}
	if validations != 0 {
		t.Error("Remove validated sshd although it had no removal to finish")
	}
	if reloads != 0 {
		t.Error("Remove reloaded sshd although it had nothing to remove")
	}
}

func TestOrphansFindsExceptionsWhoseAccountIsGone(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		filePrefix + "xxvcc-gone.conf",                       // ours, account deleted -> orphan
		filePrefix + "xxvcc-gone.conf" + removePendingSuffix, // duplicate pending state -> one result
		filePrefix + "xxvcc-pending.conf" + removePendingSuffix,
		filePrefix + "xxvcc-alive.conf", // ours, account exists -> not an orphan
		"99-somebody-else.conf",         // not ours: never touch it
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("# x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{Dir: dir}
	orphans, err := m.Orphans(func(u string) (bool, error) { return u == "xxvcc-alive", nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 2 || orphans[0] != "xxvcc-gone" || orphans[1] != "xxvcc-pending" {
		t.Fatalf("orphans = %v, want [xxvcc-gone xxvcc-pending]", orphans)
	}
}

func TestAllPropagatesDirectoryReadFailure(t *testing.T) {
	want := syscall.EACCES
	oldReadDir := readDir
	readDir = func(string) ([]os.DirEntry, error) { return nil, want }
	t.Cleanup(func() { readDir = oldReadDir })

	if _, err := (&Manager{Dir: "/unreadable"}).All(); !errors.Is(err, want) {
		t.Fatalf("All error = %v, want EACCES", err)
	}
}

func TestAllRejectsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Manager{Dir: path}).All(); err == nil || !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("All error = %v, want ENOTDIR", err)
	}
}

func TestAllRejectsSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Manager{Dir: link}).All(); err == nil {
		t.Fatal("All followed a symlinked sshd directory")
	}
}

func TestAllAllowsAbsentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	users, err := (&Manager{Dir: dir}).All()
	if err != nil || len(users) != 0 {
		t.Fatalf("All on absent directory = %v, %v; want empty success", users, err)
	}
}

func TestAllRejectsMalformedManagedArtifact(t *testing.T) {
	dir := t.TempDir()
	name := filePrefix + "not.valid.conf"
	if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Manager{Dir: dir}).All(); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("All error = %v, want malformed managed artifact", err)
	}
}
