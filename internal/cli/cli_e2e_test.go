//go:build integration

package cli_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/cli"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/netdetect"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

// The effective sshd config the fakes report. A test's verdict about sshd policy
// must come from these fixtures, never from the sshd of whatever machine happens
// to run the suite.
const (
	sshdOK       = "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
	sshdNoPubkey = "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n"
)

// fakeSched satisfies schedule.System without touching real systemd/at.
type fakeSched struct{}

func (fakeSched) HasSystemctl() bool                           { return false }
func (fakeSched) Systemctl(...string) error                    { return nil }
func (fakeSched) HasAt() bool                                  { return true }
func (fakeSched) ScheduleAt(string, time.Time) (string, error) { return "1", nil }
func (fakeSched) RemoveAtJobsFor(string) error                 { return nil }
func (fakeSched) AtrmJob(string) error                         { return nil }
func (fakeSched) AtJobs() ([]schedule.AtJob, error)            { return nil, nil }

type unavailableSched struct{}

func (unavailableSched) HasSystemctl() bool        { return false }
func (unavailableSched) Systemctl(...string) error { return nil }
func (unavailableSched) HasAt() bool               { return false }
func (unavailableSched) ScheduleAt(string, time.Time) (string, error) {
	return "", errors.New("unavailable")
}
func (unavailableSched) RemoveAtJobsFor(string) error      { return nil }
func (unavailableSched) AtrmJob(string) error              { return nil }
func (unavailableSched) AtJobs() ([]schedule.AtJob, error) { return nil, nil }

type trackingSched struct {
	jobs           map[string]string
	next           int
	removeErr      error
	beforeSchedule func(string) error
}

func newTrackingSched() *trackingSched { return &trackingSched{jobs: map[string]string{}} }

func (*trackingSched) HasSystemctl() bool        { return false }
func (*trackingSched) Systemctl(...string) error { return nil }
func (*trackingSched) HasAt() bool               { return true }
func (s *trackingSched) ScheduleAt(command string, _ time.Time) (string, error) {
	if s.beforeSchedule != nil {
		if err := s.beforeSchedule(command); err != nil {
			return "", err
		}
	}
	s.next++
	id := strconv.Itoa(s.next)
	s.jobs[id] = command
	return id, nil
}
func (s *trackingSched) RemoveAtJobsFor(command string) error {
	if s.removeErr != nil {
		return s.removeErr
	}
	for id, body := range s.jobs {
		if strings.Contains(body, command) {
			delete(s.jobs, id)
		}
	}
	return nil
}
func (s *trackingSched) AtrmJob(id string) error {
	delete(s.jobs, id)
	return nil
}
func (s *trackingSched) AtJobs() ([]schedule.AtJob, error) {
	jobs := make([]schedule.AtJob, 0, len(s.jobs))
	for id, body := range s.jobs {
		jobs = append(jobs, schedule.AtJob{ID: id, Body: body})
	}
	return jobs, nil
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

type partialFailingWriter struct{ wrote int }

func (w *partialFailingWriter) Write(p []byte) (int, error) {
	if !bytes.Contains(p, []byte("----- BEGIN LINUX TEMP ADMIN INVITE -----")) {
		return len(p), nil
	}
	n := len(p) / 2
	w.wrote += n
	return n, errors.New("output interrupted after a partial credential write")
}

func mustExternalUserExists(t *testing.T, name string) bool {
	t.Helper()
	exists, err := user.Exists(name)
	if err != nil {
		t.Fatal(err)
	}
	return exists
}

func mustExternalUserLookup(t *testing.T, name string) (user.Passwd, bool) {
	t.Helper()
	pw, ok, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return pw, ok
}

func rootDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chown(d, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, mode); err != nil {
		t.Fatal(err)
	}
	return d
}

// These account-lifecycle tests isolate the scheduler with fakeSched and do not
// exercise the host's personal cron/at queues. The dedicated userjobs suite owns
// that behavior; make the isolation explicit so App's production fail-closed nil
// checks do not turn an unrelated fixture omission into an account leak.
func noDeferredJobs(string, int) error { return nil }
func noDeferredJobDrain() error        { return nil }

func TestInviteThenRevokeEndToEnd(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	const username = "ltae2euser"
	forceDelete := func() { _ = exec.Command("userdel", "-r", "--", username).Run() }
	forceDelete()
	t.Cleanup(forceDelete)

	regDir := rootDir(t, 0o700)
	sudoDir := rootDir(t, 0o750)
	sshdDir := rootDir(t, 0o755)
	installPath := filepath.Join(rootDir(t, 0o755), "linux-temp-admin")
	// A safe stable-command stub that reports the development build's version.
	if err := os.WriteFile(installPath, []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 0.0.0-dev\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) }
	auditFile := filepath.Join(rootDir(t, 0o700), "audit.log")

	var out, errb bytes.Buffer
	app := &cli.App{
		Out:     &out,
		Err:     &errb,
		In:      strings.NewReader(""),
		P:       i18n.Printer{Lang: i18n.EN},
		Users:   user.New(),
		Sudoers: &sudoers.Manager{Dir: sudoDir, Validate: func([]byte) error { return nil }, Verify: func(string) error { return nil }},
		Scheduler: &schedule.Scheduler{
			SystemdDir: rootDir(t, 0o755), InstallPath: installPath,
			UnitPrefix: config.AutoRevokeUnitPrefix, Now: now, Sys: fakeSched{},
		},
		Registry: &registry.Store{
			Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
		},
		SSHD: &sshdconf.Manager{
			Dir: sshdDir, Validate: func() error { return nil }, Reload: func() error { return nil },
			Effective: func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdOK), nil },
		},
		SSHDConfig:               func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdOK), nil },
		SSHDHasUnverifiableMatch: func(bool) bool { return false },
		Detector:                 netdetect.New(),
		Selfmanage:               &selfmanage.Manager{InstallPath: installPath},
		Audit: &audit.Logger{
			Dir: filepath.Dir(auditFile), File: auditFile, Now: now,
			Actor: func() (string, int) { return "e2e", 0 },
		},
		InstallPath: installPath,
		Executable:  func() (string, error) { return installPath, nil },
		Now:         now,
		RandHex: func(n int) (string, error) {
			if n == 16 {
				return "0123456789abcdef0123456789abcdef", nil
			}
			return "abcdef0123", nil
		},
		StdoutIsTTY:        func() bool { return true },
		StdinIsTTY:         func() bool { return false },
		Geteuid:            func() int { return 0 },
		ClearScheduledJobs: noDeferredJobs,
		DrainScheduledJobs: noDeferredJobDrain,
	}

	// --- invite ---
	rc := app.Dispatch([]string{"invite", "--user", username, "--host", "203.0.113.5",
		"--hours", "24", "--sudo", "--confirm-sudo", username, "--yes"})
	if rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, errb.String())
	}

	if !mustExternalUserExists(t, username) {
		t.Fatal("account should exist after invite")
	}
	pw, _ := mustExternalUserLookup(t, username)
	ak := filepath.Join(pw.Home, ".ssh", "authorized_keys")
	akBytes, err := os.ReadFile(ak)
	if err != nil {
		t.Fatalf("authorized_keys: %v", err)
	}
	if !strings.HasPrefix(string(akBytes), "ssh-ed25519 ") {
		t.Errorf("authorized_keys does not look like an ed25519 key: %q", akBytes)
	}
	if fi, _ := os.Lstat(ak); fi.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode = %o, want 600", fi.Mode().Perm())
	}
	rec, found, err := app.Registry.Lookup(username)
	if err != nil || !found {
		t.Fatalf("registry should contain the user after invite: found=%v err=%v", found, err)
	}
	if !rec.IdentityBound || rec.Generation == "" || !user.MatchesManagedGeneration(pw, rec.Generation) {
		t.Fatalf("invite identity is not generation-bound: rec=%+v passwd=%+v", rec, pw)
	}
	if _, err := os.Lstat(filepath.Join(sudoDir, "linux-temp-admin-"+username)); err != nil {
		t.Errorf("sudoers drop-in missing: %v", err)
	}
	inviteOut := out.String()
	for _, want := range []string{"BEGIN LINUX TEMP ADMIN INVITE", "OPENSSH PRIVATE KEY",
		// The save-key command is kept; the SSH login command was removed from the
		// bundle, so assert the key delivery, not a login line.
		"cat > './" + username + ".key'", "Sudo: yes",
		// The Login line is now a verdict, not a slogan: it may only claim a key
		// login on a host whose effective sshd config was read and said yes.
		"Login: SSH key only (verified"} {
		if !strings.Contains(inviteOut, want) {
			t.Errorf("invite output missing %q", want)
		}
	}
	// The removed sections must be gone.
	for _, gone := range []string{"ssh -i ./", "Revoke command:", "revoke --user", "Sudo note:"} {
		if strings.Contains(inviteOut, gone) {
			t.Errorf("invite output should no longer contain %q", gone)
		}
	}
	// sshd already accepts keys here, so the tool must not have touched it.
	if ents, _ := os.ReadDir(sshdDir); len(ents) != 0 {
		t.Errorf("invite wrote an sshd drop-in on a host that did not need one: %v", ents)
	}
	if b, err := os.ReadFile(auditFile); err != nil {
		t.Errorf("audit log after invite: %v", err)
	} else if !strings.Contains(string(b), `"account.create"`) || !strings.Contains(string(b), username) {
		t.Errorf("audit log missing account.create for %s:\n%s", username, b)
	}

	// --- revoke ---
	out.Reset()
	errb.Reset()
	rc = app.Dispatch([]string{"revoke", "--user", username, "--yes"})
	if rc != 0 {
		t.Fatalf("revoke rc=%d\nstderr:\n%s", rc, errb.String())
	}
	if mustExternalUserExists(t, username) {
		t.Error("account should be gone after revoke")
	}
	if ok, _ := app.Registry.Contains(username); ok {
		t.Error("registry should not contain the user after revoke")
	}
	if _, err := os.Lstat(filepath.Join(sudoDir, "linux-temp-admin-"+username)); !os.IsNotExist(err) {
		t.Error("sudoers drop-in should be removed after revoke")
	}
	if b, err := os.ReadFile(auditFile); err != nil {
		t.Errorf("audit log after revoke: %v", err)
	} else if !strings.Contains(string(b), `"account.delete"`) {
		t.Errorf("audit log missing account.delete:\n%s", b)
	}
}

func TestInviteRollsBackWhenAutoDeleteCannotBeScheduled(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	const name = "lta-nosched1"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	a, _, _, _ := inviteApp(t)
	a.Scheduler.Sys = unavailableSched{}
	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "1", "--no-sudo", "--no-fix-sshd", "--auto-revoke", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want failure when no exact auto-delete task can be created", rc)
	}
	if mustExternalUserExists(t, name) {
		t.Fatal("account survived the failed auto-delete transaction")
	}
	if ok, err := a.Registry.Contains(name); err != nil || ok {
		t.Fatalf("registry contains rolled-back account: ok=%v err=%v", ok, err)
	}
	if strings.Contains(a.Out.(*bytes.Buffer).String(), "BEGIN LINUX TEMP ADMIN INVITE") {
		t.Fatal("credentials were printed for an account that could not be scheduled")
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), "auto-delete scheduling failed") {
		t.Fatalf("failure did not identify the scheduler: %s", a.Err.(*bytes.Buffer).String())
	}
}

func TestInvitePersistsIdentityIntentBeforeScheduling(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	const name = "lta-intent1"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	a, _, _, _ := inviteApp(t)
	tracker := newTrackingSched()
	a.Scheduler.Sys = tracker
	sawIntent := false
	tracker.beforeSchedule = func(command string) error {
		rec, found, err := a.Registry.Lookup(name)
		if err != nil {
			return err
		}
		if !found || !rec.AutoRevoke || rec.AutoUnit != "" || rec.UID < 1 || rec.Generation == "" {
			return fmt.Errorf("missing durable scheduling intent: found=%v record=%+v", found, rec)
		}
		if !strings.Contains(command, "--expected-uid "+strconv.Itoa(rec.UID)) ||
			!strings.Contains(command, "--generation "+rec.Generation) {
			return fmt.Errorf("scheduled identity does not match registry intent: %q vs %+v", command, rec)
		}
		sawIntent = true
		return nil
	}

	if rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "1", "--no-sudo", "--no-fix-sshd", "--auto-revoke", "--yes"}); rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if !sawIntent {
		t.Fatal("scheduler ran before the registry intent was observed")
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil || !found || rec.AutoUnit != "at:1" {
		t.Fatalf("final schedule was not committed to the registry: found=%v rec=%+v err=%v", found, rec, err)
	}
}

func TestInvitePersistsAccountIntentBeforeCredentialMutation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	const name = "lta-accountintent1"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	a, _, _, _ := inviteApp(t)
	probes := 0
	sawIntent := false
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		probes++
		if probes == 2 {
			rec, found, err := a.Registry.Lookup(name)
			if err != nil {
				t.Fatal(err)
			}
			if !found || rec.UID < 1 || rec.User != name {
				t.Fatalf("account identity was not durable before login confirmation: found=%v rec=%+v", found, rec)
			}
			pw, exists := mustExternalUserLookup(t, name)
			if !exists {
				t.Fatal("account did not exist at its post-create login confirmation")
			}
			if _, err := os.Lstat(filepath.Join(pw.Home, ".ssh", "authorized_keys")); !os.IsNotExist(err) {
				t.Fatalf("credentials existed before durable identity intent: %v", err)
			}
			sawIntent = true
		}
		return sysinfo.ParseSSHD(sshdOK), nil
	}

	if rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--no-sudo", "--no-fix-sshd", "--no-auto-revoke", "--yes"}); rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
	if !sawIntent {
		t.Fatal("post-create login confirmation did not observe durable account intent")
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil || !found || !rec.IdentityBound || rec.Generation == "" {
		t.Fatalf("permanent invite lacks a bound generation: found=%v rec=%+v err=%v", found, rec, err)
	}
	pw, exists := mustExternalUserLookup(t, name)
	if !exists || !user.MatchesManagedGeneration(pw, rec.Generation) {
		t.Fatalf("permanent invite passwd marker does not match registry generation: exists=%v pw=%+v rec=%+v", exists, pw, rec)
	}
	if rc := a.Dispatch([]string{"revoke", "--user", name, "--yes"}); rc != 0 {
		t.Fatalf("cleanup revoke rc=%d\nstderr:\n%s", rc, a.Err.(*bytes.Buffer).String())
	}
}

func TestInviteRollsBackWhenExplicitSudoGrantFails(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	const name = "lta-sudofail2"
	remove := func() { _ = exec.Command("userdel", "-r", "-f", "--", name).Run() }
	remove()
	t.Cleanup(remove)

	a, sudoMgr, _, _ := inviteApp(t)
	sudoMgr.Validate = func([]byte) error { return errors.New("injected sudo validation failure") }
	rc := a.Dispatch([]string{"invite", "--user", name, "--host", "203.0.113.5",
		"--hours", "1", "--sudo", "--confirm-sudo", name, "--no-auto-revoke", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want failure for an explicitly requested sudo grant", rc)
	}
	if mustExternalUserExists(t, name) {
		t.Fatal("account survived the failed sudo transaction as a silently downgraded user")
	}
	if ok, err := a.Registry.Contains(name); err != nil || ok {
		t.Fatalf("registry contains rolled-back account: ok=%v err=%v", ok, err)
	}
	if _, err := os.Lstat(sudoMgr.FilePath(name)); !os.IsNotExist(err) {
		t.Fatalf("failed sudo grant left a drop-in: %v", err)
	}
	if strings.Contains(a.Out.(*bytes.Buffer).String(), "BEGIN LINUX TEMP ADMIN INVITE") {
		t.Fatal("credentials were printed after the requested sudo grant failed")
	}
	if !strings.Contains(a.Err.(*bytes.Buffer).String(), "refusing to create the account") {
		t.Fatalf("failure did not preserve sudo transaction semantics: %s", a.Err.(*bytes.Buffer).String())
	}
}

// TestInviteFixSSHDThenRevokeEndToEnd covers the path this whole feature exists
// for: a host whose sshd refuses public-key logins. The invite must write a
// per-account exception, prove it, and print a verified invite -- and revoke must
// take the exception away again, leaving the host as it was found.
func TestInviteFixSSHDThenRevokeEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	const username = "ltae2efix"
	forceDelete := func() { _ = exec.Command("userdel", "-r", "--", username).Run() }
	forceDelete()
	t.Cleanup(forceDelete)

	regDir := rootDir(t, 0o700)
	sudoDir := rootDir(t, 0o750)
	sshdDir := rootDir(t, 0o755)
	installPath := filepath.Join(rootDir(t, 0o755), "linux-temp-admin")
	if err := os.WriteFile(installPath, []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 0.0.0-dev\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) }

	// The host refuses keys until the drop-in exists: the manager's own probe is
	// what decides, so a grant that failed to take effect would fail the invite.
	dropIn := filepath.Join(sshdDir, "10-linux-temp-admin-"+username+".conf")
	effective := func(string) (*sysinfo.SSHDConfig, error) {
		if _, err := os.Lstat(dropIn); err == nil {
			return sysinfo.ParseSSHD(sshdOK), nil
		}
		return sysinfo.ParseSSHD(sshdNoPubkey), nil
	}
	reloads := 0

	var out, errb bytes.Buffer
	app := &cli.App{
		Out: &out, Err: &errb, In: strings.NewReader(""),
		P:       i18n.Printer{Lang: i18n.EN},
		Users:   user.New(),
		Sudoers: &sudoers.Manager{Dir: sudoDir, Validate: func([]byte) error { return nil }, Verify: func(string) error { return nil }},
		SSHD: &sshdconf.Manager{
			Dir: sshdDir, Validate: func() error { return nil }, Effective: effective,
			Reload: func() error { reloads++; return nil },
		},
		SSHDConfig:               effective,
		SSHDHasUnverifiableMatch: func(bool) bool { return false },
		Scheduler: &schedule.Scheduler{
			SystemdDir: rootDir(t, 0o755), InstallPath: installPath,
			UnitPrefix: config.AutoRevokeUnitPrefix, Now: now, Sys: fakeSched{},
		},
		Registry: &registry.Store{
			Dir: regDir, File: filepath.Join(regDir, "registry.tsv"), Lock: filepath.Join(regDir, "registry.lock"),
		},
		Detector:    netdetect.New(),
		Selfmanage:  &selfmanage.Manager{InstallPath: installPath},
		InstallPath: installPath,
		Executable:  func() (string, error) { return installPath, nil },
		Now:         now,
		RandHex: func(n int) (string, error) {
			if n == 16 {
				return "0123456789abcdef0123456789abcdef", nil
			}
			return "abcdef0123", nil
		},
		StdoutIsTTY:        func() bool { return true },
		StdinIsTTY:         func() bool { return false },
		Geteuid:            func() int { return 0 },
		ClearScheduledJobs: noDeferredJobs,
		DrainScheduledJobs: noDeferredJobDrain,
	}

	// Without --fix-sshd, a non-interactive invite must refuse and change nothing:
	// a script must never quietly rewrite a remote host's sshd configuration.
	rc := app.Dispatch([]string{"invite", "--user", username, "--host", "203.0.113.5", "--hours", "24", "--yes"})
	if rc == 0 {
		t.Fatal("invite should refuse on a host that rejects keys when --fix-sshd was not passed")
	}
	if mustExternalUserExists(t, username) {
		t.Fatal("a refused invite must not create an account")
	}
	if ents, _ := os.ReadDir(sshdDir); len(ents) != 0 {
		t.Fatalf("a refused invite must not touch sshd: %v", ents)
	}

	// With --fix-sshd it goes through, and the invite may claim a verified key login.
	out.Reset()
	errb.Reset()
	rc = app.Dispatch([]string{"invite", "--user", username, "--host", "203.0.113.5",
		"--hours", "24", "--fix-sshd", "--yes"})
	if rc != 0 {
		t.Fatalf("invite --fix-sshd rc=%d\nstderr:\n%s", rc, errb.String())
	}
	if _, err := os.Lstat(dropIn); err != nil {
		t.Fatalf("sshd drop-in missing after --fix-sshd: %v", err)
	}
	body, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	// The exception must be scoped to this one account and lift only what was
	// actually blocking: a global directive here would change every other login.
	if !strings.Contains(string(body), "Match User "+username) {
		t.Errorf("drop-in is not scoped to the account:\n%s", body)
	}
	if !strings.Contains(string(body), "PubkeyAuthentication yes") {
		t.Errorf("drop-in does not lift the blocker:\n%s", body)
	}
	if strings.Contains(string(body), "AuthorizedKeysFile") {
		t.Errorf("drop-in carries a directive nothing was blocking on:\n%s", body)
	}
	if reloads == 0 {
		t.Error("sshd was never reloaded, so the grant could not have taken effect")
	}
	if !strings.Contains(out.String(), "Login: SSH key only (verified") {
		t.Errorf("invite does not claim a verified key login:\n%s", out.String())
	}

	// --- revoke puts the host back ---
	rc = app.Dispatch([]string{"revoke", "--user", username, "--yes"})
	if rc != 0 {
		t.Fatalf("revoke rc=%d\nstderr:\n%s", rc, errb.String())
	}
	if _, err := os.Lstat(dropIn); !os.IsNotExist(err) {
		t.Error("revoke must remove the sshd exception it created")
	}
	if ents, _ := os.ReadDir(sshdDir); len(ents) != 0 {
		t.Errorf("revoke left something behind in sshd_config.d: %v", ents)
	}
}
