//go:build integration

package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/cli"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/netdetect"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

// fakeSched satisfies schedule.System without touching real systemd/at.
type fakeSched struct{}

func (fakeSched) HasSystemctl() bool                     { return false }
func (fakeSched) Systemctl(...string) error              { return nil }
func (fakeSched) HasAt() bool                            { return true }
func (fakeSched) ScheduleAt(string, int) (string, error) { return "1", nil }
func (fakeSched) RemoveAtJobsFor(string)                 {}

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
	installPath := filepath.Join(rootDir(t, 0o755), "linux-temp-admin")
	// A stub at InstallPath so ensureStableInstalled treats it as present.
	if err := os.WriteFile(installPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) }

	var out, errb bytes.Buffer
	app := &cli.App{
		Out:     &out,
		Err:     &errb,
		In:      strings.NewReader(""),
		P:       i18n.Printer{Lang: i18n.EN},
		Users:   user.New(),
		Sudoers: &sudoers.Manager{Dir: sudoDir, Validate: func(string) error { return nil }, Verify: func(string) error { return nil }},
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
		Now:         now,
		RandHex:     func(int) (string, error) { return "abcdef0123", nil },
		StdoutIsTTY: func() bool { return true },
		StdinIsTTY:  func() bool { return false },
		Geteuid:     func() int { return 0 },
	}

	// --- invite ---
	rc := app.Dispatch([]string{"invite", "--user", username, "--host", "203.0.113.5",
		"--hours", "24", "--sudo", "--confirm-sudo", username, "--yes"})
	if rc != 0 {
		t.Fatalf("invite rc=%d\nstderr:\n%s", rc, errb.String())
	}

	if !user.Exists(username) {
		t.Fatal("account should exist after invite")
	}
	pw, _ := user.Lookup(username)
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
	if ok, _ := app.Registry.Contains(username); !ok {
		t.Error("registry should contain the user after invite")
	}
	if _, err := os.Lstat(filepath.Join(sudoDir, "linux-temp-admin-"+username)); err != nil {
		t.Errorf("sudoers drop-in missing: %v", err)
	}
	inviteOut := out.String()
	for _, want := range []string{"BEGIN LINUX TEMP ADMIN INVITE", "OPENSSH PRIVATE KEY",
		"ssh -i ./" + username + ".key", "Sudo: yes"} {
		if !strings.Contains(inviteOut, want) {
			t.Errorf("invite output missing %q", want)
		}
	}

	// --- revoke ---
	out.Reset()
	errb.Reset()
	rc = app.Dispatch([]string{"revoke", "--user", username, "--yes"})
	if rc != 0 {
		t.Fatalf("revoke rc=%d\nstderr:\n%s", rc, errb.String())
	}
	if user.Exists(username) {
		t.Error("account should be gone after revoke")
	}
	if ok, _ := app.Registry.Contains(username); ok {
		t.Error("registry should not contain the user after revoke")
	}
	if _, err := os.Lstat(filepath.Join(sudoDir, "linux-temp-admin-"+username)); !os.IsNotExist(err) {
		t.Error("sudoers drop-in should be removed after revoke")
	}
}
