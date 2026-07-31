package sysinfo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"golang.org/x/sys/unix"
)

func writeSysinfoCommand(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSSHPortFromConfig(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
		ok      bool
	}{
		{"explicit", "Port 2222\n", 2222, true},
		{"commented", "#Port 2222\n", 0, false},
		{"first wins", "Port 1000\nPort 2020\n", 1000, true},
		{"indented", "   Port 2200\n", 2200, true},
		{"long preceding line", strings.Repeat("x", 70<<10) + "\nPort 2201\n", 2201, true},
		{"none", "PermitRootLogin no\n", 0, false},
		{"out of range", "Port 99999\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "sshd_config")
			if err := os.WriteFile(p, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, ok, err := sshPortFromConfig(p)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want || ok != c.ok {
				t.Errorf("= (%d,%v), want (%d,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestSSHPortFromConfigReportsScanFailure(t *testing.T) {
	for _, content := range []string{
		strings.Repeat("x", maxSSHDConfigLine+1) + "\nPort 2202\n",
		"Port 2202\n" + strings.Repeat("x", maxSSHDConfigLine+1),
	} {
		p := filepath.Join(t.TempDir(), "sshd_config")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := sshPortFromConfig(p); err == nil || ok {
			t.Fatalf("sshPortFromConfig = ok %v, err %v; want scanner failure", ok, err)
		}
	}
}

func TestSSHPortFromConfigRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("Port 2202\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sshPortFromConfig(link); err == nil {
		t.Fatal("symlinked sshd config was accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := sshPortFromConfig(fifo); err == nil || !strings.Contains(err.Error(), "not a regular") {
		t.Fatalf("FIFO config error = %v, want special-file refusal", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("FIFO config blocked for %s", elapsed)
	}
}

func TestSSHPortFromConfigRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxSSHDConfigBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sshPortFromConfig(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized config error = %v, want bounded-read refusal", err)
	}
}

func TestSSHPortDefault(t *testing.T) {
	old := sshdConfigPath
	sshdConfigPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { sshdConfigPath = old })
	// No sshd and no config => default 22 (sshd may exist on this host; only assert
	// the config path fallback via sshPortFromConfig here).
	if _, ok, err := sshPortFromConfig(sshdConfigPath); ok || err == nil {
		t.Error("missing config should not yield a port")
	}
}

func TestInstallPackagesUsesLongBoundedExecution(t *testing.T) {
	old := packageCommandOptions
	t.Cleanup(func() { packageCommandOptions = old })

	t.Run("locale and argv", func(t *testing.T) {
		packageCommandOptions = old
		dir := t.TempDir()
		writeSysinfoCommand(t, dir, "dnf", `[ "$DEBIAN_FRONTEND:$LC_ALL:$LANG:$*" = "noninteractive:C:C:install -y sudo passwd" ]`)
		t.Setenv("PATH", dir)
		if err := InstallPackages("dnf", []string{"sudo", "passwd"}); err != nil {
			t.Fatalf("InstallPackages did not preserve env/argv: %v", err)
		}
	})

	t.Run("pacman refuses an implicit partial or full upgrade", func(t *testing.T) {
		packageCommandOptions = old
		dir := t.TempDir()
		writeSysinfoCommand(t, dir, "pacman", `exit 99`)
		t.Setenv("PATH", dir)
		if err := InstallPackages("pacman", []string{"sudo", "shadow"}); err == nil || !strings.Contains(err.Error(), "partial upgrades") {
			t.Fatalf("InstallPackages pacman error = %v, want an explicit partial-upgrade refusal", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		dir := t.TempDir()
		writeSysinfoCommand(t, dir, "dnf", `/bin/sleep 30 & wait`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = 50 * time.Millisecond
		packageCommandOptions = opts
		if err := InstallPackages("dnf", []string{"sudo"}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("InstallPackages error = %v, want timeout", err)
		}
	})

	t.Run("output limit", func(t *testing.T) {
		dir := t.TempDir()
		writeSysinfoCommand(t, dir, "dnf", `while :; do printf 0123456789abcdef; done`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = time.Second
		opts.MaxOutput = 64
		packageCommandOptions = opts
		if err := InstallPackages("dnf", []string{"sudo"}); !errors.Is(err, executil.ErrOutputLimit) {
			t.Fatalf("InstallPackages error = %v, want output limit", err)
		}
	})
}

func TestPackageCandidate(t *testing.T) {
	if got := PackageCandidate("chage", "apt"); got != "passwd" {
		t.Errorf("chage/apt = %q, want passwd", got)
	}
	if got := PackageCandidate("useradd", "apk"); got != "shadow" {
		t.Errorf("useradd/apk = %q, want shadow", got)
	}
	if got := PackageCandidate("chage", "dnf"); got != "shadow-utils" {
		t.Errorf("chage/dnf = %q, want shadow-utils", got)
	}
	if got := PackageCandidate("id", "apk"); got != "coreutils" {
		t.Errorf("id/apk = %q, want coreutils", got)
	}
	if got := PackageCandidate("unknown-tool", "apt"); got != "" {
		t.Errorf("unknown = %q, want empty", got)
	}
	if got := PackageCandidate("chpasswd", "apk"); got != "shadow" {
		t.Errorf("chpasswd/apk = %q, want shadow", got)
	}
}

func TestRequiredDepsShape(t *testing.T) {
	// Base: id plus 4 account deps. Password and sudo features add their own
	// helpers without making them mandatory for key-only, non-sudo invites.
	deps := RequiredDeps(false, false)
	if n := len(deps); n != 5 {
		t.Errorf("RequiredDeps(false, false) has %d deps, want 5", n)
	}
	if n := len(RequiredDeps(false, true)); n != 6 {
		t.Errorf("RequiredDeps(false, true) has %d deps, want 6", n)
	}
	if n := len(RequiredDeps(true, false)); n != 7 {
		t.Errorf("RequiredDeps(true, false) has %d deps, want 7", n)
	}
	if n := len(RequiredDeps(true, true)); n != 8 {
		t.Errorf("RequiredDeps(true, true) has %d deps, want 8", n)
	}
	passwordDep := false
	for _, dep := range RequiredDeps(false, true) {
		if dep.Label == "chpasswd" && len(dep.Names) == 1 && dep.Names[0] == "chpasswd" {
			passwordDep = true
		}
	}
	if !passwordDep {
		t.Fatal("password mode did not require chpasswd")
	}
	if got := PackageCandidate("visudo", "apt"); got != "sudo" {
		t.Errorf("PackageCandidate(visudo, apt) = %q, want sudo", got)
	}
	foundCreate := false
	foundDelete := false
	for _, dep := range deps {
		if dep.Label == "useradd" {
			foundCreate = len(dep.Names) == 1 && dep.Names[0] == "useradd"
		}
		if dep.Label == "userdel" {
			foundDelete = len(dep.Names) == 1 && dep.Names[0] == "userdel"
		}
		for _, name := range dep.Names {
			if name == "adduser" || name == "deluser" || name == "busybox" {
				t.Errorf("RequiredDeps accepts an account helper with unproven semantics: %+v", dep)
			}
		}
	}
	if !foundCreate {
		t.Fatalf("RequiredDeps does not require useradd: %+v", deps)
	}
	if !foundDelete {
		t.Fatalf("RequiredDeps does not require userdel: %+v", deps)
	}
	if got := PackageCandidate("userdel", "apt"); got != "passwd" {
		t.Errorf("PackageCandidate(userdel, apt) = %q, want passwd", got)
	}
}
