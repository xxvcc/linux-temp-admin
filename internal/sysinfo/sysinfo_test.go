package sysinfo

import (
	"context"
	"errors"
	"fmt"
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
		wantErr bool
	}{
		{name: "explicit", content: "Port 2222\n", want: 2222, ok: true},
		{name: "explicit equals", content: "Port=2223\n", want: 2223, ok: true},
		{name: "commented", content: "#Port 2222\n"},
		{name: "commented include", content: "# Include ports.conf\n"},
		{name: "inline commented include", content: "PermitRootLogin no # Include ports.conf\n"},
		{name: "include before direct port", content: "Include ports.conf\nPort 2224\n", want: 2224, ok: true},
		{name: "direct port before include", content: "Port=2225\nInclude=ports.conf\n", want: 2225, ok: true},
		{name: "active include without direct port", content: "Include ports.conf\n", wantErr: true},
		{name: "active equals include without direct port", content: "Include=ports.conf\n", wantErr: true},
		{name: "first wins", content: "Port 1000\nPort 2020\n", want: 1000, ok: true},
		{name: "indented", content: "   Port 2200\n", want: 2200, ok: true},
		{name: "long preceding line", content: strings.Repeat("x", 70<<10) + "\nPort 2201\n", want: 2201, ok: true},
		{name: "none", content: "PermitRootLogin no\n"},
		{name: "out of range", content: "Port 99999\n", wantErr: true},
		{name: "not numeric", content: "Port ssh\n", wantErr: true},
		{name: "missing value", content: "Port\n", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "sshd_config")
			if err := os.WriteFile(p, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, ok, err := sshPortFromConfig(p)
			if c.wantErr {
				if err == nil || ok {
					t.Fatalf("= (%d,%v,%v), want parse failure", got, ok, err)
				}
				return
			}
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

func TestDetectSSHPortReportsFallbackDiagnostics(t *testing.T) {
	oldCommand, oldConfig := sshdCommand, sshdConfigPath
	t.Cleanup(func() { sshdCommand, sshdConfigPath = oldCommand, oldConfig })

	t.Run("missing sshd and config uses documented default", func(t *testing.T) {
		sshdCommand = filepath.Join(t.TempDir(), "missing-sshd")
		sshdConfigPath = filepath.Join(t.TempDir(), "missing-config")
		port, err := DetectSSHPort()
		if err != nil || port != 22 {
			t.Fatalf("DetectSSHPort = (%d, %v), want (22, nil)", port, err)
		}
	})

	t.Run("static config is used when sshd is unavailable", func(t *testing.T) {
		sshdCommand = filepath.Join(t.TempDir(), "missing-sshd")
		sshdConfigPath = filepath.Join(t.TempDir(), "sshd_config")
		if err := os.WriteFile(sshdConfigPath, []byte("Port 2208\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		port, err := DetectSSHPort()
		if err != nil || port != 2208 {
			t.Fatalf("DetectSSHPort = (%d, %v), want (2208, nil)", port, err)
		}
	})

	t.Run("static include without direct port is incomplete", func(t *testing.T) {
		sshdCommand = filepath.Join(t.TempDir(), "missing-sshd")
		sshdConfigPath = filepath.Join(t.TempDir(), "sshd_config")
		if err := os.WriteFile(sshdConfigPath, []byte("Include sshd_config.d/*.conf\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		port, err := DetectSSHPort()
		if err == nil || port != 22 || !strings.Contains(err.Error(), "static port detection is incomplete") {
			t.Fatalf("DetectSSHPort = (%d, %v), want diagnosed incomplete static fallback", port, err)
		}
	})

	t.Run("config parse failure is not disguised as port 22", func(t *testing.T) {
		sshdCommand = filepath.Join(t.TempDir(), "missing-sshd")
		sshdConfigPath = filepath.Join(t.TempDir(), "sshd_config")
		if err := os.WriteFile(sshdConfigPath, []byte("Port invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		port, err := DetectSSHPort()
		if err == nil || port != 22 || !strings.Contains(err.Error(), "invalid Port") {
			t.Fatalf("DetectSSHPort = (%d, %v), want diagnostic with best-effort port 22", port, err)
		}
	})

	t.Run("failed effective probe reports static fallback", func(t *testing.T) {
		dir := t.TempDir()
		sshdCommand = writeSysinfoCommand(t, dir, "sshd", `exit 19`)
		sshdConfigPath = filepath.Join(dir, "sshd_config")
		if err := os.WriteFile(sshdConfigPath, []byte("Port 2209\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		port, err := DetectSSHPort()
		if err == nil || port != 2209 || !strings.Contains(err.Error(), "effective SSH port probe failed") {
			t.Fatalf("DetectSSHPort = (%d, %v), want diagnosed static fallback", port, err)
		}
	})

	t.Run("valid effective probe is authoritative", func(t *testing.T) {
		dir := t.TempDir()
		sshdCommand = writeSysinfoCommand(t, dir, "sshd", `printf 'port 2210\n'`)
		sshdConfigPath = filepath.Join(dir, "missing-config")
		port, err := DetectSSHPort()
		if err != nil || port != 2210 {
			t.Fatalf("DetectSSHPort = (%d, %v), want (2210, nil)", port, err)
		}
	})
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

	for _, tc := range []struct {
		name               string
		updateExit         int
		installExit        int
		wantUpdateFailure  bool
		wantInstallFailure bool
	}{
		{name: "apt success"},
		{name: "apt update failure after completed install remains an error", updateExit: 41, wantUpdateFailure: true},
		{name: "apt install failure", installExit: 42, wantInstallFailure: true},
		{name: "apt update and install failure", updateExit: 41, installExit: 42, wantUpdateFailure: true, wantInstallFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packageCommandOptions = old
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			body := fmt.Sprintf(`printf '%%s\n' "$1" >> %q
case "$1" in
update) printf 'update diagnostic'; exit %d ;;
install) printf 'install diagnostic'; exit %d ;;
*) exit 99 ;;
esac`, calls, tc.updateExit, tc.installExit)
			writeSysinfoCommand(t, dir, "apt-get", body)
			t.Setenv("PATH", dir)

			err := InstallPackages("apt", []string{"sudo"})
			if !tc.wantUpdateFailure && !tc.wantInstallFailure {
				if err != nil {
					t.Fatalf("InstallPackages apt success error = %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("InstallPackages apt unexpectedly succeeded")
				}
				if got := strings.Contains(err.Error(), "apt-get update") && strings.Contains(err.Error(), "update diagnostic"); got != tc.wantUpdateFailure {
					t.Fatalf("update failure present=%v, want %v: %v", got, tc.wantUpdateFailure, err)
				}
				if got := strings.Contains(err.Error(), "apt-get install") && strings.Contains(err.Error(), "install diagnostic"); got != tc.wantInstallFailure {
					t.Fatalf("install failure present=%v, want %v: %v", got, tc.wantInstallFailure, err)
				}
			}
			gotCalls, readErr := os.ReadFile(calls)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(gotCalls) != "update\ninstall\n" {
				t.Fatalf("apt calls = %q, want update then install", gotCalls)
			}
		})
	}

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
	if got := PackageCandidate("groupdel", "apt"); got != "passwd" {
		t.Errorf("groupdel/apt = %q, want passwd", got)
	}
}

func TestRequiredDepsShape(t *testing.T) {
	// Base: id plus 5 account deps. Password and sudo features add their own
	// helpers without making them mandatory for key-only, non-sudo invites.
	deps := RequiredDeps(false, false)
	if n := len(deps); n != 6 {
		t.Errorf("RequiredDeps(false, false) has %d deps, want 6", n)
	}
	if n := len(RequiredDeps(false, true)); n != 7 {
		t.Errorf("RequiredDeps(false, true) has %d deps, want 7", n)
	}
	if n := len(RequiredDeps(true, false)); n != 8 {
		t.Errorf("RequiredDeps(true, false) has %d deps, want 8", n)
	}
	if n := len(RequiredDeps(true, true)); n != 9 {
		t.Errorf("RequiredDeps(true, true) has %d deps, want 9", n)
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
	foundGroupDelete := false
	for _, dep := range deps {
		if dep.Label == "useradd" {
			foundCreate = len(dep.Names) == 1 && dep.Names[0] == "useradd"
		}
		if dep.Label == "userdel" {
			foundDelete = len(dep.Names) == 1 && dep.Names[0] == "userdel"
		}
		if dep.Label == "groupdel" {
			foundGroupDelete = len(dep.Names) == 1 && dep.Names[0] == "groupdel"
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
	if !foundGroupDelete {
		t.Fatalf("RequiredDeps does not require groupdel: %+v", deps)
	}
	if got := PackageCandidate("userdel", "apt"); got != "passwd" {
		t.Errorf("PackageCandidate(userdel, apt) = %q, want passwd", got)
	}
	if got := PackageCandidate("groupdel", "apk"); got != "shadow" {
		t.Errorf("PackageCandidate(groupdel, apk) = %q, want shadow", got)
	}
}

func TestMissingDepsReportsGroupdelAsBaseDependency(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"id", "useradd", "usermod", "chage", "userdel"} {
		writeSysinfoCommand(t, dir, name, "exit 0")
	}
	t.Setenv("PATH", dir)

	missing := MissingDeps(false, false)
	if len(missing) != 1 || missing[0] != "groupdel" {
		t.Fatalf("MissingDeps(false, false) = %v, want [groupdel]", missing)
	}
}
