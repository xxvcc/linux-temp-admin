package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

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
		{"none", "PermitRootLogin no\n", 0, false},
		{"out of range", "Port 99999\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "sshd_config")
			if err := os.WriteFile(p, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, ok := sshPortFromConfig(p)
			if got != c.want || ok != c.ok {
				t.Errorf("= (%d,%v), want (%d,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestSSHPortDefault(t *testing.T) {
	old := sshdConfigPath
	sshdConfigPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { sshdConfigPath = old })
	// No sshd and no config => default 22 (sshd may exist on this host; only assert
	// the config path fallback via sshPortFromConfig here).
	if _, ok := sshPortFromConfig(sshdConfigPath); ok {
		t.Error("missing config should not yield a port")
	}
}

func TestPackageCandidate(t *testing.T) {
	if got := PackageCandidate("chage", "apt"); got != "passwd" {
		t.Errorf("chage/apt = %q, want passwd", got)
	}
	if got := PackageCandidate("useradd/adduser", "apk"); got != "shadow" {
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
}

func TestRequiredDepsShape(t *testing.T) {
	// Without sudo: id plus 4 account deps. With sudo: 6.
	if n := len(RequiredDeps(false)); n != 5 {
		t.Errorf("RequiredDeps(false) has %d deps, want 5", n)
	}
	if n := len(RequiredDeps(true)); n != 6 {
		t.Errorf("RequiredDeps(true) has %d deps, want 6", n)
	}
}
