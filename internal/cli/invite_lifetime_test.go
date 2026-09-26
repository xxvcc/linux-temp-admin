package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
)

func TestPromptLifetimeKeepsExpiryUnlessPermanenceIsExplicit(t *testing.T) {
	for _, tc := range []struct {
		name, input         string
		allowPermanent, tty bool
		hours               int
		automatic, ok       bool
	}{
		{"default", "\n", true, true, 24, true, true},
		{"custom", "48\n", true, true, 48, true, true},
		{"maximum", fmt.Sprint(config.MaxExpireHours) + "\n", true, true, config.MaxExpireHours, true, true},
		{"permanent", "never\n", true, true, 24, false, true},
		{"permanent keyword case", "NEVER\n", true, true, 24, false, true},
		{"typos do not disable expiry", "n\nno\n0\n-1\n99999999\n24\n", true, true, 24, true, true},
		{"explicit automatic rejects permanent", "never\n12\n", false, true, 12, true, true},
		{"EOF cancels", "", true, true, 24, false, false},
		{"EOF after typo cancels", "nevre\n", true, true, 24, false, false},
		{"invalid pipe stops", "wrong\nnever\n", true, false, 24, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := newTestApp(t, tc.input)
			a.StdinIsTTY = func() bool { return tc.tty }
			hours, automatic, ok := a.promptLifetime(24, tc.allowPermanent)
			if hours != tc.hours || automatic != tc.automatic || ok != tc.ok {
				t.Fatalf("got (%d, %v, %v), want (%d, %v, %v)", hours, automatic, ok, tc.hours, tc.automatic, tc.ok)
			}
		})
	}
}

// Stop at the final confirmation to exercise the real invite planning and
// prompt order without account mutations. Explicit flags and piped input retain
// their existing behavior; the default terminal flow has one lifetime prompt.
func TestInviteLifetimePlanningAndConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, input                  string
		args                         []string
		tty                          bool
		lifetime                     string
		automatic                    string
		lifetimePrompts, autoPrompts int
	}{
		{"terminal default", "\nNO\n", nil, true, "expires-in=24h", "yes", 1, 0},
		{"terminal custom", "48\nNO\n", nil, true, "expires-in=48h", "yes", 1, 0},
		{"terminal permanent", "never\nNO\n", nil, true, "permanent", "no", 1, 0},
		{"explicit auto", "12\nNO\n", []string{"--auto-revoke"}, true, "expires-in=12h", "yes", 1, 0},
		{"explicit permanent", "NO\n", []string{"--no-auto-revoke"}, true, "permanent", "no", 0, 0},
		{"explicit auto and hours", "NO\n", []string{"--auto-revoke", "--hours", "12"}, true, "expires-in=12h", "yes", 0, 0},
		{"hours with explicit permanent", "NO\n", []string{"--no-auto-revoke", "--hours", "12"}, true, "permanent", "no", 0, 0},
		{"hours with choice", "n\nNO\n", []string{"--hours", "12"}, true, "permanent", "no", 0, 1},
		{"pipe automatic", "y\nNO\n", nil, false, "expires-in=24h", "yes", 0, 1},
		{"pipe permanent", "n\nNO\n", nil, false, "permanent", "no", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, out, errb := invitePlanningApp(t, tc.input, tc.tty)
			args := append([]string{"--user", "lta-plan", "--host", "192.0.2.1", "--port", "22", "--no-sudo"}, tc.args...)
			if rc := a.invite(args); rc != 0 {
				t.Fatalf("cancelled invite rc=%d: %s", rc, errb.String())
			}
			summary := out.String()
			for _, want := range []string{tc.lifetime, "auto-delete=" + tc.automatic, "sudo=no"} {
				if !strings.Contains(summary, want) {
					t.Fatalf("summary missing %q: %s", want, summary)
				}
			}
			for prompt, want := range map[string]int{"Lifetime in hours": tc.lifetimePrompts, "Auto-delete this user": tc.autoPrompts, "Type YES to confirm": 1} {
				if got := strings.Count(errb.String(), prompt); got != want {
					t.Fatalf("%q count=%d, want %d: %s", prompt, got, want, errb.String())
				}
			}
			if _, err := os.Stat(a.Registry.File); !os.IsNotExist(err) {
				t.Fatalf("cancelled invite changed registry: %v", err)
			}
		})
	}
}

func TestInviteLifetimeEOFDoesNotReachConfirmation(t *testing.T) {
	a, out, errb := invitePlanningApp(t, "", true)
	if rc := a.invite([]string{"--user", "lta-plan", "--host", "192.0.2.1", "--port", "22", "--no-sudo"}); rc != 1 {
		t.Fatalf("EOF rc=%d, want 1", rc)
	}
	if strings.Contains(out.String(), "About to create") || strings.Contains(errb.String(), "Type YES") {
		t.Fatalf("EOF was mistaken for a lifetime selection: %s %s", out.String(), errb.String())
	}
}

func TestPromptLifetimeChineseExplainsPermanentKeyword(t *testing.T) {
	a, _, errb := newTestApp(t, "never\n")
	a.P = i18n.Printer{Lang: i18n.ZH}
	_, automatic, ok := a.promptLifetime(24, true)
	if !ok || automatic || !strings.Contains(errb.String(), "永久请输入 never") {
		t.Fatalf("permanent option was not clear in Chinese: %s", errb.String())
	}
}

func invitePlanningApp(t *testing.T, input string, tty bool) (*App, *strings.Builder, *strings.Builder) {
	t.Helper()
	a, _, _ := newTestApp(t, input)
	out, errb := new(strings.Builder), new(strings.Builder)
	a.Out, a.Err = out, errb
	a.StdinIsTTY = func() bool { return tty }
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	binDir := t.TempDir()
	for _, name := range []string{"id", "useradd", "usermod", "chage", "userdel", "groupdel"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)
	return a, out, errb
}
