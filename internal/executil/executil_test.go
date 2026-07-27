package executil

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func helper(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCombinedOutputBoundsTimeOutputAndDescendants(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		start := time.Now()
		_, err := CombinedOutput(helper(t, "sleep 30 & wait"), nil, Options{Timeout: 50 * time.Millisecond, MaxOutput: 32})
		if !errors.Is(err, contextDeadlineExceeded()) || time.Since(start) > 2*time.Second {
			t.Fatalf("timeout error=%v elapsed=%s", err, time.Since(start))
		}
	})
	t.Run("output", func(t *testing.T) {
		out, err := CombinedOutput(helper(t, "while :; do printf 0123456789abcdef; done"), nil, Options{Timeout: time.Second, MaxOutput: 32})
		if !errors.Is(err, ErrOutputLimit) || len(out) != 32 {
			t.Fatalf("output len=%d err=%v, want 32-byte limit", len(out), err)
		}
	})
	t.Run("environment and stdin", func(t *testing.T) {
		t.Setenv("SYSTEMD_UNIT_PATH", "/tmp/attacker-units")
		t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/tmp/attacker-bus")
		t.Setenv("BASH_ENV", "/tmp/attacker-shell-init")
		out, err := Output(helper(t, "read value; printf '%s:%s' \"$LC_ALL\" \"$value\""), nil, Options{
			Timeout: time.Second, MaxOutput: 64, Stdin: strings.NewReader("input\n"), ExtraEnv: []string{"LC_ALL=C"},
		})
		if err != nil || string(out) != "C:input" {
			t.Fatalf("output=%q err=%v", out, err)
		}
		envOut, err := Output(helper(t, `printf '%s:%s:%s:%s' "${SYSTEMD_UNIT_PATH-unset}" "${DBUS_SYSTEM_BUS_ADDRESS-unset}" "${BASH_ENV-unset}" "$HOME"`), nil, Options{})
		if err != nil || string(envOut) != "unset:unset:unset:/root" {
			t.Fatalf("privileged helper inherited unsafe environment: output=%q err=%v", envOut, err)
		}
	})
	t.Run("parent context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		_, err := CombinedOutput(helper(t, "sleep 30"), nil, Options{
			Context: ctx, Timeout: time.Minute, MaxOutput: 32,
		})
		if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
			t.Fatalf("cancelled-parent error=%v elapsed=%s", err, time.Since(start))
		}
	})
}

// Kept behind a helper so the test does not need to compare error strings.
func contextDeadlineExceeded() error { return context.DeadlineExceeded }
