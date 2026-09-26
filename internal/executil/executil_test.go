package executil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func TestRunPinsWorkingDirectoryAndKeepsStderrInTheError(t *testing.T) {
	t.Run("working directory is pinned regardless of the caller CWD", func(t *testing.T) {
		// at(1) persists the submitting process's CWD into the queued job, so a
		// helper must never observe a caller-controlled directory that can vanish.
		gone := t.TempDir()
		restore, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(gone); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chdir(restore) })

		out, err := Output(helper(t, "pwd"), nil, Options{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("pwd helper: %v", err)
		}
		if got := strings.TrimSpace(string(out)); got != HelperWorkingDir {
			t.Fatalf("helper CWD = %q, want %q (an inherited CWD is what breaks the at fallback)", got, HelperWorkingDir)
		}
	})

	t.Run("stderr reaches the operator instead of a bare exit status", func(t *testing.T) {
		_, err := Output(helper(t, "echo '/etc/ssh/sshd_config.d/50-cloud.conf: line 4: Bad configuration option' >&2; exit 255"), nil, Options{Timeout: 5 * time.Second})
		if err == nil {
			t.Fatal("expected an error from a helper that exits 255")
		}
		if !strings.Contains(err.Error(), "50-cloud.conf: line 4: Bad configuration option") {
			t.Fatalf("error = %q, want the captured stderr folded in", err)
		}
		if !strings.Contains(err.Error(), "exit status 255") {
			t.Fatalf("error = %q, want the exit status preserved", err)
		}
	})

	t.Run("oversized stderr is bounded in the error", func(t *testing.T) {
		_, err := Output(helper(t, "i=0; while [ $i -lt 200 ]; do printf 'aaaaaaaaaaaaaaaaaaaa' >&2; i=$((i+1)); done; exit 3"), nil, Options{Timeout: 5 * time.Second})
		if err == nil {
			t.Fatal("expected an error")
		}
		if len(err.Error()) > maxErrorDetail+64 {
			t.Fatalf("error length = %d, want it bounded near %d", len(err.Error()), maxErrorDetail)
		}
	})

	t.Run("CombinedOutput keeps stderr in the output, not duplicated into the error", func(t *testing.T) {
		out, err := CombinedOutput(helper(t, "echo marker >&2; exit 1"), nil, Options{Timeout: 5 * time.Second})
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(string(out), "marker") {
			t.Fatalf("combined output = %q, want the stderr line", out)
		}
		if strings.Contains(err.Error(), "marker") {
			t.Fatalf("error = %q, want no duplicated stderr for CombinedOutput", err)
		}
	})
}

func TestEarlyParentExitCleansFailedHelpersButKeepsSuccessfulDaemons(t *testing.T) {
	for _, tc := range []struct {
		name          string
		body          string
		wantErr       bool
		wantWaitDelay bool
		wantMarker    bool
	}{
		{"inherited pipes", "(sleep 1.4; printf survived > '%s') & exit 0", true, true, false},
		{"failed parent with detached output", "(sleep 0.2; printf survived > '%s') >/dev/null 2>&1 & exit 7", true, false, false},
		{"signaled parent", "(sleep 0.2; printf survived > '%s') >/dev/null 2>&1 & kill -TERM $$", true, false, false},
		{"successful daemon", "(sleep 0.2; printf survived > '%s') >/dev/null 2>&1 & exit 0", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "marker")
			start := time.Now()
			_, err := CombinedOutput(helper(t, fmt.Sprintf(tc.body, marker)), nil, Options{Timeout: 4 * time.Second})
			if (err != nil) != tc.wantErr || errors.Is(err, exec.ErrWaitDelay) != tc.wantWaitDelay {
				t.Fatalf("helper err=%v, wantErr=%v waitDelay=%v", err, tc.wantErr, tc.wantWaitDelay)
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("helper completion exceeded bound: %s", elapsed)
			}
			// Wait past the child's intended write. This checks observable work,
			// including detached stdout, rather than treating a zombie as alive.
			if tc.wantWaitDelay {
				time.Sleep(650 * time.Millisecond)
			} else {
				time.Sleep(500 * time.Millisecond)
			}
			_, statErr := os.Stat(marker)
			if got := statErr == nil; got != tc.wantMarker {
				t.Fatalf("descendant marker present=%v want=%v (stat=%v)", got, tc.wantMarker, statErr)
			}
		})
	}
}

func TestOutputLimitAfterSuccessfulParentExitKillsDetachedOutputDescendants(t *testing.T) {
	// Race the two readiness notifications repeatedly: the helper succeeds and
	// closes its pipes just as the output pump exceeds its bound. An error result
	// must not leave the detached-output descendant alive to write afterward.
	dir := t.TempDir()
	for attempt := 0; attempt < 64; attempt++ {
		marker := filepath.Join(dir, fmt.Sprintf("survived-%d", attempt))
		body := fmt.Sprintf("(sleep 0.2; printf survived > '%s') >/dev/null 2>&1 & printf oversized; exit 0", marker)
		_, err := CombinedOutput(helper(t, body), nil, Options{Timeout: 5 * time.Second, MaxOutput: 1})
		if !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("attempt %d: err=%v want output limit", attempt, err)
		}
	}
	time.Sleep(350 * time.Millisecond)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("output-limit failure left descendants able to write: %v", entries)
	}
}
