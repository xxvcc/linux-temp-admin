package selfmanage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func versionProbeFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersionProbeBoundsBothStreamsAndScrubsEnvironment(t *testing.T) {
	m := &Manager{ProbeTimeout: 2 * time.Second, ProbeMaxOutput: 32}
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			redirect := ""
			if stream == "stderr" {
				redirect = " >&2"
			}
			path := versionProbeFixture(t, "while :; do printf 0123456789abcdef"+redirect+"; done")
			if _, err := m.runVersionProbe(path); err == nil || !strings.Contains(err.Error(), "output exceeds 32 bytes") {
				t.Fatalf("unbounded %s: error=%v", stream, err)
			}
		})
	}
	t.Setenv("LTA_TEST_CALLER_SECRET", "not-for-the-probe")
	t.Setenv("BASH_ENV", "/caller-controlled-init")
	path := versionProbeFixture(t, `[ "${LTA_TEST_CALLER_SECRET-unset}" = unset ] || exit 91
[ "${BASH_ENV-unset}" = unset ] || exit 92
[ "$PWD" = / ] || exit 93
printf '2.10.10\n'`)
	if got, err := m.runVersionProbe(path); err != nil || got != "2.10.10" {
		t.Fatalf("isolated probe version=%q error=%v", got, err)
	}
	path = versionProbeFixture(t, "printf 'private-diagnostic' >&2; exit 7")
	_, err := m.runVersionProbe(path)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 || strings.Contains(err.Error(), "private-diagnostic") {
		t.Fatalf("probe must retain the status without stderr: %v", err)
	}
}

func TestVersionProbeCleansExitedLeaderDescendants(t *testing.T) {
	// Adopt and reap test descendants only inside an isolated test subprocess;
	// changing subreaper state in the package process can affect unrelated tests.
	if os.Getenv("LTA_TEST_PROBE_REAPER") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVersionProbeCleansExitedLeaderDescendants$", "-test.v")
		cmd.Env = append(os.Environ(), "LTA_TEST_PROBE_REAPER=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated descendant cleanup: %v\n%s", err, out)
		}
		return
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, redirect, completion string
		wantWaitDelay              bool
	}{
		{"inherited output", "", "printf '2.10.10\\n'; exit 0", true},
		{"failed parent", " >/dev/null 2>&1", "exit 7", false},
		{"output limit", " >/dev/null 2>&1", "printf 0123456789012345678901234567890123456789; exit 0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidPath := filepath.Join(t.TempDir(), "pid")
			path := versionProbeFixture(t, fmt.Sprintf("/bin/sleep 10%s &\nprintf '%%s\\n' \"$!\" > '%s'\n%s", tc.redirect, pidPath, tc.completion))
			m := &Manager{ProbeTimeout: 3 * time.Second, ProbeMaxOutput: 32}
			_, probeErr := m.runVersionProbe(path)
			raw, err := os.ReadFile(pidPath)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil || pid < 1 {
				t.Fatalf("invalid child pid %q: %v", raw, err)
			}
			reaped := false
			defer func() {
				if !reaped {
					// The adopted child remains ours until Wait4 reaps it, so its PID
					// cannot be reused while this failure cleanup sends the signal.
					_ = syscall.Kill(pid, syscall.SIGKILL)
					_, _ = syscall.Wait4(pid, nil, 0, nil)
				}
			}()
			if probeErr == nil || errors.Is(probeErr, exec.ErrWaitDelay) != tc.wantWaitDelay {
				t.Fatalf("probe error=%v, want failure, WaitDelay=%v", probeErr, tc.wantWaitDelay)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				var status syscall.WaitStatus
				got, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
				if err != nil {
					t.Fatal(err)
				}
				if got == pid {
					reaped = true
					if !status.Signaled() || status.Signal() != syscall.SIGKILL {
						t.Fatalf("descendant exit=%v, want SIGKILL", status)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("probe returned but its descendant remains executable")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
