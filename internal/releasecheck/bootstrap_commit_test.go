package releasecheck

import (
	"bytes"
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

	"github.com/xxvcc/linux-temp-admin/internal/lifecycle"
	"github.com/xxvcc/linux-temp-admin/internal/version"
)

func bootstrapCommitFunctions(t *testing.T) string {
	t.Helper()
	source := readReleaseFile(t, "../../scripts/install.sh")
	start := strings.Index(source, "# BEGIN BOOTSTRAP_COMMIT_FUNCTIONS")
	end := strings.Index(source, "# END BOOTSTRAP_COMMIT_FUNCTIONS")
	if start < 0 || end <= start {
		t.Fatal("missing bootstrap commit functions")
	}
	return source[start:end]
}

func bootstrapShells(t *testing.T) [][]string {
	t.Helper()
	var shells [][]string
	for _, name := range []string{"sh", "bash", "dash", "busybox"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		args := []string{path}
		if name == "busybox" {
			args = append(args, "ash")
		}
		shells = append(shells, args)
	}
	return shells
}

func TestBootstrapVersionWitnessAcrossShells(t *testing.T) {
	for _, shell := range bootstrapShells(t) {
		for _, tc := range []struct {
			name, binary, want string
			invalid            bool
		}{
			{"canonical", "\x00LTA_RELEASE_VERSION_V1{2.10.8}\x00", "2.10.8", false},
			{"prerelease", "LTA_RELEASE_VERSION_V1{2.10.8-rc.12}", "2.10.8-rc.12", false},
			{"absent", "old binary", "", false},
			{"noncanonical", "LTA_RELEASE_VERSION_V1{02.10.8}", "", false},
			{"overlong", "LTA_RELEASE_VERSION_V1{2.10.8-" + strings.Repeat("x", 128) + "}", "", false},
			{"duplicate", "LTA_RELEASE_VERSION_V1{2.10.8}\x00LTA_RELEASE_VERSION_V1{2.10.8}", "", true},
		} {
			t.Run(filepath.Base(shell[0])+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				binary := filepath.Join(dir, "binary")
				if err := os.WriteFile(binary, []byte(tc.binary), 0o600); err != nil {
					t.Fatal(err)
				}
				body := "set -eu\nMAX_RELEASE_VERSION_BYTES=128\n" + bootstrapCommitFunctions(t) + "\nread_release_version \"$TEST_BINARY\"\n"
				cmd := exec.Command(shell[0], append(append([]string{}, shell[1:]...), "-c", body)...)
				cmd.Env = append(os.Environ(), "tmp="+dir, "TEST_BINARY="+binary)
				out, err := cmd.CombinedOutput()
				if (err != nil) != tc.invalid || (!tc.invalid && string(out) != tc.want) {
					t.Fatalf("version=%q error=%v want %q invalid=%v", out, err, tc.want, tc.invalid)
				}
			})
		}
	}
}

func TestBootstrapVersionOrderMatchesGo(t *testing.T) {
	versions := []string{"0.0.0", "2.10.8", "2.10.9", "2.10.8-rc.9", "2.10.8-rc.10", "2.10.8-rc.01", "2.10.8-rc.1", "2.10.8-a", "2.10.8-aa", "2.10.8-9", "2.10.8-10", "99999999999999999999999999999999999.0.0", "100000000000000000000000000000000000.0.0"}
	var input, want strings.Builder
	for _, a := range versions {
		for _, b := range versions {
			fmt.Fprintf(&input, "%s %s\n", a, b)
			if version.Greater(b, a) {
				want.WriteString("older\n")
			} else {
				want.WriteString("not-older\n")
			}
		}
	}
	for _, shell := range bootstrapShells(t) {
		t.Run(filepath.Base(shell[0]), func(t *testing.T) {
			body := "set -eu\n" + bootstrapCommitFunctions(t) + "\nwhile read -r a b; do compare_release_versions \"$a\" \"$b\"; done\n"
			cmd := exec.Command(shell[0], append(append([]string{}, shell[1:]...), "-c", body)...)
			cmd.Stdin = strings.NewReader(input.String())
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != want.String() {
				t.Fatalf("Shell/Go version order differs: %v\n%s", err, out)
			}
		})
	}
}

type bootstrapFixture struct {
	dir, dest, lock, marker, executed, releaseProbe, script string
	candidate                                               []byte
}

// Exercise the actual commit tail in a private temporary tree. Root-only path,
// owner and ELF checks are tested separately and by the integration installer;
// here only owner expectations and these fixture boundaries are adapted so the
// concurrency/state tests can run unprivileged without touching host state.
func newBootstrapFixture(t *testing.T, current, candidate string, blockProbe bool) *bootstrapFixture {
	t.Helper()
	dir := t.TempDir()
	f := &bootstrapFixture{dir: dir, dest: filepath.Join(dir, "installed"), lock: filepath.Join(dir, "lifecycle.lock"), executed: filepath.Join(dir, "executed"), releaseProbe: filepath.Join(dir, "release-probe"), script: filepath.Join(dir, "install.sh")}
	f.marker = f.lock + ".uninstalled"
	if current != "" {
		content := "unknown installation"
		if current != "unknown" {
			content = "LTA_RELEASE_VERSION_V1{" + current + "}"
		}
		if err := os.WriteFile(f.dest, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	witness := "# LTA_RELEASE_VERSION_V1{" + candidate + "}\n"
	if candidate == "historical" {
		candidate, witness = "2.10.7", ""
	}
	f.candidate = []byte("#!/bin/sh\n" + witness + "[ \"$1\" = version ] || exit 93\nprintf executed > \"$TEST_EXECUTED\"\n")
	if blockProbe {
		f.candidate = append(f.candidate, []byte("while [ ! -f \"$TEST_RELEASE_PROBE\" ]; do sleep 0.02; done\n")...)
	}
	f.candidate = append(f.candidate, []byte("printf '%s\\n' '"+candidate+"'\n")...)
	if err := os.WriteFile(filepath.Join(dir, "bin"), f.candidate, 0o600); err != nil {
		t.Fatal(err)
	}
	functions := bootstrapCommitFunctions(t)
	functions = strings.ReplaceAll(functions, "= 0:600", fmt.Sprintf("= %d:600", os.Geteuid()))
	functions = strings.ReplaceAll(functions, "= 0:0:", fmt.Sprintf("= %d:%d:", os.Geteuid(), os.Getegid()))
	source := readReleaseFile(t, "../../scripts/install.sh")
	start := strings.Index(source, "\nsigned_version=$(read_release_version")
	if start < 0 {
		t.Fatal("missing bootstrap commit boundary")
	}
	tail := source[start:]
	tail = strings.ReplaceAll(tail, `"$final_uid" -eq 0`, fmt.Sprintf(`"$final_uid" -eq %d`, os.Geteuid()))
	tail = strings.ReplaceAll(tail, `"$final_gid" -eq 0`, fmt.Sprintf(`"$final_gid" -eq %d`, os.Getegid()))
	body := `set -eu
umask 077
fail() { echo "error: $*" >&2; exit 1; }
check_safe_dir_chain() { :; }
sync_destination_directory_chain() { :; }
elf_machine_matches() { :; }
chown() { :; }
MAX_RELEASE_VERSION_BYTES=128
MAX_BINARY_BYTES=67108864
MAX_PROBE_BYTES=256
elf_machine=62
arch=fixture
dest_dir=$tmp
existing_ancestor=$tmp
stage=""
cleanup() { if [ -n "$stage" ]; then rm -f -- "$stage"; fi; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
got=$(sha256sum "$tmp/bin" | awk '{print $1}')
` + functions + tail
	if err := os.WriteFile(f.script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *bootstrapFixture) command(shell []string, candidate, allow string, custom bool) *exec.Cmd {
	managed := f.dest
	if custom {
		managed += "-other"
	}
	if candidate == "historical" {
		candidate = "2.10.7"
	}
	cmd := exec.Command(shell[0], append(append([]string{}, shell[1:]...), f.script)...)
	cmd.Env = append(os.Environ(), "tmp="+f.dir, "DEST="+f.dest, "MANAGED_DEST="+managed, "LIFECYCLE_LOCK="+f.lock, "allow_downgrade="+allow, "expected_version="+candidate, "TEST_EXECUTED="+f.executed, "TEST_RELEASE_PROBE="+f.releaseProbe)
	return cmd
}

func TestBootstrapRejectsBeforeCandidateExecution(t *testing.T) {
	for _, shell := range bootstrapShells(t) {
		for _, custom := range []bool{false, true} {
			for _, tc := range []struct {
				name, current, candidate, allow string
				ok                              bool
			}{
				{"downgrade", "2.10.8", "2.10.7", "0", false},
				{"same", "2.10.8", "2.10.8", "0", true},
				{"newer", "2.10.8", "2.10.9", "0", true},
				{"fresh", "", "2.10.8", "0", true},
				{"unknown current", "unknown", "2.10.8", "0", false},
				{"historical candidate", "2.10.8", "historical", "0", false},
				{"explicit downgrade", "2.10.8", "2.10.7", "1", true},
				{"explicit recovery", "unknown", "2.10.8", "1", true},
				{"explicit historical", "2.10.8", "historical", "1", true},
			} {
				t.Run(fmt.Sprintf("%s/custom=%t/%s", filepath.Base(shell[0]), custom, tc.name), func(t *testing.T) {
					f := newBootstrapFixture(t, tc.current, tc.candidate, false)
					before, _ := os.ReadFile(f.dest)
					out, err := f.command(shell, tc.candidate, tc.allow, custom).CombinedOutput()
					if (err == nil) != tc.ok {
						t.Fatalf("success=%v want=%v: %s", err == nil, tc.ok, out)
					}
					_, probeErr := os.Stat(f.executed)
					if (probeErr == nil) != tc.ok {
						t.Fatalf("candidate executed=%v want=%v", probeErr == nil, tc.ok)
					}
					after, _ := os.ReadFile(f.dest)
					want := before
					if tc.ok {
						want = f.candidate
					}
					if !bytes.Equal(after, want) {
						t.Fatal("unexpected installed bytes")
					}
				})
			}
		}
	}
}

func TestBootstrapExplicitRecoveryRequiresPinnedRelease(t *testing.T) {
	source := readReleaseFile(t, "../../scripts/install.sh")
	start := strings.Index(source, "case \"$release\" in")
	end := strings.Index(source[start:], "\n# Bash uses 1024-byte")
	if start < 0 || end < 0 {
		t.Fatal("missing installer option validation")
	}
	body := "set -eu\nMAX_RELEASE_VERSION_BYTES=128\nfail() { echo \"$*\" >&2; exit 1; }\n" + source[start:start+end]
	for _, shell := range bootstrapShells(t) {
		for _, tc := range []struct {
			release, allow string
			ok             bool
		}{{"latest", "1", false}, {"", "1", false}, {"v2.10.7", "yes", false}, {"v2.10.7", "1", true}, {"latest", "0", true}} {
			t.Run(filepath.Base(shell[0])+"/"+tc.release+"/"+tc.allow, func(t *testing.T) {
				cmd := exec.Command(shell[0], append(append([]string{}, shell[1:]...), "-c", body)...)
				cmd.Env = append(os.Environ(), "release="+tc.release, "allow_downgrade="+tc.allow)
				out, err := cmd.CombinedOutput()
				if (err == nil) != tc.ok {
					t.Fatalf("explicit recovery validation: %v\n%s", err, out)
				}
			})
		}
	}
}

func TestBootstrapUninstallMarker(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		custom, ok    bool
	}{
		{"reactivation", "uninstalled-v1\n", false, true},
		{"invalid", "uninstalled-v2\n", false, false},
		{"missing newline", "uninstalled-v1", false, false},
		{"custom preserves marker", "uninstalled-v1\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBootstrapFixture(t, "2.10.8", "2.10.8", false)
			if err := os.WriteFile(f.marker, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := f.command([]string{"/bin/sh"}, "2.10.8", "0", tc.custom).CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("marker result: %v\n%s", err, out)
			}
			_, markerErr := os.Stat(f.marker)
			if (markerErr == nil) != (tc.custom || !tc.ok) {
				t.Fatalf("marker exists=%v", markerErr == nil)
			}
			_, probeErr := os.Stat(f.executed)
			if !tc.ok && probeErr == nil {
				t.Fatal("unsafe marker allowed candidate execution")
			}
		})
	}
}

func TestBootstrapVersionComparisonFailureStopsBeforeProbe(t *testing.T) {
	for _, shell := range bootstrapShells(t) {
		for _, injected := range []string{"return 1", "return 2", "return 42", "return 127", "return 0", "echo unexpected", "printf 'not-older\\nolder\\n'", "echo not-older; return 1"} {
			t.Run(filepath.Base(shell[0])+"/"+injected, func(t *testing.T) {
				f := newBootstrapFixture(t, "2.10.8", "2.10.7", false)
				source, err := os.ReadFile(f.script)
				if err != nil {
					t.Fatal(err)
				}
				source = bytes.Replace(source, []byte("\nsigned_version=$(read_release_version"), []byte("\ncompare_release_versions() { "+injected+"; }\nsigned_version=$(read_release_version"), 1)
				if err := os.WriteFile(f.script, source, 0o700); err != nil {
					t.Fatal(err)
				}
				out, err := f.command(shell, "2.10.7", "0", false).CombinedOutput()
				if err == nil || !strings.Contains(string(out), "could not compare") {
					t.Fatalf("comparison error did not fail closed: %v\n%s", err, out)
				}
				if _, err := os.Stat(f.executed); !os.IsNotExist(err) {
					t.Fatal("candidate executed after comparison failure")
				}
			})
		}
	}
}

func TestBootstrapUnsafeStateStopsBeforeProbe(t *testing.T) {
	for _, kind := range []string{"lock mode", "lock symlink", "lock fifo", "destination symlink", "marker symlink", "marker mode"} {
		t.Run(kind, func(t *testing.T) {
			f := newBootstrapFixture(t, "2.10.7", "2.10.8", false)
			var err error
			switch kind {
			case "lock mode":
				err = os.WriteFile(f.lock, nil, 0o600)
				if err == nil {
					err = os.Chmod(f.lock, 0o666)
				}
			case "lock symlink":
				err = os.Symlink(f.dest, f.lock)
			case "lock fifo":
				err = syscall.Mkfifo(f.lock, 0o600)
			case "destination symlink":
				err = os.Remove(f.dest)
				if err == nil {
					err = os.Symlink(filepath.Join(f.dir, "bin"), f.dest)
				}
			case "marker symlink":
				err = os.Symlink(f.dest, f.marker)
			case "marker mode":
				err = os.WriteFile(f.marker, []byte("uninstalled-v1\n"), 0o600)
				if err == nil {
					err = os.Chmod(f.marker, 0o644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := f.command([]string{"/bin/sh"}, "2.10.8", "0", false).CombinedOutput()
			if err == nil {
				t.Fatalf("unsafe %s accepted: %s", kind, out)
			}
			if _, err := os.Stat(f.executed); !os.IsNotExist(err) {
				t.Fatal("candidate ran with unsafe installed state")
			}
		})
	}
}

func TestBootstrapCommitDurabilityAndReactivation(t *testing.T) {
	for _, fault := range []string{"file sync", "directory sync", "marker remove", "marker sync"} {
		t.Run(fault, func(t *testing.T) {
			f := newBootstrapFixture(t, "2.10.7", "2.10.8", false)
			if err := os.WriteFile(f.marker, []byte("uninstalled-v1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.ReadFile(f.script)
			if err != nil {
				t.Fatal(err)
			}
			inject := `
timeout() {
  if [ "$4" = sync ]; then
    case "$TEST_FAULT" in
      'file sync') [ "$5" != "$DEST" ] || return 44 ;;
      'directory sync') [ "$5" != "$dest_dir" ] || return 44 ;;
      'marker sync') [ "$5" != "$dest_dir" ] || [ -e "$LIFECYCLE_LOCK.uninstalled" ] || return 44 ;;
    esac
  fi
  command timeout "$@"
}
rm() {
  if [ "$TEST_FAULT" = 'marker remove' ] && [ "$2" = "$LIFECYCLE_LOCK.uninstalled" ]; then return 45; fi
  command rm "$@"
}
`
			source = bytes.Replace(source, []byte("\nsigned_version=$(read_release_version"), []byte(inject+"\nsigned_version=$(read_release_version"), 1)
			if err := os.WriteFile(f.script, source, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := f.command([]string{"/bin/sh"}, "2.10.8", "0", false)
			cmd.Env = append(cmd.Env, "TEST_FAULT="+fault)
			out, runErr := cmd.CombinedOutput()
			markerGone := fault == "marker sync"
			if (runErr == nil) != markerGone {
				t.Fatalf("durability result: %v\n%s", runErr, out)
			}
			if markerGone && !strings.Contains(string(out), "installed and reactivated but marker-removal durability is unknown") {
				t.Fatalf("missing committed marker warning: %s", out)
			}
			if !markerGone && !strings.Contains(string(out), "installed") {
				t.Fatalf("failure did not disclose visible installation: %s", out)
			}
			installed, _ := os.ReadFile(f.dest)
			if !bytes.Equal(installed, f.candidate) {
				t.Fatal("fixture did not reach visible installation")
			}
			_, markerErr := os.Stat(f.marker)
			if os.IsNotExist(markerErr) != markerGone {
				t.Fatalf("marker state=%v", markerErr)
			}
		})
	}
}

func TestBootstrapProbeDescendantDoesNotInheritLifecycleLock(t *testing.T) {
	f := newBootstrapFixture(t, "2.10.7", "2.10.8", false)
	f.candidate = append(f.candidate, []byte("sleep 30 &\nprintf '%s' \"$!\" > \"$TEST_CHILD_PID\"\n")...)
	if err := os.WriteFile(filepath.Join(f.dir, "bin"), f.candidate, 0o600); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(f.dir, "child.pid")
	cmd := f.command([]string{"/bin/sh"}, "2.10.8", "0", false)
	cmd.Env = append(cmd.Env, "TEST_CHILD_PID="+pidPath)
	out, err := cmd.CombinedOutput()
	pidBytes, readErr := os.ReadFile(pidPath)
	if readErr != nil {
		t.Fatalf("candidate did not create its child: %v\n%s", readErr, out)
	}
	pid, parseErr := strconv.Atoi(string(pidBytes))
	if parseErr != nil || pid <= 1 {
		t.Fatalf("invalid child PID: %q", pidBytes)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if err != nil {
		t.Fatalf("installation failed: %v\n%s", err, out)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("descendant exited before inheritance check: %v", err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/fd/9", pid)); !os.IsNotExist(err) {
		t.Fatalf("probe descendant kept lock descriptor: %v", err)
	}
	release, err := lifecycle.New(f.lock).TryAcquire()
	if err != nil {
		t.Fatalf("probe descendant kept lifecycle lock: %v", err)
	}
	_ = release()
}

func TestBootstrapAndGoShareLifecycleLock(t *testing.T) {
	t.Run("rechecks after queued newer installation", func(t *testing.T) {
		f := newBootstrapFixture(t, "2.10.7", "2.10.8", false)
		lock := lifecycle.New(f.lock)
		release, err := lock.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		cmd := f.command([]string{"/bin/sh"}, "2.10.8", "0", false)
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if err := cmd.Start(); err != nil {
			_ = release()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			_ = release()
			t.Fatalf("bootstrap did not wait for Go lock: %v\n%s", err, output.String())
		case <-time.After(150 * time.Millisecond):
		}
		if err := os.WriteFile(f.dest, []byte("LTA_RELEASE_VERSION_V1{2.10.9}"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil || !strings.Contains(output.String(), "refusing downgrade") {
			t.Fatalf("queued install did not recheck version: %v\n%s", err, output.String())
		}
		if _, err := os.Stat(f.executed); !os.IsNotExist(err) {
			t.Fatal("older queued candidate was executed")
		}
	})
	for _, terminate := range []bool{false, true} {
		t.Run(fmt.Sprintf("shell holds lock through probe/terminate=%t", terminate), func(t *testing.T) {
			f := newBootstrapFixture(t, "2.10.7", "2.10.8", true)
			cmd := f.command([]string{"/bin/sh"}, "2.10.8", "0", false)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(f.executed); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("candidate did not reach probe")
				}
				time.Sleep(10 * time.Millisecond)
			}
			lock := lifecycle.New(f.lock)
			if release, err := lock.TryAcquire(); !errors.Is(err, lifecycle.ErrBusy) {
				if release != nil {
					_ = release()
				}
				t.Fatalf("Go acquired lock during bootstrap: %v", err)
			}
			if terminate {
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}
			if err := os.WriteFile(f.releaseProbe, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			if (err != nil) != terminate {
				t.Fatalf("bootstrap exit=%v\n%s", err, output.String())
			}
			release, err := lock.TryAcquire()
			if err != nil {
				t.Fatalf("bootstrap left lifecycle lock held: %v", err)
			}
			_ = release()
			if terminate {
				content, _ := os.ReadFile(f.dest)
				if string(content) != "LTA_RELEASE_VERSION_V1{2.10.7}" {
					t.Fatal("terminated installer committed candidate")
				}
			}
		})
	}
}
