package releasecheck

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run the production traps and restoration functions in an isolated process
// group. GitHub is a local state fixture; these tests never publish a release.
func TestPublisherSignalsRestoreLatestAndKeepPrivateRecoveryEvidence(t *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM} {
		for _, group := range []bool{false, true} {
			for _, phase := range []string{"before", "armed", "complete"} {
				name := fmt.Sprintf("%s/group=%t/%s", signal, group, phase)
				t.Run(name, func(t *testing.T) {
					runPublisherSignalFixture(t, publisherSignalCase{signal: signal, group: group, phase: phase})
				})
			}
			t.Run(fmt.Sprintf("%s/group=%t/restore-failure", signal, group), func(t *testing.T) {
				runPublisherSignalFixture(t, publisherSignalCase{signal: signal, group: group, phase: "armed", failRestore: true})
			})
		}
	}
}

func TestPublisherRepeatedSignalsDoNotInterruptRecovery(t *testing.T) {
	for _, group := range []bool{false, true} {
		for _, failRestore := range []bool{false, true} {
			t.Run(fmt.Sprintf("group=%t/restore-failure=%t", group, failRestore), func(t *testing.T) {
				runPublisherSignalFixture(t, publisherSignalCase{
					signal: syscall.SIGTERM, group: group, phase: "armed", repeat: true, failRestore: failRestore,
				})
			})
		}
	}
}

func TestPublisherIncompleteExitRestoresLatest(t *testing.T) {
	for _, status := range []int{0, 42} {
		t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
			runPublisherSignalFixture(t, publisherSignalCase{phase: "armed", exitStatus: status})
		})
	}
}

func TestPublisherRecoveryRecordFailurePreventsMutation(t *testing.T) {
	runPublisherSignalFixture(t, publisherSignalCase{phase: "armed", failRecord: true, exitStatus: 42})
}

type publisherSignalCase struct {
	signal      syscall.Signal
	group       bool
	phase       string
	failRestore bool
	repeat      bool
	failRecord  bool
	exitStatus  int
}

func runPublisherSignalFixture(t *testing.T, tc publisherSignalCase) {
	t.Helper()
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	trapStart := strings.Index(publish, "LATEST_PROMOTION_ATTEMPTED=0\n")
	trapEnd := strings.Index(publish, "\n# Pin the verifier by descriptor")
	recoveryStart := strings.Index(publish, "decimal_gt() {")
	recoveryEnd := strings.Index(publish, "\nrequire_remote_tag_object() {")
	if trapStart < 0 || trapEnd <= trapStart || recoveryStart < 0 || recoveryEnd <= recoveryStart {
		t.Fatal("could not isolate production publisher traps and recovery functions")
	}
	recoveryFunctions := strings.Replace(publish[recoveryStart:recoveryEnd],
		"restore_latest_after_failed_promotion() {", "restore_latest_under_test() {", 1)
	dir := t.TempDir()
	script := filepath.Join(dir, "publisher-signals.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
umask 077
TAG=v2.8.0
REPO=mock/repo
EXPECTED_RELEASE_ID=280
COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
LTA_EXPECTED_SIGNED_BUNDLE_MANIFEST_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
BASELINE_HIGHEST_TAG=v2.7.3
BASELINE_HIGHEST_ID=273
LOCAL_COMMAND_TIMEOUT_SECONDS=5
MAX_RELEASE_VERSION_BYTES=128
work="$TEST_STATE/work"
mkdir -p "$work/gh-config" "$TEST_STATE/signed-source"
printf '%s' "$GH_TOKEN" > "$work/gh-config/hosts.yml"
printf '%s' "$GITHUB_TOKEN" > "$work/raw-api-response"
printf 'retained original signed bundle' > "$TEST_STATE/signed-source/bundle.bin"
printf 'v2.7.3\nv2.8.0\n' > "$TEST_STATE/stable"
printf 'v2.7.3 273' > "$TEST_STATE/latest"
mktemp() {
  [[ "$TEST_FAIL_RECORD" == false ]] || return 1
  local created
  created="$(command mktemp "$@")" || return 1
  printf '%s' "$created" > "$TEST_STATE/recovery-path"
  printf '%s\n' "$created"
}
gh() {
  if [[ "$1" == api && "$2" == --paginate ]]; then cat "$TEST_STATE/stable"; return 0; fi
  if [[ "$1" == release && "$2" == view ]]; then cut -d ' ' -f1 "$TEST_STATE/latest"; return 0; fi
  if [[ "$1" == api && "$2" == repos/mock/repo/releases/latest ]]; then
    read -r tag id extra < "$TEST_STATE/latest"
    [[ -z "$extra" && "$id" =~ ^[1-9][0-9]*$ ]] || return 98
    printf '%s false false true %s\n' "$tag" "$id"
    return 0
  fi
  if [[ "$1" == api && "$2" == repos/mock/repo/releases/tags/v2.7.3 ]]; then
    printf 'v2.7.3 false false true 273\n'
    return 0
  fi
  if [[ "$1" == api && "$2" == --method && "$3" == PATCH \
       && "$4" == repos/mock/repo/releases/273 ]]; then
    printf 'v2.7.3 273' > "$TEST_STATE/latest"
    printf 'v2.7.3 false false true 273\n'
    return 0
  fi
  return 99
}
gh_with_timeout() { gh "$@"; }
` + recoveryFunctions + `
restore_latest_after_failed_promotion() {
  printf 'restore\n' >> "$TEST_STATE/restore-calls"
  : > "$TEST_STATE/restore-started"
  if [[ "$TEST_REPEAT" == true ]]; then
    while [[ ! -e "$TEST_STATE/release-recovery" ]]; do sleep 0.01; done
  fi
  [[ "$TEST_FAIL_RESTORE" == false ]] || return 1
  restore_latest_under_test
}
` + publish[trapStart:trapEnd] + `
if [[ "$TEST_PHASE" != before ]]; then
  arm_latest_restoration
  : > "$TEST_STATE/mutation-attempted"
  printf 'v2.8.0 280' > "$TEST_STATE/latest"
fi
if [[ "$TEST_PHASE" == complete ]]; then PUBLISH_COMPLETE=1; fi
: > "$TEST_STATE/ready"
if [[ "$TEST_SIGNAL" == 0 ]]; then exit "$TEST_EXIT_STATUS"; fi
while :; do sleep 0.01; done
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "publisher-test-credential-must-never-survive"
	cmd := exec.Command("/bin/bash", "-p", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(), "TEST_STATE="+dir, "TEST_PHASE="+tc.phase,
		fmt.Sprintf("TEST_SIGNAL=%d", tc.signal), fmt.Sprintf("TEST_REPEAT=%t", tc.repeat),
		fmt.Sprintf("TEST_FAIL_RESTORE=%t", tc.failRestore), fmt.Sprintf("TEST_FAIL_RECORD=%t", tc.failRecord),
		fmt.Sprintf("TEST_EXIT_STATUS=%d", tc.exitStatus), "GH_TOKEN="+secret, "GITHUB_TOKEN="+secret)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		// All children belong to this fixture's fresh process group. Kill any
		// survivors even if an assertion failed while Bash was awaiting a signal.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("publisher signal fixture did not exit after SIGKILL")
		}
		if recoveryPath, err := os.ReadFile(filepath.Join(dir, "recovery-path")); err == nil {
			if !strings.HasPrefix(string(recoveryPath), "/tmp/lta-publish-recovery.") {
				t.Errorf("unexpected fixture recovery path: %q", recoveryPath)
				return
			}
			if err := os.RemoveAll(string(recoveryPath)); err != nil {
				t.Error(err)
			}
		}
	})
	waitForMarker := func(name string) {
		t.Helper()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return
			}
			select {
			case <-done:
				t.Fatalf("publisher exited before %s: %v\n%s", name, waitErr, output.String())
			case <-deadline.C:
				t.Fatalf("timed out awaiting publisher marker %s", name)
			case <-ticker.C:
			}
		}
	}
	if tc.signal != 0 {
		waitForMarker("ready")
		target := cmd.Process.Pid
		if tc.group {
			target = -target
		}
		if err := syscall.Kill(target, tc.signal); err != nil {
			t.Fatal(err)
		}
		if tc.repeat {
			waitForMarker("restore-started")
			for _, signal := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM} {
				if err := syscall.Kill(target, signal); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "release-recovery"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("publisher did not complete its signal cleanup")
	}
	wantStatus := tc.exitStatus
	if tc.signal != 0 {
		wantStatus = 128 + int(tc.signal)
	} else if tc.failRecord || wantStatus == 0 {
		wantStatus = 1
	}
	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != wantStatus {
		t.Fatalf("publisher exit = %v, want %d\n%s", waitErr, wantStatus, output.String())
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("publisher printed a credential during cleanup")
	}
	if _, err := os.Stat(filepath.Join(dir, "work")); !os.IsNotExist(err) {
		t.Fatalf("credential-bearing workspace survived cleanup: %v", err)
	}
	if bundle, err := os.ReadFile(filepath.Join(dir, "signed-source/bundle.bin")); err != nil || string(bundle) != "retained original signed bundle" {
		t.Fatalf("cleanup changed the source signed bundle: %q, %v", bundle, err)
	}
	wantRestoration := tc.phase == "armed" && !tc.failRecord
	calls, err := os.ReadFile(filepath.Join(dir, "restore-calls"))
	if wantRestoration {
		if err != nil || string(calls) != "restore\n" {
			t.Fatalf("restoration must run exactly once: %q, %v\n%s", calls, err, output.String())
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("publisher restored Latest without an incomplete mutation: %q, %v", calls, err)
	}
	wantLatest := "v2.7.3 273"
	if tc.phase == "complete" || tc.failRestore {
		wantLatest = "v2.8.0 280"
	}
	if latest, err := os.ReadFile(filepath.Join(dir, "latest")); err != nil || string(latest) != wantLatest {
		t.Fatalf("Latest = %q, %v; want %s\n%s", latest, err, wantLatest, output.String())
	}
	recoveryPath, err := os.ReadFile(filepath.Join(dir, "recovery-path"))
	if tc.phase == "before" || tc.failRecord {
		if !os.IsNotExist(err) {
			t.Fatalf("unexpected recovery record path: %q, %v", recoveryPath, err)
		}
		if tc.failRecord {
			if _, err := os.Stat(filepath.Join(dir, "mutation-attempted")); !os.IsNotExist(err) {
				t.Fatalf("publisher mutated Latest despite recovery record failure: %v", err)
			}
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !tc.failRestore {
		if _, err := os.Stat(string(recoveryPath)); !os.IsNotExist(err) {
			t.Fatalf("successful restoration or completed publication retained recovery record: %v", err)
		}
		return
	}
	contextPath := filepath.Join(string(recoveryPath), "context.tsv")
	context, err := os.ReadFile(contextPath)
	if err != nil {
		t.Fatalf("failed restoration lost recovery evidence: %v\n%s", err, output.String())
	}
	wantContext := "linux-temp-admin publication recovery v1\n" +
		"repo\tmock/repo\ntag\tv2.8.0\nrelease-id\t280\ncommit\t" + strings.Repeat("a", 40) + "\n" +
		"signed-bundle-manifest-sha256\t" + strings.Repeat("b", 64) + "\n" +
		"baseline-highest-tag\tv2.7.3\nbaseline-highest-release-id\t273\n" + fmt.Sprintf("exit-status\t%d\n", wantStatus)
	if string(context) != wantContext || strings.Contains(string(context), secret) {
		t.Fatalf("retained recovery record differs from the exact credential-free identity record: %q", context)
	}
	for path, mode := range map[string]os.FileMode{string(recoveryPath): 0o700, contextPath: 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("recovery evidence %s must have mode %o: %v, %v", path, mode, info, err)
		}
	}
	entries, err := os.ReadDir(string(recoveryPath))
	if err != nil || len(entries) != 1 || entries[0].Name() != "context.tsv" {
		t.Fatalf("failed restoration retained files other than minimal recovery evidence: %v, %v", entries, err)
	}
	if !strings.Contains(output.String(), "private recovery identifiers retained at: "+contextPath) {
		t.Fatalf("publisher did not identify its retained recovery record: %s", output.String())
	}
}
