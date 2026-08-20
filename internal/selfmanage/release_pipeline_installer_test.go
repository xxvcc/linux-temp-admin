package selfmanage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

func TestInstallerSyncsDestinationDirectoryChainAcrossShells(t *testing.T) {
	installer := readReleaseFile(t, "../../scripts/install.sh")
	start := strings.Index(installer, "sync_destination_directory_chain() {")
	if start < 0 {
		t.Fatal("could not locate installer directory-chain sync function")
	}
	endRel := strings.Index(installer[start:], "\n}\n\ncheck_safe_dir_chain")
	if endRel < 0 {
		t.Fatal("could not isolate installer directory-chain sync function")
	}
	function := installer[start : start+endRel+2]

	type shellCase struct {
		name string
		path string
		args []string
	}
	shells := []shellCase{
		{name: "sh", path: "/bin/sh"},
		{name: "bash", path: "/bin/bash"},
		{name: "dash", path: "/bin/dash"},
	}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		shells = append(shells, shellCase{name: "busybox-ash", path: busybox, args: []string{"ash"}})
	}

	for _, shell := range shells {
		if _, err := os.Stat(shell.path); err != nil {
			continue
		}
		t.Run(shell.name, func(t *testing.T) {
			dir := t.TempDir()
			leaf := filepath.Join(dir, "one", "two")
			if err := os.MkdirAll(leaf, 0o700); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "sync.log")
			source := `set -eu
fail() { echo "error: $*" >&2; exit 1; }
timeout() {
  [ "$1" = -k ] && [ "$2" = 5 ] && [ "$3" = 30 ] && [ "$4" = sync ]
  printf '%s\n' "$5" >> "$TEST_SYNC_LOG"
  [ -z "$TEST_FAIL_DIR" ] || [ "$5" != "$TEST_FAIL_DIR" ]
}
` + function + `
sync_destination_directory_chain "$TEST_LEAF"
`
			runShellFixture(t, shell.path, shell.args, source,
				"TEST_LEAF="+leaf,
				"TEST_SYNC_LOG="+logPath,
				"TEST_FAIL_DIR=",
			)
			logBytes, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for path := leaf; ; path = filepath.Dir(path) {
				want = append(want, path)
				if path == "/" {
					break
				}
			}
			if got := strings.Fields(string(logBytes)); !slices.Equal(got, want) {
				t.Fatalf("directory sync order = %q, want %q", got, want)
			}

			failureLog := filepath.Join(dir, "failure.log")
			failureScript := filepath.Join(dir, "failure.sh")
			if err := os.WriteFile(failureScript, []byte(source), 0o700); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string(nil), shell.args...), failureScript)
			cmd := exec.Command(shell.path, args...)
			cmd.Env = append(os.Environ(),
				"TEST_LEAF="+leaf,
				"TEST_SYNC_LOG="+failureLog,
				"TEST_FAIL_DIR="+filepath.Dir(leaf),
			)
			if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "could not be made durable") {
				t.Fatalf("directory sync failure was not fail-closed: err=%v\n%s", err, out)
			}
			failureBytes, err := os.ReadFile(failureLog)
			if err != nil {
				t.Fatal(err)
			}
			wantFailure := []string{leaf, filepath.Dir(leaf)}
			if got := strings.Fields(string(failureBytes)); !slices.Equal(got, wantFailure) {
				t.Fatalf("failed directory sync continued: got %q, want %q", got, wantFailure)
			}
		})
	}
}

func TestInstallerStopsWhenFileLimitCannotBeSet(t *testing.T) {
	installer := readReleaseFile(t, "../../scripts/install.sh")
	fetchStart := strings.Index(installer, "fetch_once() {")
	probeStart := strings.Index(installer, "if ! (\n  ulimit -f 1")
	if fetchStart < 0 || probeStart < 0 {
		t.Fatal("could not locate installer file-limit guards")
	}
	fetchEndRel := strings.Index(installer[fetchStart:], "\n}\n\nfetch()")
	probeEndRel := strings.Index(installer[probeStart:], "\n); then")
	if fetchEndRel < 0 || probeEndRel < 0 {
		t.Fatal("could not isolate installer file-limit guards")
	}
	fetchFunction := installer[fetchStart : fetchStart+fetchEndRel+2]
	probeBody := installer[probeStart+len("if ! (\n") : probeStart+probeEndRel]

	type shellCase struct {
		name string
		path string
		args []string
	}
	shells := []shellCase{
		{name: "sh", path: "/bin/sh"},
		{name: "bash", path: "/bin/bash"},
		{name: "dash", path: "/bin/dash"},
	}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		shells = append(shells, shellCase{name: "busybox-ash", path: busybox, args: []string{"ash"}})
	}

	for _, shell := range shells {
		if _, err := os.Stat(shell.path); err != nil {
			continue
		}
		for _, tc := range []struct {
			name string
			body string
		}{
			{
				name: "download",
				body: fmt.Sprintf(`
FSIZE_BLOCK_BYTES=512
FETCH_TIMEOUT_SECONDS=1
CONNECT_TIMEOUT_SECONDS=1
%s
( fetch_once "https://example.invalid/bin" "$TEST_TMP/out" 1024 ) || :
`, fetchFunction),
			},
			{
				name: "candidate-probe",
				body: fmt.Sprintf(`
stage=/nonexistent-candidate
tmp=$TEST_TMP
if ! (
%s
); then
  :
fi
`, probeBody),
			},
		} {
			t.Run(shell.name+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				binDir := filepath.Join(dir, "bin")
				if err := os.Mkdir(binDir, 0o700); err != nil {
					t.Fatal(err)
				}
				fakeTimeout := filepath.Join(binDir, "timeout")
				if err := os.WriteFile(fakeTimeout, []byte("#!/bin/sh\nmkdir \"$TEST_MARKER\"\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				script := filepath.Join(dir, "test.sh")
				source := `set -eu
PATH="$TEST_BIN:$PATH"
export PATH
ulimit() { return 1; }
` + tc.body + `
[ ! -d "$TEST_MARKER" ]
`
				if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
					t.Fatal(err)
				}
				args := append(append([]string(nil), shell.args...), script)
				cmd := exec.Command(shell.path, args...)
				cmd.Env = append(os.Environ(),
					"TEST_TMP="+dir,
					"TEST_BIN="+binDir,
					"TEST_MARKER="+filepath.Join(dir, "child-command-ran"),
				)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("file-limit failure reached a child command: %v\n%s", err, out)
				}
			})
		}
	}
}

func TestInstallerInspectionFailuresAreFailClosedAcrossShells(t *testing.T) {
	installer := readReleaseFile(t, "../../scripts/install.sh")
	fetchStart := strings.Index(installer, "fetch_once() {")
	checkStart := strings.Index(installer, "check_safe_dir_chain() {")
	if fetchStart < 0 || checkStart < 0 {
		t.Fatal("could not locate installer inspection functions")
	}
	fetchEndRel := strings.Index(installer[fetchStart:], "\n}\n\nfetch()")
	checkEndRel := strings.Index(installer[checkStart:], "\n}\n\ncheck_safe_dir_chain")
	if fetchEndRel < 0 || checkEndRel < 0 {
		t.Fatal("could not isolate installer inspection functions")
	}
	fetchFunction := installer[fetchStart : fetchStart+fetchEndRel+2]
	checkFunction := installer[checkStart : checkStart+checkEndRel+2]

	type shellCase struct {
		name string
		path string
		args []string
	}
	shells := []shellCase{
		{name: "sh", path: "/bin/sh"},
		{name: "bash", path: "/bin/bash"},
		{name: "dash", path: "/bin/dash"},
	}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		shells = append(shells, shellCase{name: "busybox-ash", path: busybox, args: []string{"ash"}})
	}

	for _, shell := range shells {
		if _, err := os.Stat(shell.path); err != nil {
			continue
		}
		t.Run(shell.name+"/pre-download-rm", func(t *testing.T) {
			dir := t.TempDir()
			binDir := filepath.Join(dir, "bin")
			if err := os.Mkdir(binDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(binDir, "timeout"), []byte("#!/bin/sh\nmkdir \"$TEST_TIMEOUT_MARKER\"\nexit 0\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			outPath := filepath.Join(dir, "out")
			if err := os.WriteFile(outPath, []byte("stale"), 0o600); err != nil {
				t.Fatal(err)
			}
			source := `set -eu
PATH="$TEST_BIN:$PATH"
export PATH
FSIZE_BLOCK_BYTES=512
FETCH_TIMEOUT_SECONDS=1
CONNECT_TIMEOUT_SECONDS=1
` + fetchFunction + `
rm() { return 1; }
if fetch_once "https://example.invalid/bin" "$TEST_FETCH_OUT" 1024 "$FETCH_TIMEOUT_SECONDS"; then
  echo "fetch unexpectedly succeeded" >&2
  exit 1
fi
[ ! -d "$TEST_TIMEOUT_MARKER" ]
`
			runShellFixture(t, shell.path, shell.args, source,
				"TEST_BIN="+binDir,
				"TEST_FETCH_OUT="+outPath,
				"TEST_TIMEOUT_MARKER="+filepath.Join(dir, "timeout-ran"),
			)
		})

		t.Run(shell.name+"/wc", func(t *testing.T) {
			dir := t.TempDir()
			binDir := filepath.Join(dir, "bin")
			if err := os.Mkdir(binDir, 0o700); err != nil {
				t.Fatal(err)
			}
			fakeCurl := `#!/bin/sh
set -eu
curl_out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o | --output) shift; curl_out=$1 ;;
  esac
  shift
done
[ -n "$curl_out" ]
printf payload > "$curl_out"
mkdir "$TEST_CURL_MARKER"
printf '200\n\n'
`
			if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte(fakeCurl), 0o700); err != nil {
				t.Fatal(err)
			}
			outPath := filepath.Join(dir, "out")
			source := `set -eu
PATH="$TEST_BIN:$PATH"
export PATH
FSIZE_BLOCK_BYTES=512
FETCH_TIMEOUT_SECONDS=1
CONNECT_TIMEOUT_SECONDS=1
` + fetchFunction + `
wc() {
  mkdir "$TEST_WC_MARKER"
  return 1
}
if fetch_once "https://example.invalid/bin" "$TEST_FETCH_OUT" 1024 "$FETCH_TIMEOUT_SECONDS"; then
  echo "fetch unexpectedly succeeded" >&2
  exit 1
fi
if [ ! -d "$TEST_CURL_MARKER" ]; then
  echo "curl fixture was not invoked" >&2
  exit 92
fi
if [ ! -d "$TEST_WC_MARKER" ]; then
  echo "wc failure fixture was not invoked" >&2
  exit 93
fi
if [ -e "$TEST_FETCH_OUT" ]; then
  echo "download output survived failed size inspection" >&2
  exit 94
fi
`
			runShellFixture(t, shell.path, shell.args, source,
				"TEST_BIN="+binDir,
				"TEST_FETCH_OUT="+outPath,
				"TEST_CURL_MARKER="+filepath.Join(dir, "curl-ran"),
				"TEST_WC_MARKER="+filepath.Join(dir, "wc-ran"),
			)
		})

		for _, statCase := range []struct {
			name string
			mode string
		}{
			{name: "stat-mode-failure", mode: "failure"},
			{name: "malformed-stat-mode", mode: "malformed"},
		} {
			t.Run(shell.name+"/"+statCase.name, func(t *testing.T) {
				dir := t.TempDir()
				source := `set -eu
fail() { echo "error: $*" >&2; exit 1; }
` + checkFunction + `
stat() {
  case "$2" in
    %u) printf '0\n' ;;
    %A)
      if [ "$TEST_STAT_MODE" = failure ]; then
        return 1
      fi
      printf 'not-a-directory-mode\n'
      ;;
    *) return 1 ;;
  esac
}
check_safe_dir_chain "$TEST_DIR"
mkdir "$TEST_ACCEPTED_MARKER"
`
				script := filepath.Join(dir, "fixture.sh")
				if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
					t.Fatal(err)
				}
				args := append(append([]string(nil), shell.args...), script)
				cmd := exec.Command(shell.path, args...)
				marker := filepath.Join(dir, "unsafe-mode-accepted")
				cmd.Env = append(os.Environ(),
					"TEST_DIR="+dir,
					"TEST_STAT_MODE="+statCase.mode,
					"TEST_ACCEPTED_MARKER="+marker,
				)
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("unsafe stat result was accepted: %s", out)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("directory validation continued after unsafe stat result: %v", err)
				}
			})
		}
	}
}

func runShellFixture(t *testing.T, shell string, shellArgs []string, source string, env ...string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fixture.sh")
	if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
		t.Fatal(err)
	}
	args := append(append([]string(nil), shellArgs...), script)
	cmd := exec.Command(shell, args...)
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell fixture failed: %v\n%s", err, out)
	}
}

func TestInstallerDetectsExactFileLimitBlockSize(t *testing.T) {
	installer := readReleaseFile(t, "../../scripts/install.sh")
	start := strings.Index(installer, "# Bash uses 1024-byte `ulimit -f` blocks")
	end := strings.Index(installer, "\n\nif [ ! -d \"$TMP_ROOT\" ]")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("could not isolate installer file-limit unit probe")
	}
	probe := installer[start:end]

	type shellCase struct {
		name string
		path string
		args []string
		want string
	}
	shells := []shellCase{
		{name: "bash", path: "/bin/bash", want: "1024"},
		{name: "bash-posix", path: "/bin/bash", args: []string{"--posix"}, want: "512"},
		{name: "dash", path: "/bin/dash", want: "512"},
	}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		shells = append(shells, shellCase{name: "busybox-ash", path: busybox, args: []string{"ash"}, want: "512"})
	}
	for _, shell := range shells {
		t.Run(shell.name, func(t *testing.T) {
			if _, err := os.Stat(shell.path); err != nil {
				t.Skip(err)
			}
			script := filepath.Join(t.TempDir(), "probe.sh")
			source := `set -eu
fail() { echo "error: $*" >&2; exit 1; }
` + probe + `
printf '%s' "$FSIZE_BLOCK_BYTES"
`
			if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string(nil), shell.args...), script)
			out, err := exec.Command(shell.path, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("file-limit unit probe failed: %v\n%s", err, out)
			}
			if got := string(out); got != shell.want {
				t.Fatalf("file-limit block size = %q, want %q", got, shell.want)
			}
		})
	}
}

// InstallerPinnedReleaseEndToEnd exercises the disposable-host integration
// entry point declared in release_pipeline_integration_test.go.
func InstallerPinnedReleaseEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installer end-to-end test requires root")
	}
	for _, command := range []string{"curl", "openssl", "sha256sum", "timeout"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("installer dependency unavailable: %s", command)
		}
	}

	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("unsupported installer test architecture: %s", runtime.GOARCH)
	}
	asset := "linux-temp-admin-linux-" + runtime.GOARCH
	destDir, err := os.MkdirTemp("/usr/local/lib", ".lta-installer-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(destDir) })
	dest := filepath.Join(destDir, "linux-temp-admin")
	coreEvidence := filepath.Join(destDir, "core-limits")
	activationEvidence := filepath.Join(destDir, "activation-evidence")
	activationBlock := filepath.Join(destDir, "activation-block")
	tombstone := filepath.Join(destDir, "uninstalled-marker")
	if err := os.WriteFile(tombstone, []byte("uninstalled-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := []byte(fmt.Sprintf(`#!/bin/sh
case "$1" in
  version)
    awk '$1 == "Max" && $2 == "core" && $3 == "file" && $4 == "size" { print $5, $6 }' /proc/self/limits > "$LTA_CORE_EVIDENCE"
    printf '2.8.0\n'
    ;;
  --lang)
    [ "$#" -eq 4 ] && [ "$2" = en ] && [ "$3" = install ] && [ "$4" = --force ] || exit 76
    [ ! -e '%s' ] || exit 77
    /bin/cp -- "$0" '%s'
    /bin/chown 0:0 '%s'
    /bin/chmod 0755 '%s'
    /bin/rm -f -- '%s'
    printf 'delegated\n' > '%s'
    ;;
  *) exit 78 ;;
esac
`, activationBlock, dest, dest, dest, tombstone, activationEvidence))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, candidate)
	keyDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyDER})
	sum := sha256.Sum256(candidate)
	sigSum := sha256.Sum256(signature)
	manifest := []byte(fmt.Sprintf("%x  %s\n%x  %s.sig\n", sum, asset, sigSum, asset))

	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch filepath.Base(r.URL.Path) {
		case asset:
			_, _ = w.Write(candidate)
		case asset + ".sig":
			_, _ = w.Write(signature)
		case "SHA256SUMS":
			_, _ = w.Write(manifest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	certPath := filepath.Join(t.TempDir(), "test-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	installer := readReleaseFile(t, "../../scripts/install.sh")
	installer = strings.ReplaceAll(installer,
		`MIRROR_ROOT=https://dl.ll.cd/linux-temp-admin`,
		`MIRROR_ROOT=`+server.URL)
	installer = strings.ReplaceAll(installer,
		`GITHUB_RELEASE_ROOT=https://github.com/xxvcc/linux-temp-admin/releases`,
		`GITHUB_RELEASE_ROOT=`+server.URL)
	installer = strings.ReplaceAll(installer,
		"MANAGED_DEST=/usr/local/sbin/linux-temp-admin",
		"MANAGED_DEST="+dest)
	keyStart := strings.Index(installer, "RELEASE_PUBKEY_PEMS='")
	if keyStart < 0 {
		t.Fatal("installer keyring start not found")
	}
	keyBodyStart := keyStart + len("RELEASE_PUBKEY_PEMS='")
	keyEndRel := strings.Index(installer[keyBodyStart:], "'\n# LTA_RELEASE_KEYS_END")
	if keyEndRel < 0 {
		t.Fatal("installer keyring end not found")
	}
	installer = installer[:keyBodyStart] + "\n" + strings.TrimSpace(string(keyPEM)) + "\n" +
		installer[keyBodyStart+keyEndRel:]
	installerPath := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(installerPath, []byte(installer), 0o700); err != nil {
		t.Fatal(err)
	}

	doubleSlash := exec.Command("/bin/sh", installerPath)
	doubleSlash.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"DEST=//tmp/lta-must-not-install",
		"LTA_RELEASE=v2.8.0",
	}
	requestsBeforeDoubleSlash := requests.Load()
	doubleSlashOut, doubleSlashErr := doubleSlash.CombinedOutput()
	if doubleSlashErr == nil || !strings.Contains(string(doubleSlashOut), "DEST must not begin with //") {
		t.Fatalf("ambiguous double-slash destination was not rejected: err=%v\n%s", doubleSlashErr, doubleSlashOut)
	}
	if got := requests.Load(); got != requestsBeforeDoubleSlash {
		t.Fatalf("ambiguous destination made %d network requests", got-requestsBeforeDoubleSlash)
	}

	run := func(release string) ([]byte, error) {
		env := make([]string, 0, len(os.Environ())+5)
		for _, entry := range os.Environ() {
			if strings.HasPrefix(entry, "LTA_RELEASE=") || strings.HasPrefix(entry, "DEST=") ||
				strings.HasPrefix(entry, "CURL_CA_BUNDLE=") || strings.HasPrefix(entry, "LTA_CORE_EVIDENCE=") ||
				strings.HasPrefix(entry, "HTTPS_PROXY=") || strings.HasPrefix(entry, "https_proxy=") ||
				strings.HasPrefix(entry, "ALL_PROXY=") || strings.HasPrefix(entry, "all_proxy=") ||
				strings.HasPrefix(entry, "NO_PROXY=") || strings.HasPrefix(entry, "no_proxy=") {
				continue
			}
			env = append(env, entry)
		}
		env = append(env,
			"LTA_RELEASE="+release,
			"CURL_CA_BUNDLE="+certPath,
			"LTA_CORE_EVIDENCE="+coreEvidence,
			"NO_PROXY=127.0.0.1,localhost",
		)
		cmd := exec.Command("/bin/sh", installerPath)
		cmd.Env = env
		return cmd.CombinedOutput()
	}

	tooLongRelease := "v2.3.4-" + strings.Repeat("a", validate.MaxReleaseVersionBytes-len("2.3.4-")+1)
	if len(tooLongRelease) != validate.MaxReleaseVersionBytes+2 {
		t.Fatalf("overlong installer fixture has length %d", len(tooLongRelease))
	}
	for _, release := range []string{"", "v02.8.0", "v2.8.0?query", "../v2.8.0", "v2.8", tooLongRelease} {
		before := requests.Load()
		out, err := run(release)
		if err == nil {
			t.Errorf("invalid LTA_RELEASE %q unexpectedly succeeded: %s", release, out)
		}
		if after := requests.Load(); after != before {
			t.Errorf("invalid LTA_RELEASE %q made %d network requests", release, after-before)
		}
		if _, statErr := os.Lstat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("invalid LTA_RELEASE %q changed target: %v", release, statErr)
		}
	}

	out, err := run("v2.8.1")
	if err == nil || !strings.Contains(string(out), "version does not match LTA_RELEASE") {
		t.Fatalf("signed version mismatch was not rejected: err=%v\n%s", err, out)
	}
	if _, statErr := os.Lstat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("version mismatch changed target: %v", statErr)
	}

	if err := os.WriteFile(activationBlock, []byte("block\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = run("v2.8.0")
	if err == nil || !strings.Contains(string(out), "could not complete the managed install/reactivation") {
		t.Fatalf("candidate install refusal was not fail-closed: err=%v\n%s", err, out)
	}
	if _, statErr := os.Lstat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("candidate install refusal changed target: %v", statErr)
	}
	if _, statErr := os.Stat(tombstone); statErr != nil {
		t.Fatalf("candidate install refusal removed the uninstall marker: %v", statErr)
	}
	if err := os.Remove(activationBlock); err != nil {
		t.Fatal(err)
	}

	out, err = run("v2.8.0")
	if err != nil {
		t.Fatalf("pinned from-zero install failed: %v\n%s", err, out)
	}
	installed, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, candidate) {
		t.Fatal("installed bytes differ from the signed candidate")
	}
	if evidence, err := os.ReadFile(activationEvidence); err != nil || string(evidence) != "delegated\n" {
		t.Fatalf("managed install was not delegated to the signed candidate: evidence=%q err=%v", evidence, err)
	}
	if _, err := os.Lstat(tombstone); !os.IsNotExist(err) {
		t.Fatalf("successful delegated install did not clear the uninstall marker: %v", err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode = %04o, want 0755", fi.Mode().Perm())
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 || stat.Gid != 0 {
		t.Fatalf("installed ownership is not root:root: %#v", fi.Sys())
	}
	limits, err := os.ReadFile(coreEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(limits)) != "0 0" {
		t.Fatalf("candidate core soft/hard limits = %q, want 0 0", strings.TrimSpace(string(limits)))
	}
}

// InstallerOfficialMirrorFallbackBoundary exercises the disposable-host
// integration entry point declared in release_pipeline_integration_test.go.
func InstallerOfficialMirrorFallbackBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installer end-to-end test requires root")
	}
	for _, command := range []string{"curl", "openssl", "sha256sum", "timeout"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("installer dependency unavailable: %s", command)
		}
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("unsupported installer test architecture: %s", runtime.GOARCH)
	}

	asset := "linux-temp-admin-linux-" + runtime.GOARCH
	candidate := []byte("#!/bin/sh\n[ \"$1\" = version ] && printf '2.8.0\\n'\n")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	goodSig := ed25519.Sign(priv, candidate)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongSig := ed25519.Sign(wrongPriv, candidate)
	keyDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyDER})
	releaseSums := func(sig []byte) string {
		return fmt.Sprintf("%x  %s\n%x  %s.sig\n", sha256.Sum256(candidate), asset, sha256.Sum256(sig), asset)
	}
	goodSum := releaseSums(goodSig)

	var mu sync.Mutex
	mode := ""
	requests := make(map[string]int)
	mirrorCacheBypass := false
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		currentMode := mode
		requests[r.URL.Path]++
		if strings.HasPrefix(r.URL.Path, "/mirror/") && r.URL.Query().Has("download") {
			mirrorCacheBypass = true
		}
		mu.Unlock()
		if r.URL.Path == "/mirror/latest.json" {
			switch currentMode {
			case "manifest-transfer":
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			case "manifest-redirect":
				http.Redirect(w, r, server.URL+"/mirror/redirected-latest.json", http.StatusFound)
				return
			case "manifest-invalid":
				_, _ = w.Write([]byte(`{"version":"2.8.0","tag":"v2.8.1","base_url":"` + server.URL + `/mirror/v2.8.0","published_at":"2026-07-27T05:00:00Z"}` + "\n"))
				return
			case "manifest-time-invalid":
				_, _ = w.Write([]byte(`{"version":"2.8.0","tag":"v2.8.0","base_url":"` + server.URL + `/mirror/v2.8.0","published_at":"2026-02-30T05:00:00Z"}` + "\n"))
				return
			case "manifest-format-invalid":
				_, _ = w.Write([]byte(`{"tag":"v2.8.0","version":"2.8.0","base_url":"` + server.URL + `/mirror/v2.8.0","published_at":"2026-07-27T05:00:00Z"}` + "\n"))
				return
			default:
				_, _ = w.Write([]byte(`{"version":"2.8.0","tag":"v2.8.0","base_url":"` + server.URL + `/mirror/v2.8.0","published_at":"2026-07-27T05:00:00Z"}` + "\n"))
				return
			}
		}
		name := filepath.Base(r.URL.Path)
		isMirror := strings.HasPrefix(r.URL.Path, "/mirror/")
		switch name {
		case "SHA256SUMS":
			if isMirror && currentMode == "sums-transfer" {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			} else if isMirror && currentMode == "sums-redirect" {
				http.Redirect(w, r, server.URL+"/mirror/v2.8.0/redirected-sums", http.StatusFound)
			} else if isMirror && currentMode == "sums-no-newline" {
				_, _ = w.Write([]byte(strings.TrimSuffix(goodSum, "\n")))
			} else if isMirror && currentMode == "sums-uppercase" {
				_, _ = w.Write([]byte(strings.ToUpper(goodSum[:64]) + goodSum[64:]))
			} else if isMirror && currentMode == "checksum-invalid" {
				_, _ = fmt.Fprintf(w, "%064d  %s\n%x  %s.sig\n", 0, asset, sha256.Sum256(goodSig), asset)
			} else if isMirror && currentMode == "signature-checksum-invalid" {
				_, _ = fmt.Fprintf(w, "%x  %s\n%064d  %s.sig\n", sha256.Sum256(candidate), asset, 0, asset)
			} else if isMirror && currentMode == "signature-invalid" {
				_, _ = w.Write([]byte(releaseSums(wrongSig)))
			} else if isMirror && currentMode == "signature-hex" {
				_, _ = w.Write([]byte(releaseSums([]byte(fmt.Sprintf("%x", goodSig)))))
			} else if isMirror && currentMode == "signature-newline" {
				_, _ = w.Write([]byte(releaseSums(append(append([]byte(nil), goodSig...), '\n'))))
			} else {
				_, _ = w.Write([]byte(goodSum))
			}
		case asset:
			if isMirror && currentMode == "binary-transfer" {
				http.NotFound(w, r)
			} else {
				_, _ = w.Write(candidate)
			}
		case asset + ".sig":
			if isMirror && currentMode == "asset-transfer" {
				http.NotFound(w, r)
			} else if isMirror && currentMode == "signature-invalid" {
				_, _ = w.Write(wrongSig)
			} else if isMirror && currentMode == "signature-hex" {
				_, _ = fmt.Fprintf(w, "%x", goodSig)
			} else if isMirror && currentMode == "signature-newline" {
				_, _ = w.Write(append(append([]byte(nil), goodSig...), '\n'))
			} else {
				_, _ = w.Write(goodSig)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	certPath := filepath.Join(t.TempDir(), "test-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	installer := readReleaseFile(t, "../../scripts/install.sh")
	installer = strings.ReplaceAll(installer, "MIRROR_ROOT=https://dl.ll.cd/linux-temp-admin", "MIRROR_ROOT="+server.URL+"/mirror")
	installer = strings.ReplaceAll(installer, "GITHUB_RELEASE_ROOT=https://github.com/xxvcc/linux-temp-admin/releases", "GITHUB_RELEASE_ROOT="+server.URL+"/github")
	installer = strings.ReplaceAll(installer, "MIRROR_FETCH_ATTEMPTS=2", "MIRROR_FETCH_ATTEMPTS=1")
	installer = strings.ReplaceAll(installer, "GITHUB_FETCH_ATTEMPTS=4", "GITHUB_FETCH_ATTEMPTS=1")
	keyStart := strings.Index(installer, "RELEASE_PUBKEY_PEMS='")
	if keyStart < 0 {
		t.Fatal("installer keyring start not found")
	}
	keyBodyStart := keyStart + len("RELEASE_PUBKEY_PEMS='")
	keyEndRel := strings.Index(installer[keyBodyStart:], "'\n# LTA_RELEASE_KEYS_END")
	if keyEndRel < 0 {
		t.Fatal("installer keyring end not found")
	}
	installer = installer[:keyBodyStart] + "\n" + strings.TrimSpace(string(keyPEM)) + "\n" + installer[keyBodyStart+keyEndRel:]
	installerPath := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(installerPath, []byte(installer), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name             string
		mode             string
		release          string
		wantOK           bool
		wantGitHub       int
		wantGitHubLatest bool
	}{
		{name: "mirror exact success", mode: "success", release: "v2.8.0", wantOK: true},
		{name: "checksum transport falls back complete set", mode: "sums-transfer", release: "v2.8.0", wantOK: true, wantGitHub: 3},
		{name: "checksum redirect stops", mode: "sums-redirect", release: "v2.8.0"},
		{name: "binary transport falls back complete set", mode: "binary-transfer", release: "v2.8.0", wantOK: true, wantGitHub: 3},
		{name: "asset transport falls back complete set", mode: "asset-transfer", release: "v2.8.0", wantOK: true, wantGitHub: 3},
		{name: "checksum failure stops", mode: "checksum-invalid", release: "v2.8.0"},
		{name: "signature checksum failure stops", mode: "signature-checksum-invalid", release: "v2.8.0"},
		{name: "signature failure stops", mode: "signature-invalid", release: "v2.8.0"},
		{name: "noncanonical checksum newline stops", mode: "sums-no-newline", release: "v2.8.0"},
		{name: "noncanonical uppercase checksum stops", mode: "sums-uppercase", release: "v2.8.0"},
		{name: "hex signature format stops", mode: "signature-hex", release: "v2.8.0"},
		{name: "newline signature format stops", mode: "signature-newline", release: "v2.8.0"},
		{name: "candidate version failure stops", mode: "success", release: "v2.8.1"},
		{name: "latest pins fallback tag", mode: "asset-transfer", release: "latest", wantOK: true, wantGitHub: 3},
		{name: "manifest transport uses GitHub Latest", mode: "manifest-transfer", release: "latest", wantOK: true, wantGitHub: 3, wantGitHubLatest: true},
		{name: "manifest redirect stops", mode: "manifest-redirect", release: "latest"},
		{name: "manifest contradiction stops", mode: "manifest-invalid", release: "latest"},
		{name: "manifest timestamp stops", mode: "manifest-time-invalid", release: "latest"},
		{name: "manifest field order stops", mode: "manifest-format-invalid", release: "latest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			destDir, err := os.MkdirTemp("/usr/local/lib", ".lta-mirror-installer-test-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(destDir) })
			dest := filepath.Join(destDir, "linux-temp-admin")
			mu.Lock()
			mode = tc.mode
			requests = make(map[string]int)
			mirrorCacheBypass = false
			mu.Unlock()
			cmd := exec.Command("/bin/sh", installerPath)
			cmd.Env = []string{
				"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
				"DEST=" + dest,
				"LTA_RELEASE=" + tc.release,
				"CURL_CA_BUNDLE=" + certPath,
				"NO_PROXY=127.0.0.1,localhost",
			}
			out, runErr := cmd.CombinedOutput()
			if (runErr == nil) != tc.wantOK {
				t.Fatalf("installer err=%v wantOK=%v\n%s", runErr, tc.wantOK, out)
			}
			mu.Lock()
			gotRequests := make(map[string]int, len(requests))
			for path, count := range requests {
				gotRequests[path] = count
			}
			gotMirrorCacheBypass := mirrorCacheBypass
			mu.Unlock()
			if gotMirrorCacheBypass {
				t.Fatal("official mirror request unexpectedly used the GitHub download=1 cache bypass")
			}
			if gotRequests["/mirror/redirected-latest.json"] != 0 ||
				gotRequests["/mirror/v2.8.0/redirected-sums"] != 0 {
				t.Fatalf("official mirror redirect was followed: %v", gotRequests)
			}
			manifestRequests := gotRequests["/mirror/latest.json"]
			if tc.release == "latest" && manifestRequests != 1 {
				t.Fatalf("latest release made %d mirror manifest requests, want 1; all=%v", manifestRequests, gotRequests)
			}
			if tc.release != "latest" && manifestRequests != 0 {
				t.Fatalf("exact release made %d mirror manifest requests, want 0; all=%v", manifestRequests, gotRequests)
			}
			githubRequests := 0
			latestRequests := 0
			for path, count := range gotRequests {
				if strings.HasPrefix(path, "/github/") {
					githubRequests += count
					if strings.Contains(path, "/latest/download/") {
						latestRequests += count
					}
				}
			}
			if githubRequests != tc.wantGitHub {
				t.Fatalf("GitHub requests=%d, want %d; all=%v", githubRequests, tc.wantGitHub, gotRequests)
			}
			if (latestRequests > 0) != tc.wantGitHubLatest {
				t.Fatalf("GitHub Latest requests=%d, wantLatest=%v; all=%v", latestRequests, tc.wantGitHubLatest, gotRequests)
			}
		})
	}
}

func TestInstallerResolverClassifierMatchesGoPublicAddressPolicy(t *testing.T) {
	installer := readReleaseFile(t, "../../scripts/install.sh")
	start := strings.Index(installer, "validate_resolver_output() {")
	if start < 0 {
		t.Fatal("could not locate installer public-address classifier")
	}
	end := strings.Index(installer[start:], "\n\nresolve_public_address() {")
	if end < 0 {
		t.Fatal("could not isolate installer public-address classifier")
	}
	classifier := installer[start : start+end+2]

	addresses := []string{
		"8.8.8.8", "100.63.255.255", "100.128.0.1", "192.0.1.1", "198.20.0.1",
		"0.0.0.1", "10.0.0.1", "100.64.0.1", "100.127.255.254", "127.0.0.1",
		"169.254.1.1", "172.16.0.1", "172.31.255.254", "192.168.0.1", "192.0.0.1",
		"192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.175.48.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
		"2606:4700:4700::1111", "2000::1", "2001:200::1", "2001:db9::1", "3fef:ffff::1", "3ff0::1", "3fff:1000::1",
		"::", "::1", "100:0:0:1::1", "4000::1", "fc00::1", "fdff::1", "fec0::1", "fe80::1", "ff02::1",
		"64:ff9b::808:808", "64:ff9b:1::1", "100::1", "2001:1ff::1",
		"2001:db8::1", "2002::1", "3fff::1", "3fff:0fff::1", "5f00::1",
		"::ffff:8.8.8.8", "::ffff:10.0.0.1",
	}
	for _, address := range addresses {
		t.Run(strings.ReplaceAll(address, ":", "_"), func(t *testing.T) {
			script := filepath.Join(t.TempDir(), "classify.sh")
			source := `set -eu
` + classifier + `
if result=$(printf '%s STREAM resolved.example\n' "$TEST_ADDRESS" | validate_resolver_output getent); then
  printf 'public:%s\n' "$result"
else
  printf 'refused:%s\n' "$?"
fi
`
			if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/sh", script)
			cmd.Env = append(os.Environ(), "TEST_ADDRESS="+address)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("classifier fixture failed: %v\n%s", err, out)
			}
			wantPublic := validate.PublicIP(net.ParseIP(address))
			gotPublic := strings.HasPrefix(string(out), "public:")
			if gotPublic != wantPublic {
				t.Fatalf("installer public=%v, Go public=%v, output=%q", gotPublic, wantPublic, out)
			}
			if !wantPublic && string(out) != "refused:2\n" {
				t.Fatalf("non-public address classification=%q, want policy status 2", out)
			}
		})
	}
}

func TestInstallerGitHubRedirectsResolveBeforeRequestAcrossShells(t *testing.T) {
	installer := readReleaseFile(t, "../../scripts/install.sh")
	networkStart := strings.Index(installer, "validate_resolver_output() {")
	fetchStart := strings.Index(installer, "fetch_once() {")
	if networkStart < 0 || fetchStart < 0 {
		t.Fatal("could not locate installer redirect guards")
	}
	networkEnd := strings.Index(installer[networkStart:], "\n# RLIMIT_FSIZE")
	fetchEnd := strings.Index(installer[fetchStart:], "\n}\n\nfetch()")
	if networkEnd < 0 || fetchEnd < 0 {
		t.Fatal("could not isolate installer redirect guards")
	}
	networkFunctions := installer[networkStart : networkStart+networkEnd]
	fetchFunction := installer[fetchStart : fetchStart+fetchEnd+2]
	if got := strings.Count(networkFunctions, "command -v nslookup"); got != 1 {
		t.Fatalf("installer nslookup availability probe count=%d, want 1", got)
	}
	if got := strings.Count(networkFunctions, " nslookup -type="); got != 2 {
		t.Fatalf("installer nslookup invocation count=%d, want 2", got)
	}
	// BusyBox builds with FEATURE_PREFER_APPLETS ignore PATH fixtures when an
	// applet invokes another applet. Point only the external resolver dependency
	// at an absolute fixture while retaining the installer's parser and policy.
	fixtureNetworkFunctions := strings.Replace(
		networkFunctions,
		"command -v nslookup",
		`command -v "$TEST_NSLOOKUP_COMMAND"`,
		1,
	)
	fixtureNetworkFunctions = strings.ReplaceAll(
		fixtureNetworkFunctions,
		" nslookup -type=",
		` "$TEST_NSLOOKUP_COMMAND" -type=`,
	)

	type shellCase struct {
		name       string
		path       string
		args       []string
		busyboxBin bool
	}
	shells := []shellCase{
		{name: "bash", path: "/bin/bash"},
		{name: "dash", path: "/bin/dash"},
	}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		shells = append(shells, shellCase{name: "busybox-ash", path: busybox, args: []string{"ash"}, busyboxBin: true})
	}

	for _, shell := range shells {
		if _, err := os.Stat(shell.path); err != nil {
			continue
		}
		for _, tc := range []struct {
			name           string
			resolver       string
			resolverOutput string
			redirectURL    string
			secondPrivate  bool
			slowChain      bool
			slowResolver   bool
			curlDelay      string
			resolverDelay  string
			fetchTimeout   string
			nslookupOld    bool
			wantRC         int
			wantRequests   int
		}{
			{name: "getent public", resolver: "getent", resolverOutput: "93.184.216.34 STREAM redirect.example", wantRC: 0, wantRequests: 2},
			{name: "getent private", resolver: "getent", resolverOutput: "127.0.0.1 STREAM redirect.example", wantRC: 2, wantRequests: 1},
			{name: "getent mixed", resolver: "getent", resolverOutput: "93.184.216.34 STREAM redirect.example\n10.0.0.1 STREAM redirect.example", wantRC: 2, wantRequests: 1},
			{name: "second redirect private", resolver: "getent", resolverOutput: "93.184.216.34 STREAM redirect.example", secondPrivate: true, wantRC: 2, wantRequests: 2},
			{name: "multi-hop shares one wall clock budget", resolver: "getent", resolverOutput: "93.184.216.34 STREAM redirect.example", slowChain: true, curlDelay: "0.4", fetchTimeout: "1", wantRC: 1, wantRequests: -1},
			{name: "DNS shares the wall clock budget", resolver: "getent", resolverOutput: "93.184.216.34 STREAM redirect.example", slowResolver: true, curlDelay: "0.4", resolverDelay: "0.8", fetchTimeout: "1", wantRC: 1, wantRequests: 1},
			{name: "nslookup fallback", resolver: "nslookup", resolverOutput: "93.184.216.34", wantRC: 0, wantRequests: 2},
			{name: "old busybox nslookup fallback", resolver: "nslookup", resolverOutput: "93.184.216.34", nslookupOld: true, wantRC: 0, wantRequests: 2},
			{name: "public IPv4 literal", resolver: "none", redirectURL: "https://8.8.8.8/asset", wantRC: 0, wantRequests: 2},
			{name: "private IPv4 literal", resolver: "none", redirectURL: "https://127.0.0.1/asset", wantRC: 2, wantRequests: 1},
			{name: "public IPv6 literal", resolver: "none", redirectURL: "https://[2606:4700:4700::1111]/asset", wantRC: 0, wantRequests: 2},
			{name: "private IPv6 literal", resolver: "none", redirectURL: "https://[::1]/asset", wantRC: 2, wantRequests: 1},
			{name: "non-https redirect", resolver: "none", redirectURL: "http://127.0.0.1/asset", wantRC: 2, wantRequests: 1},
			{name: "missing resolver", resolver: "none", wantRC: 1, wantRequests: 1},
		} {
			t.Run(shell.name+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				binDir := filepath.Join(dir, "bin")
				if err := os.Mkdir(binDir, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, command := range []string{"awk", "rm", "sleep", "timeout", "wc"} {
					target := shell.path
					if !shell.busyboxBin {
						var err error
						target, err = exec.LookPath(command)
						if err != nil {
							t.Skipf("installer dependency unavailable: %s", command)
						}
					}
					if err := os.Symlink(target, filepath.Join(binDir, command)); err != nil {
						t.Fatal(err)
					}
				}
				curlFixture := `#!/bin/sh
curl_url=
curl_out=
curl_resolve=
curl_noproxy=
curl_location=0
curl_max_redirs=
curl_max_time=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --resolve) shift; curl_resolve=$1 ;;
    --noproxy) shift; curl_noproxy=$1 ;;
    --location) curl_location=1 ;;
    --max-redirs) shift; curl_max_redirs=$1 ;;
    --max-time) shift; curl_max_time=$1 ;;
    -o | --output) shift; curl_out=$1 ;;
    https://*) curl_url=$1 ;;
  esac
  shift
done
[ "$curl_noproxy" = '*' ] && [ "$curl_location" = 1 ] && [ "$curl_max_redirs" = 0 ] || exit 85
printf '%s|%s|%s\n' "$curl_url" "$curl_resolve" "$curl_max_time" >> "$TEST_CURL_MARKER"
: > "$curl_out"
if [ -n "$TEST_CURL_DELAY" ]; then
  sleep "$TEST_CURL_DELAY"
fi
case "$curl_url" in
  https://github.example/asset)
    printf '302\n%s\n' "${TEST_REDIRECT_URL:-https://redirect.example/asset}"
    exit 47
    ;;
  https://redirect.example/asset)
    [ "$curl_resolve" = 'redirect.example:443:93.184.216.34' ] || exit 86
    if [ "$TEST_SECOND_PRIVATE" = 1 ]; then
      printf '302\nhttps://second.example/asset\n'
      exit 47
    elif [ "$TEST_SLOW_CHAIN" = 1 ]; then
      printf '302\nhttps://second.example/asset\n'
      exit 47
    else
      printf payload > "$curl_out"
      printf '200\n\n'
    fi
    ;;
  https://8.8.8.8/asset | https://\[2606:4700:4700::1111\]/asset)
    [ -z "$curl_resolve" ] || exit 88
    printf payload > "$curl_out"
    printf '200\n\n'
    ;;
  https://second.example/asset)
    [ "$curl_resolve" = 'second.example:443:93.184.216.34' ] || exit 89
    printf payload > "$curl_out"
    printf '200\n\n'
    ;;
  *) exit 87 ;;
esac
`
				if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte(curlFixture), 0o700); err != nil {
					t.Fatal(err)
				}
				switch tc.resolver {
				case "getent":
					fixture := `#!/bin/sh
if [ -n "$TEST_RESOLVER_DELAY" ]; then
  sleep "$TEST_RESOLVER_DELAY"
fi
if [ "$2" = second.example ]; then
  if [ "$TEST_SECOND_PRIVATE" = 1 ]; then
    printf '127.0.0.1 STREAM second.example\n'
  else
    printf '93.184.216.34 STREAM second.example\n'
  fi
else
  printf '%s\n' "$TEST_RESOLVER_OUTPUT"
fi
`
					if err := os.WriteFile(filepath.Join(binDir, "getent"), []byte(fixture), 0o700); err != nil {
						t.Fatal(err)
					}
				case "nslookup":
					fixture := `#!/bin/sh
printf '%s\n' "$*" >> "$TEST_NSLOOKUP_MARKER"
if [ "$TEST_NSLOOKUP_OLD" = 1 ]; then
  printf 'Server: resolver.invalid\nAddress 1: 10.0.0.53 resolver.invalid\n\n'
  printf 'Name: redirect.example\nAddress 1: %s redirect.example\n' "$TEST_RESOLVER_OUTPUT"
else
  printf 'Server:\tresolver.invalid\nAddress: 10.0.0.53#53\n\n'
  printf 'Name:\tredirect.example\nAddress: %s\n' "$TEST_RESOLVER_OUTPUT"
fi
`
					if err := os.WriteFile(filepath.Join(binDir, "nslookup"), []byte(fixture), 0o700); err != nil {
						t.Fatal(err)
					}
				}

				script := filepath.Join(dir, "redirect.sh")
				source := `set -eu
PATH="$TEST_BIN"
export PATH
FSIZE_BLOCK_BYTES=512
CONNECT_TIMEOUT_SECONDS=2
` + fixtureNetworkFunctions + "\n" + fetchFunction + `
if fetch_once 'https://github.example/asset' "$TEST_OUT" 4096 "$TEST_FETCH_TIMEOUT" 1; then
  fetch_rc=0
else
  fetch_rc=$?
fi
printf 'rc=%s\n' "$fetch_rc"
`
				if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
					t.Fatal(err)
				}
				args := append(append([]string(nil), shell.args...), script)
				cmd := exec.Command(shell.path, args...)
				marker := filepath.Join(dir, "curl-requests")
				nslookupMarker := filepath.Join(dir, "nslookup-requests")
				nslookupOld := "0"
				if tc.nslookupOld {
					nslookupOld = "1"
				}
				secondPrivate := "0"
				if tc.secondPrivate {
					secondPrivate = "1"
				}
				slowChain := "0"
				if tc.slowChain {
					slowChain = "1"
				}
				fetchTimeout := tc.fetchTimeout
				if fetchTimeout == "" {
					fetchTimeout = "5"
				}
				cmd.Env = []string{
					"TEST_BIN=" + binDir,
					"TEST_CURL_MARKER=" + marker,
					"TEST_NSLOOKUP_COMMAND=" + filepath.Join(binDir, "nslookup"),
					"TEST_NSLOOKUP_MARKER=" + nslookupMarker,
					"TEST_OUT=" + filepath.Join(dir, "out"),
					"TEST_RESOLVER_OUTPUT=" + tc.resolverOutput,
					"TEST_NSLOOKUP_OLD=" + nslookupOld,
					"TEST_REDIRECT_URL=" + tc.redirectURL,
					"TEST_SECOND_PRIVATE=" + secondPrivate,
					"TEST_SLOW_CHAIN=" + slowChain,
					"TEST_CURL_DELAY=" + tc.curlDelay,
					"TEST_RESOLVER_DELAY=" + tc.resolverDelay,
					"TEST_FETCH_TIMEOUT=" + fetchTimeout,
				}
				started := time.Now()
				out, err := cmd.CombinedOutput()
				elapsed := time.Since(started)
				if err != nil {
					t.Fatalf("redirect fixture failed: %v\n%s", err, out)
				}
				if tc.resolver == "nslookup" {
					calls, err := os.ReadFile(nslookupMarker)
					if err != nil {
						t.Fatalf("nslookup fixture was not invoked: %v", err)
					}
					const wantCalls = "-type=A redirect.example\n-type=AAAA redirect.example\n"
					if string(calls) != wantCalls {
						t.Fatalf("nslookup calls=%q, want %q", calls, wantCalls)
					}
				}
				if string(out) != fmt.Sprintf("rc=%d\n", tc.wantRC) {
					t.Fatalf("fetch result=%q, want rc=%d", out, tc.wantRC)
				}
				requests, err := os.ReadFile(marker)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(requests)), "\n")
				if tc.slowChain && (len(lines) < 2 || len(lines) > 3) {
					t.Fatalf("slow redirect chain made %d requests, want 2 or 3: %q", len(lines), requests)
				}
				if !tc.slowChain && len(lines) != tc.wantRequests {
					t.Fatalf("curl requests=%d, want %d: %q", len(lines), tc.wantRequests, requests)
				}
				if (tc.slowChain || tc.slowResolver) && elapsed > 2*time.Second {
					t.Fatalf("shared one-second fetch budget took %s", elapsed)
				}
				if tc.slowChain {
					previous := 2.0
					for _, line := range lines {
						parts := strings.SplitN(line, "|", 3)
						if len(parts) != 3 {
							t.Fatalf("malformed curl request evidence: %q", line)
						}
						remaining, err := strconv.ParseFloat(parts[2], 64)
						if err != nil || remaining <= 0 || remaining >= previous {
							t.Fatalf("per-hop remaining budgets did not decrease: %q", requests)
						}
						previous = remaining
					}
				}
				if len(lines) >= 2 {
					wantLine := "https://redirect.example/asset|redirect.example:443:93.184.216.34"
					if tc.redirectURL != "" {
						wantLine = tc.redirectURL + "|"
					}
					parts := strings.SplitN(lines[1], "|", 3)
					if len(parts) != 3 {
						t.Fatalf("malformed curl request evidence: %q", lines[1])
					}
					gotLine := strings.Join(parts[:2], "|")
					if gotLine != wantLine {
						t.Fatalf("redirect request did not use the validated endpoint: got %q, want %q", gotLine, wantLine)
					}
				}
			})
		}
	}
}

func TestInstallerFetchRejectsHTTPRedirectAndChunkedOverflow(t *testing.T) {
	for _, command := range []string{"curl", "timeout"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("installer dependency unavailable: %s", command)
		}
	}

	var plainRequests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainRequests.Add(1)
		_, _ = w.Write([]byte("redirect downgrade reached"))
	}))
	defer plain.Close()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, plain.URL+"/hit", http.StatusFound)
		case "/redirect-overflow":
			w.Header().Set("Location", plain.URL+"/hit")
			w.WriteHeader(http.StatusFound)
			chunk := bytes.Repeat([]byte("x"), 1024)
			for i := 0; i < 64; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		case "/overflow":
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}
			chunk := bytes.Repeat([]byte("x"), 1024)
			for i := 0; i < 64; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				flusher.Flush()
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer tlsServer.Close()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "test-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	installer := readReleaseFile(t, "../../scripts/install.sh")
	fetchStart := strings.Index(installer, "fetch_once() {")
	unitStart := strings.Index(installer, "# Bash uses 1024-byte `ulimit -f` blocks")
	unitEnd := strings.Index(installer, "\n\nif [ ! -d \"$TMP_ROOT\" ]")
	if fetchStart < 0 || unitStart < 0 || unitEnd < 0 {
		t.Fatal("could not locate installer fetch guards")
	}
	fetchEndRel := strings.Index(installer[fetchStart:], "\n}\n\nfetch()")
	if fetchEndRel < 0 {
		t.Fatal("could not isolate installer fetch function")
	}
	fetchFunction := installer[fetchStart : fetchStart+fetchEndRel+2]
	unitProbe := installer[unitStart:unitEnd]

	run := func(t *testing.T, path string, wantRC int) {
		t.Helper()
		script := filepath.Join(t.TempDir(), "fetch-test.sh")
		source := `set -eu
fail() { echo "error: $*" >&2; exit 1; }
` + unitProbe + `
FETCH_TIMEOUT_SECONDS=5
CONNECT_TIMEOUT_SECONDS=2
` + fetchFunction + `
out=$TEST_DIR/out
if fetch_once "$TEST_URL` + path + `" "$out" 4096 "$FETCH_TIMEOUT_SECONDS"; then
  echo "unsafe fetch unexpectedly succeeded" >&2
  exit 1
else
  fetch_rc=$?
fi
[ "$fetch_rc" -eq ` + fmt.Sprint(wantRC) + ` ]
[ ! -e "$out" ]
`
		if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
			t.Fatal(err)
		}
		env := make([]string, 0, len(os.Environ())+4)
		for _, entry := range os.Environ() {
			if strings.HasPrefix(entry, "CURL_CA_BUNDLE=") ||
				strings.HasPrefix(entry, "HTTPS_PROXY=") || strings.HasPrefix(entry, "https_proxy=") ||
				strings.HasPrefix(entry, "ALL_PROXY=") || strings.HasPrefix(entry, "all_proxy=") ||
				strings.HasPrefix(entry, "NO_PROXY=") || strings.HasPrefix(entry, "no_proxy=") {
				continue
			}
			env = append(env, entry)
		}
		env = append(env,
			"CURL_CA_BUNDLE="+certPath,
			"TEST_DIR="+dir,
			"TEST_URL="+tlsServer.URL,
			"NO_PROXY=127.0.0.1,localhost",
		)
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("installer fetch guard failed: %v\n%s", err, out)
		}
	}

	t.Run("https redirect to http", func(t *testing.T) {
		run(t, "/redirect", 2)
		if got := plainRequests.Load(); got != 0 {
			t.Fatalf("HTTP redirect endpoint received %d requests, want 0", got)
		}
	})
	t.Run("oversized redirect remains policy failure", func(t *testing.T) {
		run(t, "/redirect-overflow", 2)
		if got := plainRequests.Load(); got != 0 {
			t.Fatalf("HTTP redirect endpoint received %d requests, want 0", got)
		}
	})
	t.Run("chunked overflow", func(t *testing.T) {
		run(t, "/overflow", 1)
	})
}
