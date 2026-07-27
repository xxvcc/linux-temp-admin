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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

func TestReleaseWriterIsSeparatedFromCandidateWorkflow(t *testing.T) {
	release := readReleaseFile(t, "../../.github/workflows/release.yml")
	stage := readReleaseFile(t, "../../.github/workflows/stage-release.yml")
	if strings.Contains(release, "contents: write") {
		t.Fatal("candidate-tag Release workflow must not receive contents:write")
	}
	for _, required := range []string{"workflow_run:", "contents: write", "refusing to refresh any remote asset"} {
		if !strings.Contains(stage, required) {
			t.Fatalf("trusted stage workflow is missing %q", required)
		}
	}
	if !strings.Contains(stage, ".verification.verified") || !strings.Contains(stage, "valid GitHub-recognized OpenPGP signature") ||
		strings.Count(stage, ".verification.signature") != 2 || strings.Count(stage, "-----BEGIN PGP SIGNATURE-----") != 2 {
		t.Fatal("trusted stage workflow does not reject unsigned annotated tags")
	}
	if !strings.Contains(stage, "[[ \"$lookup_status\" -eq 1 ]]") ||
		strings.Contains(stage, "[[ \"$lookup_status\" -ne 124") {
		t.Fatal("trusted stage workflow accepts an abnormal release-lookup exit status as an HTTP 404")
	}
	if strings.Contains(stage, "--clobber") {
		t.Fatal("trusted stage workflow must never refresh an existing draft")
	}
	for _, required := range []string{
		`find dist -mindepth 1 -printf '%P\t%y\n'`,
		`wc -c < dist/SHA256SUMS`,
		"1048576",
		"Re-resolve the protected tag immediately before the first write",
	} {
		if !strings.Contains(stage, required) {
			t.Fatalf("trusted stage workflow does not reject malformed artifacts or stale tags: missing %q", required)
		}
	}
	for _, required := range []string{
		"group: stage-release-writer",
		"LTA_RELEASE_ENVIRONMENT_CONFIGURED",
		"github.event.workflow_run.path == '.github/workflows/release.yml'",
		"needs: configuration-gate",
		"name: release-staging",
	} {
		if !strings.Contains(stage, required) {
			t.Fatalf("trusted stage workflow is missing protected-environment guard %q", required)
		}
	}
	if !strings.Contains(release, "timeout-minutes: 60") || strings.Count(release, "timeout-minutes:") != 5 ||
		strings.Count(stage, "timeout-minutes:") != 2 {
		t.Fatal("release workflows must bound every release-critical job")
	}
	for _, required := range []string{
		`root_go_root="$(sudo mktemp -d /tmp/lta-release-root-go.XXXXXXXXXX)"`,
		`sudo stat -Lc '%u %g %a' -- "$root_go_root"`,
		`sudo install -d -o 0 -g 0 -m 0700`,
		`sudo env "PATH=$PATH" HOME=/root TMPDIR=/tmp`,
		`GOCACHE="$root_go_root/gocache"`,
		`GOMODCACHE="$root_go_root/gomodcache"`,
		`GOPATH="$root_go_root/gopath" GOTMPDIR="$root_go_root/gotmp"`,
	} {
		if !strings.Contains(release, required) {
			t.Fatalf("release root test gate is missing safe root workspace guard %q", required)
		}
	}
	if strings.Contains(release, `${RUNNER_TEMP}/lta-root-`) ||
		strings.Contains(release, `sudo -E env "PATH=$PATH"`) {
		t.Fatal("release root test gate inherits or stores privileged Go state below the runner account")
	}
}

func TestReleaseArtifactHandoffUsesAuditedNode24Actions(t *testing.T) {
	release := readReleaseFile(t, "../../.github/workflows/release.yml")
	stage := readReleaseFile(t, "../../.github/workflows/stage-release.yml")
	for name, check := range map[string]struct {
		content string
		pin     string
	}{
		"upload":   {release, "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"},
		"download": {stage, "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"},
	} {
		if !strings.Contains(check.content, check.pin) {
			t.Errorf("release %s action is not pinned to the audited native Node.js 24 version", name)
		}
	}
}

func TestMirrorReleaseWorkflowPublishesVerifiedImmutableContentFailClosed(t *testing.T) {
	mirror := readReleaseFile(t, "../../.github/workflows/mirror-release.yml")
	installer := readReleaseFile(t, "../../scripts/install.sh")
	for _, required := range []string{
		"workflow_dispatch:",
		"group: linux-temp-admin-release-mirror-stable",
		"cancel-in-progress: false",
		"environment: release-mirror",
		"LTA_RELEASE_MIRROR_ENVIRONMENT_CONFIGURED",
		`TAG: ${{ inputs.tag }}`,
		`[[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]]`,
		`[[ "$GITHUB_REF" == "refs/heads/$DEFAULT_BRANCH" ]]`,
		`$GITHUB_REPOSITORY/.github/workflows/mirror-release.yml@refs/heads/$DEFAULT_BRANCH`,
		`[[ "$GITHUB_SHA" == "$TRUSTED_WORKFLOW_SHA" ]]`,
		"GH_HOST: github.com",
		"GH_PROMPT_DISABLED: '1'",
		"timeout -k 5 60 gh api",
		"persist-credentials: false",
		"MIRROR_BASE_URL: https://dl.ll.cd/linux-temp-admin",
		"GITHUB_RELEASE_ROOT=https://github.com/xxvcc/linux-temp-admin/releases",
		"cmp scripts/install.sh released-source/scripts/install.sh",
		".immutable == true",
		"SHA256SUMS does not name the exact signed asset set",
		"sha256sum -c --strict SHA256SUMS",
		"openssl pkeyutl -verify",
		"sudo --non-interactive --user=nobody",
		"/usr/bin/env -i HOME=/nonexistent",
		`[[ -d "$HOME/.ssh" && ! -L "$HOME/.ssh" ]]`,
		"--ignore-existing",
		"--delay-updates",
		"-o BatchMode=yes",
		"StrictHostKeyChecking=yes",
		`cmp "deploy/$TAG/$asset" "public-check/$asset"`,
		"INSTALLER_SHA256",
		"LTA_RELEASE=latest",
		"mirror canary used the GitHub transport fallback",
		"upgrade --yes --force",
		"self-upgrade canary used the GitHub transport fallback",
		"linux-temp-admin-mirror-canary-owned-$GITHUB_RUN_ID",
	} {
		if !strings.Contains(mirror, required) {
			t.Fatalf("mirror workflow is missing fail-closed publication guard %q", required)
		}
	}
	for _, prohibited := range []string{
		"\n  release:",
		"github.event.release.tag_name",
		"types: [published, edited]",
		"contents: write",
		"--clobber",
		"--delete",
	} {
		if strings.Contains(mirror, prohibited) {
			t.Fatalf("mirror workflow contains unsafe publication behavior %q", prohibited)
		}
	}
	jobEnvStart := strings.Index(mirror, "    env:\n")
	stepsStart := strings.Index(mirror, "    steps:\n")
	if jobEnvStart < 0 || stepsStart <= jobEnvStart {
		t.Fatal("could not isolate mirror job environment")
	}
	if strings.Contains(mirror[jobEnvStart:stepsStart], "GH_TOKEN") {
		t.Fatal("mirror job exposes the GitHub token to release binaries instead of scoping it to API steps")
	}
	if strings.Count(mirror, "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") != 2 {
		t.Fatal("mirror workflow checkout actions are not exactly pinned to the reviewed commit")
	}
	if strings.Count(mirror, "--location --max-redirs 0") != 4 {
		t.Fatal("public mirror verification must reject redirects for every stable and versioned fetch")
	}

	ordered := []string{
		"Upload immutable version without overwriting existing files",
		"Verify immutable version through public mirror",
		"Confirm GitHub Latest immediately before stable update",
		"Publish stable installer",
		"Publish latest manifest last",
		"Remove SSH identity",
	}
	previous := -1
	for _, marker := range ordered {
		index := strings.Index(mirror, marker)
		if index <= previous {
			t.Fatalf("mirror publication step %q is absent or out of order", marker)
		}
		previous = index
	}

	uploadStart := strings.Index(mirror, ordered[0])
	uploadEnd := strings.Index(mirror, ordered[1])
	upload := mirror[uploadStart:uploadEnd]
	if trustCheck, write := strings.Index(upload, "git/ref/tags/$TAG"), strings.Index(upload, "rsync --archive"); trustCheck < 0 || write < 0 || trustCheck > write {
		t.Fatal("mirror workflow does not re-resolve the protected tag immediately before its first write")
	}

	manifestStart := strings.Index(mirror, ordered[4])
	manifestEnd := strings.Index(mirror, ordered[5])
	manifest := mirror[manifestStart:manifestEnd]
	latestCheck := strings.Index(manifest, "releases/latest")
	manifestWrite := strings.Index(manifest, "rsync --archive")
	publicCompare := strings.Index(manifest, "cmp latest.json public-latest.json")
	if latestCheck < 0 || manifestWrite < 0 || publicCompare < 0 ||
		latestCheck > manifestWrite || manifestWrite > publicCompare {
		t.Fatal("latest.json is not atomically published after a final Latest check and before public comparison")
	}

	canaryStart := strings.Index(mirror, "Install from the public mirror as a real root client")
	if canaryStart < 0 {
		t.Fatal("mirror workflow is missing the public installation canary")
	}
	canary := mirror[canaryStart:]
	if !strings.Contains(canary, "downloaded the complete release set from the official mirror") ||
		!strings.Contains(canary, "falling back to GitHub") {
		t.Fatal("public installation canary does not prove that the mirror served the complete release set")
	}
	for _, expectedOutput := range []string{
		"downloaded the complete release set from the official mirror",
		"falling back to GitHub",
	} {
		if !strings.Contains(installer, expectedOutput) {
			t.Fatalf("mirror canary depends on installer output that does not exist: %q", expectedOutput)
		}
	}
}

func TestStageReleaseLookupAcceptsOnlyExactGHHTTPErrorStatus(t *testing.T) {
	stage := readReleaseFile(t, "../../.github/workflows/stage-release.yml")
	start := strings.Index(stage, "          lookup=\"$(mktemp)\"")
	endMarker := "          rm -f -- \"$lookup\""
	if start < 0 {
		t.Fatal("could not isolate staged-release absence check")
	}
	end := strings.Index(stage[start:], endMarker)
	if end < 0 {
		t.Fatal("could not isolate staged-release absence check")
	}
	end += start + len(endMarker)
	body := stage[start:end]
	body = strings.TrimPrefix(body, "          ")
	body = strings.ReplaceAll(body, "\n          ", "\n")

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "timeout"), []byte(`#!/bin/sh
shift 3
exec "$@"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "gh"), []byte(`#!/bin/sh
printf 'HTTP/2 404 Not Found\n\n{}\n'
exit "${MOCK_GH_STATUS:?}"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "lookup.sh")
	if err := os.WriteFile(script, []byte("#!/bin/bash\nset -Eeuo pipefail\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status int
		ok     bool
	}{
		{status: 1, ok: true},
		{status: 0, ok: false},
		{status: 2, ok: false},
		{status: 124, ok: false},
		{status: 137, ok: false},
	} {
		t.Run(fmt.Sprintf("status-%d", tc.status), func(t *testing.T) {
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = []string{
				"PATH=" + binDir + ":/usr/bin:/bin",
				fmt.Sprintf("MOCK_GH_STATUS=%d", tc.status),
				"GH_REPO=xxvcc/linux-temp-admin",
				"TAG=v2.8.0",
			}
			out, err := cmd.CombinedOutput()
			if tc.ok && err != nil {
				t.Fatalf("exact HTTP error status was rejected: %v\n%s", err, out)
			}
			if !tc.ok && err == nil {
				t.Fatalf("abnormal status was accepted: %s", out)
			}
		})
	}
}

func TestManualLatestRecoveryUsesSanitizedBoundedGitHubClient(t *testing.T) {
	releasing := readReleaseFile(t, "../../docs/releasing.md")
	start := strings.Index(releasing, "For manual incident recovery only")
	if start < 0 {
		t.Fatal("could not isolate manual Latest recovery documentation")
	}
	end := strings.Index(releasing[start:], "Any other tag, success response")
	if end < 0 {
		t.Fatal("could not isolate manual Latest recovery documentation")
	}
	recovery := releasing[start : start+end]
	for _, required := range []string{
		"/usr/bin/sudo /usr/bin/env -i",
		"TAG=\"$TAG\" /bin/bash -p",
		"read -r -s -p 'Short-lived github.com release token: ' GH_TOKEN </dev/tty",
		"export GH_TOKEN GH_CONFIG_DIR GH_HOST GH_PROMPT_DISABLED GH_PAGER",
		"GH_CONFIG_DIR=\"$work/gh-config\"",
		"GH_PROMPT_DISABLED=1",
		"gh_with_timeout() {",
		"timeout -k 5 300 gh \"$@\"",
		"[[ \"$latest_status\" -eq 1 ]]",
	} {
		if !strings.Contains(recovery, required) {
			t.Errorf("manual Latest recovery is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GH_TOKEN=\"$GH_TOKEN\" TAG=\"$TAG\"",
		"if gh api --include",
		"\n  gh release edit",
		"\n  gh release view",
	} {
		if strings.Contains(recovery, forbidden) {
			t.Errorf("manual Latest recovery bypasses its sanitized bounded client: %q", forbidden)
		}
	}
	if strings.Contains(releasing, `GH_TOKEN="$GH_TOKEN"`) {
		t.Fatal("release documentation exposes GH_TOKEN through a command argument")
	}
	if got := strings.Count(releasing, "read -r -s -p 'Short-lived github.com release token: ' GH_TOKEN </dev/tty"); got != 3 {
		t.Fatalf("release documentation has %d protected GH_TOKEN prompts, want 3", got)
	}
}

func TestReleaseScriptsBindSignerIdentityAndClientSizeLimit(t *testing.T) {
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	release := readReleaseFile(t, "../../.github/workflows/release.yml")
	stage := readReleaseFile(t, "../../.github/workflows/stage-release.yml")
	for name, content := range map[string]string{
		"offline": offline,
		"prepare": prepare,
		"publish": publish,
	} {
		if !strings.HasPrefix(content, "#!/bin/bash -p\n") || !strings.Contains(content, "privileged Bash mode is required") {
			t.Fatalf("%s trusted script does not reject imported Bash functions and BASH_ENV", name)
		}
		if !strings.Contains(content, "ulimit -c 0") {
			t.Fatalf("%s trusted script does not disable core dumps before handling release data", name)
		}
	}

	for name, content := range map[string]string{
		"offline": offline,
		"publish": publish,
	} {
		for _, required := range []string{
			"LTA_EXPECTED_RELEASE_SIGNER_PUBKEY",
			"RELEASE_SIGNER_PUBKEY",
			`trusted_signer="/proc/$$/fd/${trusted_signer_fd}"`,
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s script is missing %q", name, required)
			}
		}
	}
	for name, content := range map[string]string{"prepare": prepare, "publish": publish} {
		if !strings.Contains(content, "Accept: application/octet-stream") || !strings.Contains(content, "ulimit -f") {
			t.Fatalf("%s does not use bounded authenticated draft downloads", name)
		}
		if !strings.Contains(content, `-c gpg.openpgp.program="$gpg_wrapper"`) {
			t.Fatalf("%s allows local Git config to replace the pinned OpenPGP verifier", name)
		}
	}
	for name, content := range map[string]string{"prepare": prepare, "offline": offline, "publish": publish} {
		for _, required := range []string{
			"local_with_timeout() {",
			"local_with_timeout readlink",
			"local_with_timeout stat",
			"allow_sticky_leaf",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s release script leaves path validation unbounded or noncanonical: missing %q", name, required)
			}
		}
	}
	for name, content := range map[string]string{"prepare": prepare, "offline": offline} {
		if !strings.Contains(content, "readlink -m") {
			t.Fatalf("%s release script does not canonicalize a new output path before creation", name)
		}
	}
	for name, content := range map[string]string{
		"prepare": prepare,
		"offline": offline,
		"publish": publish,
		"release": release,
		"stage":   stage,
	} {
		if !strings.Contains(content, "67108864") {
			t.Fatalf("%s release phase does not enforce the 64 MiB client limit", name)
		}
	}
	if !strings.Contains(publish, "stable_tag_gt") || !strings.Contains(publish, "highest_stable_release") || !strings.Contains(publish, "BASELINE_HIGHEST_TAG") {
		t.Fatal("publisher does not enforce a monotonic, unchanged stable Latest baseline")
	}
	if !strings.Contains(publish, "public versioned route") ||
		!strings.Contains(publish, "restore_latest_after_failed_promotion") ||
		!strings.Contains(publish, "restored the exact highest alternative") ||
		!strings.Contains(publish, "appeared during final verification") ||
		!strings.Contains(publish, "Latest changed during final verification") {
		t.Fatal("publisher does not defer Latest promotion or detect a concurrent higher stable release")
	}
	if !strings.Contains(publish, "publishing a prerelease unexpectedly changed Latest") {
		t.Fatal("publisher does not verify that a prerelease leaves Latest unchanged")
	}
	installer := readReleaseFile(t, "../../scripts/install.sh")
	if !strings.Contains(installer, "download=1") || !strings.Contains(publish, "download=1") {
		t.Fatal("installer and publisher must retain the release-CDN cache-bypass retry")
	}
	probe := strings.Index(installer, "candidate_version=$(awk")
	finalStageHash := strings.LastIndex(installer, `sha256sum "$stage"`)
	if probe < 0 || finalStageHash < probe {
		t.Fatal("installer does not revalidate the signed staging bytes after its version probe")
	}
	if strings.Contains(installer, `([.][0-9]+){2}`) ||
		!strings.Contains(installer, `[0-9]+[.][0-9]+[.][0-9]+`) {
		t.Fatal("installer version probe must avoid awk interval expressions unsupported by deployed mawk versions")
	}
	if strings.Contains(installer, "wget") || !strings.Contains(installer, "required command not found: $command_name") ||
		!strings.Contains(installer, "--proto '=https' --proto-redir '=https'") {
		t.Fatal("installer must require curl and enforce HTTPS for initial and redirected requests")
	}
	if !strings.Contains(installer, "ulimit -c 0") ||
		!strings.Contains(installer, "/proc/self/limits") ||
		!strings.Contains(installer, "512 | 1024") ||
		!strings.Contains(installer, "fetch_max + FSIZE_BLOCK_BYTES - 1") {
		t.Fatal("installer does not disable core dumps or account for shell-specific RLIMIT_FSIZE units")
	}
	if !strings.Contains(installer, `release="${LTA_RELEASE-latest}"`) ||
		!strings.Contains(installer, "downloaded binary version does not match LTA_RELEASE") {
		t.Fatal("installer does not support rollback-resistant exact release pinning")
	}
	if !strings.Contains(installer, `//*) fail "DEST must not begin with //"`) ||
		!strings.Contains(installer, `/ | //) break`) {
		t.Fatal("installer does not reject ambiguous double-slash destinations and terminate ancestor traversal defensively")
	}
	for _, required := range []string{
		"MANAGED_DEST=/usr/local/sbin/linux-temp-admin",
		`[ "$DEST" = "$MANAGED_DEST" ]`,
		`"$stage" --lang en install --force`,
		"installed destination differs from the verified candidate",
		`stat -c %g -- "$DEST"`,
		"installed destination group is not root",
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("installer does not delegate managed-path lifecycle activation: missing %q", required)
		}
	}
	if !strings.Contains(installer, "OPENSSL_CONF=/dev/null") || !strings.Contains(installer, "unset OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES") {
		t.Fatal("root installer does not neutralize caller-controlled OpenSSL module configuration")
	}
	for name, content := range map[string]string{"prepare": prepare, "publish": publish} {
		for _, required := range []string{"GIT_NO_REPLACE_OBJECTS=1", "compare/${tag_commit}...main", "tree_mode"} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s script is missing source-provenance guard %q", name, required)
			}
		}
	}
	if !strings.Contains(release, "git ls-files -s -z") || !strings.Contains(release, "120000") || !strings.Contains(release, "160000") {
		t.Fatal("candidate workflow does not reject symlink/submodule source trees")
	}
	for name, content := range map[string]string{"prepare": prepare, "release": release} {
		for _, required := range []string{"lta-module-cache", "proxy.golang.org", "sum.golang.org", "GOVCS='*:off'"} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s release build does not isolate dependency provenance: missing %q", name, required)
			}
		}
	}
	if !strings.Contains(release, "cache: false") || !strings.Contains(prepare, "unset GOROOT GOEXPERIMENT") {
		t.Fatal("release builds do not clear shared caches and caller-controlled Go toolchain settings")
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

func TestInstallerPinnedReleaseEndToEnd(t *testing.T) {
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

	for _, release := range []string{"", "v02.8.0", "v2.8.0?query", "../v2.8.0", "v2.8"} {
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

func TestInstallerOfficialMirrorFallbackBoundary(t *testing.T) {
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

func TestDocumentedBootstrapsRunInsideSanitizedRootShell(t *testing.T) {
	documents := map[string]struct {
		path           string
		wantCurlCount  int
		wantSudoDirect int
	}{
		"README.md":    {path: "../../README.md", wantCurlCount: 1, wantSudoDirect: 0},
		"README.en.md": {path: "../../README.en.md", wantCurlCount: 1, wantSudoDirect: 0},
		"releasing.md": {path: "../../docs/releasing.md", wantCurlCount: 2, wantSudoDirect: 0},
	}
	for name, document := range documents {
		content := readReleaseFile(t, document.path)
		if strings.Contains(content, "sudo linux-temp-admin") ||
			strings.Contains(content, "sudo -E") {
			t.Errorf("%s documents a PATH-dependent or broadly environment-preserving sudo invocation", name)
		}
		streamingRootShell := false
		for _, line := range strings.Split(content, "\n") {
			if strings.HasSuffix(strings.TrimSpace(line), "| sudo sh") {
				streamingRootShell = true
			}
		}
		if streamingRootShell || strings.Contains(content, "curl -fsSL") {
			t.Errorf("%s still documents a streaming root-shell bootstrap", name)
		}
		for _, required := range []string{
			"if ! FSIZE_BLOCK_BYTES=$(\n",
			"512 | 1024",
			"INSTALLER_BLOCKS=$(( (INSTALLER_MAX_BYTES + FSIZE_BLOCK_BYTES - 1) / FSIZE_BLOCK_BYTES ))",
			`ulimit -f "$INSTALLER_BLOCKS" || exit 1`,
			"curl -q --fail --silent --show-error --location",
			`--max-filesize "$INSTALLER_MAX_BYTES"`,
			"--proto '=https' --proto-redir '=https'",
			`--output "$installer"`,
		} {
			if got := strings.Count(content, required); got != document.wantCurlCount {
				t.Errorf("%s count(%q)=%d, want %d", name, required, got, document.wantCurlCount)
			}
		}
		if strings.Contains(content, `sudo sh "$installer"`) {
			t.Errorf("%s resolves the root shell through PATH", name)
		}
		for _, forbidden := range []string{
			`sudo /bin/sh "$installer"`,
			`/usr/bin/sudo /bin/sh "$installer"`,
			`sudo install -o 0 -g 0 -m 0600`,
			`/usr/bin/sudo install -o 0 -g 0 -m 0600`,
		} {
			if strings.Contains(content, forbidden) {
				t.Errorf("%s crosses the privilege boundary through caller-owned installer bytes: %q", name, forbidden)
			}
		}
		if got := strings.Count(content, `sudo /bin/sh "$installer"`); got != document.wantSudoDirect {
			t.Errorf("%s direct sudo installer count=%d, want %d", name, got, document.wantSudoDirect)
		}
	}
	releasing := readReleaseFile(t, "../../docs/releasing.md")
	for _, required := range []string{
		"INSTALLER_COMMIT", "INSTALLER_SHA256", "LTA_RELEASE_TAG",
		"stat -Lc '%u %a' -- /tmp", `[[ "$tmp_meta" =~ ^0\ 1[0-7]{3}$ ]]`,
		"mktemp /tmp/.lta-bootstrap.", "sha256sum -c -",
		"/usr/bin/sudo /usr/bin/env -i", "/usr/bin/env -i HOME=/root",
	} {
		if !strings.Contains(releasing, required) {
			t.Errorf("high-assurance bootstrap is missing %q", required)
		}
	}
	if strings.Contains(releasing, "sha256sum -c --strict") {
		t.Error("high-assurance bootstrap uses the GNU-only sha256sum --strict option")
	}
	for _, required := range []string{
		"TRUSTED_SIGNER_SOURCE=/opt/lta-reviewed-source",
		"TRUSTED_SIGNER_COMMIT='replace-with-the-independently-recorded-40-hex-audited-commit'",
		"/bin/bash -p <<'LTA_TRUSTED_SIGNER'", `find "$TRUSTED_SIGNER_SOURCE" -print0`,
		"check_safe_source_dir", "8#$source_dir_mode & 8#7022",
		"8#$source_mode & 8#7022", "GIT_CONFIG_NOSYSTEM=1", "GIT_NO_REPLACE_OBJECTS=1",
		"GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "timeout -k 5 60 git",
		`-c core.bare=false -c core.fsmonitor=false -c core.hooksPath=/dev/null`,
		`$TRUSTED_SIGNER_SOURCE/.git/commondir`,
		`$TRUSTED_SIGNER_SOURCE/.git/objects/info/alternates`,
		`rev-parse --verify 'HEAD^{commit}'`, `[[ "$source_head" == "$TRUSTED_SIGNER_COMMIT" ]]`,
		`ls-tree -r -z "$TRUSTED_SIGNER_COMMIT"`, "120000|160000",
		`archive --format=tar --output="$source_archive" "$TRUSTED_SIGNER_COMMIT"`,
		`cd -- "$source_snapshot"`,
		`[[ "$tmp_meta" =~ ^0\ 1[0-7]{3}$ ]]`,
		"signer_arch=$(env -i", "go env GOARCH", "amd64) signer_tune=GOAMD64=v1",
		"arm64) signer_tune=GOARM64=v8.0", "for build_id in a b",
		`GOCACHE="$build_root/$build_id/gocache"`,
		`GOMODCACHE="$build_root/$build_id/gomodcache"`,
		`GOPATH="$build_root/$build_id/gopath" GOTMPDIR="$build_root/$build_id/gotmp"`,
		`GOARCH="$signer_arch" "$signer_tune"`,
		`cmp "$build_root/a/lta-release" "$build_root/b/lta-release"`,
	} {
		if !strings.Contains(releasing, required) {
			t.Errorf("trusted signer setup is missing %q", required)
		}
	}
	if strings.Contains(releasing, "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1") {
		t.Error("trusted signer setup is hard-coded to amd64")
	}
	bootstrapBlocks := func(content string) []string {
		var blocks []string
		for _, section := range strings.Split(content, "```bash\n")[1:] {
			end := strings.Index(section, "\n```")
			if end < 0 {
				continue
			}
			block := section[:end]
			if strings.Contains(block, "raw.githubusercontent.com/xxvcc/linux-temp-admin/") ||
				strings.Contains(block, "https://dl.ll.cd/linux-temp-admin/install.sh") {
				blocks = append(blocks, block)
			}
		}
		return blocks
	}
	heredocBody := func(block string) (string, error) {
		const opener = "<<'LTA_BOOTSTRAP'"
		openerAt := strings.Index(block, opener)
		if openerAt < 0 {
			return "", fmt.Errorf("missing quoted bootstrap heredoc")
		}
		afterOpener := openerAt + len(opener)
		lineEnd := strings.Index(block[afterOpener:], "\n")
		if lineEnd < 0 {
			return "", fmt.Errorf("missing bootstrap heredoc body")
		}
		start := afterOpener + lineEnd + 1
		endRel := strings.Index(block[start:], "\nLTA_BOOTSTRAP")
		if endRel < 0 {
			return "", fmt.Errorf("missing bootstrap heredoc terminator")
		}
		return block[start : start+endRel], nil
	}
	highAssuranceBlocks := bootstrapBlocks(releasing)
	if len(highAssuranceBlocks) != 2 {
		t.Fatalf("releasing.md bootstrap block count=%d, want 2", len(highAssuranceBlocks))
	}
	for name, document := range documents {
		blocks := bootstrapBlocks(readReleaseFile(t, document.path))
		if len(blocks) != document.wantCurlCount {
			t.Errorf("%s bootstrap block count=%d, want %d", name, len(blocks), document.wantCurlCount)
			continue
		}
		for i, block := range blocks {
			if mirrorAt := strings.Index(block, "https://dl.ll.cd/linux-temp-admin/install.sh"); mirrorAt >= 0 {
				githubAt := strings.Index(block, "https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh")
				if githubAt <= mirrorAt {
					t.Errorf("%s bootstrap block %d does not try the official mirror before raw GitHub", name, i+1)
				}
				if !strings.Contains(block, "--location --max-redirs 0") ||
					!strings.Contains(block, "official mirror installer redirected; refusing source-policy fallback") {
					t.Errorf("%s bootstrap block %d does not reject official-mirror redirects", name, i+1)
				}
			}
			body, err := heredocBody(block)
			if err != nil {
				t.Errorf("%s bootstrap block %d: %v", name, i+1, err)
				continue
			}
			prefix := block[:strings.Index(block, "<<'LTA_BOOTSTRAP'")]
			if strings.Count(prefix, "/usr/bin/sudo /usr/bin/env -i") != 1 ||
				!strings.Contains(prefix, "HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C") {
				t.Errorf("%s bootstrap block %d does not enter one sanitized root shell", name, i+1)
			}
			if strings.Contains(prefix, "mktemp") || strings.Contains(prefix, "curl ") {
				t.Errorf("%s bootstrap block %d handles installer bytes before entering the root shell", name, i+1)
			}
			for _, required := range []string{
				"ulimit -c 0", "stat -Lc '%u %a' -- /tmp",
				"mktemp /tmp/.lta-bootstrap.", `timeout -k 5 70 curl -q`,
				`installer_size=$(wc -c < "$installer")`,
			} {
				if !strings.Contains(body, required) {
					t.Errorf("%s bootstrap block %d is missing %q", name, i+1, required)
				}
			}
			if strings.Contains(body, "sudo ") || strings.Contains(body, "/usr/bin/sudo") {
				t.Errorf("%s bootstrap block %d re-crosses the privilege boundary", name, i+1)
			}

			t.Run(fmt.Sprintf("%s download failure/block %d", name, i+1), func(t *testing.T) {
				dir := t.TempDir()
				binDir := filepath.Join(dir, "bin")
				if err := os.Mkdir(binDir, 0o700); err != nil {
					t.Fatal(err)
				}
				curlFixture := `#!/bin/sh
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) shift; out=$1 ;;
  esac
  shift
done
[ -n "$out" ] || exit 88
printf '%s\n' '#!/bin/sh' ': > "$TEST_EXEC_MARKER"' > "$out"
exit 55
`
				timeoutFixture := `#!/bin/sh
case "$1" in -k) shift 2 ;; esac
shift
exec "$@"
`
				for fixtureName, fixture := range map[string]string{
					"curl": curlFixture, "timeout": timeoutFixture,
				} {
					if err := os.WriteFile(filepath.Join(binDir, fixtureName), []byte(fixture), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				marker := filepath.Join(dir, "installer-ran")
				testShell := "/bin/sh"
				if strings.Contains(body, "set -Eeuo pipefail") {
					testShell = "/bin/bash"
				}
				env := make([]string, 0, len(os.Environ())+5)
				for _, entry := range os.Environ() {
					if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "TEST_") ||
						strings.HasPrefix(entry, "INSTALLER_") || strings.HasPrefix(entry, "LTA_RELEASE_TAG=") {
						continue
					}
					env = append(env, entry)
				}
				env = append(env,
					"PATH="+binDir+":/usr/sbin:/usr/bin:/sbin:/bin",
					"TEST_EXEC_MARKER="+marker,
					"INSTALLER_COMMIT="+strings.Repeat("a", 40),
					"INSTALLER_SHA256="+strings.Repeat("0", 64),
					"LTA_RELEASE_TAG=v9.9.9",
				)
				cmd := exec.Command(testShell, "-c", body)
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(out), "installer download failed or exceeded its limit") {
					t.Fatalf("failed installer download was not fail-closed: err=%v\n%s", err, out)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("downloaded installer ran after curl failure: %v", err)
				}
			})
		}
	}
	for _, shell := range []struct {
		name string
		args []string
	}{
		{name: "bash"},
		{name: "bash-posix", args: []string{"--posix"}},
	} {
		t.Run("high-assurance malformed stat/"+shell.name, func(t *testing.T) {
			body, err := heredocBody(highAssuranceBlocks[1])
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			binDir := filepath.Join(dir, "bin")
			if err := os.Mkdir(binDir, 0o700); err != nil {
				t.Fatal(err)
			}
			fixtures := map[string]string{
				"stat": "#!/bin/sh\nprintf '0 1777\\nunexpected\\n'\n",
				"curl": "#!/bin/sh\n: > \"$TEST_CURL_MARKER\"\nexit 99\n",
				"sudo": "#!/bin/sh\n: > \"$TEST_SUDO_MARKER\"\nexit 99\n",
			}
			for name, fixture := range fixtures {
				if err := os.WriteFile(filepath.Join(binDir, name), []byte(fixture), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			curlMarker := filepath.Join(dir, "curl-ran")
			sudoMarker := filepath.Join(dir, "sudo-ran")
			env := make([]string, 0, len(os.Environ())+6)
			for _, entry := range os.Environ() {
				if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "BASH_FUNC_") ||
					strings.HasPrefix(entry, "TEST_") || strings.HasPrefix(entry, "INSTALLER_") ||
					strings.HasPrefix(entry, "LTA_RELEASE_TAG=") {
					continue
				}
				env = append(env, entry)
			}
			env = append(env,
				"PATH="+binDir+":"+os.Getenv("PATH"),
				"TEST_CURL_MARKER="+curlMarker,
				"TEST_SUDO_MARKER="+sudoMarker,
				"INSTALLER_COMMIT="+strings.Repeat("0", 40),
				"INSTALLER_SHA256="+strings.Repeat("0", 64),
				"LTA_RELEASE_TAG=v9.9.9",
			)
			args := append(append([]string(nil), shell.args...), "-c", body)
			cmd := exec.Command("/bin/bash", args...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "/tmp must be root-owned, sticky") {
				t.Fatalf("malformed stat metadata was not rejected: err=%v\n%s", err, out)
			}
			for commandName, marker := range map[string]string{"curl": curlMarker, "sudo": sudoMarker} {
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("%s ran after malformed stat metadata: %v", commandName, err)
				}
			}
		})
	}
	for name, document := range documents {
		content := readReleaseFile(t, document.path)
		blocks := bootstrapBlocks(content)
		if len(blocks) != document.wantCurlCount {
			t.Errorf("%s bootstrap block count=%d, want %d", name, len(blocks), document.wantCurlCount)
			continue
		}
		for i, block := range blocks {
			t.Run(fmt.Sprintf("%s hard file limit/block %d", name, i+1), func(t *testing.T) {
				body, err := heredocBody(block)
				if err != nil {
					t.Fatal(err)
				}
				dir, err := os.MkdirTemp("/tmp", "lta-bootstrap-limit-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				if os.Geteuid() == 0 {
					if err := os.Chown(dir, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
				binDir := filepath.Join(dir, "bin")
				if err := os.Mkdir(binDir, 0o755); err != nil {
					t.Fatal(err)
				}
				for commandName, markerVariable := range map[string]string{
					"curl": "TEST_CURL_MARKER",
					"sudo": "TEST_SUDO_MARKER",
				} {
					fixture := "#!/bin/sh\nmkdir \"$" + markerVariable + "\"\nexit 0\n"
					if err := os.WriteFile(filepath.Join(binDir, commandName), []byte(fixture), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				testShell := "/bin/sh"
				if strings.Contains(body, "set -Eeuo pipefail") {
					testShell = "/bin/bash"
				}
				env := make([]string, 0, len(os.Environ())+9)
				for _, entry := range os.Environ() {
					if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "TEST_") ||
						strings.HasPrefix(entry, "INSTALLER_") || strings.HasPrefix(entry, "LTA_RELEASE_TAG=") {
						continue
					}
					env = append(env, entry)
				}
				curlMarker := filepath.Join(dir, "curl-ran")
				sudoMarker := filepath.Join(dir, "sudo-ran")
				env = append(env,
					"PATH="+binDir+":"+os.Getenv("PATH"),
					"TEST_SHELL="+testShell,
					"TEST_BLOCK="+body,
					"TEST_CURL_MARKER="+curlMarker,
					"TEST_SUDO_MARKER="+sudoMarker,
					"INSTALLER_COMMIT="+strings.Repeat("0", 40),
					"INSTALLER_SHA256="+strings.Repeat("0", 64),
					"LTA_RELEASE_TAG=v9.9.9",
				)
				cmd := exec.Command("/bin/sh", "-c", "ulimit -S -f 0 || exit 90\nulimit -H -f 0 || exit 91\nexec \"$TEST_SHELL\" -c \"$TEST_BLOCK\"")
				cmd.Env = env
				if os.Geteuid() == 0 {
					cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
				}
				out, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatalf("bootstrap unexpectedly succeeded with inherited hard RLIMIT_FSIZE=0: %s", out)
				}
				if !strings.Contains(string(out), "cannot determine the shell file-size limit unit") {
					t.Fatalf("bootstrap did not report its file-limit failure: %v\n%s", err, out)
				}
				for markerName, marker := range map[string]string{"curl": curlMarker, "sudo": sudoMarker} {
					if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
						t.Fatalf("%s ran after file-limit setup failure: %v", markerName, statErr)
					}
				}
			})
		}
	}

	type signalShellCase struct {
		name string
		path string
		args []string
	}
	signalShells := []signalShellCase{
		{name: "bash", path: "/bin/bash"},
		{name: "bash-posix", path: "/bin/bash", args: []string{"--posix"}},
		{name: "dash", path: "/bin/dash"},
	}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		signalShells = append(signalShells, signalShellCase{name: "busybox-ash", path: busybox, args: []string{"ash"}})
	}
	signals := []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "hup", signal: syscall.SIGHUP},
		{name: "int", signal: syscall.SIGINT},
		{name: "term", signal: syscall.SIGTERM},
	}
	for name, document := range documents {
		blocks := bootstrapBlocks(readReleaseFile(t, document.path))
		for i, block := range blocks {
			body, err := heredocBody(block)
			if err != nil {
				t.Fatalf("%s bootstrap block %d: %v", name, i+1, err)
			}
			const signalTrap = "trap 'exit 1' HUP INT TERM\n"
			if strings.Count(body, signalTrap) != 1 {
				t.Fatalf("%s bootstrap block %d must install one terminating signal trap", name, i+1)
			}
			body = strings.Replace(body, signalTrap, signalTrap+
				`: > "$TEST_SIGNAL_READY"
while :; do :; done
`, 1)

			bashOnly := strings.Contains(body, "set -Eeuo pipefail")
			for _, shell := range signalShells {
				if bashOnly && shell.name != "bash" && shell.name != "bash-posix" {
					continue
				}
				if _, err := os.Stat(shell.path); err != nil {
					continue
				}
				for _, sig := range signals {
					t.Run(fmt.Sprintf("%s signal stop/block %d/%s/%s", name, i+1, shell.name, sig.name), func(t *testing.T) {
						dir := t.TempDir()
						binDir := filepath.Join(dir, "bin")
						if err := os.Mkdir(binDir, 0o700); err != nil {
							t.Fatal(err)
						}
						for commandName, markerVariable := range map[string]string{
							"curl": "TEST_CURL_MARKER",
							"sudo": "TEST_SUDO_MARKER",
						} {
							fixture := "#!/bin/sh\n: > \"$" + markerVariable + "\"\nexit 99\n"
							if err := os.WriteFile(filepath.Join(binDir, commandName), []byte(fixture), 0o700); err != nil {
								t.Fatal(err)
							}
						}

						ready := filepath.Join(dir, "ready")
						curlMarker := filepath.Join(dir, "curl-ran")
						sudoMarker := filepath.Join(dir, "sudo-ran")
						env := make([]string, 0, len(os.Environ())+7)
						for _, entry := range os.Environ() {
							if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "TEST_") ||
								strings.HasPrefix(entry, "INSTALLER_") || strings.HasPrefix(entry, "LTA_RELEASE_TAG=") {
								continue
							}
							env = append(env, entry)
						}
						env = append(env,
							"PATH="+binDir+":"+os.Getenv("PATH"),
							"TEST_SIGNAL_READY="+ready,
							"TEST_CURL_MARKER="+curlMarker,
							"TEST_SUDO_MARKER="+sudoMarker,
							"INSTALLER_COMMIT="+strings.Repeat("0", 40),
							"INSTALLER_SHA256="+strings.Repeat("0", 64),
							"LTA_RELEASE_TAG=v9.9.9",
						)

						args := append(append([]string(nil), shell.args...), "-c", body)
						cmd := exec.Command(shell.path, args...)
						cmd.Env = env
						var output bytes.Buffer
						cmd.Stdout = &output
						cmd.Stderr = &output
						if err := cmd.Start(); err != nil {
							t.Fatal(err)
						}
						deadline := time.Now().Add(2 * time.Second)
						for {
							if _, err := os.Stat(ready); err == nil {
								break
							} else if !os.IsNotExist(err) {
								_ = cmd.Process.Kill()
								_ = cmd.Wait()
								t.Fatal(err)
							}
							if time.Now().After(deadline) {
								_ = cmd.Process.Kill()
								_ = cmd.Wait()
								t.Fatalf("bootstrap did not reach its signal guard:\n%s", output.Bytes())
							}
							time.Sleep(5 * time.Millisecond)
						}
						if err := cmd.Process.Signal(sig.signal); err != nil {
							_ = cmd.Process.Kill()
							_ = cmd.Wait()
							t.Fatal(err)
						}
						done := make(chan error, 1)
						go func() { done <- cmd.Wait() }()
						select {
						case err := <-done:
							if err == nil {
								t.Fatalf("bootstrap succeeded after %s:\n%s", sig.name, output.Bytes())
							}
						case <-time.After(2 * time.Second):
							_ = cmd.Process.Kill()
							<-done
							t.Fatalf("bootstrap did not terminate after %s:\n%s", sig.name, output.Bytes())
						}
						for commandName, marker := range map[string]string{"curl": curlMarker, "sudo": sudoMarker} {
							if _, err := os.Stat(marker); !os.IsNotExist(err) {
								t.Fatalf("%s ran after %s: %v\n%s", commandName, sig.name, err, output.Bytes())
							}
						}
					})
				}
			}
		}
	}

	security := readReleaseFile(t, "../../SECURITY.md")
	if strings.Contains(security, "LTA_ALLOW_UNVERIFIED") ||
		!strings.Contains(security, "no unsigned or checksum-only fallback") {
		t.Fatal("SECURITY.md does not describe the current fail-closed bootstrap")
	}
}

func TestTrustedReleaseScriptsPinTemporaryDirectoryAndGitHubHost(t *testing.T) {
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	for name, content := range map[string]string{
		"offline": offline,
		"prepare": prepare,
		"publish": publish,
	} {
		for _, required := range []string{
			"require_trusted_tmp",
			`stat -Lc '%u %a' -- /tmp`,
			`"$tmp_uid" == 0`,
			`8#$tmp_mode & 8#7000) == 8#1000`,
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s trusted script is missing temporary-directory guard %q", name, required)
			}
		}
		if strings.Index(content, "require_trusted_tmp") > strings.Index(content, `mktemp -d /tmp/`) {
			t.Fatalf("%s validates /tmp only after creating its private snapshot", name)
		}
	}
	for name, content := range map[string]string{"prepare": prepare, "publish": publish} {
		if !strings.Contains(content, "GH_HOST=github.com") ||
			!strings.Contains(content, "export PATH LC_ALL GIT_NO_REPLACE_OBJECTS GIT_NO_LAZY_FETCH GIT_TERMINAL_PROMPT") {
			t.Fatalf("%s does not override and export the fixed GitHub host", name)
		}
		if strings.Index(content, "GH_HOST=github.com") > strings.Index(content, "gh_with_timeout api") {
			t.Fatalf("%s sets GH_HOST only after its first GitHub call", name)
		}
		if !strings.Contains(content, `gh_with_timeout() {`) ||
			!strings.Contains(content, `timeout -k 5 300 gh "$@"`) {
			t.Fatalf("%s does not bound GitHub CLI calls", name)
		}
	}
	stage := readReleaseFile(t, "../../.github/workflows/stage-release.yml")
	if strings.Count(stage, "GH_HOST: github.com") != 2 {
		t.Fatal("trusted staging workflow does not pin github.com for every gh-bearing step")
	}
	if strings.Count(stage, "GH_PROMPT_DISABLED: '1'") != 2 ||
		!strings.Contains(stage, `timeout -k 5 600 gh release create`) ||
		!strings.Contains(stage, "could not prove release $TAG is absent") {
		t.Fatal("trusted staging workflow does not bound GitHub calls and fail closed on ambiguous release lookup")
	}
	preflight := strings.Index(publish, "for command_name in")
	firstMutation := strings.Index(publish, `gh_with_timeout release upload "$TAG"`)
	if preflight < 0 || firstMutation < 0 || preflight > firstMutation {
		t.Fatal("publisher command preflight does not precede its first remote mutation")
	}
	for _, command := range []string{"curl", "timeout", "sleep", "diff", "gh", "git"} {
		if !strings.Contains(publish[preflight:firstMutation], command) {
			t.Fatalf("publisher does not preflight post-mutation command %q", command)
		}
	}
}

func TestTrustedReleaseScriptsBoundLocalCommands(t *testing.T) {
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	for name, content := range map[string]string{"prepare": prepare, "publish": publish} {
		for _, required := range []string{
			"GIT_NO_LAZY_FETCH=1",
			"GIT_TERMINAL_PROMPT=0",
			"GH_PROMPT_DISABLED=1",
			"git_with_timeout() {",
			"--batch --no-auto-key-retrieve",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s release script is missing bounded local-command guard %q", name, required)
			}
		}
	}
	if !strings.Contains(prepare, `timeout -k 30 "$GO_BUILD_TIMEOUT_SECONDS"`) ||
		!strings.Contains(prepare, "MAX_SOURCE_ARCHIVE_BYTES=134217728") ||
		!strings.Contains(prepare, `git_with_timeout -C "$SOURCE_DIR" archive`) {
		t.Fatal("prepare phase does not bound its compiler or source export")
	}
	for name, content := range map[string]string{"prepare": prepare, "offline": offline} {
		for _, required := range []string{
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" mkdir -m 0700`,
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" chmod 0600`,
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" sha256sum`,
			`exec sha256sum -c --strict`,
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s release script leaves final transfer-media operation unbounded: missing %q", name, required)
			}
		}
	}
	if !strings.Contains(prepare, `bounded_copy "$prepared_work/$name" "$OUT_DIR/$name" "$limit"`) ||
		!strings.Contains(offline, `bounded_copy "$signed_work/$name" "$SIGNED_DIR/$name" "$limit"`) {
		t.Fatal("prepare/offline release output is not copied through the bounded transfer helper")
	}
	for name, content := range map[string]string{"offline": offline, "publish": publish} {
		for _, required := range []string{
			"signer_with_timeout() {",
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS"`,
			`cp --reflink=never --sparse=never`,
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s release script is missing bounded snapshot/signer guard %q", name, required)
			}
		}
	}
	if !strings.Contains(offline, "offline private key must be an absolute regular non-symlink file") {
		t.Fatal("offline signer does not reject special-file private keys before the ceremony")
	}
	if strings.Contains(publish, `"$trusted_signer" verify`) ||
		strings.Count(publish, "signer_with_timeout verify") != 2 {
		t.Fatal("publisher has an unbounded verifier invocation")
	}
}

func TestTrustedTemporaryDirectoryGuardWithMockStat(t *testing.T) {
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	start := strings.Index(offline, "require_trusted_tmp() {")
	end := strings.Index(offline[start:], "\nrequire_trusted_tmp\n")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate trusted temporary-directory guard")
	}
	guard := offline[start : start+end]
	tests := []struct {
		name   string
		uid    string
		mode   string
		wantOK bool
	}{
		{name: "root owned sticky", uid: "0", mode: "1777", wantOK: true},
		{name: "setgid sticky", uid: "0", mode: "3777", wantOK: false},
		{name: "setuid sticky", uid: "0", mode: "5777", wantOK: false},
		{name: "all special bits", uid: "0", mode: "7777", wantOK: false},
		{name: "non-root owner", uid: "1000", mode: "1777", wantOK: false},
		{name: "missing sticky bit", uid: "0", mode: "0777", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "tmp-guard.sh")
			body := `#!/bin/bash
	set -Eeuo pipefail
	stat() { printf '%s %s\n' "$TEST_UID" "$TEST_MODE"; }
	local_with_timeout() { "$@"; }
	` + guard + `
	require_trusted_tmp
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = append(os.Environ(), "TEST_UID="+tt.uid, "TEST_MODE="+tt.mode)
			out, err := cmd.CombinedOutput()
			if tt.wantOK && err != nil {
				t.Fatalf("trusted /tmp guard failed: %v\n%s", err, out)
			}
			if !tt.wantOK && err == nil {
				t.Fatalf("unsafe /tmp metadata unexpectedly passed: %s", out)
			}
		})
	}
}

func TestTrustedOnlineReleaseEnvironmentIsSanitizedBeforeArchiveUse(t *testing.T) {
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	for name, content := range map[string]string{"prepare": prepare, "publish": publish} {
		for _, required := range []string{
			"compgen -A variable",
			"unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY",
			"unset SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE",
			"unset GH_CONFIG_DIR XDG_CONFIG_HOME GIT_SSL_CAINFO GIT_SSL_CAPATH",
			"unset TAR_OPTIONS GZIP BZIP2 BZIP XZ_OPT",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			`GH_CONFIG_DIR="$work/gh-config"`,
			"set GH_TOKEN to a short-lived github.com release token",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s does not sanitize inherited release environment: missing %q", name, required)
			}
		}
	}
	if strings.Contains(prepare, "go version | awk") || !strings.Contains(prepare, `go_version_output="$(timeout`) {
		t.Fatal("prepare release still allows a successful-looking Go version pipeline to hide a command failure")
	}
	releasing := readReleaseFile(t, "../../docs/releasing.md")
	if strings.Contains(releasing, "go version | awk") ||
		!strings.Contains(releasing, "if ! trusted_go_version=") ||
		!strings.Contains(releasing, "hash-object --no-filters") ||
		strings.Contains(releasing, "diff --no-ext-diff --no-textconv") {
		t.Fatal("trusted signer instructions do not isolate Git attributes and Go version failures")
	}

	start := strings.Index(prepare, "PATH=/usr/local/go/bin:")
	end := strings.Index(prepare[start:], "\nhash -r")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate preparation environment sanitization")
	}
	sanitization := prepare[start : start+end+len("\nhash -r")]

	dir := t.TempDir()
	sourceDir := filepath.Join(dir, "source")
	extractDir := filepath.Join(dir, "extract")
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "payload"), bytes.Repeat([]byte("x"), 32768), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "source.tar")
	archiveCmd := exec.Command("tar", "-cf", archive, "-C", sourceDir, "payload")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TAR_OPTIONS=") {
			archiveCmd.Env = append(archiveCmd.Env, entry)
		}
	}
	if out, err := archiveCmd.CombinedOutput(); err != nil {
		t.Fatalf("create test archive: %v\n%s", err, out)
	}
	marker := filepath.Join(dir, "tar-options-executed")
	attack := filepath.Join(dir, "attack.sh")
	if err := os.WriteFile(attack, []byte("#!/bin/sh\n: > \"$TEST_MARKER\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	testScript := filepath.Join(dir, "sanitize.sh")
	body := "#!/bin/bash\nset -Eeuo pipefail\n" + sanitization + `
[[ -z ${TAR_OPTIONS+x} && -z ${HTTPS_PROXY+x} && -z ${SSL_CERT_FILE+x} && -z ${GIT_TRACE+x} ]]
[[ "$GIT_CONFIG_NOSYSTEM" == 1 && "$GIT_CONFIG_GLOBAL" == /dev/null ]]
timeout -k 5 30 tar --extract --file="$TEST_ARCHIVE" --directory="$TEST_EXTRACT" --no-same-owner --no-same-permissions
`
	if err := os.WriteFile(testScript, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	env := make([]string, 0, len(os.Environ())+8)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "TAR_OPTIONS=") || strings.HasPrefix(entry, "HTTPS_PROXY=") ||
			strings.HasPrefix(entry, "SSL_CERT_FILE=") || strings.HasPrefix(entry, "GIT_TRACE=") ||
			strings.HasPrefix(entry, "TEST_") {
			continue
		}
		env = append(env, entry)
	}
	env = append(env,
		"TAR_OPTIONS=--checkpoint=1 --checkpoint-action=exec="+attack,
		"HTTPS_PROXY=http://127.0.0.1:9",
		"SSL_CERT_FILE="+filepath.Join(dir, "attacker-ca.pem"),
		"GIT_TRACE="+filepath.Join(dir, "git-trace"),
		"TEST_MARKER="+marker,
		"TEST_ARCHIVE="+archive,
		"TEST_EXTRACT="+extractDir,
	)
	cmd := exec.Command("/bin/bash", "-p", testScript)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sanitized archive extraction failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("inherited TAR_OPTIONS executed a command: %v", err)
	}
}

func TestTrustedSignerDocumentationBlockParsesAsBash(t *testing.T) {
	releasing := readReleaseFile(t, "../../docs/releasing.md")
	const opener = "/bin/bash -p <<'LTA_TRUSTED_SIGNER'\n"
	start := strings.Index(releasing, opener)
	if start < 0 {
		t.Fatal("trusted signer heredoc opener is missing")
	}
	start += len(opener)
	end := strings.Index(releasing[start:], "\nLTA_TRUSTED_SIGNER\n")
	if end < 0 {
		t.Fatal("trusted signer heredoc terminator is missing")
	}
	body := releasing[start : start+end]
	cmd := exec.Command("/bin/bash", "-n")
	cmd.Stdin = strings.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("trusted signer documentation block has invalid Bash syntax: %v\n%s", err, out)
	}
}

func TestPrepareRejectsFailingGoVersionCommandWithValidLookingOutput(t *testing.T) {
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	start := strings.Index(prepare, `go_version_output="$(timeout`)
	end := strings.Index(prepare[start:], "\n\nwork=")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate Go version gate")
	}
	versionGate := prepare[start : start+end]
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mockGo := filepath.Join(binDir, "go")
	if err := os.WriteFile(mockGo, []byte("#!/bin/sh\necho 'go version go1.26.5 linux/amd64'\nexit 23\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "gate-passed")
	script := filepath.Join(dir, "version-gate.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
GO_VERSION=go1.26.5
` + versionGate + `
: > "$TEST_MARKER"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = []string{
		"PATH=" + binDir + ":/usr/bin:/bin",
		"TEST_MARKER=" + marker,
	}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "could not execute the trusted Go toolchain") {
		t.Fatalf("failing Go version command was not rejected: err=%v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Go version gate continued after command failure: %v", err)
	}
}

func TestPrepareArchiveVerificationRejectsLocalAttributeRewrite(t *testing.T) {
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	start := strings.Index(prepare, `timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" tar --extract`)
	endMarker := `done < "$work/tag-tree"`
	end := strings.Index(prepare[start:], endMarker)
	if start < 0 || end < 0 {
		t.Fatal("could not isolate source archive verification")
	}
	verification := prepare[start : start+end+len(endMarker)]

	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init", "-q")
	payload := filepath.Join(repo, "payload.txt")
	if err := os.WriteFile(payload, []byte("value=$Format:%H$\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "payload.txt")
	runGit("-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "payload")
	marker := filepath.Join(dir, "filter-executed")
	attack := filepath.Join(dir, "attack.sh")
	if err := os.WriteFile(attack, []byte("#!/bin/sh\n: > \"$TEST_FILTER_MARKER\"\ncat\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runGit("config", "filter.evil.clean", attack)
	runGit("config", "filter.evil.smudge", attack)
	if err := os.WriteFile(filepath.Join(repo, ".git", "info", "attributes"), []byte("payload.txt export-subst filter=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(filepath.Join(work, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(work, "source.tar")
	runGit("archive", "--format=tar", "--output="+archive, "HEAD")
	treeCmd := exec.Command("git", "-C", repo, "ls-tree", "-r", "-z", "HEAD")
	treeBytes, err := treeCmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "tag-tree"), treeBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "verify-archive.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
LOCAL_COMMAND_TIMEOUT_SECONDS=30
SOURCE_DIR="$TEST_REPO"
source_archive="$TEST_ARCHIVE"
work="$TEST_WORK"
git_with_timeout() { command git "$@"; }
` + verification + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(),
		"TEST_REPO="+repo,
		"TEST_ARCHIVE="+archive,
		"TEST_WORK="+work,
		"TEST_FILTER_MARKER="+marker,
	)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "exported source differs from tagged Git object") {
		t.Fatalf("local attribute rewrite was not detected: err=%v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("local Git clean/smudge filter executed: %v", err)
	}
}

func TestReleaseOutputPathRejectsSymlinkedOrWritableParent(t *testing.T) {
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	start := strings.Index(offline, "require_safe_directory_path() {")
	end := strings.Index(offline[start:], "\nPREPARED_DIR=")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate trusted output-path guards")
	}
	guards := offline[start : start+end]
	dir := t.TempDir()
	realParent := filepath.Join(dir, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(dir, "linked")
	if err := os.Symlink(realParent, symlinkParent); err != nil {
		t.Fatal(err)
	}
	writableParent := filepath.Join(dir, "writable")
	if err := os.Mkdir(writableParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writableParent, 0o777); err != nil {
		t.Fatal(err)
	}

	for name, output := range map[string]string{
		"symlinked ancestor": filepath.Join(symlinkParent, "out"),
		"writable parent":    filepath.Join(writableParent, "out"),
	} {
		t.Run(name, func(t *testing.T) {
			script := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".sh")
			body := "#!/bin/bash\nset -Eeuo pipefail\nLOCAL_COMMAND_TIMEOUT_SECONDS=120\nlocal_with_timeout() { timeout -k 5 \"$LOCAL_COMMAND_TIMEOUT_SECONDS\" \"$@\"; }\n" + guards + `
require_safe_new_output_path "$TEST_OUTPUT" "test output"
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = append(os.Environ(), "TEST_OUTPUT="+output)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("unsafe output parent passed validation: %s", out)
			}
		})
	}
}

func TestTrustedReleaseDirectoryLeavesRejectStickyMode(t *testing.T) {
	for _, releaseScript := range []string{
		"../../scripts/prepare-release.sh",
		"../../scripts/publish-release.sh",
	} {
		releaseScript := releaseScript
		t.Run(filepath.Base(releaseScript), func(t *testing.T) {
			content := readReleaseFile(t, releaseScript)
			dirStart := strings.Index(content, "require_safe_directory_path() {")
			sourceStart := strings.Index(content, "require_safe_source_repo() {")
			if dirStart < 0 || sourceStart < 0 {
				t.Fatal("could not locate trusted source-directory guards")
			}
			dirEnd := strings.Index(content[dirStart:], "\n}\n")
			sourceEnd := strings.Index(content[sourceStart:], "\n}\n")
			if dirEnd < 0 || sourceEnd < 0 {
				t.Fatal("could not isolate trusted source-directory guards")
			}
			guards := content[dirStart:dirStart+dirEnd+2] + "\n" +
				content[sourceStart:sourceStart+sourceEnd+2]

			for _, tt := range []struct {
				name     string
				repoMode os.FileMode
				gitMode  os.FileMode
				wantOK   bool
			}{
				{name: "private source and Git directory", repoMode: 0o700, gitMode: 0o700, wantOK: true},
				{name: "sticky source leaf", repoMode: 0o777 | os.ModeSticky, gitMode: 0o700, wantOK: false},
				{name: "sticky Git leaf", repoMode: 0o700, gitMode: 0o777 | os.ModeSticky, wantOK: false},
			} {
				tt := tt
				t.Run(tt.name, func(t *testing.T) {
					dir := t.TempDir()
					repo := filepath.Join(dir, "repo")
					gitDir := filepath.Join(repo, ".git")
					if err := os.MkdirAll(filepath.Join(gitDir, "objects", "info"), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(repo, tt.repoMode); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(gitDir, tt.gitMode); err != nil {
						t.Fatal(err)
					}
					script := filepath.Join(dir, "source-guard.sh")
					body := `#!/bin/bash
set -Eeuo pipefail
LOCAL_COMMAND_TIMEOUT_SECONDS=120
local_with_timeout() { timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" "$@"; }
SOURCE_DIR="$TEST_REPO"
` + guards + `
require_safe_source_repo
`
					if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command("/bin/bash", script)
					cmd.Env = append(os.Environ(), "TEST_REPO="+repo)
					out, err := cmd.CombinedOutput()
					if tt.wantOK && err != nil {
						t.Fatalf("private trusted source was rejected: %v\n%s", err, out)
					}
					if !tt.wantOK && err == nil {
						t.Fatalf("sticky trusted-directory leaf unexpectedly passed: %s", out)
					}
				})
			}
		})
	}
}

func TestReleaseOutputPathAllowsStickyParentButRejectsNoncanonicalPath(t *testing.T) {
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	start := strings.Index(offline, "require_safe_directory_path() {")
	end := strings.Index(offline[start:], "\nPREPARED_DIR=")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate trusted output-path guards")
	}
	guards := offline[start : start+end]
	dir := t.TempDir()
	const stickyParent = "/tmp"
	outputLeaf := filepath.Base(filepath.Dir(dir)) + "-output"
	outputPath := filepath.Join(stickyParent, outputLeaf)
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("test output path must begin nonexistent: %v", err)
	}
	noncanonicalOutputPath := stickyParent + "//" + outputLeaf + "-other"

	script := filepath.Join(dir, "output-path.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
LOCAL_COMMAND_TIMEOUT_SECONDS=120
local_with_timeout() { timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" "$@"; }
` + guards + `
require_safe_new_output_path "$TEST_OUTPUT_PATH" "test output"
if require_safe_directory_path "$TEST_STICKY_PARENT" "test leaf"; then
  echo "sticky leaf unexpectedly passed" >&2
  exit 90
fi
if require_safe_new_output_path "$TEST_NONCANONICAL_OUTPUT_PATH" "test output"; then
  echo "noncanonical output unexpectedly passed" >&2
  exit 91
fi
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(),
		"TEST_STICKY_PARENT="+stickyParent,
		"TEST_OUTPUT_PATH="+outputPath,
		"TEST_NONCANONICAL_OUTPUT_PATH="+noncanonicalOutputPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sticky-parent/noncanonical output guard failed: %v\n%s", err, out)
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("output path guard created its target: %v", err)
	}
}

func TestPublisherResumeAndRecoveryGuards(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	for _, required := range []string{
		"resume exactly matching published release (no asset mutation)",
		"require_exact_signed_assets",
		"require_remote_asset_digests",
		"RESUMING_ALREADY_LATEST",
		"LATEST_PROMOTION_ATTEMPTED=1",
		"restore_latest_after_failed_promotion",
		"highest_stable_release_excluding",
		"require_latest_exact",
		"HTTP/[0-9.]+ 404",
		"CRITICAL: automatic Latest restoration failed",
	} {
		if !strings.Contains(publish, required) {
			t.Fatalf("publisher resume/recovery path is missing %q", required)
		}
	}
	resume := strings.Index(publish, "resume exactly matching published release")
	upload := strings.Index(publish, `gh_with_timeout release upload "$TAG"`)
	if resume < 0 || upload < 0 || resume < upload {
		t.Fatal("published-release resume path is not separated from draft asset upload")
	}
}

func TestOnlineReleaseScriptsRejectTimedOutLatest404(t *testing.T) {
	scripts := []string{
		"../../scripts/prepare-release.sh",
		"../../scripts/publish-release.sh",
	}
	tests := []struct {
		name   string
		status string
		wantOK bool
	}{
		{name: "ordinary REST 404", status: "1", wantOK: true},
		{name: "timeout after REST 404", status: "124", wantOK: false},
		{name: "forced kill after REST 404", status: "137", wantOK: false},
	}

	for _, releaseScript := range scripts {
		releaseScript := releaseScript
		t.Run(filepath.Base(releaseScript), func(t *testing.T) {
			content := readReleaseFile(t, releaseScript)
			start := strings.Index(content, "current_latest_tag() {")
			if start < 0 {
				t.Fatal("could not locate current_latest_tag")
			}
			end := strings.Index(content[start:], "\n}\n")
			if end < 0 {
				t.Fatal("could not isolate current_latest_tag")
			}
			latestFunction := content[start : start+end+2]

			for _, tt := range tests {
				tt := tt
				t.Run(tt.name, func(t *testing.T) {
					dir := t.TempDir()
					script := filepath.Join(dir, "latest-test.sh")
					body := `#!/bin/bash
set -Eeuo pipefail
REPO=mock/repo
work="$TEST_STATE/work"
mkdir -p "$work"
gh_with_timeout() {
  if [[ "$1" == release && "$2" == view ]]; then
    printf 'no latest release\n' >&2
    return 1
  fi
  if [[ "$1" == api && "$2" == --include ]]; then
    printf 'HTTP/2.0 404 Not Found\n'
    return "$TEST_API_STATUS"
  fi
  return 99
}
` + latestFunction + `
current_latest_tag > "$TEST_STATE/result"
`
					if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command("/bin/bash", script)
					cmd.Env = append(os.Environ(), "TEST_STATE="+dir, "TEST_API_STATUS="+tt.status)
					out, err := cmd.CombinedOutput()
					if tt.wantOK && err != nil {
						t.Fatalf("ordinary REST 404 was rejected: %v\n%s", err, out)
					}
					if !tt.wantOK && err == nil {
						t.Fatalf("REST 404 with exit status %s unexpectedly passed: %s", tt.status, out)
					}
				})
			}
		})
	}
}

func TestPublisherLatestRestorationWithMockGitHub(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	start := strings.Index(publish, "decimal_gt() {")
	end := strings.Index(publish, "\nrelease_state() {")
	if start < 0 || end <= start {
		t.Fatal("could not isolate publisher Latest recovery functions")
	}
	recoveryFunctions := publish[start:end]

	tests := []struct {
		name       string
		stableTags string
		initial    string
		expected   string
		apiMode    string
		wantOK     bool
	}{
		{
			name:       "restore previous highest stable",
			stableTags: "v2.7.3\nv2.8.0\n",
			initial:    "v2.8.0",
			expected:   "v2.7.3",
			apiMode:    "404",
			wantOK:     true,
		},
		{
			name:       "restore concurrently published higher stable",
			stableTags: "v2.7.3\nv2.8.0\nv2.9.0\n",
			initial:    "v2.8.0",
			expected:   "v2.9.0",
			apiMode:    "404",
			wantOK:     true,
		},
		{
			name:       "clear Latest when no alternative exists",
			stableTags: "v2.8.0\n",
			initial:    "v2.8.0",
			expected:   "",
			apiMode:    "404",
			wantOK:     true,
		},
		{
			name:       "transport failure is not empty Latest",
			stableTags: "v2.8.0\n",
			initial:    "v2.8.0",
			expected:   "",
			apiMode:    "transport",
			wantOK:     false,
		},
		{
			name:       "mixed 404 and server error is not empty Latest",
			stableTags: "v2.8.0\n",
			initial:    "v2.8.0",
			expected:   "",
			apiMode:    "mixed",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "recovery-test.sh")
			body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
LOCAL_COMMAND_TIMEOUT_SECONDS=120
work="$TEST_STATE/work"
mkdir -p "$work"
printf '%s' "$TEST_STABLE_TAGS" > "$TEST_STATE/stable"
printf '%s' "$TEST_INITIAL_LATEST" > "$TEST_STATE/latest"
gh() {
  if [[ "$1" == api && "$2" == --paginate ]]; then
    cat "$TEST_STATE/stable"
    return 0
  fi
  if [[ "$1" == api && "$2" == --include ]]; then
    if [[ "$TEST_API_MODE" == 404 ]]; then
      printf 'HTTP/2.0 404 Not Found\n'
    elif [[ "$TEST_API_MODE" == mixed ]]; then
      printf 'HTTP/2.0 404 Not Found\nHTTP/2.0 500 Internal Server Error\n'
    else
      printf 'network unavailable\n'
    fi
    return 1
  fi
  if [[ "$1" == release && "$2" == view ]]; then
    if [[ -s "$TEST_STATE/latest" ]]; then
      cat "$TEST_STATE/latest"
      return 0
    fi
    printf 'no latest release\n' >&2
    return 1
  fi
  if [[ "$1" == release && "$2" == edit ]]; then
    local tag=$3 arg
    for arg in "$@"; do
      case "$arg" in
        --latest) printf '%s' "$tag" > "$TEST_STATE/latest"; return 0 ;;
        --latest=false) : > "$TEST_STATE/latest"; return 0 ;;
      esac
    done
  fi
  printf 'unexpected gh invocation: %q ' "$@" >&2
  return 99
}
gh_with_timeout() { gh "$@"; }
` + recoveryFunctions + `
restore_latest_after_failed_promotion
actual="$(cat "$TEST_STATE/latest")"
[[ "$actual" == "$TEST_EXPECTED_LATEST" ]]
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = append(os.Environ(),
				"TEST_STATE="+dir,
				"TEST_STABLE_TAGS="+tt.stableTags,
				"TEST_INITIAL_LATEST="+tt.initial,
				"TEST_EXPECTED_LATEST="+tt.expected,
				"TEST_API_MODE="+tt.apiMode,
			)
			out, err := cmd.CombinedOutput()
			if tt.wantOK && err != nil {
				t.Fatalf("mock recovery failed: %v\n%s", err, out)
			}
			if !tt.wantOK && err == nil {
				t.Fatalf("mock recovery unexpectedly succeeded: %s", out)
			}
		})
	}
}

func TestPublisherPublishedAssetValidationWithMockGitHub(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	start := strings.Index(publish, "remote_asset_names() {")
	end := strings.Index(publish, "\nif [[ \"$TAG\" == *-* ]]; then")
	if start < 0 || end <= start {
		t.Fatal("could not isolate publisher remote-asset validation functions")
	}
	assetFunctions := publish[start:end]

	assets := []string{
		"SHA256SUMS",
		"linux-temp-admin-linux-amd64",
		"linux-temp-admin-linux-amd64.sig",
		"linux-temp-admin-linux-arm64",
		"linux-temp-admin-linux-arm64.sig",
	}
	tests := []struct {
		name       string
		extraAsset bool
		badDigest  bool
		wantOK     bool
	}{
		{name: "exact published asset set", wantOK: true},
		{name: "extra published asset", extraAsset: true, wantOK: false},
		{name: "wrong published digest", badDigest: true, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bundle := filepath.Join(dir, "bundle")
			if err := os.Mkdir(bundle, 0o700); err != nil {
				t.Fatal(err)
			}
			var names, digests strings.Builder
			for _, name := range assets {
				body := []byte("mock-" + name + "\n")
				if err := os.WriteFile(filepath.Join(bundle, name), body, 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(body)
				fmt.Fprintf(&names, "%s\n", name)
				fmt.Fprintf(&digests, "%s\tsha256:%x\t%d\n", name, sum, len(body))
			}
			if tt.extraAsset {
				names.WriteString("unexpected.txt\n")
			}
			digestOutput := digests.String()
			if tt.badDigest {
				digestOutput = strings.Replace(digestOutput, "sha256:", "sha256:00", 1)
			}

			script := filepath.Join(dir, "asset-test.sh")
			body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
BUNDLE_DIR="$TEST_BUNDLE"
gh() {
  [[ "$1" == release && "$2" == view ]] || return 99
  case "$*" in
    *'.assets[].name'*) printf '%s' "$TEST_ASSET_NAMES" ;;
    *'.digest // ""'*) printf '%s' "$TEST_ASSET_DIGESTS" ;;
    *) return 98 ;;
  esac
}
gh_with_timeout() { gh "$@"; }
` + assetFunctions + `
require_exact_signed_assets
require_remote_asset_digests
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = append(os.Environ(),
				"TEST_BUNDLE="+bundle,
				"TEST_ASSET_NAMES="+names.String(),
				"TEST_ASSET_DIGESTS="+digestOutput,
			)
			out, err := cmd.CombinedOutput()
			if tt.wantOK && err != nil {
				t.Fatalf("exact published asset validation failed: %v\n%s", err, out)
			}
			if !tt.wantOK && err == nil {
				t.Fatalf("mismatched published assets unexpectedly passed: %s", out)
			}
		})
	}
}

func TestPublisherExitTrapRestoresLatestWithMockGitHub(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	cleanupStart := strings.Index(publish, "cleanup() {")
	cleanupEnd := strings.Index(publish[cleanupStart:], "\ntrap cleanup EXIT")
	recoveryStart := strings.Index(publish, "decimal_gt() {")
	recoveryEnd := strings.Index(publish, "\nrelease_state() {")
	if cleanupStart < 0 || cleanupEnd < 0 || recoveryStart < 0 || recoveryEnd <= recoveryStart {
		t.Fatal("could not isolate publisher EXIT recovery logic")
	}
	cleanupFunction := publish[cleanupStart : cleanupStart+cleanupEnd]
	recoveryFunctions := publish[recoveryStart:recoveryEnd]

	dir := t.TempDir()
	script := filepath.Join(dir, "trap-test.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
LOCAL_COMMAND_TIMEOUT_SECONDS=120
work="$TEST_STATE/work"
mkdir -p "$work"
printf 'v2.7.3\nv2.8.0\n' > "$TEST_STATE/stable"
printf 'v2.8.0' > "$TEST_STATE/latest"
gh() {
  if [[ "$1" == api && "$2" == --paginate ]]; then cat "$TEST_STATE/stable"; return 0; fi
  if [[ "$1" == release && "$2" == view ]]; then cat "$TEST_STATE/latest"; return 0; fi
  if [[ "$1" == release && "$2" == edit && "$4" == --repo && "$6" == --latest ]]; then
    printf '%s' "$3" > "$TEST_STATE/latest"
    return 0
  fi
  return 99
}
gh_with_timeout() { gh "$@"; }
` + cleanupFunction + "\n" + recoveryFunctions + `
LATEST_PROMOTION_ATTEMPTED=1
PUBLISH_COMPLETE=0
trap cleanup EXIT
exit 42
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(), "TEST_STATE="+dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("failure injection unexpectedly succeeded: %s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 42 {
		t.Fatalf("EXIT trap did not preserve failure status 42: %v\n%s", err, out)
	}
	latest, readErr := os.ReadFile(filepath.Join(dir, "latest"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(latest) != "v2.7.3" {
		t.Fatalf("EXIT trap restored Latest to %q, want v2.7.3\n%s", latest, out)
	}
}

func TestPublisherReadOnlyResumeFailureDoesNotDemoteLatest(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	cleanupStart := strings.Index(publish, "cleanup() {")
	cleanupEnd := strings.Index(publish[cleanupStart:], "\ntrap cleanup EXIT")
	if cleanupStart < 0 || cleanupEnd < 0 {
		t.Fatal("could not isolate publisher cleanup logic")
	}
	cleanupFunction := publish[cleanupStart : cleanupStart+cleanupEnd]

	dir := t.TempDir()
	script := filepath.Join(dir, "read-only-resume.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
LOCAL_COMMAND_TIMEOUT_SECONDS=120
work="$TEST_STATE/work"
mkdir -p "$work"
restore_latest_after_failed_promotion() { : > "$TEST_STATE/demoted"; }
` + cleanupFunction + `
LATEST_PROMOTION_ATTEMPTED=0
PUBLISH_COMPLETE=0
trap cleanup EXIT
exit 42
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(), "TEST_STATE="+dir)
	out, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 42 {
		t.Fatalf("read-only resume did not preserve status 42: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "demoted")); !os.IsNotExist(err) {
		t.Fatalf("read-only resume attempted to demote pre-existing Latest: %v", err)
	}
}

func TestPublisherCleanupFailurePreservesOriginalExitStatus(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	cleanupStart := strings.Index(publish, "cleanup() {")
	cleanupEnd := strings.Index(publish[cleanupStart:], "\ntrap cleanup EXIT")
	if cleanupStart < 0 || cleanupEnd < 0 {
		t.Fatal("could not isolate publisher cleanup logic")
	}
	cleanupFunction := publish[cleanupStart : cleanupStart+cleanupEnd]

	dir := t.TempDir()
	script := filepath.Join(dir, "cleanup-failure.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
LOCAL_COMMAND_TIMEOUT_SECONDS=120
work="$TEST_STATE/work"
mkdir -p "$work"
timeout() { return 1; }
` + cleanupFunction + `
LATEST_PROMOTION_ATTEMPTED=0
PUBLISH_COMPLETE=0
trap cleanup EXIT
exit 42
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(), "TEST_STATE="+dir)
	out, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 42 {
		t.Fatalf("cleanup failure changed status 42: %v\n%s", err, out)
	}
}

func TestVulnerabilityScannerIsPinnedAndRunsInReleaseGate(t *testing.T) {
	goWorkflow := readReleaseFile(t, "../../.github/workflows/go.yml")
	releaseWorkflow := readReleaseFile(t, "../../.github/workflows/release.yml")
	for name, content := range map[string]string{"Go": goWorkflow, "Release": releaseWorkflow} {
		if !strings.Contains(content, "golang.org/x/vuln/cmd/govulncheck@v1.6.0") {
			t.Fatalf("%s workflow does not pin govulncheck v1.6.0", name)
		}
		if strings.Contains(content, "govulncheck@latest") {
			t.Fatalf("%s workflow still uses a floating govulncheck version", name)
		}
	}
	if !strings.Contains(releaseWorkflow, "Release vulnerability gate") || !strings.Contains(releaseWorkflow, `"$GOBIN/govulncheck" ./...`) {
		t.Fatal("tag Release workflow does not rerun the pinned vulnerability scan")
	}
}

func TestRootIntegrationPackagesRunSerially(t *testing.T) {
	var paths []string
	for _, pattern := range []string{"../../.github/workflows/*.yml", "../../.github/workflows/*.yaml"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	paths = append(paths, "../../CONTRIBUTING.md")
	commandCount := 0
	for _, path := range paths {
		content := readReleaseFile(t, path)
		count, unserialized := rootIntegrationPackageCommands(content)
		commandCount += count
		for _, line := range unserialized {
			t.Errorf("%s:%d runs root integration packages without -p 1", path, line)
		}
	}
	if commandCount != 4 {
		t.Fatalf("found %d root integration package commands, want 4", commandCount)
	}

	goWorkflow := readReleaseFile(t, "../../.github/workflows/go.yml")
	if !strings.Contains(goWorkflow, `go test -count=1 -race -p 1 -tags integration ./...`) {
		t.Error("Go workflow does not force an uncached serialized root integration run")
	}
	releaseWorkflow := readReleaseFile(t, "../../.github/workflows/release.yml")
	if !strings.Contains(releaseWorkflow, `go test -mod=readonly -count=1 -race -p 1 -tags integration ./...`) {
		t.Error("Release workflow does not force an uncached serialized root integration run")
	}

	bait := "# go test -p 1 -tags integration ./...\n" +
		"go test -tags integration ./... # -p 1\n" +
		"go test -p 1 -tags integration ./... && go test -tags integration ./...\n" +
		"go test -p 1 -tags integration ./...; go test -tags integration ./...\n"
	count, unserialized := rootIntegrationPackageCommands(bait)
	if count != 5 || len(unserialized) != 3 || unserialized[0] != 2 || unserialized[1] != 3 || unserialized[2] != 4 {
		t.Fatalf("root command scan accepted a comment bait or missed a chained unserialized command: count=%d lines=%v", count, unserialized)
	}
}

func rootIntegrationPackageCommands(content string) (int, []int) {
	content = strings.ReplaceAll(content, "\\\n", " ")
	commandCount := 0
	var unserialized []int
	for lineNumber, line := range strings.Split(content, "\n") {
		for _, fields := range shellCommandFields(line) {
			goTest := false
			integration := false
			allPackages := false
			serialized := false
			for i, field := range fields {
				if field == "go" && i+1 < len(fields) && fields[i+1] == "test" {
					goTest = true
				}
				if field == "-tags" && i+1 < len(fields) {
					integration = integration || commaListContains(fields[i+1], "integration")
				} else if strings.HasPrefix(field, "-tags=") {
					integration = integration || commaListContains(strings.TrimPrefix(field, "-tags="), "integration")
				}
				if field == "./..." {
					allPackages = true
				}
				if field == "-p=1" || (field == "-p" && i+1 < len(fields) && fields[i+1] == "1") {
					serialized = true
				}
			}
			if !goTest || !integration || !allPackages {
				continue
			}
			commandCount++
			if !serialized {
				unserialized = append(unserialized, lineNumber+1)
			}
		}
	}
	return commandCount, unserialized
}

func shellCommandFields(line string) [][]string {
	var commands [][]string
	var fields []string
	var field strings.Builder
	var quote byte
	escaped := false

	flushField := func() {
		if field.Len() == 0 {
			return
		}
		fields = append(fields, field.String())
		field.Reset()
	}
	flushCommand := func() {
		flushField()
		if len(fields) == 0 {
			return
		}
		commands = append(commands, fields)
		fields = nil
	}

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			field.WriteByte(ch)
			escaped = false
			continue
		}
		if quote != '\'' && ch == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				field.WriteByte(ch)
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == '#' && field.Len() == 0 {
			break
		}
		if ch == ';' || ch == '|' || (ch == '&' && i+1 < len(line) && line[i+1] == '&') {
			flushCommand()
			if i+1 < len(line) && line[i+1] == ch {
				i++
			}
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\r' {
			flushField()
			continue
		}
		field.WriteByte(ch)
	}
	if escaped {
		field.WriteByte('\\')
	}
	flushCommand()
	return commands
}

func commaListContains(list, want string) bool {
	for _, item := range strings.Split(list, ",") {
		if item == want {
			return true
		}
	}
	return false
}

func TestReleaseKeyringValidationIsPortableAcrossAwkImplementations(t *testing.T) {
	const portableCheck = `length($0) != 64 || $0 !~ /^[0-9A-Fa-f]+$/`
	const nonPortableCheck = `$0 !~ /^[0-9A-Fa-f]{64}$/`
	for _, path := range []string{
		"../../scripts/prepare-release.sh",
		"../../scripts/offline-sign-release.sh",
		"../../scripts/publish-release.sh",
	} {
		content := readReleaseFile(t, path)
		if !strings.Contains(content, portableCheck) {
			t.Errorf("%s does not use the POSIX-awk key length check", path)
		}
		if strings.Contains(content, nonPortableCheck) {
			t.Errorf("%s uses interval expressions that Debian mawk does not support", path)
		}
	}
}

func TestOfflineSigningRejectsWrongKeyFromRotationKeyring(t *testing.T) {
	dir := t.TempDir()
	prepared := filepath.Join(dir, "prepared")
	oldKey := strings.Repeat("11", 32)
	newKey := strings.Repeat("22", 32)
	manifestHash := writePreparedRelease(t, prepared, oldKey+"\n"+newKey+"\n")

	signer := filepath.Join(dir, "trusted-signer")
	signerScript := "#!/bin/sh\ncase \"$1\" in\nversion) echo lta-release-offline-v1 ;;\npubkey) echo " + newKey + " ;;\n*) exit 99 ;;\nesac\n"
	if err := os.WriteFile(signer, []byte(signerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	signerHash := sha256.Sum256([]byte(signerScript))
	privateKey := filepath.Join(dir, "test.key")
	if err := os.WriteFile(privateKey, []byte("test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "signed")
	cmd := exec.Command("../../scripts/offline-sign-release.sh", prepared, signed)
	cmd.Env = []string{
		"HOME=" + dir,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LTA_SIGN_KEY=" + privateKey,
		"LTA_TRUSTED_SIGNER=" + signer,
		fmt.Sprintf("LTA_TRUSTED_SIGNER_SHA256=%x", signerHash),
		"LTA_EXPECTED_TAG=v2.8.0",
		"LTA_EXPECTED_COMMIT=" + strings.Repeat("a", 40),
		"LTA_EXPECTED_PREPARED_MANIFEST_SHA256=" + manifestHash,
		"LTA_EXPECTED_RELEASE_SIGNER_PUBKEY=" + oldKey,
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("offline signer accepted NEW when OLD was independently selected: %s", out)
	}
	if !strings.Contains(string(out), "not the independently selected release-signing key") {
		t.Fatalf("unexpected rejection: %s", out)
	}
	if _, err := os.Lstat(signed); !os.IsNotExist(err) {
		t.Fatalf("failed signing ceremony left output behind: %v", err)
	}
}

func TestOfflineSigningProducesBundleBoundToSelectedKey(t *testing.T) {
	dir := t.TempDir()
	signer := filepath.Join(dir, "lta-release")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", signer, "../../cmd/lta-release")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build trusted signer: %v\n%s", err, out)
	}

	privateKey := filepath.Join(dir, "release.key")
	keygen := exec.Command(signer, "keygen", privateKey)
	pubOut, err := keygen.Output()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := strings.TrimSpace(string(pubOut))
	if len(publicKey) != 64 {
		t.Fatalf("generated public key has length %d", len(publicKey))
	}

	prepared := filepath.Join(dir, "prepared")
	manifestHash := writePreparedRelease(t, prepared, publicKey+"\n")
	signerBytes, err := os.ReadFile(signer)
	if err != nil {
		t.Fatal(err)
	}
	signerHash := sha256.Sum256(signerBytes)
	signed := filepath.Join(dir, "signed")
	cmd := exec.Command("../../scripts/offline-sign-release.sh", prepared, signed)
	cmd.Env = []string{
		"HOME=" + dir,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LTA_SIGN_KEY=" + privateKey,
		"LTA_TRUSTED_SIGNER=" + signer,
		fmt.Sprintf("LTA_TRUSTED_SIGNER_SHA256=%x", signerHash),
		"LTA_EXPECTED_TAG=v2.8.0",
		"LTA_EXPECTED_COMMIT=" + strings.Repeat("a", 40),
		"LTA_EXPECTED_PREPARED_MANIFEST_SHA256=" + manifestHash,
		"LTA_EXPECTED_RELEASE_SIGNER_PUBKEY=" + publicKey,
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline signing failed: %v\n%s", err, out)
	}
	gotKey, err := os.ReadFile(filepath.Join(signed, "RELEASE_SIGNER_PUBKEY"))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotKey) != publicKey+"\n" {
		t.Fatalf("bundle selected key=%q, want %q", gotKey, publicKey)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		asset := filepath.Join(signed, "linux-temp-admin-linux-"+arch)
		verify := exec.Command(signer, "verify", filepath.Join(signed, "RELEASE_SIGNER_PUBKEY"), asset, asset+".sig")
		if out, err := verify.CombinedOutput(); err != nil {
			t.Fatalf("verify %s bundle signature: %v\n%s", arch, err, out)
		}
	}
}

func TestOfflineSigningBoundsSnapshotBeforeManifestValidation(t *testing.T) {
	dir := t.TempDir()
	prepared := filepath.Join(dir, "prepared")
	publicKey := strings.Repeat("11", 32)
	manifestHash := writePreparedRelease(t, prepared, publicKey+"\n")
	if err := os.WriteFile(filepath.Join(prepared, "TAG"), bytes.Repeat([]byte{'v'}, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}

	signer := filepath.Join(dir, "trusted-signer")
	signerScript := "#!/bin/sh\n[ \"$1\" = version ] && { echo lta-release-offline-v1; exit 0; }\nexit 99\n"
	if err := os.WriteFile(signer, []byte(signerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	signerHash := sha256.Sum256([]byte(signerScript))
	privateKey := filepath.Join(dir, "test.key")
	if err := os.WriteFile(privateKey, []byte("test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "signed")
	cmd := exec.Command("../../scripts/offline-sign-release.sh", prepared, signed)
	cmd.Env = []string{
		"HOME=" + dir,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LTA_SIGN_KEY=" + privateKey,
		"LTA_TRUSTED_SIGNER=" + signer,
		fmt.Sprintf("LTA_TRUSTED_SIGNER_SHA256=%x", signerHash),
		"LTA_EXPECTED_TAG=v2.8.0",
		"LTA_EXPECTED_COMMIT=" + strings.Repeat("a", 40),
		"LTA_EXPECTED_PREPARED_MANIFEST_SHA256=" + manifestHash,
		"LTA_EXPECTED_RELEASE_SIGNER_PUBKEY=" + publicKey,
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("offline signer accepted oversized metadata: %s", out)
	}
	if !strings.Contains(string(out), "snapshot limit") {
		t.Fatalf("unexpected oversized-input rejection: %s", out)
	}
	if _, err := os.Lstat(signed); !os.IsNotExist(err) {
		t.Fatalf("oversized input left signed output behind: %v", err)
	}
}

func writePreparedRelease(t *testing.T, prepared, keyring string) string {
	t.Helper()
	if err := os.Mkdir(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"COMMIT":                       []byte(strings.Repeat("a", 40) + "\n"),
		"TAG":                          []byte("v2.8.0\n"),
		"VERSION":                      []byte("2.8.0\n"),
		"release_pubkey.hex":           []byte(keyring),
		"linux-temp-admin-linux-amd64": []byte("amd64"),
		"linux-temp-admin-linux-arm64": []byte("arm64"),
	}
	order := []string{"COMMIT", "TAG", "VERSION", "release_pubkey.hex", "linux-temp-admin-linux-amd64", "linux-temp-admin-linux-arm64"}
	var manifest strings.Builder
	for _, name := range order {
		if err := os.WriteFile(filepath.Join(prepared, name), files[name], 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&manifest, "%x  %s\n", sum, name)
	}
	manifestBytes := []byte(manifest.String())
	if err := os.WriteFile(filepath.Join(prepared, "PREPARED_SHA256SUMS"), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(manifestBytes)
	return fmt.Sprintf("%x", manifestHash)
}

func readReleaseFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
