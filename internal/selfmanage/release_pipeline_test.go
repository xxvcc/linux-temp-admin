package selfmanage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func workflowUses(t *testing.T, path string) []string {
	t.Helper()
	content := readReleaseFile(t, path)
	var uses []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- uses: ") {
			uses = append(uses, strings.TrimPrefix(trimmed, "- uses: "))
		} else if strings.HasPrefix(trimmed, "uses: ") {
			uses = append(uses, strings.TrimPrefix(trimmed, "uses: "))
		}
	}
	return uses
}

func TestReleaseWriterIsSeparatedFromCandidateWorkflow(t *testing.T) {
	release := readReleaseFile(t, "../../.github/workflows/release.yml")
	stage := readReleaseFile(t, "../../.github/workflows/stage-release.yml")
	validateTag := workflowRunStep(t, "../../.github/workflows/stage-release.yml", "Validate triggering tag and commit")
	validateArtifact := workflowRunStep(t, "../../.github/workflows/stage-release.yml", "Validate transferred artifact")
	createDraft := workflowRunStep(t, "../../.github/workflows/stage-release.yml", "Create a new unsigned DRAFT release")
	if strings.Contains(release, "contents: write") {
		t.Fatal("candidate-tag Release workflow must not receive contents:write")
	}
	for _, required := range []string{"workflow_run:", "contents: write", "refusing to refresh any remote asset"} {
		if !strings.Contains(stage, required) {
			t.Fatalf("trusted stage workflow is missing %q", required)
		}
	}
	for _, script := range []string{validateTag, createDraft} {
		requireExecutableShellFragment(t, script, ".verification.verified")
		requireExecutableShellFragment(t, script, ".verification.signature")
		requireExecutableShellFragment(t, script, "-----BEGIN PGP SIGNATURE-----")
	}
	requireExecutableShellFragment(t, createDraft, `gh api --paginate`)
	requireExecutableShellFragment(t, createDraft, `releases?per_page=100`)
	requireExecutableShellFragment(t, createDraft, `(( match_count == 0 ))`)
	if strings.Contains(stage, `releases/tags/${TAG}`) {
		t.Fatal("trusted stage workflow does not enumerate authenticated draft and published Release identities")
	}
	if strings.Contains(stage, "--clobber") {
		t.Fatal("trusted stage workflow must never refresh an existing draft")
	}
	for _, required := range []string{
		`find dist -mindepth 1 -printf '%P\t%y\n'`,
		`wc -c < dist/SHA256SUMS`,
		"1048576",
	} {
		requireExecutableShellFragment(t, validateArtifact, required)
	}
	requireExecutableShellFragment(t, createDraft, `git/ref/tags/${TAG}`)
	requireExecutableShellFragment(t, createDraft, `timeout -k 5 600 gh release create`)
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
	releaseGate := workflowRunStep(t, "../../.github/workflows/release.yml", "Release test gate")
	for _, required := range []string{
		`root_go_root="$(sudo mktemp -d /tmp/lta-release-root-go.XXXXXXXXXX)"`,
		`sudo stat -Lc '%u %g %a' -- "$root_go_root"`,
		`sudo install -d -o 0 -g 0 -m 0700`,
		`sudo env "PATH=$PATH" HOME=/root TMPDIR=/tmp`,
		`GOCACHE="$root_go_root/gocache"`,
		`GOMODCACHE="$root_go_root/gomodcache"`,
		`GOPATH="$root_go_root/gopath" GOTMPDIR="$root_go_root/gotmp"`,
	} {
		requireExecutableShellFragment(t, releaseGate, required)
	}
	if strings.Contains(release, `${RUNNER_TEMP}/lta-root-`) ||
		strings.Contains(release, `sudo -E env "PATH=$PATH"`) {
		t.Fatal("release root test gate inherits or stores privileged Go state below the runner account")
	}
}

func TestReleaseArtifactHandoffUsesAuditedNode24Actions(t *testing.T) {
	for name, check := range map[string]struct {
		path string
		pin  string
	}{
		"upload":   {"../../.github/workflows/release.yml", "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"},
		"download": {"../../.github/workflows/stage-release.yml", "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"},
	} {
		if !slices.Contains(workflowUses(t, check.path), check.pin) {
			t.Errorf("release %s action is not pinned to the audited native Node.js 24 version", name)
		}
	}
}

func TestReleaseBuildsEmbedAuthenticatedStaticVersionWitness(t *testing.T) {
	const buildFlags = `-ldflags "-s -w -X github.com/xxvcc/linux-temp-admin/internal/buildinfo.Version=${VERSION} -X github.com/xxvcc/linux-temp-admin/internal/buildinfo.ReleaseVersionWitness=LTA_RELEASE_VERSION_V1{${VERSION}}"`
	for name, script := range map[string]string{
		"candidate workflow": workflowRunStep(t, "../../.github/workflows/release.yml", "Build reproducible static binaries"),
		"trusted rebuild":    readReleaseFile(t, "../../scripts/prepare-release.sh"),
	} {
		if countExecutableShellFragment(script, buildFlags) != 1 {
			t.Fatalf("%s must embed exactly one authenticated static version witness", name)
		}
	}
}

func TestReleaseVersionLengthContractIsEnforcedAcrossEveryPipelineBoundary(t *testing.T) {
	for name, check := range map[string]struct {
		script   string
		required []string
	}{
		"candidate workflow": {
			script: workflowRunStep(t, "../../.github/workflows/release.yml", "Derive exact version and gate"),
			required: []string{
				`version="${GITHUB_REF_NAME#v}"`,
				`(( ${#version} <= 128 ))`,
			},
		},
		"staging workflow": {
			script:   workflowRunStep(t, "../../.github/workflows/stage-release.yml", "Validate triggering tag and commit"),
			required: []string{`(( ${#TAG} <= 129 ))`},
		},
		"mirror workflow": {
			script:   workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Validate deployment configuration"),
			required: []string{`(( ${#TAG} <= 129 ))`},
		},
		"installer": {
			script: readReleaseFile(t, "../../scripts/install.sh"),
			required: []string{
				"MAX_RELEASE_VERSION_BYTES=128",
				`[ "${#release}" -le $((MAX_RELEASE_VERSION_BYTES + 1)) ]`,
				`[ "${#expected_version}" -le "$MAX_RELEASE_VERSION_BYTES" ]`,
			},
		},
		"trusted preparation": {
			script: readReleaseFile(t, "../../scripts/prepare-release.sh"),
			required: []string{
				"MAX_RELEASE_VERSION_BYTES=128",
				`(( ${#TAG} <= MAX_RELEASE_VERSION_BYTES + 1 ))`,
			},
		},
		"offline signing": {
			script: readReleaseFile(t, "../../scripts/offline-sign-release.sh"),
			required: []string{
				"MAX_RELEASE_VERSION_BYTES=128",
				`${#TAG} -le $((MAX_RELEASE_VERSION_BYTES + 1))`,
				`${#VERSION} -le $MAX_RELEASE_VERSION_BYTES`,
			},
		},
		"trusted publication": {
			script: readReleaseFile(t, "../../scripts/publish-release.sh"),
			required: []string{
				"MAX_RELEASE_VERSION_BYTES=128",
				`${#TAG} -le $((MAX_RELEASE_VERSION_BYTES + 1))`,
				`${#VERSION} -le $MAX_RELEASE_VERSION_BYTES`,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, required := range check.required {
				requireExecutableShellFragment(t, check.script, required)
			}
		})
	}
	document := readReleaseFile(t, "../../docs/releasing.md")
	for _, required := range []string{`[[ ${#TAG} -le 129 ]]`, `[[ ${#LTA_RELEASE_TAG} -le 129`} {
		if !strings.Contains(document, required) {
			t.Errorf("manual release procedures do not preserve %q", required)
		}
	}
}

func TestMirrorReleaseWorkflowPublishesVerifiedImmutableContentFailClosed(t *testing.T) {
	mirror := readReleaseFile(t, "../../.github/workflows/mirror-release.yml")
	installer := readReleaseFile(t, "../../scripts/install.sh")
	validateConfig := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Validate deployment configuration")
	requireImmutable := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Require an immutable public release")
	bindTag := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Bind signed tag and trusted release keyring")
	verifySignatures := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Verify checksums and ed25519 signatures")
	verifyBinaries := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Verify released binaries")
	configureSSH := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Configure pinned SSH identity")
	upload := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Upload immutable version without overwriting existing files")
	verifyPublic := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Verify immutable version through public mirror")
	publishStable := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Publish stable installer")
	manifest := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Publish latest manifest last")
	canary := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Install from the public mirror as a real root client")
	for _, required := range []string{
		"workflow_dispatch:",
		"group: linux-temp-admin-release-mirror-stable",
		"cancel-in-progress: false",
		"environment: release-mirror",
		"LTA_RELEASE_MIRROR_ENVIRONMENT_CONFIGURED",
		`TAG: ${{ inputs.tag }}`,
		"GH_HOST: github.com",
		"GH_PROMPT_DISABLED: '1'",
		"persist-credentials: false",
		"MIRROR_BASE_URL: https://dl.ll.cd/linux-temp-admin",
	} {
		if !strings.Contains(mirror, required) {
			t.Fatalf("mirror workflow is missing fail-closed publication guard %q", required)
		}
	}
	for _, check := range []struct {
		script   string
		required []string
	}{
		{validateConfig, []string{`[[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]]`, `[[ "$GITHUB_REF" == "refs/heads/$DEFAULT_BRANCH" ]]`, `$GITHUB_REPOSITORY/.github/workflows/mirror-release.yml@refs/heads/$DEFAULT_BRANCH`, `[[ "$GITHUB_SHA" == "$TRUSTED_WORKFLOW_SHA" ]]`}},
		{requireImmutable, []string{"timeout -k 5 60 gh api", ".immutable == true"}},
		{bindTag, []string{"GITHUB_RELEASE_ROOT=https://github.com/xxvcc/linux-temp-admin/releases"}},
		{verifySignatures, []string{"sha256sum -c --strict SHA256SUMS", "openssl pkeyutl -verify"}},
		{verifyBinaries, []string{"sudo --non-interactive --user=nobody", "/usr/bin/env -i HOME=/nonexistent"}},
		{configureSSH, []string{`[[ -d "$HOME/.ssh" && ! -L "$HOME/.ssh" ]]`, "-o BatchMode=yes", "StrictHostKeyChecking=yes"}},
		{upload, []string{"--ignore-existing", "--delay-updates"}},
		{verifyPublic, []string{`cmp "deploy/$TAG/$asset" "public-check/$asset"`}},
		{canary, []string{"INSTALLER_SHA256", "LTA_RELEASE=latest", "mirror canary used the GitHub transport fallback", "upgrade --yes --force", "self-upgrade canary used the GitHub transport fallback", "linux-temp-admin-mirror-canary-owned-$GITHUB_RUN_ID"}},
	} {
		for _, required := range check.required {
			requireExecutableShellFragment(t, check.script, required)
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
	checkoutPin := "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1"
	checkoutCount := 0
	for _, action := range workflowUses(t, "../../.github/workflows/mirror-release.yml") {
		if action == checkoutPin {
			checkoutCount++
		}
	}
	if checkoutCount != 2 {
		t.Fatal("mirror workflow checkout actions are not exactly pinned to the reviewed commit")
	}
	if countExecutableShellFragment(verifyPublic+"\n"+publishStable+"\n"+manifest+"\n"+canary, "--location --max-redirs 0") != 4 {
		t.Fatal("public mirror verification must reject redirects for every stable and versioned fetch")
	}

	uploadCommands := strings.Join(executableShellLines(upload), "\n")
	if trustCheck, write := strings.Index(uploadCommands, "git/ref/tags/$TAG"), strings.Index(uploadCommands, "rsync --archive"); trustCheck < 0 || write < 0 || trustCheck > write {
		t.Fatal("mirror workflow does not re-resolve the protected tag immediately before its first write")
	}

	manifestCommands := strings.Join(executableShellLines(manifest), "\n")
	latestCheck := strings.Index(manifestCommands, "releases/latest")
	manifestWrite := strings.Index(manifestCommands, "rsync --archive")
	publicCompare := strings.Index(manifestCommands, "cmp latest.json public-latest.json")
	if latestCheck < 0 || manifestWrite < 0 || publicCompare < 0 ||
		latestCheck > manifestWrite || manifestWrite > publicCompare {
		t.Fatal("latest.json is not atomically published after a final Latest check and before public comparison")
	}

	for _, expectedOutput := range []string{
		"downloaded the complete release set from the official mirror",
		"falling back to GitHub",
	} {
		requireExecutableShellFragment(t, installer, expectedOutput)
	}
}

func TestStageReleaseLookupRejectsEveryExistingDraftOrPublishedTag(t *testing.T) {
	step := workflowRunStep(t, "../../.github/workflows/stage-release.yml", "Create a new unsigned DRAFT release")
	start := strings.Index(step, "release_records=\"")
	endMarker := `ref_json="$(timeout -k 5 60 gh api "repos/${GH_REPO}/git/ref/tags/${TAG}")"`
	if start < 0 {
		t.Fatal("could not isolate staged-release absence check")
	}
	end := strings.Index(step[start:], endMarker)
	if end < 0 {
		t.Fatal("could not isolate staged-release absence check")
	}
	body := step[start : start+end]

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
printf '%b' "${MOCK_RELEASES-}"
exit "${MOCK_GH_STATUS:?}"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "lookup.sh")
	if err := os.WriteFile(script, []byte("#!/bin/bash\nset -Eeuo pipefail\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		status   int
		releases string
		ok       bool
	}{
		{name: "empty list", status: 0, ok: true},
		{name: "unrelated release", status: 0, releases: "v2.7.3\\t100\\n", ok: true},
		{name: "existing draft", status: 0, releases: "v2.8.0\\t101\\n"},
		{name: "duplicate matching tag", status: 0, releases: "v2.8.0\\t101\\nv2.8.0\\t102\\n"},
		{name: "zero id", status: 0, releases: "v2.7.3\\t0\\n"},
		{name: "extra field", status: 0, releases: "v2.7.3\\t100\\textra\\n"},
		{name: "api failure", status: 1},
		{name: "api timeout", status: 124},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = []string{
				"PATH=" + binDir + ":/usr/bin:/bin",
				fmt.Sprintf("MOCK_GH_STATUS=%d", tc.status),
				"MOCK_RELEASES=" + tc.releases,
				"GH_REPO=xxvcc/linux-temp-admin",
				"TAG=v2.8.0",
			}
			out, err := cmd.CombinedOutput()
			if tc.ok && err != nil {
				t.Fatalf("absent tag was rejected: %v\n%s", err, out)
			}
			if !tc.ok && err == nil {
				t.Fatalf("existing, malformed, or unverified state was accepted: %s", out)
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
		"enumerate_recovery_target() {",
		"expected_fallback_id=$fallback_id",
		"highest stable fallback changed during Latest recovery",
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
	if got := strings.Count(recovery, "\nenumerate_recovery_target\n"); got != 2 {
		t.Fatalf("manual Latest recovery enumerates stable Releases %d times, want 2", got)
	}
	if got := strings.Count(releasing, "read -r -s -p 'Short-lived github.com release token: ' GH_TOKEN </dev/tty"); got != 3 {
		t.Fatalf("release documentation has %d protected GH_TOKEN prompts, want 3", got)
	}
	const opener = "/bin/bash -p <<'LTA_LATEST_RECOVERY'\n"
	bodyStart := strings.Index(recovery, opener)
	if bodyStart < 0 {
		t.Fatal("manual Latest recovery heredoc opener is missing")
	}
	bodyStart += len(opener)
	bodyEnd := strings.Index(recovery[bodyStart:], "\nLTA_LATEST_RECOVERY\n")
	if bodyEnd < 0 {
		t.Fatal("manual Latest recovery heredoc terminator is missing")
	}
	cmd := exec.Command("/bin/bash", "-n")
	cmd.Stdin = strings.NewReader(recovery[bodyStart : bodyStart+bodyEnd])
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("manual Latest recovery block has invalid Bash syntax: %v\n%s", err, out)
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
		`timeout -k 5 30 sync "$stage"`,
		`timeout -k 5 30 sync "$DEST"`,
		`timeout -k 5 30 sync "$dest_dir"`,
		`sync_destination_directory_chain "$dest_dir"`,
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

func TestTransferOutputsAreDurableBeforeSuccess(t *testing.T) {
	for name, path := range map[string]string{
		"prepared": "../../scripts/prepare-release.sh",
		"signed":   "../../scripts/offline-sign-release.sh",
	} {
		content := readReleaseFile(t, path)
		hashCheck := strings.LastIndex(content, "exec sha256sum -c --strict")
		syncCall := strings.LastIndex(content, "sync_output_directory \"")
		complete := strings.LastIndex(content, "complete=1")
		if hashCheck < 0 || syncCall < hashCheck || complete < syncCall {
			t.Fatalf("%s transfer output is not synced after verification and before success", name)
		}
		for _, required := range []string{
			`local_with_timeout sync -- "$directory/$path"`,
			`local_with_timeout sync -- "$directory"`,
			`local_with_timeout sync -- "$parent"`,
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s transfer output misses durability operation %q", name, required)
			}
		}
	}

	installer := readReleaseFile(t, "../../scripts/install.sh")
	directoryCreate := strings.Index(installer, `mkdir -p -- "$dest_dir"`)
	directoryChainSync := strings.Index(installer, `sync_destination_directory_chain "$dest_dir"`)
	stageCreate := strings.Index(installer, `stage=$(mktemp "${dest_dir}/.linux-temp-admin.XXXXXX")`)
	commit := strings.Index(installer, `mv -fT -- "$stage" "$DEST"`)
	stageSync := strings.Index(installer, `timeout -k 5 30 sync "$stage"`)
	destinationSync := strings.Index(installer, `timeout -k 5 30 sync "$DEST"`)
	directorySync := strings.Index(installer, `timeout -k 5 30 sync "$dest_dir"`)
	success := strings.LastIndex(installer, `echo "installed ${DEST}`)
	if directoryCreate < 0 || directoryChainSync < directoryCreate ||
		stageCreate < directoryChainSync || stageSync < 0 || commit < stageSync || destinationSync < commit ||
		directorySync < destinationSync || success < directorySync {
		t.Fatal("custom installer destination is not synced around commit and before success")
	}
	for _, required := range []string{
		`timeout -k 5 30 sync "$sync_dir"`,
		`sync_dir=$(dirname -- "$sync_dir")`,
		`/ | //) break`,
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("custom installer directory-chain durability misses %q", required)
		}
	}
}
