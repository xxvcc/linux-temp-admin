package selfmanage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func workflowRunStep(t *testing.T, path, wantName string) string {
	t.Helper()
	content := readReleaseFile(t, path)
	lines := strings.Split(content, "\n")
	inSteps := false
	stepName := ""
	for i, line := range lines {
		switch {
		case line == "    steps:":
			inSteps = true
		case inSteps && strings.HasPrefix(line, "      - name: "):
			stepName = strings.TrimPrefix(line, "      - name: ")
		case inSteps && stepName == wantName && line == "        run: |":
			var script strings.Builder
			for _, bodyLine := range lines[i+1:] {
				if bodyLine == "" {
					script.WriteByte('\n')
					continue
				}
				if !strings.HasPrefix(bodyLine, "          ") {
					break
				}
				script.WriteString(strings.TrimPrefix(bodyLine, "          "))
				script.WriteByte('\n')
			}
			if script.Len() == 0 {
				t.Fatalf("workflow step %q has an empty run block", wantName)
			}
			return script.String()
		}
	}
	t.Fatalf("workflow step %q was not found in %s", wantName, path)
	return ""
}

func workflowStepNames(t *testing.T, path string) []string {
	t.Helper()
	content := readReleaseFile(t, path)
	var names []string
	inSteps := false
	for _, line := range strings.Split(content, "\n") {
		if line == "    steps:" {
			inSteps = true
			continue
		}
		if inSteps && strings.HasPrefix(line, "      - name: ") {
			names = append(names, strings.TrimPrefix(line, "      - name: "))
		}
	}
	return names
}

func executableShellLines(script string) []string {
	var commands []string
	var continued strings.Builder
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || (continued.Len() == 0 && strings.HasPrefix(line, "#")) {
			continue
		}
		if continued.Len() > 0 {
			continued.WriteByte(' ')
		}
		continued.WriteString(strings.TrimSuffix(line, "\\"))
		if strings.HasSuffix(line, "\\") {
			continue
		}
		commands = append(commands, continued.String())
		continued.Reset()
	}
	if continued.Len() > 0 {
		commands = append(commands, continued.String())
	}
	return commands
}

func requireExecutableShellLine(t *testing.T, script, want string) {
	t.Helper()
	for _, command := range executableShellLines(script) {
		if command == want {
			return
		}
	}
	t.Fatalf("run block does not execute %q", want)
}

func requireExecutableShellFragment(t *testing.T, script, want string) {
	t.Helper()
	for _, command := range executableShellLines(script) {
		if strings.Contains(command, want) {
			return
		}
	}
	t.Fatalf("shell does not execute a command containing %q", want)
}

func countExecutableShellFragment(script, want string) int {
	count := 0
	for _, command := range executableShellLines(script) {
		if strings.Contains(command, want) {
			count++
		}
	}
	return count
}

func generatedReleaseSafetyBlock(t *testing.T, script string) string {
	t.Helper()
	const startMarker = "# BEGIN GENERATED RELEASE SAFETY PRIMITIVES\n"
	const endMarker = "# END GENERATED RELEASE SAFETY PRIMITIVES\n"
	start := strings.Index(script, startMarker)
	if start < 0 {
		t.Fatal("generated release safety block start was not found")
	}
	start += len(startMarker)
	end := strings.Index(script[start:], endMarker)
	if end < 0 {
		t.Fatal("generated release safety block end was not found")
	}
	return script[start : start+end]
}

func TestMirrorReleaseWorkflowKeepsPublicationStepsOrdered(t *testing.T) {
	names := workflowStepNames(t, "../../.github/workflows/mirror-release.yml")
	ordered := []string{
		"Upload immutable version without overwriting existing files",
		"Verify immutable version through public mirror",
		"Confirm GitHub Latest immediately before stable update",
		"Publish stable installer",
		"Publish latest manifest last",
		"Remove SSH identity",
	}
	previous := -1
	for _, want := range ordered {
		index := -1
		for i, name := range names {
			if name == want {
				index = i
				break
			}
		}
		if index <= previous {
			t.Fatalf("mirror publication step %q is absent or out of order", want)
		}
		previous = index
	}
}

type mirrorAssetFixture struct {
	name           string
	id             int
	body           []byte
	digest         string
	advertisedSize int64
	apiURL         string
}

func defaultMirrorAssetFixtures() []mirrorAssetFixture {
	fixtures := []mirrorAssetFixture{
		{name: "SHA256SUMS", id: 1001, body: []byte("checksums\n")},
		{name: "linux-temp-admin-linux-amd64", id: 1002, body: []byte("amd64 binary")},
		{name: "linux-temp-admin-linux-amd64.sig", id: 1003, body: bytes.Repeat([]byte{0x31}, 64)},
		{name: "linux-temp-admin-linux-arm64", id: 1004, body: []byte("arm64 binary")},
		{name: "linux-temp-admin-linux-arm64.sig", id: 1005, body: bytes.Repeat([]byte{0x32}, 64)},
	}
	for i := range fixtures {
		digest := sha256.Sum256(fixtures[i].body)
		fixtures[i].digest = "sha256:" + hex.EncodeToString(digest[:])
		fixtures[i].advertisedSize = int64(len(fixtures[i].body))
		fixtures[i].apiURL = fmt.Sprintf(
			"https://api.github.com/repos/xxvcc/linux-temp-admin/releases/assets/%d",
			fixtures[i].id,
		)
	}
	return fixtures
}

type mirrorDownloadResult struct {
	output         string
	downloadURLs   []string
	timeoutBudgets []int
	files          map[string][]byte
	err            error
}

func runMirrorDownloadStep(t *testing.T, script string, fixtures []mirrorAssetFixture) mirrorDownloadResult {
	t.Helper()
	return runMirrorDownloadStepWithOptions(t, script, fixtures, mirrorDownloadOptions{})
}

type mirrorDownloadOptions struct {
	slowAssetID        int
	slowAssetDelay     string
	failingAssetID     int
	traceTimeoutBudget bool
}

func runMirrorDownloadStepWithOptions(
	t *testing.T,
	script string,
	fixtures []mirrorAssetFixture,
	options mirrorDownloadOptions,
) mirrorDownloadResult {
	t.Helper()
	type apiAsset struct {
		Name   string `json:"name"`
		ID     int    `json:"id"`
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
		URL    string `json:"url"`
	}
	type apiRelease struct {
		ID        int        `json:"id"`
		Immutable bool       `json:"immutable"`
		Assets    []apiAsset `json:"assets"`
	}

	root := t.TempDir()
	work := filepath.Join(root, "work")
	mockBin := filepath.Join(root, "bin")
	assetDir := filepath.Join(root, "assets")
	for _, dir := range []string{work, mockBin, assetDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	release := apiRelease{ID: 777, Immutable: true}
	for _, fixture := range fixtures {
		release.Assets = append(release.Assets, apiAsset{
			Name: fixture.name, ID: fixture.id, Digest: fixture.digest,
			Size: fixture.advertisedSize, URL: fixture.apiURL,
		})
		if err := os.WriteFile(filepath.Join(assetDir, fmt.Sprint(fixture.id)), fixture.body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	releaseJSON, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	releasePath := filepath.Join(root, "release.json")
	if err := os.WriteFile(releasePath, releaseJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	downloadLog := filepath.Join(root, "downloads.log")
	timeoutLog := filepath.Join(root, "timeouts.log")
	ghMock := `#!/bin/bash
set -Eeuo pipefail
[[ "$1" == api ]]
if [[ "$2" == "repos/$GITHUB_REPOSITORY/releases/tags/$TAG" ]]; then
  exec /bin/cat "$TEST_RELEASE_JSON"
fi
endpoint="${!#}"
case "$endpoint" in
  https://api.github.com/repos/xxvcc/linux-temp-admin/releases/assets/*)
    asset_id="${endpoint##*/}"
    printf '%s\n' "$endpoint" >> "$TEST_DOWNLOAD_LOG"
    if [[ "$asset_id" == "$TEST_SLOW_ASSET_ID" ]]; then
      /bin/sleep "$TEST_SLOW_ASSET_DELAY"
    fi
    if [[ "$asset_id" == "$TEST_FAILING_ASSET_ID" ]]; then
      printf 'partial download'
      exit 42
    fi
    exec /bin/cat "$TEST_ASSET_DIR/$asset_id"
    ;;
esac
printf 'unexpected gh invocation:' >&2
printf ' %q' "$@" >&2
printf '\n' >&2
exit 97
`
	if err := os.WriteFile(filepath.Join(mockBin, "gh"), []byte(ghMock), 0o700); err != nil {
		t.Fatal(err)
	}
	if options.traceTimeoutBudget {
		timeoutMock := `#!/bin/bash
set -Eeuo pipefail
if [[ "$1" == -k ]]; then
  shift 2
fi
budget="$1"
shift
endpoint="${!#}"
if [[ "$1" == gh && "$endpoint" == https://api.github.com/repos/xxvcc/linux-temp-admin/releases/assets/* ]]; then
  printf '%s\n' "$budget" >> "$TEST_TIMEOUT_LOG"
fi
exec "$@"
`
		if err := os.WriteFile(filepath.Join(mockBin, "timeout"), []byte(timeoutMock), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	scriptPath := filepath.Join(work, "download.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}

	blocked := []string{"PATH=", "GITHUB_REPOSITORY=", "TAG=", "RELEASE_ID=", "TEST_"}
	env := make([]string, 0, len(os.Environ())+11)
	for _, entry := range os.Environ() {
		skip := false
		for _, prefix := range blocked {
			if strings.HasPrefix(entry, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			env = append(env, entry)
		}
	}
	env = append(env,
		"PATH="+mockBin+":"+os.Getenv("PATH"),
		"GITHUB_REPOSITORY=xxvcc/linux-temp-admin",
		"TAG=v2.10.3",
		"RELEASE_ID=777",
		"TEST_RELEASE_JSON="+releasePath,
		"TEST_DOWNLOAD_LOG="+downloadLog,
		"TEST_ASSET_DIR="+assetDir,
		"TEST_SLOW_ASSET_ID="+strconv.Itoa(options.slowAssetID),
		"TEST_SLOW_ASSET_DELAY="+options.slowAssetDelay,
		"TEST_FAILING_ASSET_ID="+strconv.Itoa(options.failingAssetID),
		"TEST_TIMEOUT_LOG="+timeoutLog,
	)
	cmd := exec.Command("/bin/bash", scriptPath)
	cmd.Dir = work
	cmd.Env = env
	output, runErr := cmd.CombinedOutput()

	var downloadURLs []string
	if logBytes, readErr := os.ReadFile(downloadLog); readErr == nil {
		downloadURLs = strings.Fields(string(logBytes))
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	var timeoutBudgets []int
	if logBytes, readErr := os.ReadFile(timeoutLog); readErr == nil {
		for _, field := range strings.Fields(string(logBytes)) {
			budget, parseErr := strconv.Atoi(field)
			if parseErr != nil {
				t.Fatalf("parse timeout budget %q: %v", field, parseErr)
			}
			timeoutBudgets = append(timeoutBudgets, budget)
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	files := make(map[string][]byte)
	rel := filepath.Join(work, "rel")
	if entries, readErr := os.ReadDir(rel); readErr == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() {
				body, fileErr := os.ReadFile(filepath.Join(rel, entry.Name()))
				if fileErr != nil {
					t.Fatal(fileErr)
				}
				files[entry.Name()] = body
			}
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return mirrorDownloadResult{
		output: string(output), downloadURLs: downloadURLs, timeoutBudgets: timeoutBudgets,
		files: files, err: runErr,
	}
}

func TestMirrorReleaseAssetDownloadsAreAuthenticatedAndBounded(t *testing.T) {
	script := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Download exact signed release assets")

	t.Run("valid exact assets", func(t *testing.T) {
		fixtures := defaultMirrorAssetFixtures()
		result := runMirrorDownloadStep(t, script, fixtures)
		if result.err != nil {
			t.Fatalf("bounded download step failed: %v\n%s", result.err, result.output)
		}
		if len(result.downloadURLs) != len(fixtures) {
			t.Fatalf("downloaded %d assets, want %d: %v", len(result.downloadURLs), len(fixtures), result.downloadURLs)
		}
		for index, fixture := range fixtures {
			if result.downloadURLs[index] != fixture.apiURL {
				t.Errorf("download %d used %q, want bound API URL %q", index, result.downloadURLs[index], fixture.apiURL)
			}
			if !bytes.Equal(result.files[fixture.name], fixture.body) {
				t.Errorf("downloaded bytes differ for %s", fixture.name)
			}
		}
	})

	for _, test := range []struct {
		name   string
		mutate func([]mirrorAssetFixture)
	}{
		{
			name: "oversized advertised binary",
			mutate: func(fixtures []mirrorAssetFixture) {
				fixtures[1].advertisedSize = 67108865
			},
		},
		{
			name: "missing authenticated digest",
			mutate: func(fixtures []mirrorAssetFixture) {
				fixtures[0].digest = ""
			},
		},
		{
			name: "asset URL not bound to identity",
			mutate: func(fixtures []mirrorAssetFixture) {
				fixtures[0].apiURL = "https://api.github.com/repos/other/project/releases/assets/1001"
			},
		},
		{
			name: "duplicate asset identity",
			mutate: func(fixtures []mirrorAssetFixture) {
				fixtures[1].id = fixtures[0].id
				fixtures[1].apiURL = fixtures[0].apiURL
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixtures := defaultMirrorAssetFixtures()
			test.mutate(fixtures)
			result := runMirrorDownloadStep(t, script, fixtures)
			if result.err == nil {
				t.Fatalf("invalid release metadata passed: %s", result.output)
			}
			if len(result.downloadURLs) != 0 || len(result.files) != 0 {
				t.Fatalf("metadata failure downloaded assets: urls=%v files=%v", result.downloadURLs, result.files)
			}
		})
	}

	t.Run("1024-byte ulimit blocks stop an oversized stream", func(t *testing.T) {
		fixtures := defaultMirrorAssetFixtures()
		fixtures[0].body = bytes.Repeat([]byte("x"), 1048577)
		digest := sha256.Sum256(fixtures[0].body)
		fixtures[0].digest = "sha256:" + hex.EncodeToString(digest[:])
		fixtures[0].advertisedSize = 1048576
		result := runMirrorDownloadStep(t, script, fixtures)
		if result.err == nil {
			t.Fatalf("oversized stream passed: %s", result.output)
		}
		if len(result.downloadURLs) != 1 || result.downloadURLs[0] != fixtures[0].apiURL {
			t.Fatalf("oversized stream did not use only its bound first asset URL: %v", result.downloadURLs)
		}
		if !strings.Contains(result.output, "bounded authenticated release download failed: SHA256SUMS") {
			t.Fatalf("oversized stream returned the wrong diagnostic: %s", result.output)
		}
		if len(result.files) != 0 {
			t.Fatalf("oversized stream left a downloadable file after failure: %v", result.files)
		}
	})

	t.Run("same-size body with a different digest is removed", func(t *testing.T) {
		fixtures := defaultMirrorAssetFixtures()
		fixtures[0].body = append([]byte(nil), fixtures[0].body...)
		fixtures[0].body[0] ^= 0xff
		result := runMirrorDownloadStep(t, script, fixtures)
		if result.err == nil {
			t.Fatalf("same-size digest mismatch passed: %s", result.output)
		}
		if len(result.downloadURLs) != 1 || result.downloadURLs[0] != fixtures[0].apiURL {
			t.Fatalf("digest mismatch did not stop after its bound first asset URL: %v", result.downloadURLs)
		}
		if !strings.Contains(result.output, "release asset digest changed during download: SHA256SUMS") {
			t.Fatalf("digest mismatch returned the wrong diagnostic: %s", result.output)
		}
		if len(result.files) != 0 {
			t.Fatalf("digest mismatch left its downloaded file behind: %v", result.files)
		}
	})

	t.Run("in-limit body that differs from advertised size is removed", func(t *testing.T) {
		fixtures := defaultMirrorAssetFixtures()
		fixtures[0].advertisedSize++
		result := runMirrorDownloadStep(t, script, fixtures)
		if result.err == nil {
			t.Fatalf("advertised size mismatch passed: %s", result.output)
		}
		if len(result.downloadURLs) != 1 || result.downloadURLs[0] != fixtures[0].apiURL {
			t.Fatalf("size mismatch did not stop after its bound first asset URL: %v", result.downloadURLs)
		}
		if !strings.Contains(result.output, "release asset size changed during download: SHA256SUMS") {
			t.Fatalf("size mismatch returned the wrong diagnostic: %s", result.output)
		}
		if len(result.files) != 0 {
			t.Fatalf("size mismatch left its downloaded file behind: %v", result.files)
		}
	})

	t.Run("slow downloads consume one shared budget and failed output is removed", func(t *testing.T) {
		fixtures := defaultMirrorAssetFixtures()
		result := runMirrorDownloadStepWithOptions(t, script, fixtures, mirrorDownloadOptions{
			slowAssetID:        fixtures[0].id,
			slowAssetDelay:     "1.2",
			failingAssetID:     fixtures[1].id,
			traceTimeoutBudget: true,
		})
		if result.err == nil {
			t.Fatalf("failing slow download passed: %s", result.output)
		}
		if len(result.downloadURLs) != 2 || result.downloadURLs[0] != fixtures[0].apiURL ||
			result.downloadURLs[1] != fixtures[1].apiURL {
			t.Fatalf("slow failure used unexpected asset URLs: %v", result.downloadURLs)
		}
		if len(result.timeoutBudgets) != 2 || result.timeoutBudgets[0] <= result.timeoutBudgets[1] {
			t.Fatalf("per-asset timeout budgets did not decrease: %v", result.timeoutBudgets)
		}
		if result.timeoutBudgets[0] > 300 || result.timeoutBudgets[1] <= 0 {
			t.Fatalf("per-asset timeout budgets escaped the shared 300-second bound: %v", result.timeoutBudgets)
		}
		if !strings.Contains(result.output, "bounded authenticated release download failed: linux-temp-admin-linux-amd64") {
			t.Fatalf("failing download returned the wrong diagnostic: %s", result.output)
		}
		if !bytes.Equal(result.files[fixtures[0].name], fixtures[0].body) {
			t.Fatalf("completed asset was not preserved after a later failure: %v", result.files)
		}
		if _, exists := result.files[fixtures[1].name]; exists {
			t.Fatalf("failed partial asset was not removed: %v", result.files)
		}
		if len(result.files) != 1 {
			t.Fatalf("slow failure left unexpected files: %v", result.files)
		}
	})
}

func markdownNumberedItem(t *testing.T, document string, number int) string {
	t.Helper()
	prefix := fmt.Sprintf("%d. ", number)
	lines := strings.Split(document, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		item := []string{strings.TrimPrefix(line, prefix)}
		for _, continuation := range lines[i+1:] {
			if continuation == "" || (len(continuation) > 0 && continuation[0] >= '0' && continuation[0] <= '9') {
				break
			}
			if !strings.HasPrefix(continuation, "   ") {
				break
			}
			item = append(item, strings.TrimSpace(continuation))
		}
		return strings.Join(item, " ")
	}
	t.Fatalf("Markdown item %d was not found", number)
	return ""
}

func TestMirrorRecoveryDocumentsAndEnforcesTrustMaterialBoundary(t *testing.T) {
	bind := workflowRunStep(t, "../../.github/workflows/mirror-release.yml", "Bind signed tag and trusted release keyring")
	requireExecutableShellLine(t, bind, "cmp scripts/install.sh released-source/scripts/install.sh")
	requireExecutableShellLine(t, bind, "cmp internal/selfmanage/release_pubkey.hex released-source/internal/selfmanage/release_pubkey.hex")

	document := readReleaseFile(t, "../../docs/releasing.md")
	recoveryStart := strings.Index(document, "Recovery is deliberately narrow:")
	if recoveryStart < 0 {
		t.Fatal("could not isolate documented mirror recovery procedure")
	}
	recoveryEnd := strings.Index(document[recoveryStart:], "An intentional emergency downgrade")
	if recoveryEnd < 0 {
		t.Fatal("could not isolate documented mirror recovery procedure")
	}
	recovery := document[recoveryStart : recoveryStart+recoveryEnd]
	itemOne := markdownNumberedItem(t, recovery, 1)
	for _, required := range []string{
		"scripts/install.sh", "internal/selfmanage/release_pubkey.hex", "byte-identical", "do not bypass either `cmp`",
	} {
		if !strings.Contains(itemOne, required) {
			t.Errorf("routine retry boundary is missing %q", required)
		}
	}
	itemFive := markdownNumberedItem(t, recovery, 5)
	for _, required := range []string{
		"separately reviewed incident change", "exact tag", "commit", "installer digest", "keyring digest",
	} {
		if !strings.Contains(itemFive, required) {
			t.Errorf("total-loss recovery boundary is missing %q", required)
		}
	}
	if strings.Contains(itemFive, "dispatch each required immutable tag") {
		t.Fatal("total-loss recovery still claims every historical tag is directly dispatchable")
	}
}

func extractPublisherFunction(t *testing.T, name, nextName string) string {
	t.Helper()
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	startMarker := name + "() {"
	endMarker := "\n" + nextName + "() {"
	start := strings.Index(publish, startMarker)
	if start < 0 {
		t.Fatalf("publisher function %s was not found", name)
	}
	end := strings.Index(publish[start:], endMarker)
	if end < 0 {
		t.Fatalf("could not isolate publisher function %s", name)
	}
	return publish[start : start+end]
}

func TestPublisherExactAssetGuardReturnsToItsCaller(t *testing.T) {
	guard := extractPublisherFunction(t, "require_exact_signed_assets", "require_remote_asset_digests")
	for _, test := range []struct {
		name string
		mock string
	}{
		{name: "mismatched names", mock: "remote_asset_names() { printf 'unexpected\\n'; }"},
		{name: "listing failure", mock: "remote_asset_names() { return 7; }"},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := "#!/bin/bash\nset -Eeuo pipefail\n" + test.mock + "\n" + guard + `
if require_exact_signed_assets; then
  echo "invalid asset listing passed" >&2
  exit 90
fi
printf 'caller recovered\n'
`
			path := filepath.Join(t.TempDir(), "guard.sh")
			if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("/bin/bash", path).CombinedOutput()
			if err != nil {
				t.Fatalf("asset guard exited instead of returning: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "caller recovered") {
				t.Fatalf("caller did not regain control: %s", out)
			}
		})
	}
}

func TestGeneratedReleaseSafetyPrimitivesAreCurrentAndSelfContained(t *testing.T) {
	cmd := exec.Command("python3", "-B", "../../scripts/sync-release-safety-primitives.py")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated release safety primitives are stale: %v\n%s", err, out)
	}
	allFunctions := []string{
		"local_with_timeout", "require_trusted_tmp", "require_safe_directory_path",
		"require_regular_file_path", "require_safe_file_path", "require_real_directory_path",
		"require_safe_source_repo", "require_safe_new_output_path", "bounded_copy", "sync_output_directory",
	}
	expected := map[string]map[string]bool{
		"../../scripts/prepare-release.sh": {
			"local_with_timeout": true, "require_trusted_tmp": true, "require_safe_directory_path": true,
			"require_safe_source_repo": true, "require_safe_new_output_path": true,
			"bounded_copy": true, "sync_output_directory": true,
		},
		"../../scripts/offline-sign-release.sh": {
			"local_with_timeout": true, "require_trusted_tmp": true, "require_safe_directory_path": true,
			"require_regular_file_path": true, "require_safe_file_path": true, "require_real_directory_path": true,
			"require_safe_new_output_path": true, "bounded_copy": true, "sync_output_directory": true,
		},
		"../../scripts/publish-release.sh": {
			"local_with_timeout": true, "require_trusted_tmp": true, "require_safe_directory_path": true,
			"require_regular_file_path": true, "require_safe_file_path": true, "require_real_directory_path": true,
			"require_safe_source_repo": true, "bounded_copy": true,
		},
	}
	for path, wanted := range expected {
		content := readReleaseFile(t, path)
		if strings.Contains(content, "release-safety-primitives.inc") {
			t.Errorf("%s loads the generation template at release runtime", path)
		}
		for _, function := range allFunctions {
			count := strings.Count(content, "\n"+function+"() {")
			want := 0
			if wanted[function] {
				want = 1
			}
			if count != want {
				t.Errorf("%s defines %s %d times, want %d", path, function, count, want)
			}
		}
	}
}

func TestGeneratedBoundedCopyStopsWhenFileLimitCannotBeSet(t *testing.T) {
	template := readReleaseFile(t, "../../scripts/release-safety-primitives.inc")
	start := strings.Index(template, "bounded_copy() {")
	if start < 0 {
		t.Fatal("bounded_copy template function was not found")
	}
	end := strings.Index(template[start:], "\n# END COMPONENT bounded_copy")
	if end < 0 {
		t.Fatal("could not isolate bounded_copy template function")
	}
	boundedCopy := template[start : start+end]
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "destination")
	if err := os.WriteFile(source, []byte("must not be copied"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
set -Eeuo pipefail
LOCAL_COMMAND_TIMEOUT_SECONDS=30
local_with_timeout() { "$@"; }
ulimit() { return 1; }
` + boundedCopy + `
if bounded_copy "$TEST_SOURCE" "$TEST_DESTINATION" 1048576; then
  echo "bounded_copy ignored a failed file-size limit" >&2
  exit 90
fi
[[ ! -e "$TEST_DESTINATION" ]]
`
	path := filepath.Join(dir, "bounded-copy.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", path)
	cmd.Env = append(os.Environ(), "TEST_SOURCE="+source, "TEST_DESTINATION="+destination)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bounded_copy did not fail closed when ulimit failed: %v\n%s", err, out)
	}
}
