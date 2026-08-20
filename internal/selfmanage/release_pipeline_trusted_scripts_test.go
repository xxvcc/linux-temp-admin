package selfmanage

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTrustedReleaseScriptsPinTemporaryDirectoryAndGitHubHost(t *testing.T) {
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	for name, content := range map[string]string{
		"offline": offline,
		"prepare": prepare,
		"publish": publish,
	} {
		commands := strings.Join(executableShellLines(content), "\n")
		for _, required := range []string{
			"require_trusted_tmp",
			`stat -Lc '%u %a' -- /tmp`,
			`"$tmp_uid" == 0`,
			`8#$tmp_mode & 8#7000) == 8#1000`,
		} {
			requireExecutableShellFragment(t, content, required)
		}
		if strings.Index(commands, "require_trusted_tmp") > strings.Index(commands, `mktemp -d /tmp/`) {
			t.Fatalf("%s validates /tmp only after creating its private snapshot", name)
		}
	}
	for name, content := range map[string]string{"prepare": prepare, "publish": publish} {
		commands := strings.Join(executableShellLines(content), "\n")
		requireExecutableShellFragment(t, content, "GH_HOST=github.com")
		requireExecutableShellFragment(t, content, "export PATH LC_ALL GIT_NO_REPLACE_OBJECTS GIT_NO_LAZY_FETCH GIT_TERMINAL_PROMPT")
		if strings.Index(commands, "GH_HOST=github.com") > strings.Index(commands, "gh_with_timeout api") {
			t.Fatalf("%s sets GH_HOST only after its first GitHub call", name)
		}
		requireExecutableShellFragment(t, content, `gh_with_timeout() {`)
		requireExecutableShellFragment(t, content, `timeout -k 5 300 gh "$@"`)
	}
	stage := readReleaseFile(t, "../../.github/workflows/stage-release.yml")
	if strings.Count(stage, "GH_HOST: github.com") != 2 {
		t.Fatal("trusted staging workflow does not pin github.com for every gh-bearing step")
	}
	createDraft := workflowRunStep(t, "../../.github/workflows/stage-release.yml", "Create a new unsigned DRAFT release")
	if strings.Count(stage, "GH_PROMPT_DISABLED: '1'") != 2 {
		t.Fatal("trusted staging workflow does not bound GitHub calls and fail closed on ambiguous release lookup")
	}
	requireExecutableShellFragment(t, createDraft, `timeout -k 5 600 gh release create`)
	requireExecutableShellFragment(t, createDraft, "could not prove release $TAG is absent")
	publishCommands := strings.Join(executableShellLines(publish), "\n")
	preflight := strings.Index(publishCommands, "for command_name in")
	firstMutation := -1
	for _, mutation := range []string{
		"gh_with_timeout api --method PATCH",
		"gh_with_timeout api --method POST",
		"gh_with_timeout api --method DELETE",
	} {
		index := strings.Index(publishCommands, mutation)
		if index >= 0 && (firstMutation < 0 || index < firstMutation) {
			firstMutation = index
		}
	}
	if preflight < 0 || firstMutation < 0 || preflight > firstMutation {
		t.Fatal("publisher command preflight does not precede its first remote mutation")
	}
	for _, command := range []string{"curl", "timeout", "sleep", "diff", "gh", "git"} {
		if !strings.Contains(publishCommands[preflight:firstMutation], command) {
			t.Fatalf("publisher does not preflight post-mutation command %q", command)
		}
	}
}

func TestTrustedReleaseScriptsBoundLocalCommands(t *testing.T) {
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	offline := readReleaseFile(t, "../../scripts/offline-sign-release.sh")
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	for _, content := range map[string]string{"prepare": prepare, "publish": publish} {
		for _, required := range []string{
			"GIT_NO_LAZY_FETCH=1",
			"GIT_TERMINAL_PROMPT=0",
			"GH_PROMPT_DISABLED=1",
			"git_with_timeout() {",
			"--batch --no-auto-key-retrieve",
		} {
			requireExecutableShellFragment(t, content, required)
		}
	}
	for _, required := range []string{`timeout -k 30 "$GO_BUILD_TIMEOUT_SECONDS"`, "MAX_SOURCE_ARCHIVE_BYTES=134217728", `git_with_timeout -C "$SOURCE_DIR" archive`} {
		requireExecutableShellFragment(t, prepare, required)
	}
	for _, content := range map[string]string{"prepare": prepare, "offline": offline} {
		for _, required := range []string{
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" mkdir -m 0700`,
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" chmod 0600`,
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" sha256sum`,
			`exec sha256sum -c --strict`,
		} {
			requireExecutableShellFragment(t, content, required)
		}
	}
	requireExecutableShellFragment(t, prepare, `bounded_copy "$prepared_work/$name" "$OUT_DIR/$name" "$limit"`)
	requireExecutableShellFragment(t, offline, `bounded_copy "$signed_work/$name" "$SIGNED_DIR/$name" "$limit"`)
	for _, content := range map[string]string{"offline": offline, "publish": publish} {
		for _, required := range []string{
			"signer_with_timeout() {",
			`timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS"`,
			`cp --reflink=never --sparse=never`,
		} {
			requireExecutableShellFragment(t, content, required)
		}
	}
	requireExecutableShellFragment(t, offline, "offline private key must be an absolute regular non-symlink file")
	if countExecutableShellFragment(publish, `"$trusted_signer" verify`) != 0 ||
		countExecutableShellFragment(publish, "signer_with_timeout verify") != 2 {
		t.Fatal("publisher has an unbounded verifier invocation")
	}
}

func shellRegion(t *testing.T, content, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(content, startMarker)
	if start < 0 {
		t.Fatalf("shell region start %q was not found", startMarker)
	}
	end := strings.Index(content[start:], endMarker)
	if end < 0 {
		t.Fatalf("shell region end %q was not found after %q", endMarker, startMarker)
	}
	return content[start : start+end]
}

func runFailedFileLimitFixture(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "file-limit.sh")
	fixture := `#!/bin/bash
set -Eeuo pipefail
ulimit() {
  printf 'limit\n' >> "$TEST_CALL_LOG"
  return 1
}
mark_writer() {
  printf 'writer\n' >> "$TEST_CALL_LOG"
  return 1
}
` + body + `
[[ -s "$TEST_CALL_LOG" ]]
if grep -Fqx writer "$TEST_CALL_LOG"; then
  echo "writer ran after the file-size limit failed" >&2
  exit 91
fi
[[ ! -e "$TEST_EXPECTED_OUTPUT" ]]
`
	if err := os.WriteFile(script, []byte(fixture), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(), "TEST_STATE="+dir, "TEST_CALL_LOG="+filepath.Join(dir, "calls"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("file-limit fixture failed: %v\n%s", err, out)
	}
}

func TestTrustedReleaseWritersStopWhenFileLimitCannotBeSet(t *testing.T) {
	prepare := readReleaseFile(t, "../../scripts/prepare-release.sh")
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")

	if got := strings.Count(prepare, `ulimit -f "$blocks" || exit 1`); got != 2 {
		t.Fatalf("prepare has %d fail-closed block limits, want 2", got)
	}
	if got := strings.Count(prepare, `ulimit -f "$source_blocks" || exit 1`); got != 1 {
		t.Fatalf("prepare has %d fail-closed source-archive limits, want 1", got)
	}
	if got := strings.Count(publish, `ulimit -f "$blocks" || exit 1`); got != 3 {
		t.Fatalf("publisher has %d fail-closed block limits, want 3", got)
	}
	for name, content := range map[string]string{"prepare": prepare, "publish": publish} {
		for _, unsafe := range []string{`ulimit -f "$blocks";`, `ulimit -f "$source_blocks";`} {
			if strings.Contains(content, unsafe) {
				t.Fatalf("%s still continues after a failed file-size limit: %s", name, unsafe)
			}
		}
	}

	prepareDownload := shellRegion(t, prepare, "download_draft_asset() {", "\ndownload_draft_asset linux-temp-admin-linux-amd64")
	publishDownload := extractPublisherFunction(t, "download_draft_asset", "replace_bound_draft_assets")
	archiveExport := shellRegion(t, prepare, `source_blocks=$(( (MAX_SOURCE_ARCHIVE_BYTES + 1023) / 1024 ))`, "\n[[ -s \"$source_archive\"")
	publicFetch := extractPublisherFunction(t, "public_fetch", "verify_public_set")

	t.Run("prepare draft download", func(t *testing.T) {
		runFailedFileLimitFixture(t, `
REPO=mock/repo
work="$TEST_STATE"
mkdir -p "$work/ci"
TEST_EXPECTED_OUTPUT="$work/ci/asset"
draft_assets=$'asset\t1\thttps://api.github.com/repos/mock/repo/releases/assets/1'
gh_with_timeout() { mark_writer; }
`+prepareDownload+`
if download_draft_asset asset 1024; then
  echo "prepare download ignored the failed file-size limit" >&2
  exit 90
fi
`)
	})

	t.Run("prepare source archive", func(t *testing.T) {
		runFailedFileLimitFixture(t, `
MAX_SOURCE_ARCHIVE_BYTES=134217728
SOURCE_DIR=/mock/source
tag_commit=deadbeef
source_archive="$TEST_STATE/source.tar"
TEST_EXPECTED_OUTPUT="$source_archive"
git_with_timeout() { mark_writer; }
if (
`+archiveExport+`
); then
  echo "source export ignored the failed file-size limit" >&2
  exit 90
fi
`)
	})

	t.Run("publisher draft download", func(t *testing.T) {
		runFailedFileLimitFixture(t, `
REPO=mock/repo
EXPECTED_RELEASE_ID=12345
TEST_EXPECTED_OUTPUT="$TEST_STATE/asset"
gh_with_timeout() {
  if [[ "$*" == *--paginate* ]]; then
    printf '1\thttps://api.github.com/repos/mock/repo/releases/assets/1\n'
    return 0
  fi
  mark_writer
}
`+publishDownload+`
if download_draft_asset asset 1024 "$TEST_EXPECTED_OUTPUT"; then
  echo "publisher draft download ignored the failed file-size limit" >&2
  exit 90
fi
`)
	})

	t.Run("publisher public download", func(t *testing.T) {
		runFailedFileLimitFixture(t, `
TEST_EXPECTED_OUTPUT="$TEST_STATE/public-asset"
timeout() { mark_writer; }
sleep() { :; }
`+publicFetch+`
if public_fetch https://example.test/asset "$TEST_EXPECTED_OUTPUT" 1024; then
  echo "public download ignored the failed file-size limit" >&2
  exit 90
fi
`)
	})
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
	if err := os.WriteFile(mockGo, []byte("#!/bin/sh\necho 'go version go1.26.6 linux/amd64'\nexit 23\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "gate-passed")
	script := filepath.Join(dir, "version-gate.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
GO_VERSION=go1.26.6
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
	guards := generatedReleaseSafetyBlock(t, offline)
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
	guards := generatedReleaseSafetyBlock(t, offline)
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
		`repos/${REPO}/releases?per_page=100`,
		`repos/${REPO}/releases/${EXPECTED_RELEASE_ID}`,
		"initial_release_state",
		"bind_initial_release",
		"readonly EXPECTED_RELEASE_ID RELEASE_WAS_DRAFT",
		"replace_bound_draft_assets",
		"publish_bound_release",
		"secure_failed_publication_state",
		"set_latest_by_release_id",
		"require_remote_asset_digests",
		"RESUMING_ALREADY_LATEST",
		"LATEST_PROMOTION_ATTEMPTED=1",
		"restore_latest_after_failed_promotion",
		"highest_stable_release_excluding",
		"require_latest_release_exact",
		"require_immutable_release",
		"HTTP/[0-9.]+ 404",
		"CRITICAL: automatic Latest restoration failed",
	} {
		if !strings.Contains(publish, required) {
			t.Fatalf("publisher resume/recovery path is missing %q", required)
		}
	}
	resume := strings.Index(publish, "resume exactly matching published release")
	upload := strings.Index(publish, "\n  replace_bound_draft_assets\n")
	if resume < 0 || upload < 0 || resume < upload {
		t.Fatal("published-release resume path is not separated from draft asset upload")
	}
	if strings.Count(publish, "require_immutable_release") != 4 {
		t.Fatal("publisher must define and enforce the immutable-Release gate before and after public verification")
	}
	immutableAfterPublish := strings.Index(publish, "\nif ! require_immutable_release; then")
	versionedVerification := strings.Index(publish, `echo ">> [publish 3/4] independently verify public versioned assets"`)
	promotionGate := strings.Index(publish, "\n    require_immutable_release\n    set_latest_by_release_id")
	latestVerification := strings.Index(publish, `verify_public_set "https://github.com/${REPO}/releases/latest/download"`)
	if immutableAfterPublish < 0 || versionedVerification < 0 || immutableAfterPublish > versionedVerification ||
		promotionGate < 0 || latestVerification < 0 || promotionGate > latestVerification {
		t.Fatal("publisher does not enforce immutable state before public fetching and Latest promotion")
	}
	if strings.Count(publish, `require_latest_release_exact "$TAG" "$EXPECTED_RELEASE_ID"`) != 2 {
		t.Fatal("publisher does not verify the promoted target's exact numeric Latest identity before and after Latest downloads")
	}
	for _, forbidden := range []string{
		"gh_with_timeout release upload",
		"gh_with_timeout release edit",
		"gh_with_timeout release delete",
		`--method PATCH "repos/${REPO}/releases/tags/`,
		`--method DELETE "repos/${REPO}/releases/tags/`,
		`--method POST "repos/${REPO}/releases/tags/`,
		"require_tag_release_identity",
	} {
		if strings.Contains(publish, forbidden) {
			t.Fatalf("publisher still performs a tag-addressed Release mutation: %q", forbidden)
		}
	}
	bind := strings.Index(publish, "\nbind_initial_release\nreadonly EXPECTED_RELEASE_ID RELEASE_WAS_DRAFT")
	baseline := strings.Index(publish, "\nBASELINE_HIGHEST_TAG=")
	if bind < 0 || baseline < 0 || bind > baseline {
		t.Fatal("publisher does not bind the numeric Release identity from its initial state before baseline checks")
	}
}

func TestPublisherDraftAssetReplacementIsRecoverableAndBound(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	start := strings.Index(publish, "remote_asset_names() {")
	end := strings.Index(publish[start:], "\nif [[ \"$TAG\" == *-* ]]")
	if start < 0 || end <= 0 {
		t.Fatal("could not isolate publisher draft-asset replacement functions")
	}
	functions := publish[start : start+end]

	const (
		checksums = "SHA256SUMS"
		amd64     = "linux-temp-admin-linux-amd64"
		amd64Sig  = "linux-temp-admin-linux-amd64.sig"
		arm64     = "linux-temp-admin-linux-arm64"
		arm64Sig  = "linux-temp-admin-linux-arm64.sig"
	)
	type replacementCase struct {
		name    string
		assets  []string
		wantOK  bool
		wantErr string
		failAt  int
	}
	tests := []replacementCase{
		{
			name:   "staged unsigned set",
			assets: []string{checksums, amd64, arm64},
			wantOK: true,
		},
		{
			name:   "resume after one core deletion",
			assets: []string{checksums, amd64, amd64Sig, arm64Sig},
			wantOK: true,
		},
		{
			name:   "resume after one signature deletion",
			assets: []string{checksums, amd64, amd64Sig, arm64},
			wantOK: true,
		},
		{
			name:    "reject partial unsigned set",
			assets:  []string{checksums, amd64},
			wantErr: "neither the staged set nor a recoverable one-asset interruption",
		},
		{
			name:    "reject two-asset deficit after signing began",
			assets:  []string{checksums, amd64, amd64Sig},
			wantErr: "neither the staged set nor a recoverable one-asset interruption",
		},
		{
			name:    "reject unexpected asset",
			assets:  []string{checksums, amd64, arm64, "untrusted-extra"},
			wantErr: "unexpected asset",
		},
		{
			name:    "reject duplicate asset name",
			assets:  []string{checksums, amd64, arm64, amd64},
			wantErr: "repeats an asset name or identity",
		},
	}
	exactAssets := []string{checksums, amd64, amd64Sig, arm64, arm64Sig}
	for failAt := 1; failAt <= 10; failAt++ {
		tests = append(tests, replacementCase{
			name:   fmt.Sprintf("resume exact set after ambiguous mutation %02d", failAt),
			assets: exactAssets,
			wantOK: true,
			failAt: failAt,
		})
	}
	for failAt := 1; failAt <= 2; failAt++ {
		tests = append(tests, replacementCase{
			name:   fmt.Sprintf("resume missing signatures after ambiguous upload %02d", failAt),
			assets: []string{checksums, amd64, arm64},
			wantOK: true,
			failAt: failAt,
		})
	}

	assertRecoverableRecords := func(t *testing.T, path string, wantExact bool) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		allowed := map[string]bool{
			checksums: true,
			amd64:     true,
			amd64Sig:  true,
			arm64:     true,
			arm64Sig:  true,
		}
		seenNames := make(map[string]bool)
		seenIDs := make(map[string]bool)
		coreCount := 0
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		for _, line := range lines {
			fields := strings.Split(line, "\t")
			if len(fields) != 3 || !allowed[fields[0]] || seenNames[fields[0]] || seenIDs[fields[1]] {
				t.Fatalf("unsafe residual draft asset record %q after ambiguous mutation", line)
			}
			seenNames[fields[0]] = true
			seenIDs[fields[1]] = true
			if fields[0] == checksums || fields[0] == amd64 || fields[0] == arm64 {
				coreCount++
			}
		}
		if !((len(seenNames) == 3 && coreCount == 3) || len(seenNames) == 4 || len(seenNames) == 5) {
			t.Fatalf("ambiguous mutation left a non-recoverable asset set: %s", data)
		}
		if wantExact && len(seenNames) != len(allowed) {
			t.Fatalf("resumed replacement left %d assets, want exact set of %d: %s", len(seenNames), len(allowed), data)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bundle := filepath.Join(dir, "bundle")
			if err := os.Mkdir(bundle, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{checksums, amd64, amd64Sig, arm64, arm64Sig} {
				if err := os.WriteFile(filepath.Join(bundle, name), []byte("signed "+name+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var records strings.Builder
			for i, name := range tt.assets {
				id := 100 + i
				fmt.Fprintf(&records, "%s\t%d\thttps://api.github.com/repos/mock/repo/releases/assets/%d\n", name, id, id)
			}
			if err := os.WriteFile(filepath.Join(dir, "records"), []byte(records.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "next-id"), []byte("1000"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "mutations"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "mutation-count"), []byte("0"), 0o600); err != nil {
				t.Fatal(err)
			}

			script := filepath.Join(dir, "replace-assets.sh")
			body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
EXPECTED_RELEASE_ID=12345
BUNDLE_DIR="$TEST_BUNDLE"
require_draft() { return 0; }
record_applied_mutation() {
  local count
  count="$(<"$TEST_STATE/mutation-count")"
  count=$((count + 1))
  printf '%s' "$count" > "$TEST_STATE/mutation-count"
  (( TEST_FAIL_AT == 0 || count != TEST_FAIL_AT ))
}
gh_with_timeout() {
  if [[ "$1" == api && "$2" == --paginate \
       && "$3" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}/assets?per_page=100" ]]; then
    case "$5" in
      '.[].name') cut -f1 "$TEST_STATE/records" ;;
      *'@tsv'*) cat "$TEST_STATE/records" ;;
      *) return 98 ;;
    esac
    return 0
  fi
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}" \
       && "$3" == --jq && "$4" == .upload_url ]]; then
    printf 'https://uploads.github.com/repos/%s/releases/%s/assets{?name,label}\n' \
      "$REPO" "$EXPECTED_RELEASE_ID"
    return 0
  fi
  if [[ "$1" == api && "$2" == --method && "$3" == DELETE ]]; then
    local id=${4##*/} before after
    printf 'DELETE %s\n' "$4" >> "$TEST_STATE/mutations"
    before="$(wc -l < "$TEST_STATE/records")"
    awk -F '\t' -v id="$id" '$2 != id' "$TEST_STATE/records" > "$TEST_STATE/records.next"
    after="$(wc -l < "$TEST_STATE/records.next")"
    [[ "$before" -eq $((after + 1)) ]] || return 97
    mv "$TEST_STATE/records.next" "$TEST_STATE/records"
	  record_applied_mutation || return $?
    return 0
  fi
  if [[ "$1" == api && "$2" == --method && "$3" == POST ]]; then
    local endpoint= input= arg name id size
    for arg in "$@"; do
      case "$arg" in
        https://uploads.github.com/*) endpoint=$arg ;;
      esac
    done
    for ((i=1; i <= $#; i++)); do
      if [[ "${!i}" == --input ]]; then
        i=$((i + 1))
        input=${!i}
        break
      fi
    done
    [[ "$endpoint" == "https://uploads.github.com/repos/${REPO}/releases/${EXPECTED_RELEASE_ID}/assets?name="* \
       && -f "$input" ]] || return 96
    name=${endpoint##*?name=}
    id="$(<"$TEST_STATE/next-id")"
    printf '%s' "$((id + 1))" > "$TEST_STATE/next-id"
    size="$(wc -c < "$input")"
    printf 'POST %s\n' "$endpoint" >> "$TEST_STATE/mutations"
    printf '%s\t%s\thttps://api.github.com/repos/%s/releases/assets/%s\n' \
      "$name" "$id" "$REPO" "$id" >> "$TEST_STATE/records"
	  record_applied_mutation || return $?
    printf '%s\t%s\t%s\thttps://api.github.com/repos/%s/releases/assets/%s\n' \
      "$id" "$name" "$size" "$REPO" "$id"
    return 0
  fi
  printf 'unexpected mock GitHub call: %q ' "$@" >&2
  return 99
}
	` + functions + `
if [[ "$TEST_WANT_OK" == true ]]; then
	require_recoverable_draft_assets
	replace_bound_draft_assets
	require_exact_signed_assets
else
	if require_recoverable_draft_assets; then
	  echo 'unsafe draft asset state passed the entry precheck' >&2
	  exit 89
	fi
	if replace_bound_draft_assets; then
	  echo 'unsafe draft asset state was accepted' >&2
    exit 90
  fi
  [[ ! -s "$TEST_STATE/mutations" ]]
fi
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			run := func(failAt int) ([]byte, error) {
				cmd := exec.Command("/bin/bash", script)
				cmd.Env = append(os.Environ(),
					"TEST_STATE="+dir,
					"TEST_BUNDLE="+bundle,
					"TEST_WANT_OK="+strconv.FormatBool(tt.wantOK),
					"TEST_FAIL_AT="+strconv.Itoa(failAt),
				)
				return cmd.CombinedOutput()
			}
			out, err := run(tt.failAt)
			if tt.failAt > 0 {
				if err == nil {
					t.Fatalf("ambiguous mutation %d unexpectedly completed: %s", tt.failAt, out)
				}
				assertRecoverableRecords(t, filepath.Join(dir, "records"), false)
				if writeErr := os.WriteFile(filepath.Join(dir, "mutation-count"), []byte("0"), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
				resumeOut, resumeErr := run(0)
				if resumeErr != nil {
					t.Fatalf("draft did not resume after ambiguous mutation %d: %v\nfirst run:\n%s\nresume:\n%s",
						tt.failAt, resumeErr, out, resumeOut)
				}
				assertRecoverableRecords(t, filepath.Join(dir, "records"), true)
				return
			}
			if tt.wantOK {
				if err != nil {
					t.Fatalf("recoverable draft asset replacement failed: %v\n%s", err, out)
				}
				mutations, readErr := os.ReadFile(filepath.Join(dir, "mutations"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				mutationLog := string(mutations)
				firstPOST := strings.Index(mutationLog, "POST ")
				firstDELETE := strings.Index(mutationLog, "DELETE ")
				if firstPOST < 0 || firstDELETE < 0 || firstPOST > firstDELETE {
					t.Fatalf("missing assets were not filled before destructive replacement:\n%s", mutationLog)
				}
				for _, line := range strings.Split(strings.TrimSpace(mutationLog), "\n") {
					if strings.HasPrefix(line, "POST ") && !strings.Contains(line, "/releases/12345/assets?name=") {
						t.Fatalf("asset upload escaped the bound Release ID: %s", line)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("fail-closed fixture did not handle rejection: %v\n%s", err, out)
				}
				if !strings.Contains(string(out), tt.wantErr) {
					t.Fatalf("draft rejection did not explain %q: %s", tt.wantErr, out)
				}
			}
		})
	}
}

func TestPublisherBindsInitialReleaseIdentity(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	start := strings.Index(publish, "initial_release_state() {")
	if start < 0 {
		t.Fatal("could not locate publisher initial Release state reader")
	}
	end := strings.Index(publish[start:], "\nrequire_remote_tag_object() {")
	if end < 0 {
		t.Fatal("could not isolate publisher initial Release identity binding")
	}
	initialGuards := publish[start : start+end]

	for _, tc := range []struct {
		name    string
		records string
		want    string
	}{
		{name: "mutable draft", records: "v2.8.0\ttrue\tfalse\tfalse\t12345", want: "1 12345\n"},
		{name: "immutable published release", records: "v2.8.0\tfalse\tfalse\ttrue\t12345", want: "0 12345\n"},
		{
			name: "unrelated releases do not hide unique draft",
			records: "v2.7.3\tfalse\tfalse\ttrue\t11111\n" +
				"v2.8.0\ttrue\tfalse\tfalse\t12345\n" +
				"v2.9.0-rc.1\tfalse\ttrue\ttrue\t22222",
			want: "1 12345\n",
		},
		{name: "mutable published release", records: "v2.8.0\tfalse\tfalse\tfalse\t12345"},
		{name: "immutable draft", records: "v2.8.0\ttrue\tfalse\ttrue\t12345"},
		{name: "no matching release", records: "v2.8.1\tfalse\tfalse\ttrue\t12345"},
		{name: "empty release list"},
		{name: "missing numeric identity", records: "v2.8.0\tfalse\tfalse\ttrue\tnull"},
		{name: "zero identity", records: "v2.8.0\tfalse\tfalse\ttrue\t0"},
		{
			name: "duplicate tag is ambiguous",
			records: "v2.8.0\ttrue\tfalse\tfalse\t12345\n" +
				"v2.8.0\tfalse\tfalse\ttrue\t67890",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := filepath.Join(t.TempDir(), "initial-release.sh")
			body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
expected_prerelease=false
gh_with_timeout() {
  [[ "$1" == api && "$2" == --paginate \
     && "$3" == "repos/${REPO}/releases?per_page=100" ]] || return 99
  printf '%s\n' "$TEST_RELEASE_RECORDS"
}
` + initialGuards + `
bind_initial_release
printf '%s %s\n' "$RELEASE_WAS_DRAFT" "$EXPECTED_RELEASE_ID"
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = append(os.Environ(), "TEST_RELEASE_RECORDS="+tc.records)
			out, err := cmd.CombinedOutput()
			if tc.want != "" {
				if err != nil || string(out) != tc.want {
					t.Fatalf("valid initial Release state was rejected: %v\n%s", err, out)
				}
			} else if err == nil {
				t.Fatalf("unsafe initial Release records %q were accepted: %s", tc.records, out)
			}
		})
	}

	t.Run("published-only tag endpoint is unnecessary and numeric identity remains fixed", func(t *testing.T) {
		script := filepath.Join(t.TempDir(), "draft-identity.sh")
		body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
expected_prerelease=false
printf 'v2.8.0\ttrue\tfalse\tfalse\t12345\n' > "$TEST_STATE/release-records"
printf 'v2.8.0 true false false 12345\n' > "$TEST_STATE/bound-state"
gh_with_timeout() {
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/tags/${TAG}" ]]; then
    printf 'HTTP 404: published release not found\n' >&2
    printf 'tag\n' >> "$TEST_STATE/calls"
    return 1
  fi
  if [[ "$1" == api && "$2" == --paginate \
       && "$3" == "repos/${REPO}/releases?per_page=100" ]]; then
    printf 'list\n' >> "$TEST_STATE/calls"
    cat "$TEST_STATE/release-records"
    return 0
  fi
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/12345" ]]; then
    printf 'bound\n' >> "$TEST_STATE/calls"
    cat "$TEST_STATE/bound-state"
    return 0
  fi
  return 99
}
` + initialGuards + `
if gh_with_timeout api "repos/${REPO}/releases/tags/${TAG}" >/dev/null 2>&1; then
  echo "published-only tag endpoint unexpectedly exposed the draft" >&2
  exit 98
fi
: > "$TEST_STATE/calls"
bind_initial_release
require_draft
grep -Fxq list "$TEST_STATE/calls"
grep -Fxq bound "$TEST_STATE/calls"
if grep -Fxq tag "$TEST_STATE/calls"; then
  echo "publisher depended on the published-only tag endpoint" >&2
  exit 97
fi
printf 'v2.8.0 true false false 67890\n' > "$TEST_STATE/bound-state"
require_draft
`
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/bash", script)
		cmd.Env = append(os.Environ(), "TEST_STATE="+filepath.Dir(script))
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "identity changed") {
			t.Fatalf("replacement draft Release identity was accepted: %v\n%s", err, out)
		}
	})
}

func TestPublisherRejectsMutableReleaseState(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	identityStart := strings.Index(publish, "initial_release_state() {")
	identityEnd := strings.Index(publish, "\nbind_initial_release() {")
	gateStart := strings.Index(publish, "require_immutable_release() {")
	if identityStart < 0 || identityEnd <= identityStart || gateStart < 0 {
		t.Fatal("could not locate publisher immutable-Release gate")
	}
	gateEnd := strings.Index(publish[gateStart:], "\n}\n")
	if gateEnd < 0 {
		t.Fatal("could not isolate publisher immutable-Release gate")
	}
	gate := publish[identityStart:identityEnd] + "\n" + publish[gateStart:gateStart+gateEnd+2]

	for _, tc := range []struct {
		name  string
		state string
		ok    bool
	}{
		{name: "expected immutable release", state: "v2.8.0 false false true 12345", ok: true},
		{name: "mutable release", state: "v2.8.0 false false false 12345"},
		{name: "draft release", state: "v2.8.0 true false true 12345"},
		{name: "wrong prerelease state", state: "v2.8.0 false true true 12345"},
		{name: "different tag", state: "v2.8.1 false false true 12345"},
		{name: "missing numeric identity", state: "v2.8.0 false false true null"},
		{name: "zero identity", state: "v2.8.0 false false true 0"},
		{name: "different numeric identity", state: "v2.8.0 false false true 67890"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := filepath.Join(t.TempDir(), "immutable-gate.sh")
			body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
expected_prerelease=false
EXPECTED_RELEASE_ID=12345
gh_with_timeout() {
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}" ]]; then
    printf '%s\n' "$TEST_RELEASE_STATE"
    return 0
  fi
  return 99
}
` + gate + `
require_immutable_release
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = append(os.Environ(), "TEST_RELEASE_STATE="+tc.state)
			out, err := cmd.CombinedOutput()
			if tc.ok && err != nil {
				t.Fatalf("immutable release was rejected: %v\n%s", err, out)
			}
			if !tc.ok && err == nil {
				t.Fatalf("unsafe release state %q was accepted", tc.state)
			}
		})
	}

	t.Run("release identity remains fixed", func(t *testing.T) {
		script := filepath.Join(t.TempDir(), "immutable-identity.sh")
		body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
expected_prerelease=false
EXPECTED_RELEASE_ID=12345
gh_with_timeout() {
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}" ]]; then
    printf '%s\n' "$TEST_RELEASE_STATE"
    return 0
  fi
  return 99
}
` + gate + `
TEST_RELEASE_STATE="v2.8.0 false false true 12345"
require_immutable_release
TEST_RELEASE_STATE="v2.8.0 false false true 67890"
require_immutable_release
`
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("/bin/bash", script).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "identity changed") {
			t.Fatalf("replacement Release identity was accepted: %v\n%s", err, out)
		}
	})
}

func TestPublisherMutationStaysBoundAfterTagReplacement(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	start := strings.Index(publish, "initial_release_state() {")
	if start < 0 {
		t.Fatal("could not locate bound publication functions")
	}
	end := strings.Index(publish[start:], "\nsecure_failed_publication_state() {")
	if end <= 0 {
		t.Fatal("could not isolate bound publication functions")
	}
	functions := publish[start : start+end]
	dir := t.TempDir()
	script := filepath.Join(dir, "bound-publication.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
expected_prerelease=false
EXPECTED_RELEASE_ID=12345
printf 'v2.8.0\ttrue\tfalse\tfalse\t12345\n' > "$TEST_STATE/release-records"
printf 'v2.8.0 true false false 12345\n' > "$TEST_STATE/bound-state"
gh_with_timeout() {
  printf '%q ' "$@" >> "$TEST_STATE/calls"
  printf '\n' >> "$TEST_STATE/calls"
  if [[ "$1" == api && "$2" == --paginate \
       && "$3" == "repos/${REPO}/releases?per_page=100" ]]; then
    printf 'list\n' >> "$TEST_STATE/tag-queries"
    cat "$TEST_STATE/release-records"
    return 0
  fi
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}" ]]; then
    cat "$TEST_STATE/bound-state"
    return 0
  fi
  if [[ "$1" == api && "$2" == --method && "$3" == PATCH ]]; then
    [[ "$4" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}" ]] || return 97
    printf 'v2.8.0 false false true 12345\n' > "$TEST_STATE/bound-state"
    printf 'v2.8.0 false false true 12345\n'
    return 0
  fi
  return 99
}
` + functions + `
printf 'v2.8.0\ttrue\tfalse\tfalse\t67890\n' > "$TEST_STATE/release-records"
publish_bound_release
require_immutable_release
grep -Fq 'api --method PATCH repos/mock/repo/releases/12345 ' "$TEST_STATE/calls"
if grep -Fq 'api --method PATCH repos/mock/repo/releases/67890 ' "$TEST_STATE/calls"; then
  echo "publication targeted replacement Release" >&2
  exit 91
fi
if grep -Fq 'api --paginate ' "$TEST_STATE/calls" || [[ -s "$TEST_STATE/tag-queries" ]]; then
  echo "publisher re-resolved the tag after binding the numeric Release ID" >&2
  exit 92
fi
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(), "TEST_STATE="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bound publication race guard failed: %v\n%s", err, out)
	}
}

func TestPublisherRollsMutablePublicationBackToBoundDraft(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	start := strings.Index(publish, "initial_release_state() {")
	if start < 0 {
		t.Fatal("could not locate mutable-publication rollback functions")
	}
	end := strings.Index(publish[start:], "\nresolve_published_stable_release_id() {")
	if end <= 0 {
		t.Fatal("could not isolate mutable-publication rollback functions")
	}
	functions := publish[start : start+end]
	dir := t.TempDir()
	script := filepath.Join(dir, "mutable-rollback.sh")
	body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.8.0
REPO=mock/repo
expected_prerelease=false
EXPECTED_RELEASE_ID=12345
printf 'v2.8.0 false false false 12345\n' > "$TEST_STATE/release-state"
printf 'v2.8.0\tfalse\tfalse\tfalse\t12345\n' > "$TEST_STATE/release-records"
gh_with_timeout() {
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}" ]]; then
    cat "$TEST_STATE/release-state"
    return 0
  fi
  if [[ "$1" == api && "$2" == --paginate \
       && "$3" == "repos/${REPO}/releases?per_page=100" ]]; then
    printf 'list\n' >> "$TEST_STATE/tag-queries"
    cat "$TEST_STATE/release-records"
    return 0
  fi
  if [[ "$1" == api && "$2" == --method && "$3" == PATCH ]]; then
    [[ "$4" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}" ]] || return 97
    [[ "$*" == *'-F draft=true'* && "$*" == *'-f make_latest=false'* ]] || return 96
    printf '%s\n' "$4" > "$TEST_STATE/write-endpoint"
    printf 'v2.8.0 true false false 12345\n' > "$TEST_STATE/release-state"
    cat "$TEST_STATE/release-state"
    return 0
  fi
  return 99
}
` + functions + `
secure_failed_publication_state
[[ "$(cat "$TEST_STATE/release-state")" == 'v2.8.0 true false false 12345' ]]
[[ "$(cat "$TEST_STATE/write-endpoint")" == 'repos/mock/repo/releases/12345' ]]

# If another Release takes over the tag mapping after an ambiguous publication,
# the original numeric Release must still be returned to draft without resolving
# or following that replacement mapping.
printf 'v2.8.0 false false false 12345\n' > "$TEST_STATE/release-state"
printf 'v2.8.0\ttrue\tfalse\tfalse\t67890\n' > "$TEST_STATE/release-records"
: > "$TEST_STATE/write-endpoint"
secure_failed_publication_state
[[ "$(cat "$TEST_STATE/release-state")" == 'v2.8.0 true false false 12345' ]]
[[ "$(cat "$TEST_STATE/write-endpoint")" == 'repos/mock/repo/releases/12345' ]]
[[ ! -s "$TEST_STATE/tag-queries" ]]
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(os.Environ(), "TEST_STATE="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mutable publication was not safely returned to the bound draft: %v\n%s", err, out)
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
	end := strings.Index(publish, "\nrequire_remote_tag_object() {")
	if start < 0 || end <= start {
		t.Fatal("could not isolate publisher Latest recovery functions")
	}
	recoveryFunctions := publish[start:end]

	tests := []struct {
		name                string
		stableTags          string
		stableAfterMutation string
		latestAfterMutation string
		initial             string
		expected            string
		apiMode             string
		mutableFallback     bool
		wantOK              bool
		wantErr             string
	}{
		{
			name:       "restore previous highest stable",
			stableTags: "v2.7.3\nv2.8.0\n",
			initial:    "v2.8.0 280",
			expected:   "v2.7.3 273",
			apiMode:    "404",
			wantOK:     true,
		},
		{
			name:       "restore concurrently published higher stable",
			stableTags: "v2.7.3\nv2.8.0\nv2.9.0\n",
			initial:    "v2.8.0 280",
			expected:   "v2.9.0 290",
			apiMode:    "404",
			wantOK:     true,
		},
		{
			name:                "detect higher stable published during restoration",
			stableTags:          "v2.7.3\nv2.8.0\n",
			stableAfterMutation: "v2.7.3\nv2.8.0\nv2.9.0\n",
			initial:             "v2.8.0 280",
			expected:            "v2.7.3 273",
			apiMode:             "404",
			wantOK:              false,
			wantErr:             "highest stable release changed during Latest restoration",
		},
		{
			name:                "reject same-tag replacement Release during restoration",
			stableTags:          "v2.7.3\nv2.8.0\n",
			latestAfterMutation: "v2.7.3 999",
			initial:             "v2.8.0 280",
			expected:            "v2.7.3 273",
			apiMode:             "404",
			wantOK:              false,
			wantErr:             "Latest restoration failed: Latest is v2.7.3 (999)",
		},
		{
			name:            "reject mutable fallback Release",
			stableTags:      "v2.7.3\nv2.8.0\n",
			initial:         "v2.8.0 280",
			apiMode:         "404",
			mutableFallback: true,
			wantOK:          false,
			wantErr:         "does not resolve to one published GitHub Release",
		},
		{
			name:       "clear Latest when no alternative exists",
			stableTags: "v2.8.0\n",
			initial:    "v2.8.0 280",
			expected:   "",
			apiMode:    "404",
			wantOK:     true,
		},
		{
			name:       "transport failure is not empty Latest",
			stableTags: "v2.8.0\n",
			initial:    "v2.8.0 280",
			expected:   "",
			apiMode:    "transport",
			wantOK:     false,
		},
		{
			name:       "mixed 404 and server error is not empty Latest",
			stableTags: "v2.8.0\n",
			initial:    "v2.8.0 280",
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
EXPECTED_RELEASE_ID=280
LOCAL_COMMAND_TIMEOUT_SECONDS=120
MAX_RELEASE_VERSION_BYTES=128
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
      read -r tag id extra < "$TEST_STATE/latest"
      [[ -z "$extra" && "$id" =~ ^[1-9][0-9]*$ ]] || return 95
      printf '%s\n' "$tag"
      return 0
    fi
    printf 'no latest release\n' >&2
    return 1
  fi
	if [[ "$1" == api && "$2" == repos/mock/repo/releases/latest ]]; then
	  [[ -s "$TEST_STATE/latest" ]] || return 1
	  read -r tag id extra < "$TEST_STATE/latest"
	  [[ -z "$extra" && "$id" =~ ^[1-9][0-9]*$ ]] || return 95
	  printf '%s false false true %s\n' "$tag" "$id"
	  return 0
	fi
  if [[ "$1" == api && "$2" == repos/mock/repo/releases/tags/* ]]; then
	  local tag=${2##*/} id immutable=true
    case "$tag" in
      v2.7.3) id=273 ;;
      v2.8.0) id=280 ;;
      v2.9.0) id=290 ;;
      *) return 97 ;;
    esac
	  if [[ "$TEST_MUTABLE_FALLBACK" == true && "$tag" != "$TAG" ]]; then
	    immutable=false
	  fi
	  printf '%s false false %s %s\n' "$tag" "$immutable" "$id"
    return 0
  fi
  if [[ "$1" == api && "$2" == --method && "$3" == PATCH ]]; then
    local id=${4##*/} tag arg
    case "$id" in
      273) tag=v2.7.3 ;;
      280) tag=v2.8.0 ;;
      290) tag=v2.9.0 ;;
      *) return 96 ;;
    esac
    for arg in "$@"; do
      case "$arg" in
		make_latest=true) printf '%s %s' "$tag" "$id" > "$TEST_STATE/latest" ;;
        make_latest=false) : > "$TEST_STATE/latest" ;;
      esac
    done
    if [[ -n "$TEST_STABLE_AFTER_MUTATION" ]]; then
      printf '%s' "$TEST_STABLE_AFTER_MUTATION" > "$TEST_STATE/stable"
    fi
	if [[ -n "$TEST_LATEST_AFTER_MUTATION" ]]; then
	  printf '%s' "$TEST_LATEST_AFTER_MUTATION" > "$TEST_STATE/latest"
	fi
    printf '%s false false true %s\n' "$tag" "$id"
    return 0
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
				"TEST_STABLE_AFTER_MUTATION="+tt.stableAfterMutation,
				"TEST_LATEST_AFTER_MUTATION="+tt.latestAfterMutation,
				"TEST_INITIAL_LATEST="+tt.initial,
				"TEST_EXPECTED_LATEST="+tt.expected,
				"TEST_API_MODE="+tt.apiMode,
				"TEST_MUTABLE_FALLBACK="+strconv.FormatBool(tt.mutableFallback),
			)
			out, err := cmd.CombinedOutput()
			if tt.wantOK && err != nil {
				t.Fatalf("mock recovery failed: %v\n%s", err, out)
			}
			if !tt.wantOK && err == nil {
				t.Fatalf("mock recovery unexpectedly succeeded: %s", out)
			}
			if tt.wantErr != "" && !strings.Contains(string(out), tt.wantErr) {
				t.Fatalf("mock recovery did not report %q: %v\n%s", tt.wantErr, err, out)
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
EXPECTED_RELEASE_ID=12345
BUNDLE_DIR="$TEST_BUNDLE"
gh() {
  [[ "$1" == api && "$2" == --paginate \
     && "$3" == "repos/${REPO}/releases/${EXPECTED_RELEASE_ID}/assets?per_page=100" ]] || return 99
  case "$*" in
    *'.[].name'*) printf '%s' "$TEST_ASSET_NAMES" ;;
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
	recoveryEnd := strings.Index(publish, "\nrequire_remote_tag_object() {")
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
EXPECTED_RELEASE_ID=280
LOCAL_COMMAND_TIMEOUT_SECONDS=120
MAX_RELEASE_VERSION_BYTES=128
work="$TEST_STATE/work"
mkdir -p "$work"
printf 'v2.7.3\nv2.8.0\n' > "$TEST_STATE/stable"
printf 'v2.8.0 280' > "$TEST_STATE/latest"
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
	if string(latest) != "v2.7.3 273" {
		t.Fatalf("EXIT trap restored Latest to %q, want v2.7.3 Release 273\n%s", latest, out)
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
	if !strings.Contains(string(out), "bounded-copy limit") {
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
