package selfmanage

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
	"unicode"
)

func TestDocumentedConvenienceBootstrapPolicy(t *testing.T) {
	const installPipeline = "curl -fsSL https://dl.ll.cd/linux-temp-admin/install.sh | /usr/bin/sudo /bin/sh"
	const readmeBootstrap = "set -o pipefail\n" + installPipeline + " &&\n" +
		"/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo"
	const releaseBootstrap = "set -o pipefail\n" + installPipeline

	documents := map[string]struct {
		path      string
		bootstrap string
		riskText  string
	}{
		"README.md": {
			path:      "../../README.md",
			bootstrap: readmeBootstrap,
			riskText:  "不认证脚本本身，也不能阻止已经收到的部分脚本开始执行",
		},
		"README.en.md": {
			path:      "../../README.en.md",
			bootstrap: readmeBootstrap,
			riskText:  "does not authenticate the script or stop an already received partial script from beginning execution",
		},
		"installing.md": {
			path:      "../../docs/installing.md",
			bootstrap: releaseBootstrap,
			riskText:  "不认证脚本本身，也不能阻止已经收到的部分脚本开始执行",
		},
		"installing.en.md": {
			path:      "../../docs/installing.en.md",
			bootstrap: releaseBootstrap,
			riskText:  "does not authenticate the script or stop an already received partial script from beginning execution",
		},
		"releasing.md": {
			path:      "../../docs/releasing.md",
			bootstrap: releaseBootstrap,
			riskText:  "does not authenticate the script",
		},
	}
	for name, document := range documents {
		content := readReleaseFile(t, document.path)
		if got := strings.Count(content, document.bootstrap); got != 1 {
			t.Errorf("%s convenience bootstrap count=%d, want 1", name, got)
		}
		if got := strings.Count(content, installPipeline); got != 1 {
			t.Errorf("%s streaming install pipeline count=%d, want 1", name, got)
		}
		if got := strings.Count(content, "curl -fsSL"); got != 1 {
			t.Errorf("%s curl -fsSL count=%d, want 1", name, got)
		}
		if !strings.Contains(content, document.riskText) {
			t.Errorf("%s does not disclose the streaming bootstrap trust boundary", name)
		}
		for _, forbidden := range []string{
			"| sudo sh",
			"https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh",
		} {
			if strings.Contains(content, forbidden) {
				t.Errorf("%s contains an unapproved convenience bootstrap form %q", name, forbidden)
			}
		}
	}

	t.Run("curl failure stops invite but cannot retract streamed bytes", func(t *testing.T) {
		dir := t.TempDir()
		binDir := filepath.Join(dir, "bin")
		if err := os.Mkdir(binDir, 0o700); err != nil {
			t.Fatal(err)
		}
		curlFixture := `#!/bin/sh
printf '%s\n' '#!/bin/sh' ': > "$TEST_INSTALLER_MARKER"'
exit 55
`
		if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte(curlFixture), 0o700); err != nil {
			t.Fatal(err)
		}
		installerMarker := filepath.Join(dir, "installer-ran")
		inviteMarker := filepath.Join(dir, "invite-ran")
		script := strings.Replace(readmeBootstrap, "/usr/bin/sudo /bin/sh", "/bin/sh", 1)
		script = strings.Replace(script,
			"/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo",
			`: > "$TEST_INVITE_MARKER"`, 1)
		cmd := exec.Command("/bin/bash", "-c", script)
		env := make([]string, 0, len(os.Environ())+3)
		for _, entry := range os.Environ() {
			if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "TEST_") {
				continue
			}
			env = append(env, entry)
		}
		cmd.Env = append(env,
			"PATH="+binDir+":"+os.Getenv("PATH"),
			"TEST_INSTALLER_MARKER="+installerMarker,
			"TEST_INVITE_MARKER="+inviteMarker,
		)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("convenience bootstrap succeeded after curl failure: %s", out)
		}
		if _, err := os.Stat(installerMarker); err != nil {
			t.Fatalf("partial streamed installer did not begin, test no longer exercises the documented risk: %v", err)
		}
		if _, err := os.Stat(inviteMarker); !os.IsNotExist(err) {
			t.Fatalf("invite ran after curl failure: %v", err)
		}
	})
}

func TestReadmesRemainFocusedUserEntrypoints(t *testing.T) {
	documents := []struct {
		name      string
		path      string
		required  []string
		forbidden []string
	}{
		{
			name: "README.md",
			path: "../../README.md",
			required: []string{
				"[安装、升级与下载验证](docs/installing.md)",
				"[管理员指南](docs/operator-guide.md)",
				"[安全模型](docs/security-model.md)",
			},
			forbidden: []string{
				"## 安装、升级与诊断", "### 写入的文件", "### 关于\"过期\"和\"自动删除\"",
				"--allow-non-tty-private-key-output", "--url-file", "Match all",
			},
		},
		{
			name: "README.en.md",
			path: "../../README.en.md",
			required: []string{
				"[Installation, upgrades, and download verification](docs/installing.en.md)",
				"[Operator guide](docs/operator-guide.en.md)",
				"[Security model](docs/security-model.en.md)",
			},
			forbidden: []string{
				"## Install, upgrade, and doctor", "### Files written", "### Expiry vs auto-delete",
				"--allow-non-tty-private-key-output", "--url-file", "Match all",
			},
		},
	}
	for _, document := range documents {
		t.Run(document.name, func(t *testing.T) {
			content := readReleaseFile(t, document.path)
			lines := strings.Count(content, "\n")
			if lines > 200 {
				t.Errorf("%s has %d lines; user entrypoint limit is 200", document.name, lines)
			}
			for _, required := range document.required {
				if !strings.Contains(content, required) {
					t.Errorf("%s is missing user-guide link %q", document.name, required)
				}
			}
			for _, forbidden := range document.forbidden {
				if strings.Contains(content, forbidden) {
					t.Errorf("%s absorbed advanced documentation %q", document.name, forbidden)
				}
			}
		})
	}

	for _, pair := range []struct {
		zhPath string
		enPath string
		zhLink string
		enLink string
	}{
		{"../../docs/installing.md", "../../docs/installing.en.md", "[English](installing.en.md)", "[中文](installing.md)"},
		{"../../docs/operator-guide.md", "../../docs/operator-guide.en.md", "[English](operator-guide.en.md)", "[中文](operator-guide.md)"},
		{"../../docs/security-model.md", "../../docs/security-model.en.md", "[English](security-model.en.md)", "[中文](security-model.md)"},
	} {
		zh := readReleaseFile(t, pair.zhPath)
		en := readReleaseFile(t, pair.enPath)
		if !strings.Contains(zh, pair.zhLink) || !strings.Contains(en, pair.enLink) {
			t.Errorf("bilingual document pair %s / %s lacks reciprocal navigation", pair.zhPath, pair.enPath)
		}
		zhLines := strings.Count(zh, "\n")
		enLines := strings.Count(en, "\n")
		if difference := zhLines - enLines; difference < -5 || difference > 5 {
			t.Errorf("bilingual document pair %s / %s drifted in structure: %d vs %d lines",
				pair.zhPath, pair.enPath, zhLines, enLines)
		}
	}
}

func TestUserDocumentationRelativeLinksResolve(t *testing.T) {
	headingSlugs := func(content string) map[string]bool {
		result := make(map[string]bool)
		inFence := false
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "```") {
				inFence = !inFence
				continue
			}
			if inFence {
				continue
			}
			if !strings.HasPrefix(line, "#") {
				continue
			}
			heading := strings.TrimSpace(strings.TrimLeft(line, "#"))
			var slug strings.Builder
			for _, character := range strings.ToLower(heading) {
				switch {
				case unicode.IsLetter(character), unicode.IsNumber(character), character == '-', character == '_':
					slug.WriteRune(character)
				case unicode.IsSpace(character):
					slug.WriteByte('-')
				}
			}
			result[slug.String()] = true
		}
		return result
	}
	documents := []string{
		"../../README.md",
		"../../README.en.md",
		"../../docs/installing.md",
		"../../docs/installing.en.md",
		"../../docs/operator-guide.md",
		"../../docs/operator-guide.en.md",
		"../../docs/security-model.md",
		"../../docs/security-model.en.md",
		"../../SECURITY.md",
	}
	for _, document := range documents {
		content := readReleaseFile(t, document)
		for lineNumber, line := range strings.Split(content, "\n") {
			remaining := line
			for {
				start := strings.Index(remaining, "](")
				if start < 0 {
					break
				}
				remaining = remaining[start+2:]
				end := strings.IndexByte(remaining, ')')
				if end < 0 {
					t.Fatalf("%s:%d has an unterminated Markdown link", document, lineNumber+1)
				}
				target := remaining[:end]
				remaining = remaining[end+1:]
				if target == "" || strings.HasPrefix(target, "#") ||
					strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://") ||
					strings.HasPrefix(target, "mailto:") {
					continue
				}
				parts := strings.SplitN(target, "#", 2)
				path := parts[0]
				if path == "" {
					continue
				}
				resolved := filepath.Clean(filepath.Join(filepath.Dir(document), path))
				targetContent, err := os.ReadFile(resolved)
				if err != nil {
					t.Errorf("%s:%d link target %q does not resolve: %v", document, lineNumber+1, target, err)
					continue
				}
				if len(parts) == 2 && parts[1] != "" && !headingSlugs(string(targetContent))[parts[1]] {
					t.Errorf("%s:%d link target %q has no matching heading", document, lineNumber+1, target)
				}
			}
		}
	}
}

func TestDocumentedHighAssuranceBootstrapRunsInsideSanitizedRootShell(t *testing.T) {
	documents := map[string]struct {
		path           string
		wantCurlCount  int
		wantSudoDirect int
	}{
		"releasing.md": {path: "../../docs/releasing.md", wantCurlCount: 1, wantSudoDirect: 0},
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
		if streamingRootShell {
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
			if strings.Contains(block, "raw.githubusercontent.com/xxvcc/linux-temp-admin/") {
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
	if len(highAssuranceBlocks) != 1 {
		t.Fatalf("releasing.md high-assurance bootstrap block count=%d, want 1", len(highAssuranceBlocks))
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
			body, err := heredocBody(highAssuranceBlocks[0])
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
