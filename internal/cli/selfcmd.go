package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

const procSelfExe = "/proc/self/exe"

// Two maximum-length URLs plus their line terminators must fit. The parser
// accepts a missing final newline as well.
const maxUpgradeURLFileBytes = int64(2*2048 + 2)

// readRunningBinary reads the inode this process is executing, not the mutable
// pathname it was launched through. Executable exists only to point tests at a
// fixture; production leaves it nil and uses Linux's stable /proc handle.
func (a *App) readRunningBinary() ([]byte, error) {
	path := procSelfExe
	if a.Executable != nil {
		var err error
		path, err = a.Executable()
		if err != nil {
			return nil, fmt.Errorf("locate test executable: %w", err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	maxBytes := int64(config.MaxUpgradeBytes)
	if a.Selfmanage != nil && a.Selfmanage.MaxBytes > 0 {
		maxBytes = a.Selfmanage.MaxBytes
	}
	bin, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(bin)) > maxBytes {
		return nil, fmt.Errorf("running binary exceeds %d-byte install limit", maxBytes)
	}
	return bin, nil
}

func (a *App) install(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var force bool
	fs.BoolVar(&force, "force", false, "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	return a.withLifecycleLockAllowUninstalled(func() int { return a.installLocked(force) })
}

func (a *App) installLocked(force bool) int {
	bin, err := a.readRunningBinary()
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法读取当前运行程序", "cannot read the running binary"), err)
		return 1
	}
	wasUninstalled := false
	if a.Lifecycle != nil {
		wasUninstalled, err = a.Lifecycle.IsUninstalled()
		if err != nil {
			a.errorf("%s: %v", a.P.M("无法验证卸载状态，拒绝安装", "cannot verify uninstall state; refusing to install"), err)
			return 1
		}
	}
	installed, err := a.Selfmanage.Install(bin, force)
	if err != nil {
		if installed {
			a.errorf("%s: %v", a.P.M("命令已替换，但无法确认该替换已持久化", "the command was replaced, but the replacement's durability is unknown"), err)
			a.audit("install", "", "fail", "command replaced but durability unknown: "+err.Error(), nil)
		} else {
			a.errorf("%v", err)
			a.audit("install", "", "fail", "install failed before replacement: "+err.Error(), nil)
		}
		return 1
	}
	if a.Lifecycle != nil && wasUninstalled {
		if err := a.Lifecycle.ClearUninstalled(); err != nil {
			a.errorf("%s: %v", a.P.M("命令已安装，但无法清除卸载状态标记", "the command is installed, but the uninstall-state marker could not be cleared"), err)
			a.audit("install", "", "fail", "installed but uninstall marker cleanup failed: "+err.Error(), nil)
			return 1
		}
	}
	if !installed {
		if wasUninstalled {
			a.audit("install", "", "ok", "existing stable command reactivated", nil)
			a.success(a.P.M("已重新启用稳定命令："+a.InstallPath, "reactivated the stable command: "+a.InstallPath))
			return 0
		}
		// The running binary already *is* the stable command. Saying "installed"
		// here would claim a privileged write that never happened -- and would put
		// a matching lie in the audit log.
		a.info(a.P.M("已是稳定命令，无需安装："+a.InstallPath,
			"already the stable command; nothing to install: "+a.InstallPath))
		return 0
	}
	a.audit("install", "", "ok", a.InstallPath, nil)
	a.success(a.P.M("已安装稳定命令："+a.InstallPath, "installed the stable command: "+a.InstallPath))
	return 0
}

func (a *App) upgrade(args []string) int {
	return a.upgradeResult(args).status
}

func (a *App) upgradeResult(args []string) commandResult {
	if !a.requireRoot() {
		return statusResult(1)
	}
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	// Flag diagnostics can quote a malformed argument verbatim. Upgrade arguments
	// may be mistaken secret URLs, so emit only our fixed diagnostics below.
	fs.SetOutput(io.Discard)
	urlFlag := fs.String("url", "", "")
	urlFileFlag := fs.String("url-file", "", "")
	var force, yes bool
	fs.BoolVar(&force, "force", false, "")
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	if err := fs.Parse(args); err != nil {
		a.errorf("%s", a.P.M("升级参数不合法", "invalid upgrade options"))
		return statusResult(1)
	}
	if fs.NArg() != 0 {
		a.errorf("%s", a.P.M("upgrade 不接受位置参数", "upgrade does not accept positional arguments"))
		return statusResult(1)
	}
	if *urlFlag != "" && *urlFileFlag != "" {
		a.errorf("%s", a.P.M("--url 与 --url-file 不能同时使用", "--url and --url-file are mutually exclusive"))
		return statusResult(1)
	}
	if *urlFlag != "" && !safeCommandLineUpgradeURL(*urlFlag) {
		a.errorf("%s", a.P.M(
			"--url 只接受不含用户信息、查询参数或片段的非敏感 URL；含凭据或令牌时请使用 --url-file",
			"--url accepts only non-secret URLs without userinfo, query parameters, or fragments; use --url-file for credentials or tokens"))
		return statusResult(1)
	}
	customURL := *urlFlag != "" || *urlFileFlag != ""
	binURL := *urlFlag
	sigURL := ""
	if *urlFileFlag != "" {
		urls, err := readUpgradeURLFile(*urlFileFlag)
		if err != nil {
			a.errorf("%s: %v", a.P.M("无法读取升级 URL 文件", "cannot read upgrade URL file"), err)
			return statusResult(1)
		}
		binURL, sigURL = urls.binary, urls.signature
	}
	if customURL {
		if err := validUpgradeURL(binURL); err != nil {
			a.errorf("%s: %v", a.P.M("升级 URL 不合法", "invalid upgrade URL"), err)
			return statusResult(1)
		}
		if sigURL == "" {
			var err error
			sigURL, err = detachedSignatureURL(binURL)
			if err != nil {
				a.errorf("%s: %v", a.P.M("升级 URL 不合法", "invalid upgrade URL"), err)
				return statusResult(1)
			}
		} else if err := validUpgradeURL(sigURL); err != nil {
			a.errorf("%s: %v", a.P.M("签名 URL 不合法", "invalid signature URL"), err)
			return statusResult(1)
		}
	}

	if !yes {
		if customURL {
			displayBinURL := selfmanage.RedactedURL(binURL)
			displaySigURL := selfmanage.RedactedURL(sigURL)
			a.printf("%s\n  %s\n  %s", a.P.M("将下载并验签后升级：", "will download, verify, and upgrade from:"), displayBinURL, displaySigURL)
		} else {
			a.printf("%s\n  %s\n  %s", a.P.M(
				"将优先从官方镜像下载并验签，传输失败时回退 GitHub：",
				"will download and verify from the official mirror, with GitHub as a transport fallback:"),
				config.ReleaseMirrorBaseURL, config.GitHubReleaseRoot)
		}
		if a.prompt(a.P.M("确认请输入 YES: ", "type YES to confirm: ")) != "YES" {
			a.warnf("%s", a.P.M("已取消", "cancelled"))
			return statusResult(0)
		}
	}
	var candidate *selfmanage.UpgradeCandidate
	var err error
	if customURL {
		candidate, err = a.Selfmanage.PrepareUpgrade(binURL, sigURL)
	} else {
		candidate, err = a.prepareOfficialUpgrade()
	}
	if err != nil {
		a.errorf("%s: %v", a.P.M("升级失败", "upgrade failed"), err)
		a.audit("upgrade", "", "fail", "upgrade preparation failed before replacement: "+err.Error(), nil)
		return statusResult(1)
	}
	result := commandResult{}
	result.status = a.withLifecycleLock(func() int {
		result = a.upgradePreparedLocked(candidate, force)
		return result.status
	})
	return result
}

func (a *App) prepareOfficialUpgrade() (*selfmanage.UpgradeCandidate, error) {
	asset := config.BinaryAssetPrefix + runtime.GOARCH
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, fmt.Errorf("official releases do not support architecture %s", runtime.GOARCH)
	}
	manifest, err := a.Selfmanage.FetchReleaseManifest(
		config.ReleaseMirrorManifestURL, config.ReleaseMirrorBaseURL)
	if err != nil {
		if !selfmanage.IsTransportFailure(err) {
			return nil, fmt.Errorf("official mirror manifest failed validation: %w", err)
		}
		a.warnf("%s", a.P.M(
			"官方镜像索引传输失败，正在回退 GitHub。",
			"official mirror index transfer failed; falling back to GitHub."))
		return a.Selfmanage.PrepareReleaseUpgrade(
			config.GitHubLatestReleaseBaseURL, asset, "")
	}
	candidate, err := a.Selfmanage.PrepareMirrorReleaseUpgrade(manifest.BaseURL, asset, manifest.Version)
	if err == nil {
		a.info(a.P.M("已通过官方镜像下载并验签。", "downloaded and verified through the official mirror."))
		return candidate, nil
	}
	if !selfmanage.IsTransportFailure(err) {
		return nil, fmt.Errorf("official mirror release failed verification: %w", err)
	}
	a.warnf("%s", a.P.M(
		"官方镜像版本资产传输不完整，正在从 GitHub 重新下载同一版本。",
		"official mirror release transfer was incomplete; downloading the same version again from GitHub."))
	githubBase := config.GitHubReleaseRoot + "/download/" + manifest.Tag
	return a.Selfmanage.PrepareReleaseUpgrade(githubBase, asset, manifest.Version)
}

func safeCommandLineUpgradeURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

type upgradeURLs struct {
	binary    string
	signature string
}

// readUpgradeURLFile keeps credentials and signed query values out of argv,
// shell history, sudo logs, and /proc. The first line is the binary URL; an
// optional second line is an independently signed signature URL. With one line,
// the signature URL is derived by appending .sig to the binary path. The file
// itself must be a root-only regular non-symlink; O_NONBLOCK makes special-file
// mistakes fail fast.
func readUpgradeURLFile(path string) (upgradeURLs, error) {
	if !filepath.IsAbs(path) {
		return upgradeURLs{}, errors.New("path must be absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return upgradeURLs{}, errors.New("open failed")
	}
	f := os.NewFile(uintptr(fd), "upgrade-url")
	if f == nil {
		_ = unix.Close(fd)
		return upgradeURLs{}, errors.New("open failed")
	}
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return upgradeURLs{}, errors.New("metadata check failed")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() || st.Mode&0o7777 != 0o600 {
		return upgradeURLs{}, errors.New("file must be an owner-owned regular non-symlink with mode 0600")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxUpgradeURLFileBytes+1))
	if err != nil {
		return upgradeURLs{}, errors.New("read failed")
	}
	if int64(len(b)) > maxUpgradeURLFileBytes {
		return upgradeURLs{}, errors.New("file is too large")
	}
	content := string(b)
	content = strings.TrimSuffix(content, "\n")
	lines := strings.Split(content, "\n")
	if len(lines) < 1 || len(lines) > 2 {
		return upgradeURLs{}, errors.New("file must contain one binary URL and at most one signature URL")
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
		if lines[i] == "" || strings.ContainsRune(lines[i], '\r') || strings.TrimSpace(lines[i]) != lines[i] {
			return upgradeURLs{}, errors.New("each URL must occupy one non-empty line without surrounding whitespace")
		}
	}
	urls := upgradeURLs{binary: lines[0]}
	if len(lines) == 2 {
		urls.signature = lines[1]
	}
	return urls, nil
}

func validUpgradeURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("malformed URL syntax")
	}
	if !validate.UpgradeURL(rawURL) || u.Scheme != "https" ||
		u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return errors.New("URL must be a valid HTTPS URL of at most 2048 bytes")
	}
	return nil
}

// detachedSignatureURL adds .sig to the binary URL's path, not to its complete
// serialized form. Authentication query parameters and fragments therefore
// remain attached to the signature request instead of becoming part of the
// binary path ("?token=...sig").
func detachedSignatureURL(binaryURL string) (string, error) {
	u, err := url.Parse(binaryURL)
	if err != nil {
		// net/url parse errors quote the complete input. The value may carry basic
		// auth or a signed query, so never propagate that text to the terminal.
		return "", errors.New("malformed URL syntax")
	}
	u.Path += ".sig"
	if u.RawPath != "" {
		u.RawPath += ".sig"
	}
	return u.String(), nil
}

func (a *App) upgradePreparedLocked(candidate *selfmanage.UpgradeCandidate, force bool) commandResult {
	previous := ""
	if v, err := a.Selfmanage.InstalledVersion(); err == nil {
		previous = v
	} else if !errors.Is(err, selfmanage.ErrNotInstalled) {
		previous = "unknown"
	}
	newVer, err := a.Selfmanage.ApplyUpgrade(candidate, force)
	if err != nil {
		var durability *fsutil.DurabilityError
		if newVer != "" && errors.As(err, &durability) {
			a.errorf("%s: %v", a.P.M("命令已替换，但无法确认升级已持久化", "the command was replaced, but the upgrade's durability is unknown"), err)
			a.audit("upgrade", "", "fail", versionTransition(previous, newVer)+" visible but durability unknown: "+err.Error(), nil)
		} else {
			a.errorf("%s: %v", a.P.M("升级失败", "upgrade failed"), err)
			a.audit("upgrade", "", "fail", "upgrade failed before replacement: "+err.Error(), nil)
		}
		return statusResult(1)
	}
	if newVer == "" {
		current, probeErr := a.Selfmanage.InstalledVersion()
		if probeErr != nil {
			current = buildinfo.Version
		}
		a.success(a.P.M("已是最新版本："+current, "already up to date: "+current))
		return statusResult(0)
	}
	a.audit("upgrade", "", "ok", versionTransition(previous, newVer), nil)
	a.success(a.P.M("已升级到 "+newVer, "upgraded to "+newVer))
	return commandResult{applied: true}
}

func versionTransition(previous, next string) string {
	if previous == "" {
		previous = "not installed"
	}
	return previous + " -> " + next
}
