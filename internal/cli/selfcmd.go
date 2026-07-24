package cli

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
)

const procSelfExe = "/proc/self/exe"

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
	bin, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
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
	return a.withLifecycleLock(func() int { return a.installLocked(force) })
}

func (a *App) installLocked(force bool) int {
	bin, err := a.readRunningBinary()
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法读取当前运行程序", "cannot read the running binary"), err)
		return 1
	}
	installed, err := a.Selfmanage.Install(bin, force)
	if err != nil {
		a.errorf("%v", err)
		return 1
	}
	if !installed {
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
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	urlFlag := fs.String("url", "", "")
	var force, yes bool
	fs.BoolVar(&force, "force", false, "")
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	binURL := *urlFlag
	if binURL == "" {
		binURL = config.ReleaseBaseURL + config.BinaryAssetPrefix + runtime.GOARCH
	}
	sigURL := binURL + ".sig"

	if !yes {
		a.printf("%s\n  %s\n  %s", a.P.M("将下载并验签后升级：", "will download, verify, and upgrade from:"), binURL, sigURL)
		if a.prompt(a.P.M("确认请输入 YES: ", "type YES to confirm: ")) != "YES" {
			a.warnf("%s", a.P.M("已取消", "cancelled"))
			return 0
		}
	}
	return a.withLifecycleLock(func() int {
		return a.upgradeLocked(binURL, sigURL, force)
	})
}

func (a *App) upgradeLocked(binURL, sigURL string, force bool) int {
	newVer, err := a.Selfmanage.Upgrade(binURL, sigURL, buildinfo.Version, force)
	if err != nil {
		a.errorf("%s: %v", a.P.M("升级失败", "upgrade failed"), err)
		return 1
	}
	if newVer == "" {
		a.success(a.P.M("已是最新版本："+buildinfo.Version, "already up to date: "+buildinfo.Version))
		return 0
	}
	a.audit("upgrade", "", "ok", buildinfo.Version+" -> "+newVer, nil)
	a.success(a.P.M("已升级到 "+newVer, "upgraded to "+newVer))
	return 0
}
