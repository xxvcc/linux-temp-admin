package cli

import (
	"flag"
	"os"
	"runtime"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
)

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
	exe, err := os.Executable()
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法定位当前程序", "cannot locate the running binary"), err)
		return 1
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		a.errorf("%v", err)
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

func (a *App) uninstall(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var force, yes bool
	fs.BoolVar(&force, "force", false, "")
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	if !force {
		recs, err := a.Registry.List()
		if err != nil {
			a.errorf("%s: %v", a.P.M("无法读取注册表，拒绝卸载（可用 --force）", "cannot read the registry; refusing to uninstall (use --force)"), err)
			return 1
		}
		if len(recs) > 0 {
			a.errorf("%s", a.P.M("仍有登记用户，拒绝卸载稳定命令；请先 revoke/cleanup，或用 --force。",
				"registered users still exist; refusing to uninstall — revoke/cleanup first, or use --force."))
			return 1
		}
	}
	if !yes {
		if a.prompt(a.P.M("确认删除 "+a.InstallPath+" 请输入 YES: ", "type YES to remove "+a.InstallPath+": ")) != "YES" {
			a.warnf("%s", a.P.M("已取消", "cancelled"))
			return 0
		}
	}
	if err := a.Selfmanage.Uninstall(force); err != nil {
		a.errorf("%v", err)
		return 1
	}
	a.audit("uninstall", "", "ok", a.InstallPath, nil)
	a.success(a.P.M("已卸载稳定命令", "uninstalled the stable command"))
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
