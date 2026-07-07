package cli

import (
	"flag"
	"fmt"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/legacy"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// parseFlags parses fs and rejects trailing positional arguments (which the
// stdlib flag package would otherwise silently drop).
func (a *App) parseFlags(fs *flag.FlagSet, args []string) bool {
	if err := fs.Parse(args); err != nil {
		return false
	}
	if fs.NArg() > 0 {
		a.errorf("%s %v", a.P.M("未知参数：", "unexpected arguments:"), fs.Args())
		return false
	}
	return true
}

func (a *App) status(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	userFlag := fs.String("user", "", "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	if u := *userFlag; u != "" {
		if !validate.Username(u) {
			a.errorf("%s", a.P.M("用户名不合法："+u, "invalid username: "+u))
			return 1
		}
		pw, ok := user.Lookup(u)
		if !ok {
			a.errorf("%s", a.P.M("用户不存在："+u, "user does not exist: "+u))
			return 1
		}
		a.printf("user=%s uid=%d gid=%d home=%s shell=%s managed=%v",
			pw.Name, pw.UID, pw.GID, pw.Home, pw.Shell, user.IsManaged(u))
		if unit, _ := a.Registry.UnitFor(u); unit != "" {
			a.printf("auto-revoke unit=%s", unit)
		}
		return 0
	}

	a.info(a.P.M("已登记的临时用户：", "Registered temporary users:"))
	recs, err := a.Registry.List()
	if err != nil {
		a.warnf("%v", err)
	}
	if len(recs) == 0 {
		a.printf("  %s", a.P.M("（无）", "(none)"))
	}
	for _, r := range recs {
		state := a.P.M("缺失", "missing")
		if user.Exists(r.User) {
			state = a.P.M("在册", "active")
		}
		a.printf("  %-22s status=%-7s sudo=%v auto=%v expires=%s host=%s port=%d unit=%s",
			r.User, state, r.Sudo, r.AutoRevoke, r.Expires, r.Host, r.Port, orNone(r.AutoUnit))
	}
	return 0
}

func (a *App) cleanupExpired(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("cleanup-expired", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var compact bool
	fs.BoolVar(&compact, "compact", false, "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	a.warnf("%s", a.P.M("此命令只查看到期/自动删除状态，不主动删除用户。",
		"This only shows expiry/auto-delete status; it does not delete users."))
	recs, _ := a.Registry.List()
	for _, r := range recs {
		exists := user.Exists(r.User)
		a.printf("  %-22s exists=%v expires=%s auto=%v", r.User, exists, r.Expires, r.AutoRevoke)
	}
	if compact {
		removed, err := a.Registry.Compact(user.Exists)
		if err != nil {
			a.warnf("%v", err)
		} else {
			a.info(fmt.Sprintf(a.P.M("已压实注册表：移除 %d 条指向已不存在用户的记录。",
				"Compacted the registry: removed %d entries for users that no longer exist."), removed))
		}
	}
	return 0
}

func (a *App) doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	if !a.parseFlags(fs, args) {
		return 1
	}
	rc := 0
	a.info(a.P.M("linux-temp-admin 诊断报告", "linux-temp-admin doctor report"))
	if a.Geteuid() == 0 {
		a.success(a.P.M("当前以 root 运行。", "running as root."))
	} else {
		a.warnf("%s", a.P.M("当前不是 root；invite/revoke 需要 root。", "not running as root; invite/revoke require root."))
	}
	for _, d := range sysinfo.RequiredDeps(true) {
		if d.Present {
			a.success(a.P.M("依赖存在：", "dependency found: ") + d.Label)
		} else {
			a.warnf("%s%s", a.P.M("缺少依赖：", "missing dependency: "), d.Label)
			if d.Label != "sudo" { // sudo is only needed for --sudo invites
				rc = 1
			}
		}
	}
	a.info(a.P.M("包管理器：", "package manager: ") + orNone(sysinfo.PackageManager()))
	a.info(a.P.M("init 系统：", "init system: ") + sysinfo.InitSystem())
	a.info(fmt.Sprintf(a.P.M("探测到 SSH 端口：%d", "detected SSH port: %d"), sysinfo.SSHPort()))
	if err := fsutil.RootSafeDir("/etc/sudoers.d"); err == nil {
		a.success(a.P.M("/etc/sudoers.d 看起来安全。", "/etc/sudoers.d looks safe."))
	} else {
		a.warnf("%s (%v)", a.P.M("/etc/sudoers.d 不可用或不安全；NOPASSWD sudo 可能不可用。",
			"/etc/sudoers.d unavailable or unsafe; NOPASSWD sudo may be unavailable."), err)
	}
	for _, f := range legacy.New().Findings() {
		a.warnf("%s", f)
	}
	return rc
}

func (a *App) menu() int {
	if !a.requireRoot() {
		return 1
	}
	for {
		a.printf("\n%s\n 1) invite\n 2) revoke\n 3) status\n 4) cleanup-expired\n 5) doctor\n 6) install\n 7) upgrade\n 8) uninstall\n 9) %s",
			a.P.M("Linux 临时管理员管理器", "Linux Temporary Admin Manager"), a.P.M("退出", "exit"))
		fmt.Fprint(a.Err, a.P.M("请选择 [1-9]: ", "select [1-9]: "))
		choice, ok := a.readLine()
		if !ok {
			return 0 // EOF
		}
		switch choice {
		case "1":
			a.invite(nil)
		case "2":
			a.revoke(nil)
		case "3":
			a.status(nil)
		case "4":
			a.cleanupExpired(nil)
		case "5":
			a.doctor(nil)
		case "6":
			a.install(nil)
		case "7":
			a.upgrade(nil)
		case "8":
			a.uninstall(nil)
		case "9":
			return 0
		default: // includes a blank line
			a.warnf("%s", a.P.M("无效选择", "invalid choice"))
		}
	}
}
