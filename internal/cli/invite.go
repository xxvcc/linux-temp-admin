package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/expiry"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

func (a *App) invite(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	prefix := fs.String("prefix", config.DefaultPrefix, "")
	userFlag := fs.String("user", "", "")
	hostFlag := fs.String("host", "", "")
	portFlag := fs.Int("port", 0, "")
	hoursFlag := fs.Int("hours", config.DefaultExpireHours, "")
	confirmSudo := fs.String("confirm-sudo", "", "")
	var fSudo, fNoSudo, fNopasswd, fAuto, fNoAuto, fYes, fAllowNonTTY, fInstallDeps, fNoInstallDeps bool
	fs.BoolVar(&fSudo, "sudo", false, "")
	fs.BoolVar(&fNoSudo, "no-sudo", false, "")
	fs.BoolVar(&fNopasswd, "nopasswd-sudo", false, "") // deprecated alias of --sudo
	fs.BoolVar(&fAuto, "auto-revoke", false, "")
	fs.BoolVar(&fNoAuto, "no-auto-revoke", false, "")
	fs.BoolVar(&fYes, "yes", false, "")
	fs.BoolVar(&fYes, "y", false, "")
	fs.BoolVar(&fAllowNonTTY, "allow-non-tty-private-key-output", false, "")
	fs.BoolVar(&fInstallDeps, "install-deps", false, "")
	fs.BoolVar(&fNoInstallDeps, "no-install-deps", false, "")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() > 0 {
		a.errorf("%s %v", a.P.M("未知参数：", "unexpected arguments:"), fs.Args())
		return 1
	}
	if fNopasswd {
		fSudo = true
	}
	portSet := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "port" {
			portSet = true
		}
	})

	hours := *hoursFlag
	if !validate.Hours(hours) {
		a.errorf("%s", a.P.M(fmt.Sprintf("--hours 必须在 1..%d 之间", config.MaxExpireHours),
			fmt.Sprintf("--hours must be between 1 and %d", config.MaxExpireHours)))
		return 1
	}
	if !validate.Prefix(*prefix) {
		a.errorf("%s", a.P.M("用户名前缀不合法："+*prefix, "invalid username prefix: "+*prefix))
		return 1
	}

	username := *userFlag
	if username == "" {
		for attempt := 0; attempt < 20; attempt++ {
			h, err := a.RandHex(5)
			if err != nil {
				a.errorf("rand: %v", err)
				return 1
			}
			cand := *prefix + "-" + h
			if !user.Exists(cand) {
				username = cand
				break
			}
		}
		if username == "" {
			a.errorf("%s", a.P.M("随机用户名多次冲突，请指定 --user", "random username collided repeatedly; specify --user"))
			return 1
		}
	}
	if !validate.Username(username) {
		a.errorf("%s", a.P.M("用户名不合法："+username, "invalid username: "+username))
		return 1
	}

	grantSudo := triState(fSudo, fNoSudo)
	autoRev := triState(fAuto, fNoAuto)

	host := *hostFlag
	if host == "" {
		if fYes {
			a.errorf("%s", a.P.M("--yes 模式请显式传入 --host", "--yes mode requires an explicit --host"))
			return 1
		}
		host = a.detectOrPromptHost()
	}
	if !validate.Host(host) {
		a.errorf("%s", a.P.M("Host 不合法："+host, "invalid host: "+host))
		return 1
	}

	port := *portFlag
	if !portSet {
		port = sysinfo.SSHPort()
	}
	if !validate.Port(port) {
		a.errorf("%s", a.P.M(fmt.Sprintf("SSH 端口不合法：%d", port), fmt.Sprintf("invalid SSH port: %d", port)))
		return 1
	}

	// Refuse a non-TTY stdout up front (before any interactive prompt), so a
	// piped run fails immediately rather than after the operator answers.
	if !a.StdoutIsTTY() && !fAllowNonTTY {
		a.errorf("%s", a.P.M("stdout 非 TTY，拒绝输出一次性私钥（可加 --allow-non-tty-private-key-output）",
			"stdout is not a TTY; refusing to print the one-time private key (add --allow-non-tty-private-key-output)"))
		return 1
	}

	if grantSudo == "ask" {
		if fYes {
			grantSudo = "no"
		} else if yesish(a.prompt(a.P.M("是否授予 sudo 管理员权限？[y/N]: ", "Grant sudo admin privileges? [y/N]: "))) {
			grantSudo = "yes"
		} else {
			grantSudo = "no"
		}
	}
	if autoRev == "ask" {
		if fYes {
			autoRev = "yes"
		} else {
			ans := a.prompt(a.P.M("是否到期后自动删除该用户？[Y/n]: ", "Auto-delete this user on expiry? [Y/n]: "))
			if ans == "" || yesish(ans) {
				autoRev = "yes"
			} else {
				autoRev = "no"
			}
		}
	}

	if grantSudo == "yes" && fYes && *confirmSudo != username {
		a.errorf("%s", a.P.M("通过 --sudo --yes 授权需同时传入 --confirm-sudo "+username,
			"granting sudo via --sudo --yes also requires --confirm-sudo "+username))
		return 1
	}

	if !fYes {
		a.printf("\n%s\n  user=%s host=%s port=%d hours=%d sudo=%s auto-delete=%s\n",
			a.P.M("即将创建一次性临时账号：", "About to create a one-time temporary account:"),
			username, host, port, hours, grantSudo, autoRev)
		if a.prompt(a.P.M("确认创建请输入 YES: ", "Type YES to confirm: ")) != "YES" {
			a.warnf("%s", a.P.M("已取消", "cancelled"))
			return 0
		}
	}

	if !a.resolveDeps(grantSudo == "yes", fInstallDeps, fNoInstallDeps, fYes) {
		return 1
	}

	return a.runInvite(username, host, port, hours, grantSudo == "yes", autoRev == "yes")
}

// resolveDeps ensures the required external account tools are present, optionally
// installing them via the package manager. Returns false (after reporting) if any
// remain missing.
func (a *App) resolveDeps(needSudo, installDeps, noInstallDeps, yes bool) bool {
	missing := sysinfo.MissingDeps(needSudo)
	if len(missing) == 0 {
		return true
	}
	pm := sysinfo.PackageManager()
	seen := map[string]bool{}
	var pkgs []string
	for _, label := range missing {
		if p := sysinfo.PackageCandidate(label, pm); p != "" && !seen[p] {
			seen[p] = true
			pkgs = append(pkgs, p)
		}
	}
	doInstall := installDeps
	if !doInstall && !noInstallDeps && !yes && a.StdinIsTTY() && pm != "" && len(pkgs) > 0 {
		doInstall = yesish(a.prompt(a.P.M("是否自动安装缺失依赖？[y/N]: ", "install missing dependencies automatically? [y/N]: ")))
	}
	if !doInstall || pm == "" || len(pkgs) == 0 {
		a.errorf("%s %v", a.P.M("缺少依赖：", "missing dependencies:"), missing)
		return false
	}
	a.info(a.P.M("安装依赖：", "installing: ") + strings.Join(pkgs, " "))
	if err := sysinfo.InstallPackages(pm, pkgs); err != nil {
		a.errorf("%s: %v", a.P.M("安装依赖失败", "dependency install failed"), err)
		return false
	}
	if still := sysinfo.MissingDeps(needSudo); len(still) > 0 {
		a.errorf("%s %v", a.P.M("安装后仍缺少：", "still missing after install:"), still)
		return false
	}
	return true
}

// runInvite performs the mutating steps with rollback on any failure.
func (a *App) runInvite(username, host string, port, hours int, wantSudo, wantAuto bool) int {
	// Preflight the registry before creating anything, so a broken/unsafe
	// registry fails fast instead of leaving a stray account behind.
	if err := a.Registry.Init(); err != nil {
		a.errorf("%s: %v", a.P.M("初始化注册表失败", "registry init failed"), err)
		return 1
	}
	kp, err := sshkey.GenerateEd25519(username + "-" + config.ManagedTag)
	if err != nil {
		a.errorf("%s: %v", a.P.M("生成密钥失败", "key generation failed"), err)
		return 1
	}

	var cleanups []func()
	rollback := func() {
		a.warnf("%s", a.P.M("创建失败，正在回滚："+username, "creation failed; rolling back: "+username))
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	failf := func(format string, args ...any) int {
		a.errorf(format, args...)
		rollback()
		return 1
	}

	if err := a.Users.Create(username, resolveShell()); err != nil {
		a.errorf("%s: %v", a.P.M("创建用户失败", "create user failed"), err)
		return 1
	}
	cleanups = append(cleanups, func() { _ = a.Users.Delete(username) })

	if err := a.Users.LockPassword(username); err != nil {
		return failf("%s: %v", a.P.M("锁定密码失败", "lock password failed"), err)
	}
	pw, ok := user.Lookup(username)
	if !ok {
		return failf("%s", a.P.M("无法定位新用户家目录", "cannot locate new user's home"))
	}
	if err := sshkey.WriteAuthorizedKeys(pw.Home, pw.UID, pw.GID, kp.AuthorizedKey); err != nil {
		return failf("%s: %v", a.P.M("写入 authorized_keys 失败", "write authorized_keys failed"), err)
	}
	if err := a.Users.SetExpiry(username, expiry.Date(a.Now(), hours)); err != nil {
		return failf("%s: %v", a.P.M("设置到期失败", "set expiry failed"), err)
	}

	sudoGranted := false
	if wantSudo {
		if err := a.Sudoers.Grant(username); err == nil {
			sudoGranted = true
			cleanups = append(cleanups, func() { a.Sudoers.Remove(username) })
		} else {
			// Grant may have written a live drop-in before its verification step
			// failed; remove it unconditionally so a failed grant can never leave an
			// unregistered NOPASSWD grant behind. Remove only ever touches the
			// managed-prefixed file for this user, so it is safe to call blindly.
			a.Sudoers.Remove(username)
			a.warnf("%s: %v", a.P.M("授予 sudo 失败，创建为普通账号", "sudo grant failed; created as a normal account"), err)
		}
	}

	// Clear any stale schedule left by a reused username before scheduling.
	staleUnit, _ := a.Registry.UnitFor(username)
	a.Scheduler.Cancel(username, staleUnit)
	autoUnit := ""
	autoScheduled := false
	if wantAuto {
		// The auto-revoke task's ExecStart runs the installed stable command, so
		// ensure a binary is present at InstallPath first (as the bash tool did),
		// otherwise the timer would fire and fail on a non-installed run.
		if err := a.ensureStableInstalled(); err != nil {
			a.warnf("%s: %v", a.P.M("无法安装稳定命令，自动删除改为仅设置到期", "cannot install the stable command; auto-delete falls back to account expiry only"), err)
		} else if unit, err := a.Scheduler.Schedule(username, hours); err == nil {
			autoUnit = unit
			autoScheduled = true
			cleanups = append(cleanups, func() { a.Scheduler.Cancel(username, unit) })
		} else {
			a.warnf("%s: %v", a.P.M("自动删除任务创建失败，仅设置到期", "auto-delete scheduling failed; account expiry only"), err)
		}
	}

	rec := registry.Record{
		User:        username,
		Created:     a.Now().Format("2006-01-02 15:04:05 MST"),
		Expires:     expiry.DisplayLocal(a.Now(), hours),
		Sudo:        sudoGranted,
		Host:        host,
		Port:        port,
		Fingerprint: kp.Fingerprint,
		AutoRevoke:  autoScheduled,
		AutoUnit:    autoUnit,
	}
	registered := false
	if err := a.Registry.Record(rec); err != nil {
		a.warnf("%s: %v", a.P.M("登记注册表失败", "registry record failed"), err)
	} else {
		registered = true
	}
	if !registered {
		// The account exists but is unregistered: an auto-revoke task could never
		// delete it (revoke refuses unregistered without --force), and a NOPASSWD
		// grant should not linger unregistered. Cancel the task and drop sudo.
		if autoScheduled {
			a.Scheduler.Cancel(username, autoUnit)
			autoScheduled = false
			autoUnit = ""
		}
		if sudoGranted {
			a.Sudoers.Remove(username)
			sudoGranted = false
		}
		a.warnf("%s", a.P.M("账号已创建但未登记；请用 revoke --force 手动撤销。",
			"account created but not registered; revoke manually with --force."))
	}

	a.printInvite(host, port, username, hours, sudoGranted, autoScheduled, autoUnit, registered, kp)
	if registered {
		a.success(a.P.M("临时账号已创建并登记："+username, "temporary account created and registered: "+username))
	} else {
		a.warnf("%s", a.P.M("临时账号已创建但未登记："+username, "temporary account created but not registered: "+username))
	}
	return 0
}

func (a *App) printInvite(host string, port int, username string, hours int, sudo, auto bool, autoUnit string, registered bool, kp *sshkey.KeyPair) {
	sshHost := host
	if isIPv6(host) {
		sshHost = "[" + host + "]"
	}
	yesno := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	// An unregistered account (registry write failed) can only be revoked with
	// --force, so print that in the copy-paste revoke command.
	revokeSuffix := ""
	if !registered {
		revokeSuffix = " --force"
	}
	fmt.Fprintf(a.Out, `
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: %s
Port: %d
User: %s
Expires: %s
Sudo: %s
Login: SSH key only
Password login: locked
Auto revoke: %s
Auto revoke unit: %s

%s
ssh -i ./%s.key -p %d %s@%s

%s
cat > './%s.key' <<'EOF_KEY'
%sEOF_KEY
chmod 600 './%s.key'

%s
sudo %s revoke --user %s%s
`,
		host, port, username, expiry.DisplayLocal(a.Now(), hours), yesno(sudo), yesno(auto), orNone(autoUnit),
		a.P.M("SSH 登录命令:", "SSH login command:"), username, port, username, sshHost,
		a.P.M("保存私钥命令:", "Save private key command:"), username, string(kp.PrivatePEM), username,
		a.P.M("撤销命令:", "Revoke command:"), a.InstallPath, username, revokeSuffix)

	if sudo {
		fmt.Fprint(a.Out, "\n"+a.P.M(
			"Sudo 提示: 已启用 NOPASSWD sudo，等同完整 root，可能留下 root 拥有的持久化；撤销只删除此账号本身。",
			"Sudo note: NOPASSWD sudo is enabled (equivalent to full root); it may leave root-owned persistence. Revoking only deletes this account itself.")+"\n")
	}
	if !auto {
		fmt.Fprint(a.Out, "\n"+a.P.M(
			"自动删除提示: 未创建自动删除任务；账号到期只阻止登录，不删除用户，请按需手动撤销。",
			"Auto-delete note: no auto-delete task was created; expiry only blocks login and does not delete the user. Revoke manually when needed.")+"\n")
	}
	fmt.Fprint(a.Out, "\n"+a.P.M(
		"安全提醒: 私钥只显示这一次、服务器不保存；仅通过可信私聊发送；用完立即撤销。",
		"Security notes: the private key is shown only once and not stored on the server; send only via trusted private chat; revoke immediately after use.")+
		"\n\n----- END LINUX TEMP ADMIN INVITE -----\n")
}

// --- helpers ---

func triState(yes, no bool) string {
	switch {
	case no:
		return "no"
	case yes:
		return "yes"
	default:
		return "ask"
	}
}

func yesish(s string) bool { return s == "y" || s == "Y" || s == "yes" || s == "YES" }

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func isIPv6(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return true
		}
	}
	return false
}

// ensureStableInstalled installs the running binary at InstallPath if none is
// present, so a scheduled auto-revoke task can execute it. A pre-existing binary
// is left as-is.
func (a *App) ensureStableInstalled() error {
	if _, err := os.Stat(a.InstallPath); err == nil {
		return nil
	}
	if a.Selfmanage == nil {
		return fmt.Errorf("self-manager not configured")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	return a.Selfmanage.Install(bin, false)
}

func resolveShell() string {
	for _, s := range []string{config.DefaultShell, "/bin/sh"} {
		if fi, err := os.Stat(s); err == nil && fi.Mode()&0o111 != 0 {
			return s
		}
	}
	return "/bin/sh"
}

func (a *App) detectOrPromptHost() string {
	if yesish(a.prompt(a.P.M("是否自动探测公网 IP？[y/N]: ", "Detect public IP automatically? [y/N]: "))) {
		if ip, ok := a.Detector.LocalPublicIP(2 * time.Second); ok {
			return ip
		}
		if ip, ok := a.Detector.PublicIP(5 * time.Second); ok {
			return ip
		}
		a.warnf("%s", a.P.M("自动探测失败，请手动输入", "auto-detect failed; enter manually"))
	}
	return a.prompt(a.P.M("请输入服务器公网 IP/域名: ", "Enter server public IP/domain: "))
}
