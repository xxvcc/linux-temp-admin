package cli

import (
	"flag"
	"fmt"
	"os"
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
	var fSudo, fNoSudo, fAuto, fNoAuto, fYes, fAllowNonTTY bool
	fs.BoolVar(&fSudo, "sudo", false, "")
	fs.BoolVar(&fNoSudo, "no-sudo", false, "")
	fs.BoolVar(&fAuto, "auto-revoke", false, "")
	fs.BoolVar(&fNoAuto, "no-auto-revoke", false, "")
	fs.BoolVar(&fYes, "yes", false, "")
	fs.BoolVar(&fYes, "y", false, "")
	fs.BoolVar(&fAllowNonTTY, "allow-non-tty-private-key-output", false, "")
	if err := fs.Parse(args); err != nil {
		return 1
	}

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
	if port == 0 {
		port = sysinfo.SSHPort()
	}
	if !validate.Port(port) {
		a.errorf("%s", a.P.M(fmt.Sprintf("SSH 端口不合法：%d", port), fmt.Sprintf("invalid SSH port: %d", port)))
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
	if !a.StdoutIsTTY() && !fAllowNonTTY {
		a.errorf("%s", a.P.M("stdout 非 TTY，拒绝输出一次性私钥（可加 --allow-non-tty-private-key-output）",
			"stdout is not a TTY; refusing to print the one-time private key (add --allow-non-tty-private-key-output)"))
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

	if missing := sysinfo.MissingDeps(grantSudo == "yes"); len(missing) > 0 {
		a.errorf("%s %v", a.P.M("缺少依赖：", "missing dependencies:"), missing)
		return 1
	}

	return a.runInvite(username, host, port, hours, grantSudo == "yes", autoRev == "yes")
}

// runInvite performs the mutating steps with rollback on any failure.
func (a *App) runInvite(username, host string, port, hours int, wantSudo, wantAuto bool) int {
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
			a.warnf("%s: %v", a.P.M("授予 sudo 失败，创建为普通账号", "sudo grant failed; created as a normal account"), err)
		}
	}

	// Clear any stale schedule left by a reused username before scheduling.
	a.Scheduler.Cancel(username)
	autoUnit := ""
	autoScheduled := false
	if wantAuto {
		if unit, err := a.Scheduler.Schedule(username, hours); err == nil {
			autoUnit = unit
			autoScheduled = true
			cleanups = append(cleanups, func() { a.Scheduler.Cancel(username) })
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
	if err := a.Registry.Init(); err != nil {
		a.warnf("%s: %v", a.P.M("初始化注册表失败", "registry init failed"), err)
	} else if err := a.Registry.Record(rec); err != nil {
		a.warnf("%s: %v", a.P.M("登记注册表失败", "registry record failed"), err)
		if autoScheduled {
			// The auto-revoke task cannot delete an unregistered account; cancel it.
			a.Scheduler.Cancel(username)
			autoScheduled = false
			autoUnit = ""
		}
	}

	a.printInvite(host, port, username, hours, sudoGranted, autoScheduled, autoUnit, kp)
	a.success(a.P.M("临时账号已创建："+username, "temporary account created: "+username))
	return 0
}

func (a *App) printInvite(host string, port int, username string, hours int, sudo, auto bool, autoUnit string, kp *sshkey.KeyPair) {
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
	fmt.Fprintf(a.Out, `
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: %s
Port: %d
User: %s
Expires: %s
Sudo: %s
Login: SSH key only
Auto revoke: %s
Auto revoke unit: %s

%s
ssh -i ./%s.key -p %d %s@%s

%s
cat > './%s.key' <<'EOF_KEY'
%sEOF_KEY
chmod 600 './%s.key'

%s
sudo %s revoke --user %s

----- END LINUX TEMP ADMIN INVITE -----
`,
		host, port, username, expiry.DisplayLocal(a.Now(), hours), yesno(sudo), yesno(auto), orNone(autoUnit),
		a.P.M("SSH 登录命令:", "SSH login command:"), username, port, username, sshHost,
		a.P.M("保存私钥命令:", "Save private key command:"), username, string(kp.PrivatePEM), username,
		a.P.M("撤销命令:", "Revoke command:"), a.InstallPath, username)
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
