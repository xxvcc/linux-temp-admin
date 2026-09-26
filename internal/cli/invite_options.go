package cli

import (
	"flag"
	"fmt"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// inviteOptions holds parsed command-line choices, before host discovery and
// interactive defaults. Tri-state values are resolved at the planning stage.
type inviteOptions struct {
	prefix, username, host    string
	port, hours               int
	portSet, hoursSet         bool
	sudo, autoRevoke, fixSSHD string
	confirmSudo               string

	yes, allowNonTTY           bool
	installDeps, noInstallDeps bool
	passwordLogin              bool
}

func (a *App) parseInviteOptions(args []string) (inviteOptions, bool) {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	prefix := fs.String("prefix", config.DefaultPrefix, "")
	userFlag := fs.String("user", "", "")
	hostFlag := fs.String("host", "", "")
	portFlag := fs.Int("port", 0, "")
	hoursFlag := fs.Int("hours", config.DefaultExpireHours, "")
	confirmSudo := fs.String("confirm-sudo", "", "")
	var fSudo, fNoSudo, fNopasswd, fAuto, fNoAuto, fYes, fAllowNonTTY, fInstallDeps, fNoInstallDeps bool
	var fFixSSHD, fNoFixSSHD, fPasswordLogin bool
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
	fs.BoolVar(&fFixSSHD, "fix-sshd", false, "")
	fs.BoolVar(&fNoFixSSHD, "no-fix-sshd", false, "")
	fs.BoolVar(&fPasswordLogin, "password-login", false, "")
	if !a.parseFlags(fs, args) {
		return inviteOptions{}, false
	}
	if (fSudo || fNopasswd) && fNoSudo {
		a.errorf("%s", a.P.M("--sudo/--nopasswd-sudo 与 --no-sudo 互斥",
			"--sudo/--nopasswd-sudo and --no-sudo are mutually exclusive"))
		return inviteOptions{}, false
	}
	if fAuto && fNoAuto {
		a.errorf("%s", a.P.M("--auto-revoke 与 --no-auto-revoke 互斥",
			"--auto-revoke and --no-auto-revoke are mutually exclusive"))
		return inviteOptions{}, false
	}
	if fInstallDeps && fNoInstallDeps {
		a.errorf("%s", a.P.M("--install-deps 与 --no-install-deps 互斥",
			"--install-deps and --no-install-deps are mutually exclusive"))
		return inviteOptions{}, false
	}
	if fFixSSHD && fNoFixSSHD {
		a.errorf("%s", a.P.M("--fix-sshd 与 --no-fix-sshd 互斥", "--fix-sshd and --no-fix-sshd are mutually exclusive"))
		return inviteOptions{}, false
	}
	if fNopasswd {
		fSudo = true
	}
	if fPasswordLogin && fFixSSHD {
		a.errorf("%s", a.P.M("--password-login 与 --fix-sshd 互斥：密码登录的前提正是不改动 sshd",
			"--password-login and --fix-sshd are mutually exclusive: password login exists precisely to leave sshd alone"))
		return inviteOptions{}, false
	}
	portSet, hoursSet := false, false
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "port":
			portSet = true
		case "hours":
			hoursSet = true
		}
	})

	hours := *hoursFlag
	if !validate.Hours(hours) {
		a.errorf("%s", a.P.M(fmt.Sprintf("--hours 必须在 1..%d 之间", config.MaxExpireHours),
			fmt.Sprintf("--hours must be between 1 and %d", config.MaxExpireHours)))
		return inviteOptions{}, false
	}
	if !validate.Prefix(*prefix) {
		a.errorf("%s", a.P.M("用户名前缀不合法："+*prefix, "invalid username prefix: "+*prefix))
		return inviteOptions{}, false
	}
	return inviteOptions{
		prefix: *prefix, username: *userFlag, host: *hostFlag,
		port: *portFlag, hours: hours, portSet: portSet, hoursSet: hoursSet,
		sudo: triState(fSudo, fNoSudo), autoRevoke: triState(fAuto, fNoAuto), fixSSHD: triState(fFixSSHD, fNoFixSSHD),
		confirmSudo: *confirmSudo, yes: fYes, allowNonTTY: fAllowNonTTY,
		installDeps: fInstallDeps, noInstallDeps: fNoInstallDeps, passwordLogin: fPasswordLogin,
	}, true
}

func (a *App) resolveInviteUsername(username, prefix string) (string, bool, bool) {
	generatedUsername := username == ""
	if username == "" {
		// Only the generation path uses the prefix. A prefix in the reserved
		// "systemd-" namespace would generate usernames the revoke path refuses to
		// delete (user.IsReservedName), so reject it here before generating. An
		// explicit --user does not use the prefix and is validated on its own below.
		if user.IsReservedName(prefix + "-") {
			a.errorf("%s", a.P.M("用户名前缀落入受保护命名空间（如 systemd-），会创建无法撤销的账号："+prefix,
				"username prefix is in a reserved namespace (e.g. systemd-) and would create an unrevocable account: "+prefix))
			return "", false, false
		}
		// Fill the username's remaining Linux-compatible length with entropy. Even
		// the longest accepted prefix retains the historical 40-bit minimum, while
		// the default prefix receives 104 bits.
		suffixBytes := (31 - len(prefix)) / 2
		for attempt := 0; attempt < 20; attempt++ {
			h, err := a.RandHex(suffixBytes)
			if err != nil {
				a.errorf("rand: %v", err)
				return "", false, false
			}
			cand := prefix + "-" + h
			// Dependency planning happens later and may need to install `id`. Use the
			// local database while choosing a candidate, then perform the authoritative
			// local+NSS check inside the lifecycle lock immediately before creation.
			exists, lookupErr := user.Exists(cand)
			if lookupErr != nil {
				a.errorf("%s: %v", a.P.M("读取账号数据库失败", "reading account database failed"), lookupErr)
				return "", false, false
			}
			if !exists {
				username = cand
				break
			}
		}
		if username == "" {
			a.errorf("%s", a.P.M("随机用户名多次冲突，请指定 --user", "random username collided repeatedly; specify --user"))
			return "", false, false
		}
	}
	if !validate.Username(username) {
		a.errorf("%s", a.P.M("用户名不合法："+username, "invalid username: "+username))
		return "", false, false
	}
	// Refuse a reserved/system name (root, daemon, systemd-*, ...): the revoke path
	// protects these, so creating one would leave an account the tool can never
	// delete — manually or via the auto-revoke timer. This is the authoritative
	// gate; it also covers an explicit --user that bypasses the prefix path above.
	if user.IsReservedName(username) {
		a.errorf("%s", a.P.M("用户名落入受保护/系统命名空间，拒绝创建（撤销将无法删除）："+username,
			"username is a reserved/system name and cannot be created (revoke would refuse to delete it): "+username))
		return "", false, false
	}

	return username, generatedUsername, true
}

// checkInvitePreconditions runs before prompts, host discovery or mutations.
func (a *App) checkInvitePreconditions(opts inviteOptions, username string, generatedUsername bool) bool {
	// Refuse a non-TTY stdout up front — before any prompt or host probe — so a
	// piped run fails immediately rather than after the operator answers.
	if !a.StdoutIsTTY() && !opts.allowNonTTY {
		a.errorf("%s", a.P.M("stdout 非 TTY，拒绝输出一次性私钥/密码（可加 --allow-non-tty-private-key-output）",
			"stdout is not a TTY; refusing to print the one-time private key or password (add --allow-non-tty-private-key-output)"))
		return false
	}

	// Everything the operator typed is validated here, before anything is probed,
	// asked, or disclosed: a bad value on the command line is a usage error, and a
	// malformed command must never get as far as a question. Only the values that
	// have to be *discovered* (a Host that must be prompted for or detected, a port
	// read from sshd) are settled later, after the login check has had its say.
	if opts.host != "" && !validate.Host(opts.host) {
		a.errorf("%s", a.P.M("Host 不合法："+opts.host, "invalid host: "+opts.host))
		return false
	}
	if opts.portSet && !validate.Port(opts.port) {
		a.errorf("%s", a.P.M(fmt.Sprintf("SSH 端口不合法：%d", opts.port), fmt.Sprintf("invalid SSH port: %d", opts.port)))
		return false
	}
	if opts.yes && opts.host == "" {
		a.errorf("%s", a.P.M("--yes 模式请显式传入 --host", "--yes mode requires an explicit --host"))
		return false
	}
	if opts.sudo == "yes" && opts.yes && generatedUsername {
		// The confirmation names the account being granted root. With a generated
		// name there is nothing to name yet: the old message interpolated this
		// run's throwaway name, and the next run generated a different one, so an
		// automated caller could never satisfy it.
		a.errorf("%s", a.P.M(
			"通过 --sudo --yes 授权必须显式指定 --user <名称> 并传入同名的 --confirm-sudo <名称>：随机生成的用户名无法事先确认",
			"granting sudo via --sudo --yes requires an explicit --user NAME together with a matching --confirm-sudo NAME; a generated username cannot be confirmed in advance"))
		return false
	}
	if opts.sudo == "yes" && opts.yes && opts.confirmSudo != username {
		a.errorf("%s", a.P.M("通过 --sudo --yes 授权需同时传入 --confirm-sudo "+username,
			"granting sudo via --sudo --yes also requires --confirm-sudo "+username))
		return false
	}
	if err := user.CheckPidfd(); err != nil {
		a.errorf("%s: %v", a.P.M("当前内核或进程沙箱不支持安全的进程撤销，拒绝创建无法可靠清理的账号",
			"the kernel or process sandbox does not support safe process revocation; refusing to create an account that cannot be reliably removed"), err)
		return false
	}

	return true
}
