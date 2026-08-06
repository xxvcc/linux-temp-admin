package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/expiry"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"github.com/xxvcc/linux-temp-admin/internal/version"
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
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() > 0 {
		a.errorf("%s %v", a.P.M("未知参数：", "unexpected arguments:"), fs.Args())
		return 1
	}
	if (fSudo || fNopasswd) && fNoSudo {
		a.errorf("%s", a.P.M("--sudo/--nopasswd-sudo 与 --no-sudo 互斥",
			"--sudo/--nopasswd-sudo and --no-sudo are mutually exclusive"))
		return 1
	}
	if fAuto && fNoAuto {
		a.errorf("%s", a.P.M("--auto-revoke 与 --no-auto-revoke 互斥",
			"--auto-revoke and --no-auto-revoke are mutually exclusive"))
		return 1
	}
	if fInstallDeps && fNoInstallDeps {
		a.errorf("%s", a.P.M("--install-deps 与 --no-install-deps 互斥",
			"--install-deps and --no-install-deps are mutually exclusive"))
		return 1
	}
	if fFixSSHD && fNoFixSSHD {
		a.errorf("%s", a.P.M("--fix-sshd 与 --no-fix-sshd 互斥", "--fix-sshd and --no-fix-sshd are mutually exclusive"))
		return 1
	}
	if fNopasswd {
		fSudo = true
	}
	if fPasswordLogin && fFixSSHD {
		a.errorf("%s", a.P.M("--password-login 与 --fix-sshd 互斥：密码登录的前提正是不改动 sshd",
			"--password-login and --fix-sshd are mutually exclusive: password login exists precisely to leave sshd alone"))
		return 1
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
		return 1
	}
	if !validate.Prefix(*prefix) {
		a.errorf("%s", a.P.M("用户名前缀不合法："+*prefix, "invalid username prefix: "+*prefix))
		return 1
	}
	username := *userFlag
	generatedUsername := username == ""
	if username == "" {
		// Only the generation path uses the prefix. A prefix in the reserved
		// "systemd-" namespace would generate usernames the revoke path refuses to
		// delete (user.IsReservedName), so reject it here before generating. An
		// explicit --user does not use the prefix and is validated on its own below.
		if user.IsReservedName(*prefix + "-") {
			a.errorf("%s", a.P.M("用户名前缀落入受保护命名空间（如 systemd-），会创建无法撤销的账号："+*prefix,
				"username prefix is in a reserved namespace (e.g. systemd-) and would create an unrevocable account: "+*prefix))
			return 1
		}
		// Fill the username's remaining Linux-compatible length with entropy. Even
		// the longest accepted prefix retains the historical 40-bit minimum, while
		// the default prefix receives 104 bits.
		suffixBytes := (31 - len(*prefix)) / 2
		for attempt := 0; attempt < 20; attempt++ {
			h, err := a.RandHex(suffixBytes)
			if err != nil {
				a.errorf("rand: %v", err)
				return 1
			}
			cand := *prefix + "-" + h
			// Dependency planning happens later and may need to install `id`. Use the
			// local database while choosing a candidate, then perform the authoritative
			// local+NSS check inside the lifecycle lock immediately before creation.
			exists, lookupErr := user.Exists(cand)
			if lookupErr != nil {
				a.errorf("%s: %v", a.P.M("读取账号数据库失败", "reading account database failed"), lookupErr)
				return 1
			}
			if !exists {
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
	// Refuse a reserved/system name (root, daemon, systemd-*, ...): the revoke path
	// protects these, so creating one would leave an account the tool can never
	// delete — manually or via the auto-revoke timer. This is the authoritative
	// gate; it also covers an explicit --user that bypasses the prefix path above.
	if user.IsReservedName(username) {
		a.errorf("%s", a.P.M("用户名落入受保护/系统命名空间，拒绝创建（撤销将无法删除）："+username,
			"username is a reserved/system name and cannot be created (revoke would refuse to delete it): "+username))
		return 1
	}

	grantSudo := triState(fSudo, fNoSudo)
	autoRev := triState(fAuto, fNoAuto)

	// Refuse a non-TTY stdout up front — before any prompt or host probe — so a
	// piped run fails immediately rather than after the operator answers.
	if !a.StdoutIsTTY() && !fAllowNonTTY {
		a.errorf("%s", a.P.M("stdout 非 TTY，拒绝输出一次性私钥/密码（可加 --allow-non-tty-private-key-output）",
			"stdout is not a TTY; refusing to print the one-time private key or password (add --allow-non-tty-private-key-output)"))
		return 1
	}

	// Everything the operator typed is validated here, before anything is probed,
	// asked, or disclosed: a bad value on the command line is a usage error, and a
	// malformed command must never get as far as a question. Only the values that
	// have to be *discovered* (a Host that must be prompted for or detected, a port
	// read from sshd) are settled later, after the login check has had its say.
	if *hostFlag != "" && !validate.Host(*hostFlag) {
		a.errorf("%s", a.P.M("Host 不合法："+*hostFlag, "invalid host: "+*hostFlag))
		return 1
	}
	if portSet && !validate.Port(*portFlag) {
		a.errorf("%s", a.P.M(fmt.Sprintf("SSH 端口不合法：%d", *portFlag), fmt.Sprintf("invalid SSH port: %d", *portFlag)))
		return 1
	}
	if fYes && *hostFlag == "" {
		a.errorf("%s", a.P.M("--yes 模式请显式传入 --host", "--yes mode requires an explicit --host"))
		return 1
	}
	if grantSudo == "yes" && fYes && *confirmSudo != username {
		a.errorf("%s", a.P.M("通过 --sudo --yes 授权需同时传入 --confirm-sudo "+username,
			"granting sudo via --sudo --yes also requires --confirm-sudo "+username))
		return 1
	}
	if err := user.CheckPidfd(); err != nil {
		a.errorf("%s: %v", a.P.M("当前内核或进程沙箱不支持安全的进程撤销，拒绝创建无法可靠清理的账号",
			"the kernel or process sandbox does not support safe process revocation; refusing to create an account that cannot be reliably removed"), err)
		return 1
	}

	// Settle how the invitee will log in FIRST. planLogin only reads (`sshd -T`)
	// and decides — it changes nothing — and it is the one question that can make
	// every other one moot: on a host whose sshd refuses this account outright, the
	// operator hears so immediately, having been asked nothing.
	//
	// That ordering is load-bearing, not cosmetic. Resolving the Host can involve
	// asking an external echo service for this server's public IP, and this tool's
	// own rule is that a root-run tool must not phone home unasked. Doing it for an
	// invite that is about to be refused would be exactly that: a pointless
	// disclosure of the server's address, plus two questions (sudo, auto-delete)
	// whose answers were never going to be used.
	//
	// It also lets the confirmation below state the login method and its price in
	// one summary, rather than springing a second question after the operator has
	// already typed YES.
	plan, ok := a.planLogin(username, fPasswordLogin, triState(fFixSSHD, fNoFixSSHD), fYes)
	if !ok {
		return 1
	}

	// A Host that was not given has to be detected or asked for; whatever comes back
	// is untrusted input and is validated like any other.
	host := *hostFlag
	if host == "" {
		host = a.detectOrPromptHost()
		if !validate.Host(host) {
			a.errorf("%s", a.P.M("Host 不合法："+host, "invalid host: "+host))
			return 1
		}
	}

	port := *portFlag
	if !portSet {
		port = sysinfo.SSHPort()
		if !validate.Port(port) {
			a.errorf("%s", a.P.M(fmt.Sprintf("SSH 端口不合法：%d", port), fmt.Sprintf("invalid SSH port: %d", port)))
			return 1
		}
	}

	if grantSudo == "ask" {
		// This tool exists to create admin accounts, so an interactive invite grants
		// sudo by default without asking — the pre-create summary still shows
		// "Sudo: yes" and can be declined, and `--no-sudo` makes a plain account. A
		// non-interactive run (--yes) is left as a plain account unless --sudo is
		// passed explicitly, which keeps the --confirm-sudo gate and scripts intact.
		if fYes {
			grantSudo = "no"
		} else {
			grantSudo = "yes"
		}
	}
	if autoRev == "ask" {
		if fYes {
			autoRev = "yes"
		} else {
			answer, answered := a.promptYesNo(a.P.M("是否到期后自动删除该用户？[Y/n]: ", "Auto-delete this user on expiry? [Y/n]: "), true)
			if !answered {
				return 1
			}
			if answer {
				autoRev = "yes"
			} else {
				autoRev = "no"
			}
		}
	}

	// The lifetime only means something when the account will auto-delete; without
	// it the account is permanent (no expiry, no deletion), so there is nothing to
	// ask. A menu-driven operator never touches --hours, so offer it here when
	// auto-delete is on and it was not set on the command line. The TTY gate
	// matters: promptHours re-asks on invalid input, and an unbounded non-TTY stdin
	// stream (e.g. `yes n | lta invite`) never reaches EOF, so without it the root
	// tool would spin forever on the pipe.
	if autoRev == "yes" && !hoursSet && !fYes && a.StdinIsTTY() {
		hours = a.promptHours(hours)
	}
	// --hours with --no-auto-revoke asks for a lifetime the permanent account will
	// not have; say so rather than silently ignoring the flag.
	if autoRev == "no" && hoursSet {
		a.warnf("%s", a.P.M("未选择自动删除，账号将永久有效，--hours 被忽略。",
			"auto-delete is off, so the account is permanent and --hours is ignored."))
	}

	// Work out what would have to be installed BEFORE the summary, so the summary
	// can name it and the YES can be its consent. This only decides — the install
	// itself is a host change and waits until after the confirmation.
	depPkgs, ok := a.planDeps(grantSudo == "yes", plan.password, fInstallDeps, fNoInstallDeps, fYes)
	if !ok {
		return 1
	}

	if !fYes {
		// A permanent account (auto-delete off) has no lifetime, so the summary shows
		// its expiry as "permanent" instead of an hours figure that would not apply.
		lifetime := fmt.Sprintf(a.P.M("有效期=%d小时", "expires-in=%dh"), hours)
		if autoRev != "yes" {
			lifetime = a.P.M("永久", "permanent")
		}
		a.printf("\n%s\n  user=%s host=%s port=%d %s sudo=%s auto-delete=%s\n  login=%s\n",
			a.P.M("即将创建一次性临时账号：", "About to create a one-time temporary account:"),
			username, host, port, lifetime, a.choiceDisplay(grantSudo), a.choiceDisplay(autoRev), a.loginSummary(plan, username))
		if len(depPkgs) > 0 {
			a.printf("  %s%s", a.P.M("确认后将安装依赖：", "dependencies to install on confirm: "), strings.Join(depPkgs, " "))
		}
		if a.prompt(a.P.M("确认创建请输入 YES: ", "Type YES to confirm: ")) != "YES" {
			a.warnf("%s", a.P.M("已取消", "cancelled"))
			return 0
		}
	}

	// Dependency packages are host prerequisites, not lifecycle state; install
	// them before taking the account lock so a package manager cannot delay an
	// already-due scheduled revoke. The account transaction starts below. Keep the
	// per-name lock outside the global lock: every account path uses that order.
	if !a.installDeps(grantSudo == "yes", plan.password, depPkgs) {
		return 1
	}
	return a.withAccountExclusiveLock(username, func() int {
		return a.withLifecycleLock(func() int {
			return a.runInviteWithIdentityPolicy(username, host, port, hours, grantSudo == "yes", autoRev == "yes", plan, generatedUsername)
		})
	})
}

func (a *App) choiceDisplay(value string) string {
	switch value {
	case "yes":
		return a.P.M("是", "yes")
	case "no":
		return a.P.M("否", "no")
	default:
		return value
	}
}

// promptHours asks for the account lifetime, offering current as the default a
// blank line accepts. It loops until the input is valid or blank. Callers must
// gate it on a.StdinIsTTY(): a closed stdin reads empty and settles on the
// default, but an unbounded non-TTY stream of invalid lines never blanks and
// would spin here forever, so it is only ever reached on a real terminal.
func (a *App) promptHours(current int) int {
	msg := fmt.Sprintf(a.P.M("有效期（小时，1-%d）[%d]: ", "Lifetime in hours (1-%d) [%d]: "),
		config.MaxExpireHours, current)
	for {
		ans := a.prompt(msg)
		if ans == "" {
			return current
		}
		if n, err := strconv.Atoi(ans); err == nil && validate.Hours(n) {
			return n
		}
		a.warnf("%s", a.P.M(fmt.Sprintf("请输入 1-%d 之间的整数", config.MaxExpireHours),
			fmt.Sprintf("enter an integer between 1 and %d", config.MaxExpireHours)))
	}
}

// promptYesNo accepts only an explicit yes/no spelling (or a blank line for the
// documented default). A typo at the auto-delete prompt must not silently turn a
// temporary account into a permanent one.
func (a *App) promptYesNo(msg string, defaultYes bool) (bool, bool) {
	for {
		fmt.Fprint(a.Err, msg)
		ans, ok := a.readLine()
		if !ok {
			a.warnf("%s", a.P.M("输入已结束，已取消", "input ended; cancelled"))
			return false, false
		}
		if ans == "" {
			return defaultYes, true
		}
		if yesish(ans) {
			return true, true
		}
		if noish(ans) {
			return false, true
		}
		a.warnf("%s", a.P.M("请输入 y 或 n", "enter y or n"))
		if !a.StdinIsTTY() {
			return false, false
		}
	}
}

// loginSummary is the confirmation prompt's one-line statement of how the
// invitee will authenticate — and, when sshd has to be touched for that to work,
// exactly which file will appear on the host. The operator should be able to see
// the full cost of the YES they are about to type.
func (a *App) loginSummary(plan loginPlan, username string) string {
	switch {
	case plan.password:
		return a.P.M("密码（本工具最弱的授权方式）", "password (the weakest grant this tool issues)")
	case plan.fixSSHD:
		path := ""
		if a.SSHD != nil {
			path = a.SSHD.FilePath(username)
		}
		return a.P.M("ssh 密钥；将为该账号写入 sshd 例外（全局策略不变）："+path,
			"ssh key; a per-account sshd exception will be written (the global policy is untouched): "+path)
	case plan.verified:
		return a.P.M("ssh 密钥（已对照 sshd 有效配置验证）",
			"ssh key (verified against the effective sshd config)")
	default:
		return a.P.M("ssh 密钥（未验证："+plan.unverified+"）",
			"ssh key (UNVERIFIED: "+plan.unverified+")")
	}
}

// loginPlan is how the invitee will authenticate, decided against sshd's
// effective configuration before a single change is made to the host.
type loginPlan struct {
	password bool                // issue a password instead of a key (--password-login)
	fixSSHD  bool                // write a per-account sshd drop-in to admit the key in config
	report   sysinfo.LoginReport // what the check found (drives the drop-in's contents)
	verified bool                // the effective-config check completed without a blocker or unknown
	// unverified says, in the invite's own words, why the config verdict was
	// inconclusive. Non-empty exactly when verified is false.
	unverified string
}

// sshdConfig reads sshd's effective configuration for user, tolerating an
// unwired probe. A tool that runs as root must not have a path that panics: an
// unset collaborator is reported as "could not read the config", which every
// caller already handles by declining to claim the login is verified.
func (a *App) sshdConfig(user string) (*sysinfo.SSHDConfig, error) {
	if a.SSHDConfig == nil {
		return nil, fmt.Errorf("no sshd config probe is wired")
	}
	cfg, err := a.SSHDConfig(user)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("sshd config probe returned no configuration")
	}
	return cfg, nil
}

// planLogin decides how the invitee will log in. It blocks known configuration
// incompatibilities and requires a conclusive effective-config verdict before a
// password is issued; a key invite may instead be marked UNVERIFIED.
//
// It runs before any mutation: on refusal the account does not exist, so there
// is nothing to roll back and nothing left behind.
func (a *App) planLogin(username string, wantPassword bool, fix string, yes bool) (loginPlan, bool) {
	// A same-name primary group is the common useradd default and is the only safe
	// pre-creation prediction. Some distributions instead select a shared group;
	// the real group set is re-checked after creation before any credential lands.
	predicted := []string{username}

	cfg, err := a.sshdConfig(username)
	if err != nil {
		// Password authentication exposes a reusable secret. Never issue one unless
		// the effective-configuration check is conclusive. Key-only invitations can
		// remain explicitly UNVERIFIED.
		if wantPassword {
			a.errorf("%s: %v", a.P.M("无法读取 sshd 有效配置，拒绝创建密码登录",
				"cannot read the effective sshd config; refusing a password login"), err)
			return loginPlan{}, false
		}
		a.warnf("%s: %v", a.P.M("无法读取 sshd 有效配置，公钥登录方式未经验证",
			"cannot read the effective sshd config; the key login method is unverified"), err)
		const reason = "the effective sshd config could not be read"
		return loginPlan{unverified: reason}, true
	}

	if wantPassword {
		rep, deferred := a.checkPasswordLoginDetailed(cfg, username, predicted, false)
		if deferred && rep.OK() {
			a.warnf("%s", a.P.M(
				"sshd 含有账号创建前无法求值的 Match Group；将先创建无凭据账号，并在设置密码前按真实用户组重新检查。",
				"sshd has a Match Group that cannot be evaluated before the account exists; a credential-less account will be created and re-checked against its real groups before any password is set."))
			a.warnf("%s", a.P.M(
				"密码登录会削弱本工具的安全模型：密码在账号的整个生命周期内都可被全网爆破，且必须以明文交付。用完请立即撤销。",
				"password login weakens this tool's security model: the password is brute-forceable from anywhere for the account's whole lifetime and must be delivered in the clear. Revoke as soon as you are done."))
			return loginPlan{password: true, report: rep, unverified: uncertainReason(rep)}, true
		}
		if !rep.Certain() {
			if rep.OK() {
				a.errorf("%s", a.P.M("sshd 有效配置检查无法确认该账号的密码凭据，拒绝创建密码登录：",
					"the effective sshd config check cannot confirm the password credential for this account; refusing a password login:"))
				a.reportUncertainty(rep)
				return loginPlan{}, false
			}
			a.errorf("%s", a.P.M("sshd 有效配置检查发现该账号密码凭据的阻碍：", "the effective sshd config check found a blocker for this account's password credential:"))
			a.reportBlockers(rep)
			return loginPlan{}, false
		}
		a.warnf("%s", a.P.M(
			"密码登录会削弱本工具的安全模型：密码在账号的整个生命周期内都可被全网爆破，且必须以明文交付。用完请立即撤销。",
			"password login weakens this tool's security model: the password is brute-forceable from anywhere for the account's whole lifetime and must be delivered in the clear. Revoke as soon as you are done."))
		return loginPlan{password: true, verified: true, report: rep}, true
	}

	rep, deferred := a.checkKeyLoginDetailed(cfg, username, predicted, false)
	a.reportUncertainty(rep)
	if deferred && rep.OK() {
		// A future account's Match Group result is unknowable until NSS can resolve
		// its real memberships. Preserve an explicit repair authorization through that
		// phase; confirmLogin will either discover no blocker, update report with the
		// real fixable blockers, or fail closed before credentials are installed.
		return loginPlan{
			fixSSHD:    fix == "yes",
			report:     rep,
			verified:   false,
			unverified: "sshd Match Group cannot be evaluated until the account exists",
		}, true
	}
	if rep.OK() {
		// Certain(), not OK(): a rule that could not be evaluated — an AllowUsers
		// entry that also pins the source address — prevents a conclusive verdict.
		return loginPlan{verified: rep.Certain(), unverified: uncertainReason(rep)}, true
	}

	a.errorf("%s", a.P.M("sshd 有效配置检查发现该账号公钥凭据的阻碍：", "the effective sshd config check found a blocker for this account's public-key credential:"))
	a.reportBlockers(rep)

	// An interactive operator who ends up unable to use a key gets one offer of the
	// password fallback at each dead end below, so a menu-only run is never stranded.
	interactive := !yes && a.StdinIsTTY()

	if !rep.Fixable() {
		// An explicit DenyUsers/DenyGroups rule is the operator saying "never this
		// account". Not being on an allow list is a default nobody spoke about, and
		// an invite may lift it; an explicit deny is a decision, and overriding it
		// would defeat the very policy this tool was pointed at.
		a.errorf("%s", a.P.M("这是 sshd 的显式拒绝规则，本工具不会为任何账号绕过它。",
			"this is an explicit sshd deny rule; the tool will not bypass it for any account."))
		if p, ok := a.offerPasswordFallback(cfg, username, interactive); ok {
			return p, true
		}
		return loginPlan{}, false
	}

	if a.SSHD == nil {
		a.errorf("%s", a.P.M("未配置 sshd 管理器，无法开启公钥登录。",
			"no sshd manager is configured; cannot enable a public-key login."))
		if p, ok := a.offerPasswordFallback(cfg, username, interactive); ok {
			return p, true
		}
		return loginPlan{}, false
	}

	switch fix {
	case "yes":
		return loginPlan{fixSSHD: true, report: rep}, true
	case "no":
		// The operator explicitly said leave sshd alone (--no-fix-sshd); a password
		// is the natural alternative that honours that.
		a.printSSHDFixHint(username, rep)
		if p, ok := a.offerPasswordFallback(cfg, username, interactive); ok {
			return p, true
		}
		return loginPlan{}, false
	}
	// "ask": a non-interactive run must never quietly rewrite a remote host's sshd
	// configuration, so it is refused unless --fix-sshd said so out loud.
	if !interactive {
		a.errorf("%s", a.P.M("非交互模式不会自动修改 sshd。确认要为该账号开启公钥登录请加 --fix-sshd（或改用 --password-login）。",
			"a non-interactive run will not modify sshd. Pass --fix-sshd to enable a public-key login for this account, or use --password-login instead."))
		a.printSSHDFixHint(username, rep)
		return loginPlan{}, false
	}
	a.warnf("%s", a.P.M(
		"可以只为该账号写一个 sshd 例外（Match User 块），不改动全局策略，撤销时随账号一并删除。",
		"A per-account sshd exception (a Match User block) can be written instead; it leaves the global policy untouched and is removed together with the account."))
	enableKey, answered := a.promptYesNo(a.P.M("是否只为该账号开启公钥登录？[y/N]: ",
		"Enable a public-key login for this account only? [y/N]: "), false)
	if !answered {
		return loginPlan{}, false
	}
	if enableKey {
		return loginPlan{fixSSHD: true, report: rep}, true
	}
	// Declined the exception — offer the password before giving up.
	if p, ok := a.offerPasswordFallback(cfg, username, interactive); ok {
		return p, true
	}
	a.printSSHDFixHint(username, rep)
	return loginPlan{}, false
}

// confirmLogin re-runs the effective-config check against the account's REAL
// groups, now that it exists, and updates the plan. It returns false when that
// check blocks the credential, or cannot conclusively assess a password. The
// caller then attempts rollback; any cleanup it cannot prove complete retains the
// credential-less account and registry witness for explicit recovery.
//
// This is where a wrong prediction is caught. planLogin had to guess the group
// set before the account existed; sshd decides Allow/DenyGroups on the real one.
func (a *App) confirmLogin(username string, groups []string, plan *loginPlan) bool {
	cfg, err := a.sshdConfig(username)
	if err != nil {
		if plan.fixSSHD || plan.password {
			// We were about to modify sshd on the strength of a reading we can no
			// longer take, or issue a reusable password whose login path can no
			// longer be checked conclusively. Refuse and let the caller roll the account back.
			a.errorf("%s: %v", a.P.M("无法重新读取 sshd 有效配置", "cannot re-read the effective sshd config"), err)
			return false
		}
		plan.verified = false
		plan.unverified = "the effective sshd config could not be read"
		return true
	}
	var rep sysinfo.LoginReport
	if plan.password {
		rep = a.checkPasswordLogin(cfg, username, groups, true)
		if !rep.Certain() {
			if rep.OK() {
				a.errorf("%s", a.P.M("sshd 有效配置检查无法确认该账号的密码凭据，拒绝签发密码：",
					"the effective sshd config check cannot confirm the password credential for this account; refusing to issue a password:"))
				a.reportUncertainty(rep)
			} else {
				a.reportBlockers(rep)
			}
			return false
		}
	} else {
		rep = a.checkKeyLogin(cfg, username, groups, true)
	}
	switch {
	case rep.OK():
		// The real groups clear it — including the case where the prediction was
		// pessimistic and no exception is needed after all. Never write to sshd on
		// the strength of a guess that turned out wrong.
		if plan.fixSSHD {
			// The confirmation summary promised an sshd exception at a named path.
			// Not writing it is the right outcome, but the operator was told it would
			// appear, so say plainly that it will not.
			a.info(a.P.M("按该账号的真实用户组复核后，sshd 有效配置本就允许此凭据；未写入 sshd 例外。",
				"re-checked against the account's real groups: the effective sshd config already permits this credential; no sshd exception was written."))
		}
		plan.fixSSHD = false
		plan.report = sysinfo.LoginReport{}
		plan.verified = rep.Certain()
		plan.unverified = uncertainReason(rep)
		a.reportUncertainty(rep)
		return true
	case plan.fixSSHD && rep.Fixable():
		// The exception must lift the blockers the REAL account has, not the ones the
		// predicted one did.
		plan.report = rep
		return true
	default:
		a.reportBlockers(rep)
		return false
	}
}

// reportBlockers explains, per blocker, why the login would fail and quotes the
// effective value that says so.
func (a *App) reportBlockers(rep sysinfo.LoginReport) {
	for _, b := range rep.Blockers {
		detail := rep.Detail[b]
		var msg string
		switch b {
		case sysinfo.BlockPubkeyDisabled:
			msg = a.P.M("sshd 未开启公钥认证（PubkeyAuthentication no）",
				"sshd has public-key authentication disabled (PubkeyAuthentication no)")
		case sysinfo.BlockPasswordDisabled:
			msg = a.P.M("sshd 未开启密码认证（PasswordAuthentication no）",
				"sshd has password authentication disabled (PasswordAuthentication no)")
		case sysinfo.BlockAuthorizedKeysFile:
			msg = a.P.M("sshd 不读取 ~/.ssh/authorized_keys（AuthorizedKeysFile = "+detail+"），而这是本工具唯一写入公钥的位置",
				"sshd does not read ~/.ssh/authorized_keys (AuthorizedKeysFile = "+detail+"), the only place this tool writes the key")
		case sysinfo.BlockAuthMethods:
			msg = a.P.M("sshd 要求多因素认证（AuthenticationMethods = "+detail+"），单凭公钥或密码无法完成登录",
				"sshd requires multiple factors (AuthenticationMethods = "+detail+"); a key or password alone cannot complete the login")
		case sysinfo.BlockKeyAlgorithm:
			// Name the directive under the spelling this host's sshd used (it was
			// renamed in 8.5), so an operator who greps for it actually finds it.
			directive := rep.AlgoDirective
			if directive == "" {
				directive = "PubkeyAcceptedAlgorithms"
			}
			msg = a.P.M("sshd 不接受 ssh-ed25519 密钥（"+directive+" = "+detail+"），而本工具只签发 ed25519",
				"sshd does not accept ssh-ed25519 keys ("+directive+" = "+detail+"), the only type this tool issues")
		case sysinfo.BlockAllowUsers:
			msg = a.P.M("该账号不在 sshd 的 AllowUsers 白名单内（"+detail+"）",
				"the account is not on sshd's AllowUsers whitelist ("+detail+")")
		case sysinfo.BlockAllowGroups:
			msg = a.P.M("该账号的用户组不在 sshd 的 AllowGroups 白名单内（"+detail+"）",
				"the account's groups are not on sshd's AllowGroups whitelist ("+detail+")")
		case sysinfo.BlockDenyUsers:
			msg = a.P.M("sshd 的 DenyUsers 明确拒绝该账号（"+detail+"）",
				"sshd's DenyUsers explicitly denies the account ("+detail+")")
		case sysinfo.BlockDenyGroups:
			msg = a.P.M("sshd 的 DenyGroups 明确拒绝该账号的用户组（"+detail+"）",
				"sshd's DenyGroups explicitly denies the account's group ("+detail+")")
		}
		a.errorf("  - %s", msg)
	}
}

// checkKeyLogin runs the key-login check and augments it with Match criteria a
// user-only `sshd -T` probe cannot evaluate in the current account phase.
func (a *App) checkKeyLogin(cfg *sysinfo.SSHDConfig, user string, groups []string, accountExists bool) sysinfo.LoginReport {
	rep, _ := a.checkKeyLoginDetailed(cfg, user, groups, accountExists)
	return rep
}

func (a *App) checkPasswordLogin(cfg *sysinfo.SSHDConfig, user string, groups []string, accountExists bool) sysinfo.LoginReport {
	rep, _ := a.checkPasswordLoginDetailed(cfg, user, groups, accountExists)
	return rep
}

func (a *App) checkKeyLoginDetailed(cfg *sysinfo.SSHDConfig, user string, groups []string, accountExists bool) (sysinfo.LoginReport, bool) {
	return a.withUnverifiableMatch(sysinfo.CheckKeyLogin(cfg, user, groups), accountExists)
}

func (a *App) checkPasswordLoginDetailed(cfg *sysinfo.SSHDConfig, user string, groups []string, accountExists bool) (sysinfo.LoginReport, bool) {
	return a.withUnverifiableMatch(sysinfo.CheckPasswordLogin(cfg, user, groups), accountExists)
}

// withUnverifiableMatch returns the augmented report and whether account
// creation alone can resolve every unknown. That second result is true only for
// a pre-account Match Group: connection-scoped rules, incomplete scans, and
// address-qualified AllowUsers remain unknown after useradd and are never
// eligible for deferred password issuance.
func (a *App) withUnverifiableMatch(rep sysinfo.LoginReport, accountExists bool) (sysinfo.LoginReport, bool) {
	hasUnverifiableMatch := sysinfo.HasUnverifiableMatch
	if a.SSHDHasUnverifiableMatch != nil {
		hasUnverifiableMatch = a.SSHDHasUnverifiableMatch
	}
	persistent := hasUnverifiableMatch(true)
	if persistent {
		rep.Unverifiable = append(rep.Unverifiable,
			"sshd has a connection-scoped or otherwise unreadable Match rule; whether this account is admitted cannot be checked from user and group information alone")
		return rep, false
	}
	if accountExists {
		return rep, false
	}
	if hasUnverifiableMatch(false) {
		deferred := len(rep.Unverifiable) == 0
		rep.Unverifiable = append(rep.Unverifiable,
			"sshd has a Match Group rule that cannot be evaluated until the account exists and its NSS groups can be resolved")
		return rep, deferred
	}
	return rep, false
}

// offerPasswordFallback is the escape hatch when the effective-config check
// reports a blocker for the planned key. If the same check conclusively admits a
// password for this account, it offers that instead, so an operator driving the
// menu (who cannot reach --password-login, a flag) has an alternative.
//
// Password login is the weakest grant the tool issues, so the offer states that
// cost first and defaults to No: it removes the dead-end without nudging anyone
// toward the weaker choice. It returns ok=false when no offer applies (not
// interactive, or sshd would refuse a password too — e.g. an explicit deny, which
// blocks passwords just as it blocks keys) or the operator declined, leaving the
// caller to refuse exactly as it would have.
func (a *App) offerPasswordFallback(cfg *sysinfo.SSHDConfig, username string, interactive bool) (loginPlan, bool) {
	if !interactive {
		return loginPlan{}, false
	}
	rep, deferred := a.checkPasswordLoginDetailed(cfg, username, []string{username}, false)
	if deferred && rep.OK() {
		a.warnf("%s", a.P.M(
			"密码策略取决于账号创建后的真实用户组；将在设置任何密码前重新检查。",
			"password policy depends on the account's real post-creation groups; it will be re-checked before any password is set."))
	} else if !rep.Certain() {
		if rep.OK() {
			a.warnf("%s", a.P.M("sshd 有效配置检查无法确认密码凭据，因此不提供密码回退。",
				"the effective sshd config check cannot confirm the password credential, so no password fallback is offered."))
			a.reportUncertainty(rep)
		}
		return loginPlan{}, false
	}
	if deferred && rep.OK() {
		a.warnf("%s", a.P.M(
			"密码在账号整个生命周期内可被全网爆破、且必须以明文交付，是本工具最弱的授权方式。",
			"A password is brute-forceable from anywhere for the account's whole lifetime and must be delivered in the clear — the weakest grant this tool issues."))
	} else {
		a.warnf("%s", a.P.M(
			"sshd 有效配置检查发现该账号公钥凭据的阻碍，但未发现密码凭据的阻碍或无法判断项。密码在账号整个生命周期内可被全网爆破、且必须以明文交付，是本工具最弱的授权方式。",
			"the effective sshd config check found a blocker for this account's key credential but no blocker or unevaluated rule for a password credential. A password is brute-forceable from anywhere for the account's whole lifetime and must be delivered in the clear — the weakest grant this tool issues."))
	}
	usePassword, answered := a.promptYesNo(a.P.M("改用密码登录？[y/N]: ", "Issue a password login instead? [y/N]: "), false)
	if !answered || !usePassword {
		return loginPlan{}, false
	}
	if deferred && rep.OK() {
		return loginPlan{password: true, report: rep, unverified: uncertainReason(rep)}, true
	}
	return loginPlan{password: true, verified: true, report: rep}, true
}

// reportUncertainty prints the notes and unevaluated rules that keep an
// effective-config verdict from being conclusive.
func (a *App) reportUncertainty(rep sysinfo.LoginReport) {
	for _, w := range rep.Warnings {
		a.warnf("%s", w)
	}
	for _, u := range rep.Unverifiable {
		a.warnf("%s", u)
	}
}

// uncertainReason is the invite's own words for why an effective-config verdict
// was inconclusive, or "" when it was conclusive.
func uncertainReason(rep sysinfo.LoginReport) string {
	if rep.Certain() {
		return ""
	}
	if len(rep.Unverifiable) > 0 {
		return rep.Unverifiable[0]
	}
	return "the effective sshd config could not be read"
}

// printSSHDFixHint prints the manual change that would make the effective config
// admit this account's key, for an operator who would rather do it themselves.
//
// It renders the same per-account Match block the tool would have written, not a
// global directive. The blocker is often something other than the pubkey switch
// (a redirected AuthorizedKeysFile, an AuthenticationMethods demanding a second
// factor), so a canned "set PubkeyAuthentication yes" would both fail to fix it
// and talk the operator into lowering the baseline for every other account on
// the host — the exact opposite of what this tool promises.
//
// reload, never restart: a restart drops the session they are typing into.
func (a *App) printSSHDFixHint(username string, rep sysinfo.LoginReport) {
	block, err := sshdconf.MatchBlock(username, []string{username}, rep)
	if err != nil {
		// Nothing renderable (an explicit deny rule): the blockers were already
		// reported, and no per-account block would lift them anyway.
		return
	}
	a.warnf("%s", a.P.M("未创建任何账号。若要手动只为该账号开启（请保留一个已登录的 root 会话）：",
		"nothing was created. To enable it by hand for this account only (keep a logged-in root session open):"))
	a.warnf("  cat > %s <<'EOF'", sshdconf.New().FilePath(username))
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		a.warnf("  %s", line)
	}
	a.warnf("  EOF")
	a.warnf("  sshd -t && systemctl reload ssh   # %s",
		a.P.M("reload 而非 restart：现有会话不受影响", "reload, not restart: live sessions survive"))
	a.warnf("  sshd -T -C user=%s   # %s", username,
		a.P.M("确认已生效", "confirm it took effect"))
}

// planDeps decides, read-only, what must be installed for the required external
// account tools to be present. It returns the package list to install after
// confirmation (nil when nothing is missing), and false — after reporting — when
// a dependency is missing and cannot or may not be installed.
//
// It runs before the confirmation summary so the summary can name the packages,
// and its consent is the final YES rather than a separate prompt: the only thing
// "no" could ever have meant is "do not create the account", which typing
// anything but YES already achieves. A --yes run keeps the old rule — install
// only with --install-deps — since it has no YES gate to stand in.
func (a *App) planDeps(needSudo, needPassword, installDeps, noInstallDeps, yes bool) ([]string, bool) {
	missing := sysinfo.MissingDeps(needSudo, needPassword)
	if len(missing) == 0 {
		return nil, true
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
	if pm == "pacman" && len(pkgs) > 0 {
		a.errorf("%s", a.P.M(
			"检测到 pacman。Arch 不支持部分升级，本工具也不会在创建账号时无人值守升级整个系统。请先由管理员执行 `pacman -Syu --needed "+strings.Join(pkgs, " ")+"`，再重试。",
			"pacman was detected. Arch does not support partial upgrades, and this tool will not upgrade the whole system unattended while creating an account. Run `pacman -Syu --needed "+strings.Join(pkgs, " ")+"` deliberately first, then retry."))
		return nil, false
	}
	// We may install when there is a package manager and a resolvable package set,
	// and permission to proceed: --install-deps outright, or an interactive run
	// whose YES will be the consent. A --yes/--no-install-deps run that did not opt
	// in, or a host with no package manager, is refused now — before the summary.
	mayInstall := pm != "" && len(pkgs) > 0 && (installDeps || (!yes && !noInstallDeps && a.StdinIsTTY()))
	if !mayInstall {
		a.errorf("%s %v", a.P.M("缺少依赖：", "missing dependencies:"), missing)
		return nil, false
	}
	return pkgs, true
}

// installDeps installs the packages planDeps selected and confirms the tools are
// now present. It is a no-op for an empty list.
func (a *App) installDeps(needSudo, needPassword bool, pkgs []string) bool {
	if len(pkgs) == 0 {
		return true
	}
	a.info(a.P.M("安装依赖：", "installing: ") + strings.Join(pkgs, " "))
	if err := sysinfo.InstallPackages(sysinfo.PackageManager(), pkgs); err != nil {
		a.errorf("%s: %v", a.P.M("安装依赖失败", "dependency install failed"), err)
		return false
	}
	if still := sysinfo.MissingDeps(needSudo, needPassword); len(still) > 0 {
		a.errorf("%s %v", a.P.M("安装后仍缺少：", "still missing after install:"), still)
		return false
	}
	return true
}

// runInviteWithIdentityPolicy performs the mutating steps with rollback on any
// failure. generatedUsername controls whether the fresh-name isolation proof is
// available for the deferred-job cleanup policy.
func (a *App) runInviteWithIdentityPolicy(username, host string, port, hours int, wantSudo, wantAuto bool, plan loginPlan, generatedUsername bool) int {
	// Preflight the registry before creating anything, so a broken/unsafe
	// registry fails fast instead of leaving a stray account behind.
	if err := a.Registry.Init(); err != nil {
		a.errorf("%s: %v", a.P.M("初始化注册表失败", "registry init failed"), err)
		return 1
	}

	// Both secrets are generated before anything is created, so a generation
	// failure cannot leave a half-made account behind. Exactly one is issued: a
	// key account has password authentication disabled, and a password account is
	// never given a key it could not use.
	var kp *sshkey.KeyPair
	var password string
	if plan.password {
		p, err := a.RandPassword(passwordLen)
		if err != nil {
			a.errorf("%s: %v", a.P.M("生成密码失败", "password generation failed"), err)
			return 1
		}
		password = p
	} else {
		k, err := sshkey.GenerateEd25519(username + "-" + config.ManagedTag)
		if err != nil {
			a.errorf("%s: %v", a.P.M("生成密钥失败", "key generation failed"), err)
			return 1
		}
		kp = k
	}
	generation, err := a.RandHex(16)
	if err != nil || !validate.Generation(generation) {
		if err == nil {
			err = fmt.Errorf("random source returned an invalid generation")
		}
		a.errorf("%s: %v", a.P.M("生成账号世代标识失败", "generating account generation failed"), err)
		return 1
	}
	fingerprint := ""
	if kp != nil {
		fingerprint = kp.Fingerprint
	}
	permanent := !wantAuto
	createdAt := a.Now()
	var revokeDeadline time.Time
	expiresDisplay := a.P.M("永久（不会过期，也不会自动删除）", "never (does not expire or auto-delete)")
	if !permanent {
		revokeDeadline = expiry.Deadline(createdAt, hours)
		expiresDisplay = expiry.DisplayLocal(revokeDeadline)
	}
	rec := registry.Record{
		User:          username,
		Created:       createdAt.Format("2006-01-02 15:04:05 MST"),
		Expires:       expiresDisplay,
		Sudo:          wantSudo,
		Host:          host,
		Port:          port,
		Fingerprint:   fingerprint,
		AutoRevoke:    wantAuto,
		Generation:    generation,
		IdentityBound: true,
		Pending:       true,
	}
	registered := false
	// A failed invite may delete the account only after every name-scoped privilege
	// grant is confirmed gone. Grant closes its gate before it can write anything;
	// only Manager.Remove returning success opens it again. Registry cleanup keys on
	// the same gates so a crash-recovery witness survives even if the account
	// disappears out of band.
	sudoRemovalConfirmed := true
	sshdRemovalConfirmed := true
	accountCleanupConfirmed := true
	// The final chage call can make the credential usable before a helper reports
	// failure. From the instant that helper is invoked, rollback must tolerate the
	// account holder changing ordinary passwd fields or a partially successful
	// activation could let chfn/chsh hold cleanup open indefinitely.
	loginActivationStarted := false
	confirmSudoRemoved := func() error {
		err := a.removeSudoGrant(username)
		if err == nil {
			sudoRemovalConfirmed = true
		}
		return err
	}
	confirmSSHDRemoved := func() error {
		err := a.removeSSHDException(username)
		if err == nil {
			sshdRemovalConfirmed = true
		}
		return err
	}

	var cleanups []func() error
	rollback := func() error {
		a.warnf("%s", a.P.M("创建失败，正在回滚："+username, "creation failed; rolling back: "+username))
		var rollbackErrs []error
		for i := len(cleanups) - 1; i >= 0; i-- {
			if err := cleanups[i](); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		return errors.Join(rollbackErrs...)
	}
	failf := func(format string, args ...any) int {
		a.errorf(format, args...)
		a.audit("account.create", username, "fail", fmt.Sprintf(format, args...), nil)
		if err := rollback(); err != nil {
			a.errorf("%s: %v", a.P.M("回滚未完整完成，请立即人工核查", "rollback did not complete; inspect immediately"), err)
			a.audit("account.rollback", username, "fail", err.Error(), nil)
		}
		return 1
	}

	// Clear any grant a reused username left behind BEFORE the account exists, so a
	// fresh account can never inherit it. The stale auto-revoke unit is cleared
	// lower down for the same reason, but a sudo drop-in is more urgent: it is
	// name-keyed, so the instant useradd creates the account the leftover
	// /etc/sudoers.d file grants it passwordless root — while this invite records
	// sudo=no. The grant this invite actually wants is (re)written below.
	//
	// ONLY when the account does not already exist. The case this guards is a
	// reused name whose account is GONE but whose grant lingers; there, useradd
	// will mint a fresh account and the stale file must not carry over. If the name
	// is a currently-LIVE account, useradd is about to fail and this invite touches
	// nothing — stripping a live account's grant (and reloading sshd out from under
	// its invitee) on the way to that failure is a regression. The generated-name
	// path is already existence-checked; an explicit --user is not, so guard here.
	exists, lookupErr := user.NameInUse(username)
	if lookupErr != nil {
		return failf("%s: %v", a.P.M("读取本地/NSS 账号数据库失败", "reading the local/NSS account database failed"), lookupErr)
	}
	if exists {
		a.errorf("%s", a.P.M("本地或 NSS 中已存在同名账号，拒绝创建："+username,
			"an account with this name already exists locally or in NSS; refusing creation: "+username))
		return 1
	}
	// A previous revoke/rollback may have reached userdel and left a durable
	// recovery witness. Never consume that witness as a side effect of creating a
	// replacement account: the operator must finish the old transaction through
	// revoke, where its recovery state is visible and auditable. In particular,
	// creating a new generation must not depend on an invite-time mail cleanup and
	// then overwrite the only evidence needed to retry it.
	staleRec, staleRegistered, err := a.Registry.Lookup(username)
	if err != nil {
		return failf("%s: %v", a.P.M("读取同名账号的旧删除状态失败", "reading prior deletion state for this username failed"), err)
	}
	if staleRegistered && staleRec.DeletionStarted {
		return failf("%s", a.P.M(
			"同名账号存在未完成的删除恢复见证；拒绝复用用户名或覆盖登记。请先运行 revoke --user "+username+" 完成恢复。",
			"an unfinished deletion-recovery witness exists for this username; refusing to reuse the name or overwrite the registry. Run revoke --user "+username+" first to complete recovery."))
	}
	if err := errors.Join(a.removeSudoGrant(username), a.removeSSHDException(username)); err != nil {
		return failf("%s: %v", a.P.M("无法清除同名账号的遗留授权，拒绝创建", "cannot remove grants left by this username; refusing creation"), err)
	}
	// A stale scheduled command is name-keyed, so it must be gone before useradd
	// makes that name live again. Reading its recorded id before writing the new
	// intent also preserves the only direct handle to an at job from an older run.
	staleUnit, err := a.Registry.UnitFor(username)
	if err != nil {
		return failf("%s: %v", a.P.M("读取旧自动删除任务失败", "reading stale auto-delete task failed"), err)
	}
	if err := a.Scheduler.Cancel(username, staleUnit); err != nil {
		return failf("%s: %v", a.P.M("无法确认旧自动删除任务已清除", "cannot confirm stale auto-delete tasks were removed"), err)
	}
	// Cancel can remove queued work, but an older at/systemd command may already be
	// executing an old binary and waiting for this transaction's lifecycle lock. It
	// has no UID/generation arguments, so letting it resume after a same-name invite
	// would apply the old deletion intent to the new account. Refuse reuse while that
	// exact root-owned command is still visible. New binaries also make this legacy
	// command shape take a nonblocking shared barrier for the username; invite owns
	// the exclusive side, closing the start-after-scan interval without suppressing
	// revokes delayed by unrelated lifecycle work.
	legacyRevoke, err := a.runningLegacyRevoke(username)
	if err != nil {
		return failf("%s: %v", a.P.M("无法检查正在运行的旧版撤销任务，拒绝复用用户名", "cannot inspect running legacy revoke tasks; refusing username reuse"), err)
	}
	if legacyRevoke {
		return failf("%s", a.P.M(
			"检测到该用户名的旧版无世代绑定撤销进程仍在运行；已拒绝复用，请等待其退出并重新运行。",
			"a legacy revoke process without a generation binding is still running for this username; reuse was refused; wait for it to exit and retry."))
	}
	// Reserve and durably burn an identity above every currently allocated local UID
	// and GID. The registry sequence commits before useradd: a crash may waste a
	// number, but this tool never reuses it for another account generation.
	minimumID, maximumID, err := a.identityAllocationRange()
	if err != nil {
		return failf("%s: %v", a.P.M("无法确定安全的 UID/GID 分配范围", "cannot determine a safe UID/GID allocation range"), err)
	}
	reservedID, identityIsolationReady, err := a.Registry.ReserveIdentity(minimumID, maximumID)
	if err != nil {
		return failf("%s: %v", a.P.M("无法持久化预留 UID/GID", "cannot durably reserve a UID/GID"), err)
	}
	rec.UID = reservedID
	rec.SequentialID = true
	// Persist the account intent before useradd. A kill or power loss after account
	// creation must leave a registry witness even if no sudo/sshd/schedule artifact
	// exists. The reserved UID is already known and is verified against passwd as
	// soon as the helper returns.
	if err := a.Registry.Record(rec); err != nil {
		return failf("%s: %v", a.P.M("登记账号创建意图失败", "recording account creation intent failed"), err)
	}
	registered = true
	// This cleanup was registered first, so reverse-order rollback runs it last,
	// after account deletion. If deletion failed, retain the row for recovery.
	cleanups = append(cleanups, func() error {
		var unconfirmed []error
		if !sudoRemovalConfirmed {
			unconfirmed = append(unconfirmed, fmt.Errorf("sudo removal is unconfirmed; keeping registry record"))
		}
		if !sshdRemovalConfirmed {
			unconfirmed = append(unconfirmed, fmt.Errorf("sshd removal is unconfirmed; keeping registry record"))
		}
		if !accountCleanupConfirmed {
			unconfirmed = append(unconfirmed, fmt.Errorf("account artifact cleanup is unconfirmed; keeping registry record"))
		}
		if err := errors.Join(unconfirmed...); err != nil {
			return err
		}
		exists, err := user.Exists(username)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("account still exists; keeping registry record")
		}
		return a.releaseRegistryAfterCleanup(username)
	})

	// useradd can create the account before reporting an error. Close the
	// registry-removal gate before invoking it. CreatePendingIdentity returns a
	// nonzero passwd snapshot with errors that happen after it has proved the full
	// pending identity, allowing this transaction to attempt the same fail-closed
	// rollback instead of discarding evidence it already captured.
	accountCleanupConfirmed = false
	pw, err := a.Users.CreatePendingIdentityWithID(username, resolveShell(), generation, reservedID)
	if err != nil && errors.Is(err, user.ErrAccountCreationNotStarted) {
		// No account helper ran, so there is no ambiguous partial account identity to
		// recover. The last registry cleanup still confirms local absence before it
		// releases the creation-intent row.
		accountCleanupConfirmed = true
		return failf("%s: %v", a.P.M("创建用户失败", "create user failed"), err)
	}
	// Keep a separately named rollback witness. A failed MarkManagedExpected call
	// may return a zero Passwd even after usermod partially ran; overwriting this
	// value would discard the last complete identity that this transaction proved.
	rollbackIdentity := pw
	cleanups = append(cleanups, func() error {
		var causes []error
		if !sudoRemovalConfirmed {
			causes = append(causes, fmt.Errorf("sudo removal is unconfirmed; account disabled and retained"))
		}
		if !sshdRemovalConfirmed {
			causes = append(causes, fmt.Errorf("sshd removal is unconfirmed; account disabled and retained"))
		}
		mayDelete := sudoRemovalConfirmed && sshdRemovalConfirmed
		cleanupErr := errors.Join(errors.Join(causes...), a.rollbackInviteAccount(username, rec, rollbackIdentity, mayDelete, loginActivationStarted))
		if cleanupErr == nil {
			accountCleanupConfirmed = true
		}
		return cleanupErr
	})
	if err != nil {
		return failf("%s: %v", a.P.M("创建用户失败", "create user failed"), err)
	}

	rec.UID = pw.UID
	// Persist the UID while the passwd entry still carries PendingGECOS. An older
	// binary ignores the appended Pending field, but it does understand that this
	// is not the managed marker and therefore refuses deletion. Once this write is
	// durable, changing the marker is safe even for that older binary.
	if err := a.Registry.Record(rec); err != nil {
		return failf("%s: %v", a.P.M("登记新账号身份失败", "recording the new account identity failed"), err)
	}
	// Put an account-level login gate in place before any deferred work is
	// drained, the pending marker is promoted, or a credential is installed.
	// useradd's initial password lock is not enough for a key-based account: a
	// public key bypasses that lock, while an account expiry is enforced for both
	// key and password authentication. If this process is killed at any later
	// setup boundary, the account therefore remains unusable until a subsequent
	// successful invite installs its requested lifetime below.
	if err := a.Users.DisableLogin(username); err != nil {
		return failf("%s: %v", a.P.M("建立新账号的安全失效状态失败", "establishing the new account's fail-closed login state failed"), err)
	}
	// Generated names combine a fresh random suffix with the monotonic UID/GID pair,
	// so neither name nor numeric identity is being reused by this tool. Clear and
	// verify once without the old polling-cycle delay. Explicit operator-selected
	// names retain the full drain because they may intentionally reuse a historical
	// name even though their numeric identity is fresh.
	quiesce := a.quiesceScheduledAccount
	if generatedUsername && rec.SequentialID && identityIsolationReady {
		quiesce = a.quiesceScheduledAccountImmediate
	} else if generatedUsername {
		a.info(a.P.M(
			"登记刚从旧版迁移，历史已释放 UID 尚未跨过一次性隔离窗口；本次将同步等待约 65 秒，后续自动用户名创建不再等待。",
			"the registry was just migrated from an older release, so historically released UIDs have not crossed the one-time isolation window; this invite waits about 65 seconds, and later generated-name invites do not."))
	} else {
		a.info(a.P.M(
			"显式用户名可能复用历史名称；为防止旧 cron/at 缓存任务跨世代执行，将同步等待约 65 秒完成清场。",
			"an explicit username may reuse a historical name; waiting about 65 seconds to prevent cached cron/at work from crossing account generations."))
	}
	if err := quiesce(username, pw); err != nil {
		return failf("%s: %v", a.P.M("无法清除同名账号或复用 UID 的遗留 cron/at 任务", "cannot clear cron/at work left by the reused username or UID"), err)
	}
	// The drain intentionally gives daemon-cached work a full polling cycle to
	// start. Re-scan now, while the account is still expired, password-locked,
	// credential-less, and marked pending. A legacy command found here triggers the
	// ordinary rollback before this identity can become usable.
	legacyRevoke, err = a.runningLegacyRevoke(username)
	if err != nil {
		return failf("%s: %v", a.P.M("任务清场后无法复查正在运行的旧版撤销任务", "cannot recheck running legacy revoke tasks after deferred-job cleanup"), err)
	}
	if legacyRevoke {
		return failf("%s", a.P.M(
			"任务清场期间启动了该用户名的旧版无世代绑定撤销进程；已回滚新账号，请等待旧任务退出后重试。",
			"a legacy revoke process without a generation binding started during deferred-job cleanup; the new account was rolled back; wait for the old task to exit before retrying."))
	}
	// Delivery can recreate /var/mail/USER during the deliberate daemon drain even
	// though pending-account creation swept an older generation's spool. Run the
	// same identity-checked cleanup again while this account is still expired,
	// password-locked, pending, credential-less, and without a Home.
	if err := a.Users.ClearManagedMailExpected(username, pw); err != nil {
		return failf("%s: %v", a.P.M(
			"任务清场后无法安全清除同名旧邮件，拒绝激活账号",
			"cannot safely clear same-name stale mail after deferred-job cleanup; refusing to activate the account"), err)
	}
	if err := a.accountStillMatches(username, pw); err != nil {
		return failf("%s: %v", a.P.M(
			"创建账号目录前账号身份发生变化",
			"the account identity changed before creating its Home"), err)
	}
	// Keep the Home absent until every inherited cron/at job and residual process
	// has been drained. A previous account generation therefore has nowhere to
	// plant authorized_keys or shell startup files that the new identity can inherit.
	if err := a.Users.CreateManagedHomeExpected(username, pw); err != nil {
		return failf("%s: %v", a.P.M(
			"任务清场后无法安全创建账号目录，拒绝激活账号",
			"cannot safely create the account Home after deferred-job cleanup; refusing to activate the account"), err)
	}
	if err := a.accountStillMatches(username, pw); err != nil {
		return failf("%s: %v", a.P.M(
			"创建账号目录期间账号身份发生变化",
			"the account identity changed while creating its Home"), err)
	}
	// The requested lifetime starts only after the deliberate deferred-job drain;
	// otherwise that safety wait would shorten a nominal one-hour invite. Persist
	// the adjusted display and absolute target while the account is still pending.
	createdAt = a.Now()
	rec.Created = createdAt.Format("2006-01-02 15:04:05 MST")
	if !permanent {
		revokeDeadline = expiry.Deadline(createdAt, hours)
		expiresDisplay = expiry.DisplayLocal(revokeDeadline)
		rec.Expires = expiresDisplay
	}
	if err := a.Registry.Record(rec); err != nil {
		return failf("%s: %v", a.P.M("登记任务清场后的账号时间失败", "recording the account time after deferred-job cleanup failed"), err)
	}
	managedIdentity, err := a.Users.MarkManagedExpected(username, generation, pw)
	if err != nil {
		return failf("%s: %v", a.P.M("完成新账号身份标记失败", "finalizing the new account identity marker failed"), err)
	}
	pw = managedIdentity
	rollbackIdentity = managedIdentity
	completed := rec
	completed.Pending = false
	if err := a.Registry.Record(completed); err != nil {
		return failf("%s: %v", a.P.M("完成新账号身份登记失败", "finalizing the new account identity record failed"), err)
	}
	rec = completed

	// The preflight had to PREDICT this account's groups, because it ran before the
	// account existed. Now they are real — and sshd decides AllowGroups/DenyGroups
	// on exactly them. Re-run the same check against the real group set before
	// anything is printed: `useradd` only gives the account a group of its own
	// name when USERGROUPS_ENAB is on, and on a host that puts new accounts in a
	// shared group instead (openSUSE ships GROUP=100 "users"), a `DenyGroups users`
	// rule would block the credential while the invite claimed config verification.
	groups, groupsErr := user.Groups(pw)
	if groupsErr != nil {
		return failf("%s: %v", a.P.M("无法可靠读取新账号的用户组", "cannot reliably read the new account's groups"), groupsErr)
	}
	if err := a.accountStillMatches(username, pw); err != nil {
		return failf("%s: %v", a.P.M("读取用户组期间账号身份发生变化", "the account identity changed while resolving its groups"), err)
	}
	if !a.confirmLogin(username, groups, &plan) {
		return failf("%s", a.P.M("按该账号的真实用户组复核后，sshd 有效配置检查发现此凭据的阻碍",
			"re-checked against the account's real groups: the effective sshd config check found a blocker for this credential"))
	}
	if err := a.accountStillMatches(username, pw); err != nil {
		return failf("%s: %v", a.P.M("复核 sshd 配置期间账号身份发生变化", "the account identity changed during the sshd configuration check"), err)
	}

	if plan.password {
		if err := a.Users.SetPassword(username, password); err != nil {
			return failf("%s: %v", a.P.M("设置密码失败", "set password failed"), err)
		}
	} else {
		if err := a.Users.DisablePasswordForKeyLogin(username); err != nil {
			return failf("%s: %v", a.P.M("禁用密码登录失败", "disable password login failed"), err)
		}
		if err := sshkey.WriteAuthorizedKeys(pw.Home, pw.UID, pw.GID, kp.AuthorizedKey); err != nil {
			return failf("%s: %v", a.P.M("写入 authorized_keys 失败", "write authorized_keys failed"), err)
		}
	}

	// The sshd exception goes in only once the account (and its key) exist, and it
	// is confirmed in the effective config against the account's real groups before
	// sshd is reloaded. Grant attempts its own rollback on failure; the CLI retries removal
	// independently before account rollback can free the username.
	sshdDropIn := ""
	if plan.fixSSHD {
		sshdRemovalConfirmed = false
		res, err := a.SSHD.Grant(username, groups, plan.report)
		if err != nil {
			cleanupErr := confirmSSHDRemoved()
			return failf("%s: %v", a.P.M("为该账号开启 sshd 公钥登录失败", "enabling the sshd public-key login for this account failed"), errors.Join(err, cleanupErr))
		}
		sshdDropIn = res.Path
		cleanups = append(cleanups, confirmSSHDRemoved)
		a.success(a.P.M("已在 sshd 配置中为该账号单独开启公钥认证（全局策略未改动）："+res.Path,
			"public-key authentication enabled in the sshd config for this account only (the global policy is untouched): "+res.Path))
		// Two independent things must both hold before the invite may say "verified":
		//   1. the reload request succeeded (res.Reloaded). `sshd -t` forks a fresh sshd
		//      to parse the file, which says nothing about the one already serving the
		//      port, so a reload request we could not complete means unverified.
		//   2. nothing about this login remained unevaluable (report.Unverifiable): the
		//      drop-in lifts the blockers we understood, but an address-qualified
		//      AllowUsers we could not evaluate still stands, and the invitee's source
		//      address decides it. Lifting the pubkey switch does not make that certain.
		switch {
		case !res.Reloaded:
			plan.verified = false
			plan.unverified = "sshd could not be asked to re-read its configuration; reload it yourself"
			a.warnf("%s", a.P.M("未能通知正在运行的 sshd 重新读取配置。若 sshd 是常驻进程，请手动运行 `sshd -t && systemctl reload ssh`，使配置变更生效（socket 激活的 sshd 无需 reload）。",
				"could not ask the running sshd to re-read its configuration. If sshd is a long-running process, run `sshd -t && systemctl reload ssh` yourself so the configuration change takes effect (a socket-activated sshd needs no reload)."))
		case len(plan.report.Unverifiable) > 0:
			plan.verified = false
			plan.unverified = plan.report.Unverifiable[0]
		default:
			plan.verified = true
			plan.unverified = ""
		}
	}

	sudoGranted := false
	if wantSudo {
		// Grant can make the drop-in live before a later verification step fails.
		// Close the deletion gate before calling it so both that partial failure and a
		// later transaction failure retain the username until removal is confirmed.
		sudoRemovalConfirmed = false
		if err := a.Sudoers.Grant(username); err != nil {
			// Grant may have written a live drop-in before its verification step
			// failed; remove it unconditionally so a failed grant can never leave an
			// unregistered NOPASSWD grant behind. Remove only ever touches the
			// managed-prefixed file for this user, so it is safe to call blindly.
			cleanupErr := confirmSudoRemoved()
			return failf("%s: %v", a.P.M("sudo 授权失败，已拒绝创建账号", "sudo grant failed; refusing to create the account"),
				errors.Join(err, cleanupErr))
		}
		sudoGranted = true
		cleanups = append(cleanups, confirmSudoRemoved)
	}

	// Whoever revokes this account later runs the binary at InstallPath — the
	// auto-revoke timer's ExecStart, and the revoke command printed in the invite.
	// If a grant was written that an older binary does not know how to remove (the
	// sshd exception), that binary would delete the account and leave the grant
	// behind forever. So refresh the installed command whenever this invite created
	// something that needs cleaning up, not only when a timer is being scheduled.
	if wantAuto || sshdDropIn != "" {
		if err := a.ensureStableInstalled(); err != nil {
			return failf("%s: %v", a.P.M("无法安装或验证稳定命令", "cannot install or verify the stable command"), err)
		}
	}

	// Commit the final grant state before creating a scheduler task. For an
	// auto-revoke account this row is the durable identity intent the task checks.
	rec.Sudo = sudoGranted
	if err := a.Registry.Record(rec); err != nil {
		return failf("%s: %v", a.P.M("登记注册表失败", "registry record failed"), err)
	}

	autoUnit := ""
	autoScheduled := false
	if wantAuto {
		// The auto-revoke task's ExecStart runs the installed stable command, so a
		// binary must be present at InstallPath (ensured above), otherwise the timer
		// would fire and fail on a non-installed run.
		if err := fsutil.RootSafeFile(a.InstallPath); err != nil {
			return failf("%s: %v", a.P.M("稳定命令不安全", "the stable command is unsafe"), err)
		}
		unit, err := a.Scheduler.Schedule(username, pw.UID, generation, revokeDeadline)
		if err != nil {
			return failf("%s: %v", a.P.M("自动删除任务创建失败，已拒绝创建临时账号", "auto-delete scheduling failed; refusing to create the temporary account"), err)
		}
		autoUnit = unit
		autoScheduled = true
		cleanups = append(cleanups, func() error { return a.Scheduler.Cancel(username, unit) })
		rec.AutoUnit = unit
		if err := a.Registry.Record(rec); err != nil {
			return failf("%s: %v", a.P.M("登记自动删除任务失败", "recording the auto-delete task failed"), err)
		}
	}

	// The pending account was deliberately expired and password-locked before the
	// deferred-job drain. Credentials replace the password lock, but the past-date
	// expiry remains the authentication-method-neutral gate until sudo/sshd policy,
	// the durable registry state, and any automatic revoke task are all complete.
	// This is the transaction's activation point: install either the requested
	// expiry or an explicit never-expire value only after every rollback witness is
	// in place. Skipping it for a permanent invite would leave the credential
	// unusable forever.
	loginActivationStarted = true
	if permanent {
		if err := a.Users.ClearExpiry(username); err != nil {
			return failf("%s: %v", a.P.M("恢复永久账号的登录有效期失败", "restoring never-expire login state for the permanent account failed"), err)
		}
	} else {
		if err := a.Users.SetExpiry(username, expiry.Date(revokeDeadline)); err != nil {
			return failf("%s: %v", a.P.M("设置到期失败", "set expiry failed"), err)
		}
	}

	if err := a.printInvite(inviteBundle{
		user: username, host: host, port: port, hours: hours,
		sudo: sudoGranted, auto: autoScheduled, autoUnit: autoUnit,
		permanent: permanent, expires: expiresDisplay,
		registered: registered, kp: kp, password: password,
		sshdDropIn: sshdDropIn, verified: plan.verified, unverified: plan.unverified,
	}); err != nil {
		return failf("%s: %v", a.P.M("邀请凭据输出失败", "writing invite credentials failed"), err)
	}
	a.audit("account.create", username, "ok", "", map[string]string{
		"host":        host,
		"port":        fmt.Sprintf("%d", port),
		"sudo":        ynStr(sudoGranted),
		"auto":        ynStr(autoScheduled),
		"registered":  ynStr(registered),
		"fingerprint": fingerprint,
		"login":       loginKind(plan),
		"sshd_dropin": orNone(sshdDropIn),
	})
	if registered {
		a.success(a.P.M("临时账号已创建并登记："+username, "temporary account created and registered: "+username))
	} else {
		a.warnf("%s", a.P.M("临时账号已创建但未登记："+username, "temporary account created but not registered: "+username))
	}
	return 0
}

// rollbackInviteAccount tears down an account created by a failed invite. It
// never deletes by name until the completed registry identity is available, all
// name-scoped grants are confirmed gone, login is disabled, and every process
// carrying the UID is confirmed terminated. Any uncertainty retains both the
// account and the registry witness for manual recovery.
func (a *App) rollbackInviteAccount(username string, rec registry.Record, expected user.Passwd, mayDelete, loginActivationStarted bool) error {
	if rec.User != username || !rec.IdentityBound || !validate.Generation(rec.Generation) ||
		expected.Name != username || !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) ||
		!validate.ManagedHome(username, expected.Home) || expected.Shell == "" {
		return fmt.Errorf("account identity is incomplete; account and registry record retained")
	}
	if rec.UID > 0 && rec.UID != expected.UID {
		return fmt.Errorf("account identity differs from the durable registry witness; account and registry record retained")
	}
	managedMarker := user.MatchesManagedGeneration(expected, rec.Generation)
	pendingMarker := rec.Pending && user.MatchesPendingGeneration(expected, rec.Generation)
	if !managedMarker && !pendingMarker {
		return fmt.Errorf("account generation marker does not match rollback state; account and registry record retained")
	}
	identityMatches := func(expected, current user.Passwd) bool { return expected == current }
	stillMatches := a.accountStillMatches
	deleteExpected := a.Users.DeleteExpectedExact
	if loginActivationStarted {
		identityMatches = user.SameAccountIdentity
		stillMatches = a.revokeAccountStillMatches
		deleteExpected = a.Users.DeleteExpected
	}
	pw, exists, err := a.lookupUser(username)
	if err != nil {
		return fmt.Errorf("verify rollback account identity: %w", err)
	}
	if !exists {
		if rec.DeletionStarted {
			if !mayDelete {
				return nil
			}
			return a.reconcileDeletionStarted(rec)
		}
		if mayDelete {
			// The account vanished after this process captured its complete identity.
			// Enter UID-only recovery before the narrow mail sweep so an unlink/fsync
			// failure cannot leave an ordinary pending row that a later revoke drops.
			if err := a.persistDeletionStarted(rec, true, expected); err != nil {
				return fmt.Errorf("persist rollback deletion recovery: %w", err)
			}
			return deleteExpected(username, expected, func() error { return nil })
		}
		return nil
	}
	if !identityMatches(expected, pw) {
		return fmt.Errorf("account identity changed before rollback; account and registry record retained")
	}
	if !mayDelete {
		if err := stillMatches(username, expected); err != nil {
			return fmt.Errorf("verify retained account before login disable: %w", err)
		}
		if err := a.Users.DisableLogin(username); err != nil {
			return fmt.Errorf("disable retained account: %w", err)
		}
		if err := a.quiesceScheduledAccountWith(username, expected, stillMatches); err != nil {
			return fmt.Errorf("quiesce retained account cron/at work and processes: %w", err)
		}
		return nil
	}
	stage, err := a.teardownLocalAccountWith(username, expected, func() error {
		return a.persistDeletionStarted(rec, true, expected)
	}, stillMatches, deleteExpected)
	if err != nil {
		return fmt.Errorf("fail-closed account teardown stopped at stage %d: %w", stage, err)
	}
	return nil
}

// ynStr renders a bool as "yes"/"no" for audit fields.
func ynStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// inviteBundle is everything the printed invite needs. It is a struct because
// the invite's honesty now depends on several facts at once (which secret was
// issued, whether sshd was asked, whether the claim was verified), and a
// positional argument list that long is one transposition away from printing a
// lie.
type inviteBundle struct {
	user, host  string
	port, hours int
	sudo, auto  bool
	permanent   bool
	expires     string
	autoUnit    string
	registered  bool
	kp          *sshkey.KeyPair // nil for a password invite
	password    string          // empty for a key invite
	sshdDropIn  string          // empty when sshd was not touched
	verified    bool            // the effective-config check completed without a blocker or unknown
	unverified  string          // why it could not be confirmed; set exactly when verified is false
}

func loginKind(p loginPlan) string {
	if p.password {
		return "password"
	}
	return "key"
}

// byPassword reports whether this invite's credential is a password. Exactly one
// secret is ever issued, so a non-empty password is what distinguishes the two
// kinds of invite.
func (b inviteBundle) byPassword() bool { return b.password != "" }

// loginLine renders the invite's Login: field. It is a computed value, never a
// literal: the old invite asserted "SSH key only" on every host, including the
// ones where sshd would refuse the key.
func (b inviteBundle) loginLine() string {
	login := "SSH key only"
	if b.byPassword() {
		login = "password"
	}
	if b.verified {
		return login + " (verified against the effective sshd config)"
	}
	reason := b.unverified
	if reason == "" {
		reason = "the effective sshd config could not be read"
	}
	return login + " (UNVERIFIED: " + reason + ")"
}

func (a *App) printInvite(b inviteBundle) error {
	var out bytes.Buffer
	defer func() { clear(out.Bytes()) }()
	if b.kp != nil {
		defer clear(b.kp.PrivatePEM)
	}
	yesno := func(v bool) string {
		if v {
			return "yes"
		}
		return "no"
	}
	passwordLine := "disabled"
	if b.byPassword() {
		passwordLine = "enabled (this invite's only credential)"
	}
	fmt.Fprintf(&out, `
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: %s
Port: %d
User: %s
Expires: %s
Sudo: %s
Login: %s
Password login: %s
Auto revoke: %s
Auto revoke unit: %s
Sshd exception: %s
`,
		b.host, b.port, b.user, b.expires, yesno(b.sudo),
		b.loginLine(), passwordLine, yesno(b.auto), orNone(b.autoUnit), orNone(b.sshdDropIn))

	// The credential only. The SSH login command that used to sit here was dropped:
	// the header carries the Host, Port, and User to build it from, and the noise
	// was not worth it for a recipient who runs ssh.
	if b.byPassword() {
		fmt.Fprintf(&out, "\n%s\n%s\n",
			a.P.M("登录密码（只显示这一次）:", "Login password (shown only once):"), b.password)
	} else {
		fmt.Fprintf(&out, `
%s
cat > './%s.key' <<'EOF_KEY'
%sEOF_KEY
chmod 600 './%s.key'
`,
			a.P.M("保存私钥命令:", "Save private key command:"), b.user, b.kp.PrivatePEM, b.user)
	}

	if b.sshdDropIn != "" {
		fmt.Fprint(&out, "\n"+a.P.M(
			"Sshd 提示: 已为该账号单独写入一个 sshd 例外（仅 Match User 块，全局策略未改动）；撤销时会删除该文件并 reload sshd。",
			"Sshd note: a per-account sshd exception was written (a Match User block only; the global policy is untouched). Revoking deletes that file and reloads sshd.")+"\n")
	}
	if b.byPassword() {
		fmt.Fprint(&out, "\n"+a.P.M(
			"密码提示: 密码登录可被全网爆破，且必须以明文交付；这是本工具最弱的一种授权方式，用完请立即撤销。",
			"Password note: a password login is brute-forceable from anywhere and must be delivered in the clear. This is the weakest grant this tool issues; revoke as soon as you are done.")+"\n")
	}
	if b.permanent {
		fmt.Fprint(&out, "\n"+a.P.M(
			"永久账号提示: 未选择自动删除，此账号不会过期、不会被自动删除；用完请手动撤销（revoke）。",
			"Permanent-account note: auto-delete was not chosen, so this account does not expire and is not auto-deleted. Revoke it by hand when done.")+"\n")
	}
	secret := a.P.M("私钥", "private key")
	if b.byPassword() {
		secret = a.P.M("密码", "password")
	}
	fmt.Fprint(&out, "\n"+a.P.M(
		"安全提醒: "+secret+"只显示这一次、服务器不保存；仅通过可信私聊发送；用完立即撤销。",
		"Security notes: the "+secret+" is shown only once and not stored on the server; send only via trusted private chat; revoke immediately after use.")+
		"\n\n----- END LINUX TEMP ADMIN INVITE -----\n")
	_, err := a.Out.Write(out.Bytes())
	return err
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

func yesish(s string) bool { return strings.EqualFold(s, "y") || strings.EqualFold(s, "yes") }

func noish(s string) bool { return strings.EqualFold(s, "n") || strings.EqualFold(s, "no") }

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// ensureStableInstalled makes sure the binary at InstallPath can actually carry
// out the auto-revoke this invite is about to schedule.
//
// The scheduled task executes whatever sits at InstallPath — not this process.
// So a binary OLDER than this one is not merely stale, it is a binary that does
// not know about everything this invite created: an older revoke deletes the
// account and its registry row while leaving this version's sshd exception
// behind forever, with the row that would have named it now gone. That is the
// default upgrade path (a host still carrying the previous release, an operator
// running a freshly built binary from their home directory), so it is not an
// edge case.
//
// An older binary is therefore replaced by this one. A newer or equal one is
// left alone. An installed command that cannot be safely identified aborts the
// invite, because executing or overwriting an untrusted root path is unsafe.
func (a *App) ensureStableInstalled() error {
	if a.Selfmanage == nil {
		return fmt.Errorf("self-manager not configured")
	}
	force := false
	installed, versionErr := a.Selfmanage.InstalledVersion()
	if versionErr == nil {
		if strings.HasSuffix(buildinfo.Version, "-dev") {
			// A development build is not ordered against releases. Install these exact
			// bytes so its scheduled cleanup always runs the code creating the account.
			force = true
		} else if !version.Greater(buildinfo.Version, installed) {
			return nil
		} else {
			a.info(fmt.Sprintf(a.P.M("已安装的稳定命令较旧（%s → %s）；自动删除任务由它执行，故一并升级。",
				"the installed stable command is older (%s -> %s); the auto-delete task runs it, so it is upgraded too."),
				installed, buildinfo.Version))
			force = true
		}
	} else if !errors.Is(versionErr, selfmanage.ErrNotInstalled) {
		return versionErr
	}
	bin, err := a.readRunningBinary()
	if err != nil {
		return err
	}
	if _, err = a.Selfmanage.Install(bin, force); err != nil {
		return err
	}
	installed, err = a.Selfmanage.InstalledVersion()
	if err != nil {
		return fmt.Errorf("verify installed command version: %w", err)
	}
	if installed != buildinfo.Version {
		return fmt.Errorf("installed command reports %s, want %s", installed, buildinfo.Version)
	}
	return nil
}

func resolveShell() string {
	for _, s := range []string{config.DefaultShell, "/bin/sh"} {
		if fi, err := os.Stat(s); err == nil && fi.Mode()&0o111 != 0 {
			return s
		}
	}
	return "/bin/sh"
}

// detectOrPromptHost resolves the invite's Host. Local-interface inspection sends
// no traffic. Fixed-address cloud metadata probes avoid DNS, redirects, and
// environment proxies, but may traverse the local or cloud-provider network. The
// external echo services disclose this server's address to a public third party,
// so they stay behind an explicit yes. Either way the result is offered as a
// default the operator must confirm or override. Metadata is unauthenticated and
// a multi-homed box can present the wrong public IP, so silently accepting either
// source could direct the invite (and a password) to the wrong SSH server.
func (a *App) detectOrPromptHost() string {
	// A local result can come from an unauthenticated HTTP metadata response or a
	// routable address on one of this host's interfaces. Neither proves that the
	// address is the SSH endpoint the invitee should use, so require an explicit
	// prompt and treat it only as the default.
	if ip, ok := a.Detector.LocalPublicIP(2 * time.Second); ok {
		a.info(fmt.Sprintf(a.P.M("使用探测到的公网 IP：%s（如需域名或其他地址请用 --host）",
			"using the detected public IP: %s (use --host for a domain or a different address)"), ip))
		return a.promptHost(ip)
	}
	queryExternal, answered := a.promptYesNo(a.P.M("本机未探测到公网 IP。是否向外部服务查询？[y/N]: ",
		"No public IP found locally. Ask an external service? [y/N]: "), false)
	if !answered {
		return ""
	}
	if queryExternal {
		if ip, ok := a.Detector.PublicIP(5 * time.Second); ok {
			return a.promptHost(ip)
		}
		a.warnf("%s", a.P.M("外部查询失败，请手动输入", "external lookup failed; enter manually"))
	}
	return a.promptHost("")
}

// promptHost asks for the Host, offering detected (when non-empty) as the
// default that a blank line accepts.
func (a *App) promptHost(detected string) string {
	if detected == "" {
		return a.prompt(a.P.M("请输入服务器公网 IP/域名: ", "Enter server public IP/domain: "))
	}
	msg := fmt.Sprintf(a.P.M("服务器公网 IP/域名 [%s]: ", "Server public IP/domain [%s]: "), detected)
	if h := a.prompt(msg); h != "" {
		return h
	}
	return detected
}
