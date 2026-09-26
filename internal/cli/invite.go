package cli

import (
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"os"
	"strconv"
	"strings"
	"time"
)

func (a *App) invite(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	opts, ok := a.parseInviteOptions(args)
	if !ok {
		return 1
	}
	username, generatedUsername, ok := a.resolveInviteUsername(opts.username, opts.prefix)
	if !ok {
		return 1
	}

	grantSudo := opts.sudo

	if !a.checkInvitePreconditions(opts, username, generatedUsername) {
		return 1
	}

	// Check login before resolving Host: discovery may contact an external IP
	// service. Rejected invites must not cause that disclosure or needless prompts.
	// The final summary includes any SSH change before the operator confirms.
	plan, ok := a.planLogin(username, opts.passwordLogin, opts.fixSSHD, opts.yes)
	if !ok {
		return 1
	}

	// A Host that was not given has to be detected or asked for; whatever comes back
	// is untrusted input and is validated like any other.
	host := opts.host
	if host == "" {
		host = a.detectOrPromptHost()
		if !validate.Host(host) {
			a.errorf("%s", a.P.M("Host 不合法："+host, "invalid host: "+host))
			return 1
		}
	}

	port := opts.port
	if !opts.portSet {
		var err error
		port, err = a.detectSSHPort()
		if err != nil {
			a.errorf("%s: %v", a.P.M("无法可靠探测 SSH 端口；请用 --port 明确指定",
				"could not reliably detect the SSH port; specify it with --port"), err)
			return 1
		}
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
		if opts.yes {
			grantSudo = "no"
		} else {
			grantSudo = "yes"
		}
	}
	hours, wantAuto, ok := a.resolveInviteLifetime(opts.autoRevoke, opts.hours, opts.hoursSet, opts.yes)
	if !ok {
		return 1
	}

	// Work out what would have to be installed BEFORE the summary, so the summary
	// can name it and the YES can be its consent. This only decides — the install
	// itself is a host change and waits until after the confirmation.
	depPkgs, ok := a.planDeps(grantSudo == "yes", plan.password, opts.installDeps, opts.noInstallDeps, opts.yes)
	if !ok {
		return 1
	}

	if !opts.yes {
		// A permanent account (auto-delete off) has no lifetime, so the summary shows
		// its expiry as "permanent" instead of an hours figure that would not apply.
		lifetime := fmt.Sprintf(a.P.M("有效期=%d小时", "expires-in=%dh"), hours)
		if !wantAuto {
			lifetime = a.P.M("永久", "permanent")
		}
		a.printf("\n%s\n  user=%s host=%s port=%d %s sudo=%s auto-delete=%s\n  login=%s\n",
			a.P.M("即将创建一次性临时账号：", "About to create a one-time temporary account:"),
			username, host, port, lifetime, a.choiceDisplay(grantSudo), a.choiceDisplay(ynStr(wantAuto)), a.loginSummary(plan, username))
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
			return a.runInvite(invitePlan{
				username: username, host: host, port: port, hours: hours,
				wantSudo: grantSudo == "yes", wantAuto: wantAuto,
				login: plan, generatedUsername: generatedUsername,
			})
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

// resolveInviteLifetime combines the default terminal flow into one question.
// Explicit flags and piped input keep their existing auto-delete choice rules.
func (a *App) resolveInviteLifetime(autoRev string, hours int, hoursSet, yes bool) (int, bool, bool) {
	wantAuto := autoRev != "no"
	if !yes && !hoursSet && wantAuto && a.StdinIsTTY() {
		return a.promptLifetime(hours, autoRev == "ask")
	}
	if autoRev == "ask" && !yes {
		var ok bool
		wantAuto, ok = a.promptYesNo(a.P.M("是否到期后自动删除该用户？[Y/n]: ", "Auto-delete this user on expiry? [Y/n]: "), true)
		if !ok {
			return hours, false, false
		}
	}
	if !wantAuto && hoursSet {
		a.warnf("%s", a.P.M("未选择自动删除，账号将永久有效，--hours 被忽略。",
			"auto-delete is off, so the account is permanent and --hours is ignored."))
	}
	return hours, wantAuto, true
}

// promptLifetime accepts permanence only through an explicit keyword. A typo
// never disables expiry; EOF cancels and invalid piped input cannot loop.
func (a *App) promptLifetime(current int, allowPermanent bool) (int, bool, bool) {
	msg := fmt.Sprintf(a.P.M("有效期（小时，1-%d）[%d]: ", "Lifetime in hours (1-%d) [%d]: "), config.MaxExpireHours, current)
	if allowPermanent {
		msg = fmt.Sprintf(a.P.M("有效期（小时，1-%d；永久请输入 never）[%d]: ",
			"Lifetime in hours (1-%d; never for a permanent account) [%d]: "), config.MaxExpireHours, current)
	}
	for {
		fmt.Fprint(a.Err, msg)
		answer, ok := a.readLine()
		if !ok {
			a.warnf("%s", a.P.M("输入已结束，已取消", "input ended; cancelled"))
			return current, false, false
		}
		if answer == "" {
			return current, true, true
		}
		if allowPermanent && strings.EqualFold(answer, "never") {
			return current, false, true
		}
		if hours, err := strconv.Atoi(answer); err == nil && validate.Hours(hours) {
			return hours, true, true
		}
		a.warnf("%s", a.P.M(fmt.Sprintf("请输入 1-%d 之间的整数", config.MaxExpireHours),
			fmt.Sprintf("enter an integer between 1 and %d", config.MaxExpireHours)))
		if !a.StdinIsTTY() {
			return current, false, false
		}
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

// invitePlan carries resolved choices from planning into the account transaction.
// Runtime identity and cleanup witnesses are kept separately on inviteTransaction.
type invitePlan struct {
	username          string
	host              string
	port              int
	hours             int
	wantSudo          bool
	wantAuto          bool
	login             loginPlan
	generatedUsername bool
}

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
