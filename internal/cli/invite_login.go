package cli

import (
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"strings"
)

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
			// Mirror the blocker path's a.SSHD == nil guard below. An unwired sshd
			// manager must not travel as a repair authorization through the deferred
			// phase: the repair is applied after useradd and after the key is
			// written, where a nil dereference would abort mid-transaction and leave
			// a created account with a completed registry row. With no repair
			// authorized, confirmLogin fails closed before any credential lands.
			fixSSHD:    fix == "yes" && a.SSHD != nil,
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
