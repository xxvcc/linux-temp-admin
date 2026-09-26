package cli

import (
	"errors"
	"flag"
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/expiry"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"strings"
	"time"
)

type doctorResult struct {
	failures int
}

func (r *doctorResult) fail() { r.failures++ }

func (r *doctorResult) merge(stage doctorResult) { r.failures += stage.failures }

func (r doctorResult) status() int {
	if r.failures > 0 {
		return 1
	}
	return 0
}

type doctorRegistryState struct {
	records  []registry.Record
	readable bool
}

func (a *App) doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	if !a.parseFlags(fs, args) {
		return 1
	}

	var result doctorResult
	result.merge(a.doctorBaseEnvironment())
	result.merge(a.doctorSSHDProbe())
	registryState, registryResult := a.doctorRegistryIdentity()
	result.merge(registryResult)
	result.merge(a.doctorRegistryMarkers(registryState))
	result.merge(a.doctorOrphanedArtifacts())
	result.merge(a.doctorScheduleValidity(registryState))
	return result.status()
}

func (a *App) doctorBaseEnvironment() doctorResult {
	var result doctorResult
	a.info(a.P.M("linux-temp-admin 诊断报告", "linux-temp-admin doctor report"))
	a.info(fmt.Sprintf(a.P.M("运行版本：%s", "running version: %s"), buildinfo.Version))
	// The version that matters most is not this process's but the one installed at
	// InstallPath: the auto-revoke timer's ExecStart runs THAT binary, so a stale or
	// missing installed copy is a real diagnostic concern. Surface it, and flag a
	// mismatch.
	switch v, state := a.installedCommandVersion(); state {
	case "absent":
		a.warnf("%s", a.P.M("已安装命令：未安装（自动删除任务需要它）",
			"installed command: not installed (the auto-delete task needs it)"))
		result.fail()
	case "unreadable":
		a.warnf("%s%s", a.P.M("无法读取已安装命令的版本：", "could not read the installed command's version: "), a.InstallPath)
		result.fail()
	case "ok":
		if v == buildinfo.Version {
			a.success(fmt.Sprintf(a.P.M("已安装命令版本：%s", "installed command version: %s"), v))
		} else {
			a.warnf("%s", fmt.Sprintf(a.P.M("已安装命令版本 %s 与运行中的 %s 不一致（自动删除任务执行的是已安装的那份，可用 upgrade 或 install 对齐）",
				"installed command version %s differs from the running %s (the auto-delete task runs the installed one; align with upgrade or install)"), v, buildinfo.Version))
			result.fail()
		}
	}
	if a.Geteuid() == 0 {
		a.success(a.P.M("当前以 root 运行。", "running as root."))
	} else {
		a.warnf("%s", a.P.M("当前不是 root；invite/revoke 需要 root。", "not running as root; invite/revoke require root."))
	}
	if err := user.CheckPidfd(); err != nil {
		a.warnf("%s: %v", a.P.M("pidfd 不可用；无法在 PID 复用安全的前提下终止临时账号进程",
			"pidfd is unavailable; temporary-account processes cannot be terminated safely across PID reuse"), err)
		result.fail()
	} else {
		a.success(a.P.M("pidfd 进程撤销能力可用。", "pidfd process revocation is available."))
	}
	var presentDeps []string
	for _, d := range sysinfo.RequiredDeps(true, true) {
		if d.Present {
			presentDeps = append(presentDeps, d.Label)
		} else {
			a.warnf("%s%s", a.P.M("缺少依赖：", "missing dependency: "), d.Label)
			if doctorDependencyIsFatal(d.Label) {
				result.fail()
			}
		}
	}
	if len(presentDeps) > 0 {
		a.success(a.P.M("依赖检查通过：", "dependencies found: ") + strings.Join(presentDeps, ", "))
	}
	a.info(a.P.M("包管理器：", "package manager: ") + orNone(sysinfo.PackageManager()))
	a.info(a.P.M("init 系统：", "init system: ") + sysinfo.InitSystem())
	sshPort, sshPortErr := a.detectSSHPort()
	if sshPortErr != nil {
		a.warnf(a.P.M("SSH 端口探测不完整（暂用 %d）：%v", "SSH port detection was incomplete (best effort %d): %v"), sshPort, sshPortErr)
		result.fail()
	} else {
		a.info(fmt.Sprintf(a.P.M("探测到 SSH 端口：%d", "detected SSH port: %d"), sshPort))
	}
	return result
}

func (a *App) doctorSSHDProbe() doctorResult {
	var result doctorResult
	// Probe with a name shaped like a fresh invite account: brand new, on no
	// whitelist, and in no group but its own. The probe name is passed to
	// SSHDConfig, not just to the check: `sshd -T` alone cannot see `Match User`
	// blocks, so asking the global view a per-user question would let doctor
	// contradict the invite it is meant to predict.
	probe := config.DefaultPrefix + "-doctor"
	cfg, err := a.sshdConfig(probe)
	if err != nil {
		a.warnf("%s (%v)", a.P.M("无法读取 sshd 有效配置；无法运行新邀请的公钥凭据检查。",
			"cannot read the effective sshd config; cannot run the public-key credential check for a new invite."), err)
		result.fail()
		return result
	}
	rep := a.checkKeyLogin(cfg, probe, []string{probe}, false)
	for _, w := range rep.Warnings {
		a.warnf("%s", w)
	}
	if rep.Certain() {
		a.success(a.P.M("sshd 有效配置检查未发现新账号公钥凭据的阻碍。",
			"the effective sshd config check found no blocker for a new account's key credential."))
	} else if rep.OK() {
		a.warnf("%s", a.P.M("sshd 有效配置检查未发现明确的公钥凭据阻碍，但存在创建前或连接时无法求值的 Match 条件，配置结论不完整。",
			"the effective sshd config check found no explicit public-key credential blocker, but a Match rule cannot be evaluated before creation or without connection attributes; the configuration verdict is inconclusive."))
		result.fail()
	} else {
		a.warnf("%s", a.P.M("sshd 有效配置检查发现新建临时账号公钥凭据的阻碍：",
			"the effective sshd config check found a blocker for a freshly created temporary account's key credential:"))
		a.reportBlockers(rep)
		if rep.Fixable() {
			a.warnf("%s", a.P.M("可用 `invite --fix-sshd` 只为该账号移除已知配置阻碍（不改动全局策略）。",
				"`invite --fix-sshd` can remove the known configuration blocker for that account only, leaving the global policy untouched."))
		}
		result.fail()
	}
	for _, u := range rep.Unverifiable {
		a.warnf("%s", u)
	}
	return result
}

func (a *App) doctorRegistryIdentity() (doctorRegistryState, doctorResult) {
	// Read the registry once and inspect the account identity recorded in every
	// row. A pending or legacy row is recovery evidence, not authority to delete a
	// live account; a UID/GECOS mismatch means the name now resolves to something
	// other than the completed identity this tool recorded.
	state := doctorRegistryState{readable: a.Registry == nil}
	var result doctorResult
	if a.Registry == nil {
		return state, result
	}

	records, err := a.Registry.List()
	if err != nil {
		a.warnf("%s: %v", a.P.M("无法读取注册表", "cannot read registry"), err)
		result.fail()
		return state, result
	}
	state.records = records
	state.readable = true
	// CheckIntegrity cannot see this: once Init has recreated the data file, an
	// empty registry trivially satisfies every sequence invariant. doctor runs in
	// its own process and never calls Init, so it asks the store to observe the
	// absence directly rather than reading a flag only invite and revoke can set.
	lostHighest, registryLost, lostErr := a.Registry.InspectRegistryLoss()
	if lostErr != nil {
		a.warnf("%s: %v", a.P.M("无法判断登记表数据文件是否丢失", "cannot determine whether the registry data file was lost"), lostErr)
		result.fail()
	}
	if registryLost {
		a.warnf("%s", a.P.M(
			fmt.Sprintf("登记表数据文件缺失但身份序列已记录先前的分配（最高 %d）：这不是全新安装，本工具此前创建的账号已失去证明其归属的登记行。撤销和孤儿清扫都依赖该证据。请从可信备份恢复登记表，不要以当前这份空表继续运作。", lostHighest),
			fmt.Sprintf("the registry data file was missing while the identity sequence already recorded prior allocations (highest %d): this is not a fresh install, and every account this tool created before now has lost the row that proves it owns them. Revoke and the orphan sweeps rely on that evidence. Restore the registry from trusted backup rather than continuing on the empty one it had to recreate.", lostHighest)))
		result.fail()
	}
	if integrityErr := a.Registry.CheckIntegrity(); integrityErr != nil {
		if errors.Is(integrityErr, registry.ErrIdentitySequenceMissing) {
			a.warnf("%s", a.P.M(
				"v5 登记表缺少 identity-sequence；邀请和登记变更已失败关闭。不要手工创建该文件。请先从可信历史独立确定本工具曾预留的最高 UID/GID，再运行 `linux-temp-admin recover-identity-sequence --highest <N>`。",
				"the v5 registry is missing identity-sequence; invites and registry mutations are fail-closed. Do not create the file by hand. First establish the highest UID/GID ever reserved by this tool from trusted history, then run `linux-temp-admin recover-identity-sequence --highest <N>`."))
		} else {
			a.warnf("%s: %v", a.P.M(
				"登记表身份序列损坏或不安全；recover-identity-sequence 不会覆盖已有对象，请从可信备份恢复或人工调查",
				"the registry identity sequence is corrupt or unsafe; recover-identity-sequence will not overwrite an existing object, so restore trusted state or investigate manually"), integrityErr)
		}
		result.fail()
	}
	for _, rec := range records {
		result.merge(a.doctorRegisteredAccountIdentity(rec))
	}
	return state, result
}

func (a *App) doctorRegisteredAccountIdentity(rec registry.Record) doctorResult {
	var result doctorResult
	pw, exists, lookupErr := a.lookupUser(rec.User)
	if lookupErr != nil {
		a.warnf("%s %s: %v", a.P.M("无法验证登记账号身份：", "cannot verify registered account identity:"), rec.User, lookupErr)
		result.fail()
		return result
	}
	switch classifyRegisteredAccount(rec, pw, exists, nil) {
	case registeredRecoveryAbsent:
		a.warnf("%s%s", a.P.M(
			"删除事务已持久化且账号已不存在；见证允许重试按 UID 校验属主的邮件清扫，并仅在 SequentialID 已证明原私有 GID 时清理残留私有组；subuid/subgid 只验证、不猜测删除。请运行 linux-temp-admin revoke 完成恢复：",
			"deletion was durably started and the account is absent; the witness authorizes an owner-checked UID-bound mail retry and, only when SequentialID proves the former private GID, cleanup of that residual group. subuid/subgid residue is verified but never guessed away. Run linux-temp-admin revoke to finish recovery: "), rec.User)
		result.fail()
	case registeredRecoveryBound:
		a.warnf("%s%s", a.P.M(
			"活账号与已持久化的删除世代精确匹配；这是可重试的中断删除，请运行 linux-temp-admin revoke 完成：",
			"the live account exactly matches a durably started deletion generation; this interrupted deletion can be retried with linux-temp-admin revoke: "), rec.User)
		result.fail()
	case registeredQuarantine:
		a.info(a.P.M(
			"账号访问已撤销，用户名和 UID 正隔离至 "+rec.QuarantineUntil+"，之后由持久化任务完成删除：",
			"account access is revoked; its name and UID are quarantined until "+rec.QuarantineUntil+" and a persistent task will then finish deletion: ") + rec.User)
	case registeredRecoveryManual:
		a.warnf("%s%s", a.P.M(
			"活账号的删除恢复见证未绑定当前世代或已不匹配；自动删除、--yes 和卸载批量删除均被拒绝。人工核查后，请直接运行 linux-temp-admin revoke --force 并输入完整用户名：",
			"the live account's deletion-recovery witness is unbound to the current generation or no longer matches; automatic deletion, --yes, and uninstall bulk deletion are refused. Inspect it, then invoke linux-temp-admin revoke --force directly and type the full username: "), rec.User)
		result.fail()
	case registeredPending:
		a.warnf("%s%s", a.P.M("登记仍是未完成的 pending 创建意图，不能证明当前账号身份：",
			"registry row is still an incomplete pending creation intent and cannot prove the current account identity: "), rec.User)
		result.fail()
	case registeredMissing:
		a.warnf("%s%s", a.P.M("登记指向已不存在的账号（可用 linux-temp-admin cleanup-expired --compact 清理）：",
			"registry row points to an absent account (remove it with linux-temp-admin cleanup-expired --compact): "), rec.User)
		result.fail()
	case registeredIdentityUnverified:
		a.warnf("%s%s", a.P.M("活账号或登记没有安全的非 root UID/GID，不能证明身份：",
			"live account or registry row has no safe non-root UID/GID and cannot prove identity: "), rec.User)
		result.fail()
	case registeredUIDMismatch:
		a.warnf("%s", fmt.Sprintf(a.P.M("登记账号 %s 的 UID 不匹配：记录为 %d，当前为 %d；拒绝自动删除。",
			"registered account %s has a UID mismatch: recorded %d, current %d; automatic deletion is refused."), rec.User, rec.UID, pw.UID))
		result.fail()
	case registeredGIDMismatch:
		a.warnf("%s", fmt.Sprintf(a.P.M("登记账号 %s 的主 GID 不匹配：SequentialID 要求为 %d，当前为 %d；拒绝自动删除。",
			"registered account %s has a primary GID mismatch: SequentialID requires %d, current %d; automatic deletion is refused."), rec.User, rec.UID, pw.GID))
		result.fail()
	case registeredLegacyIdentity:
		a.warnf("%s", a.P.M(
			"登记账号来自旧版固定身份标记，无法排除同名/同 UID 重用；自动和批量删除已禁用。人工核查后，请运行 linux-temp-admin revoke --user "+rec.User+" --force，并输入完整用户名确认。",
			"the registered account uses a legacy fixed identity marker, so same-name/same-UID reuse cannot be excluded; automatic and bulk deletion are disabled. After inspection, run linux-temp-admin revoke --user "+rec.User+" --force and type the full username to confirm."))
		result.fail()
	case registeredMarkerMismatch:
		a.warnf("%s%s", a.P.M("登记账号缺少与登记世代精确匹配的受管身份标记，可能已被替换或篡改：",
			"registered account lacks a managed identity marker matching its recorded generation and may have been replaced or modified: "), rec.User)
		result.fail()
	case registeredHomeMismatch:
		a.warnf("%s%s", a.P.M("登记账号的家目录不是本工具使用的确定路径；自动删除已禁用：",
			"registered account home is not the deterministic path used by this tool; automatic deletion is disabled: "), rec.User)
		result.fail()
	case registeredFirstFieldWitness:
		a.warnf("%s", a.P.M(
			"登记账号仍使用 v2.9.3 及更早版本的 GECOS 首字段世代见证；当前精确标记仍可安全撤销，但允许普通用户修改 full-name 的主机可在撤销前丢失该见证。请尽快运行 linux-temp-admin revoke --user "+rec.User+"，随后按当前版本重新邀请。",
			"the registered account still uses the v2.9.3-and-earlier generation witness in the GECOS full-name field. Its currently exact marker remains revocable, but a host that lets regular users change full-name can lose this witness before revoke. Run linux-temp-admin revoke --user "+rec.User+" promptly, then issue a new invite with the current version."))
		result.fail()
	}
	return result
}

func (a *App) doctorRegistryMarkers(state doctorRegistryState) doctorResult {
	var result doctorResult
	// A lifecycle marker is deliberately weaker than identity proof, but it is
	// still the only durable witness for a permanent no-sudo/no-timer account after
	// its registry row is lost. Compare markers only after a complete registry read
	// can support a missing-row claim.
	if a.Registry == nil || !state.readable {
		return result
	}
	registered := make(map[string]struct{}, len(state.records))
	for _, rec := range state.records {
		registered[rec.User] = struct{}{}
	}
	markerAccounts, err := a.listMarkerAccounts()
	if err != nil {
		a.warnf("%s: %v", a.P.M("无法扫描账号生命周期标记", "cannot scan account lifecycle markers"), err)
		result.fail()
		return result
	}
	for _, name := range markerAccounts {
		if _, ok := registered[name]; ok {
			continue
		}
		a.warnf("%s%s", a.P.M("账号带有本工具的生命周期标记，但登记表中没有对应记录；该标记只能用于发现异常，不能授权自动或批量删除：",
			"account carries this tool's lifecycle marker but has no registry row; the marker is discovery evidence only and cannot authorize automatic or bulk deletion: "), name)
		result.fail()
	}
	return result
}

func (a *App) doctorSudoersDirectory() string {
	if a.Sudoers != nil && a.Sudoers.Dir != "" {
		return a.Sudoers.Dir
	}
	return "/etc/sudoers.d"
}

func (a *App) doctorOrphanedArtifacts() doctorResult {
	var result doctorResult
	needsCompact := false
	// An sshd exception that outlived its account is a standing loosening of the
	// host's policy, and it re-arms the moment the username is reused.
	if a.SSHD != nil {
		if orphans, err := a.SSHD.Orphans(a.accountIsOursAndLive); err != nil {
			a.warnf("%s: %v", a.P.M("无法扫描孤儿 sshd 例外", "cannot scan for orphaned sshd exceptions"), err)
			result.fail()
		} else if len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿 sshd 例外（账号不存在或身份无法验证）：",
					"orphaned sshd exception (the account is absent or its identity is unverified): "), a.SSHD.FilePath(u))
			}
			needsCompact = true
			result.fail()
		}
	}
	sudoersDir := a.doctorSudoersDirectory()
	if err := fsutil.RootSafeDir(sudoersDir); err == nil {
		a.success(fmt.Sprintf(a.P.M("%s 看起来安全。", "%s looks safe."), sudoersDir))
	} else {
		a.warnf(a.P.M("%s 不可用或不安全；NOPASSWD sudo 可能不可用。 (%v)",
			"%s unavailable or unsafe; NOPASSWD sudo may be unavailable. (%v)"), sudoersDir, err)
	}
	// An orphaned NOPASSWD drop-in is the most dangerous leftover the tool can
	// produce: it re-arms full root the moment its username is reused.
	if a.Sudoers != nil {
		if orphans, err := a.Sudoers.Orphans(a.accountIsOursAndLive); err != nil {
			a.warnf("%s: %v", a.P.M("无法扫描孤儿 sudo 授权", "cannot scan for orphaned sudo grants"), err)
			result.fail()
		} else if len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿 sudo 授权（账号不存在或身份无法验证，NOPASSWD:ALL 仍在）：",
					"orphaned sudo grant (the account is absent or its identity is unverified; NOPASSWD:ALL is still on disk): "), a.Sudoers.FilePath(u))
			}
			needsCompact = true
			result.fail()
		}
	}
	// An orphaned auto-revoke unit keeps firing against a missing account, or
	// against a removed binary after uninstall.
	if a.Scheduler != nil {
		if orphans, err := a.Scheduler.Orphans(a.accountNeedsAutoRevoke); err != nil {
			a.warnf("%s: %v", a.P.M("无法扫描孤儿自动删除任务", "cannot scan for orphaned auto-delete tasks"), err)
			result.fail()
		} else if len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿自动删除任务（账号不存在或身份无法验证）：",
					"orphaned auto-delete task (the account is absent or its identity is unverified): "), u)
			}
			needsCompact = true
			result.fail()
		}
	}
	if needsCompact {
		a.warnf("%s", a.P.M("请用 `linux-temp-admin cleanup-expired --compact` 清理。",
			"remove them with `linux-temp-admin cleanup-expired --compact`."))
	}
	return result
}

func (a *App) doctorScheduleValidity(state doctorRegistryState) doctorResult {
	var result doctorResult
	// Prove that every live account marked for auto-revoke or quarantine has the
	// exact task recorded for its UID and generation. A matching username alone is
	// not health: a stale or modified task can target another generation or body.
	if a.Scheduler == nil || a.Registry == nil || !state.readable {
		return result
	}
	var strandedAuto, strandedQuarantine []string
	for _, r := range state.records {
		_, exists, existsErr := a.lookupUser(r.User)
		if existsErr != nil {
			a.warnf("%s %s: %v", a.P.M("无法确认账号状态：", "cannot determine account state:"), r.User, existsErr)
			result.fail()
			continue
		}
		if r.QuarantineUntil != "" && exists {
			deadline, parseErr := time.Parse(time.RFC3339, r.QuarantineUntil)
			if parseErr != nil {
				a.warnf("%s %s: %v", a.P.M("无法验证身份隔离任务：", "cannot verify identity-quarantine task:"), r.User, parseErr)
				result.fail()
				continue
			}
			valid, err := a.Scheduler.ValidQuarantine(r.User, r.UID, r.Generation, r.QuarantineUnit, deadline)
			if err != nil {
				a.warnf("%s %s: %v", a.P.M("无法验证身份隔离任务：", "cannot verify identity-quarantine task:"), r.User, err)
				result.fail()
				continue
			}
			if !valid {
				strandedQuarantine = append(strandedQuarantine, r.User)
			}
			continue
		}
		if !r.AutoRevoke || !exists {
			continue
		}
		deadline, parseErr := expiry.ParseDisplay(r.Expires)
		if parseErr != nil {
			a.warnf("%s %s: %v", a.P.M("无法验证自动删除到期时间：", "cannot verify auto-delete deadline:"), r.User, parseErr)
			result.fail()
			continue
		}
		valid, err := a.Scheduler.ValidSchedule(r.User, r.UID, r.Generation, r.AutoUnit, deadline)
		if err != nil {
			a.warnf("%s %s: %v", a.P.M("无法验证自动删除任务：", "cannot verify auto-delete task:"), r.User, err)
			result.fail()
			continue
		}
		if !valid {
			strandedAuto = append(strandedAuto, r.User)
		}
	}
	if len(strandedAuto) > 0 {
		for _, u := range strandedAuto {
			a.warnf("%s%s", a.P.M("账号设置了自动删除但已无可验证的对应任务（任务必须匹配 UID、世代、记录的 unit、到期时间和正文；chage 仅提供按天粒度的较晚兜底锁定）：",
				"account set to auto-delete but has no valid task left to do it (the UID, generation, recorded unit, deadline, and body must all match; chage only provides a later, day-granularity lockout backstop): "), u)
		}
		a.warnf("%s", a.P.M("到期后请用 `linux-temp-admin revoke --user <名>` 手动删除。",
			"remove them with `linux-temp-admin revoke --user <name>` once expired."))
		result.fail()
	}
	if len(strandedQuarantine) > 0 {
		for _, u := range strandedQuarantine {
			a.warnf("%s%s", a.P.M(
				"账号访问已撤销且身份仍在隔离，但已无可验证的后台终删任务（任务必须匹配 UID、世代、隔离截止时间、记录的 unit 和正文）：",
				"account access is revoked and its identity remains quarantined, but no valid background finalizer remains (the UID, generation, quarantine deadline, recorded unit, and body must all match): "), u)
		}
		a.warnf("%s", a.P.M(
			"请运行 `linux-temp-admin revoke --user <名>`；隔离截止时间已到时会立即续删，尚未到时会确认账号仍保持禁用。",
			"run `linux-temp-admin revoke --user <name>`; after the quarantine deadline it resumes deletion immediately, and before the deadline it reconfirms that access remains disabled."))
		result.fail()
	}
	return result
}

// sudo and visudo are mandatory only for --sudo invites. chpasswd is mandatory
// only for password invites. Missing optional-feature helpers do not make the
// base key-only doctor verdict fail.
func doctorDependencyIsFatal(label string) bool {
	return label != "sudo" && label != "visudo" && label != "chpasswd"
}
