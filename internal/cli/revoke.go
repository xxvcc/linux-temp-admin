package cli

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

var errPersistentQuarantineUnavailable = errors.New("persistent identity quarantine unavailable")

func (a *App) revoke(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	opts, ok := a.parseRevokeArgs(args)
	if !ok {
		return 1
	}
	opts.manualInvocation = true
	if opts.username == "" {
		opts.username = a.selectUser()
	}
	if !validate.Username(opts.username) {
		a.errorf("%s", a.P.M("用户名不合法，拒绝删除："+opts.username, "invalid username; refusing deletion: "+opts.username))
		return 1
	}
	if !opts.yes {
		rec, registered, err := a.Registry.Lookup(opts.username)
		if err != nil {
			a.errorf("%s: %v", a.P.M("读取注册表失败，拒绝继续", "reading registry failed; refusing to continue"), err)
			return 1
		}
		pw, exists, err := a.lookupUser(opts.username)
		if err != nil {
			a.errorf("%s: %v", a.P.M("读取账号数据库失败，拒绝继续", "reading account database failed; refusing to continue"), err)
			return 1
		}
		if exists {
			if opts.force && !registered {
				a.warnf("%s", a.P.M("危险：用户 "+opts.username+" 未登记；只有其余受管身份检查也通过时，--force 才会删除该账号及其确定的家目录。",
					"DANGER: "+opts.username+" is not registered; --force deletes the account and its deterministic home only if the remaining managed-identity checks also pass."))
			}
			if a.prompt(a.P.M("请输入完整用户名 "+opts.username+" 以确认删除: ",
				"type the full username "+opts.username+" to confirm deletion: ")) != opts.username {
				a.warnf("%s", a.P.M("确认不匹配，已取消", "confirmation mismatch; cancelled"))
				return 0
			}
			opts.liveConfirmed = true
			opts.confirmedIdentity = &revokeIdentitySnapshot{
				registered: registered,
				record:     rec,
				passwd:     pw,
			}
		}
	}
	run := func() int {
		return a.withLifecycleLock(func() int { return a.revokeOptionsLocked(opts) })
	}
	// Releases before generation-bound scheduling emitted the same unattended
	// command for every account generation. Such a process must never queue behind
	// an invite for the same username: after invite releases its exclusive barrier,
	// the old name-only intent could otherwise target the new account. A nonblocking
	// shared acquisition makes only that collision a successful stale-job skip.
	// Unrelated lifecycle work still queues under the global lock, and current
	// generation-bound or interactive revokes use ordinary blocking semantics.
	if opts.yes && opts.expectedUID == 0 && opts.generation == "" {
		rc, busy := a.withAccountTrySharedLock(opts.username, run)
		if busy {
			a.warnf("%s", a.P.M(
				"旧版无世代绑定的撤销命令与同名账号创建冲突，无法证明原删除意图仍指向当前账号；本次未撤销账号并以成功状态跳过，以免旧任务重试误删新世代。请在当前操作完成后运行 doctor，并按当前身份重新执行 revoke。",
				"a legacy revoke command without a generation binding collided with creation of the same account name, so its original deletion intent can no longer be proved to target the current account; no account was revoked and this run was skipped successfully to keep an old job from retrying against a new generation. Run doctor and invoke revoke again against the current identity after the in-flight operation finishes."))
			a.audit("account.delete", opts.username, "skip", "legacy unbound revoke collided with same-name invite", nil)
			return 0
		}
		return rc
	}
	return a.withAccountSharedLock(opts.username, run)
}

type revokeOptions struct {
	username         string
	confirmForce     string
	expectedUID      int
	generation       string
	yes              bool
	force            bool
	liveConfirmed    bool
	manualInvocation bool
	// synchronousFinalization is used only by uninstall, which cannot remove the
	// installed finalizer while an account still depends on it.
	synchronousFinalization bool
	confirmedIdentity       *revokeIdentitySnapshot
}

// revokeIdentitySnapshot binds an interactive full-name confirmation to the
// stable account generation that was visible before the prompt. The account lock
// is intentionally acquired only after human input, so the locked path must reject
// a same-name replacement instead of applying the old confirmation to it. Current
// trailing-witness identities may change their user-writable passwd fields while
// the operator types; older identities remain byte-for-byte strict.
type revokeIdentitySnapshot struct {
	registered bool
	record     registry.Record
	passwd     user.Passwd
}

func (s *revokeIdentitySnapshot) matches(registered bool, record registry.Record, passwd user.Passwd, exists bool) bool {
	return s != nil && exists && registered == s.registered && record == s.record &&
		user.SameAccountIdentity(s.passwd, passwd)
}

func legacyRecoveryAuthorized(identityBound bool, opts revokeOptions, stdinTTY bool) bool {
	return !identityBound && stdinTTY && opts.manualInvocation && opts.force &&
		opts.generation == "" && opts.expectedUID == 0 && !opts.yes && opts.liveConfirmed
}

func pendingRecoveryAuthorized(opts revokeOptions, stdinTTY bool) bool {
	return stdinTTY && opts.manualInvocation && opts.force &&
		opts.generation == "" && opts.expectedUID == 0 && !opts.yes && opts.liveConfirmed
}

func (a *App) parseRevokeArgs(args []string) (revokeOptions, bool) {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var opts revokeOptions
	fs.StringVar(&opts.username, "user", "", "")
	fs.StringVar(&opts.confirmForce, "confirm-force", "", "")
	fs.IntVar(&opts.expectedUID, "expected-uid", 0, "")
	fs.StringVar(&opts.generation, "generation", "", "")
	fs.BoolVar(&opts.yes, "yes", false, "")
	fs.BoolVar(&opts.yes, "y", false, "")
	fs.BoolVar(&opts.force, "force", false, "")
	if err := fs.Parse(args); err != nil {
		return revokeOptions{}, false
	}
	if fs.NArg() > 0 {
		a.errorf("%s %v", a.P.M("未知参数：", "unexpected arguments:"), fs.Args())
		return revokeOptions{}, false
	}
	return opts, true
}

// revokeLocked is the non-interactive form used by uninstall while it already
// owns the lifecycle lock. The caller must supply --user and --yes.
func (a *App) revokeLocked(args []string) int {
	opts, ok := a.parseRevokeArgs(args)
	if !ok {
		return 1
	}
	if !opts.yes || !validate.Username(opts.username) {
		a.errorf("%s", a.P.M("内部撤销必须提供合法用户名并禁用交互", "internal revoke requires a valid username and non-interactive confirmation"))
		return 1
	}
	opts.liveConfirmed = true
	opts.synchronousFinalization = true
	return a.revokeOptionsLocked(opts)
}

// revokeOptionsLocked performs one complete revoke while the process-wide
// lifecycle lock is held. Every identity and registry fact is read again here;
// the lock-free preparation only collects operator intent.
func (a *App) revokeOptionsLocked(opts revokeOptions) int {
	username := opts.username

	// One read gives every registry fact this path acts on: registration, the
	// creation UID used to detect replacement/tampering, the generation token, and
	// the auto-revoke unit.
	rec, registered, err := a.Registry.Lookup(username)
	if err != nil {
		a.errorf("%s: %v", a.P.M("读取注册表失败，拒绝继续", "reading registry failed; refusing to continue"), err)
		return 1
	}

	// New scheduled jobs are bound to one account generation. A stale job exits
	// successfully so systemd does not retry it against a replacement account.
	if opts.generation != "" || opts.expectedUID != 0 {
		if !validate.Generation(opts.generation) || !validate.AccountID(opts.expectedUID) {
			a.errorf("%s", a.P.M("自动撤销身份参数不完整或不合法", "invalid or incomplete auto-revoke identity"))
			return 1
		}
		if !registered || rec.Generation != opts.generation || rec.UID != opts.expectedUID {
			a.warnf("%s", a.P.M("陈旧的自动撤销任务已忽略：账号世代不再匹配", "ignored stale auto-revoke task: account generation no longer matches"))
			a.audit("account.delete", username, "skip", "stale scheduled generation", nil)
			return 0
		}
	}

	if !opts.force && !registered {
		a.errorf("%s", a.P.M("拒绝删除未登记用户："+username+"（如确需删除请加 --force）",
			"refusing to delete an unregistered user: "+username+" (use --force if intended)"))
		return 1
	}
	if opts.force && !registered && opts.yes && opts.confirmForce != username {
		a.errorf("%s", a.P.M("通过 --force --yes 删除未登记用户需同时传入 --confirm-force "+username,
			"deleting an unregistered user via --force --yes also requires --confirm-force "+username))
		return 1
	}

	pw, exists, err := a.lookupUser(username)
	if err != nil {
		a.errorf("%s: %v", a.P.M("读取账号数据库失败，拒绝清理状态", "reading account database failed; refusing state cleanup"), err)
		return 1
	}
	if confirmed := opts.confirmedIdentity; confirmed != nil && !confirmed.matches(registered, rec, pw, exists) {
		a.errorf("%s", a.P.M(
			"输入确认后账号或登记身份发生变化；未清理授权、禁用或删除任何账号，请重新运行并确认当前世代。",
			"the account or registry identity changed after confirmation; no grant was cleaned and no account was disabled or deleted; rerun and confirm the current generation."))
		a.audit("account.delete", username, "fail", "account identity changed after interactive confirmation", nil)
		return 1
	}
	if !exists {
		a.warnf("%s", a.P.M("用户不存在，清理登记/sudoers/sshd 例外/自动删除任务："+username,
			"user does not exist; cleaning up registry/sudoers/sshd exception/auto-delete task: "+username))
		if registered && rec.DeletionStarted {
			if err := a.reconcileDeletionStarted(rec); err != nil {
				a.errorf("%s: %v", a.P.M(
					"账号删除已开始，但删除后的邮件清扫尚未安全完成；保留登记供重试",
					"account deletion had started, but post-deletion mail cleanup could not be completed safely; keeping the registry record for retry"), err)
				return 1
			}
		}
		var cleanupErrs []error
		if err := a.cancelAccountSchedules(username, rec); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
		if err := a.removeSudoGrant(username); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
		if err := a.removeSSHDException(username); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
		if err := errors.Join(cleanupErrs...); err != nil {
			a.errorf("%s: %v", a.P.M("账号虽不存在，但残留授权或任务未清除；保留登记", "the account is absent, but grants or schedules remain; keeping the registry record"), err)
			return 1
		}
		if err := a.releaseRegistryAfterCleanup(username); err != nil {
			a.errorf("%s: %v", a.P.M("清理登记失败", "registry cleanup failed"), err)
			return 1
		}
		a.audit("account.cleanup", username, "ok", "user absent; cleaned registry/sudoers/sshd/schedule", nil)
		return 0
	}
	if !opts.yes && !opts.liveConfirmed {
		a.errorf("%s", a.P.M("确认后账号状态发生变化；拒绝删除，请重新运行并确认",
			"the account appeared after confirmation; refusing deletion; rerun and confirm the current state"))
		return 1
	}

	stdinTTY := a.StdinIsTTY != nil && a.StdinIsTTY()
	// Released v2 rows used one fixed GECOS marker, so username+UID+marker still
	// cannot distinguish the original account from a same-name/same-UID replacement.
	// Only a direct interactive operator invocation with --force and an explicit
	// full-name confirmation may recover such an account. Historical unattended
	// timers used the same --yes --force --confirm-force argv that an operator could
	// type, so no non-interactive invocation receives this exception. Scheduled and
	// uninstall-internal invocations remain blocked even though they carry --force.
	allowLegacy := legacyRecoveryAuthorized(rec.IdentityBound, opts, stdinTTY)

	// A real v2 row may still have only nine fields and no recorded UID; later v2
	// rows can carry the UID while retaining the same unbound fixed marker. Before
	// any narrowly authorized legacy recovery mutates grants or account state, run
	// the formal migration so BeginDeletion cannot rewrite the row as v5 without
	// first creating the monotonic identity sequence. Re-read both sources afterward:
	// migration may change the representation, never the semantic record or the
	// exact legacy passwd snapshot the operator confirmed.
	legacyRegistryMigration := registered && !rec.IdentityBound && allowLegacy &&
		(rec.UID == 0 || rec.UID == pw.UID) && pw.UID >= 1000 &&
		!user.IsReservedName(username) && user.IsLegacyManagedEntry(pw)
	if legacyRegistryMigration {
		if err := a.Registry.Init(); err != nil {
			a.errorf("%s: %v", a.P.M(
				"旧版登记迁移失败；未清理授权、禁用或删除账号",
				"legacy registry migration failed; no grant was cleaned and no account was disabled or deleted"), err)
			a.audit("account.delete", username, "fail", "legacy registry migration failed: "+err.Error(), nil)
			return 1
		}
		migrated, stillRegistered, err := a.Registry.Lookup(username)
		if err != nil || !stillRegistered || migrated != rec {
			if err == nil {
				err = fmt.Errorf("registry identity changed during migration")
			}
			a.errorf("%s: %v", a.P.M(
				"旧版登记迁移期间账号登记身份发生变化；未清理授权、禁用或删除账号",
				"the registry identity changed during legacy migration; no grant was cleaned and no account was disabled or deleted"), err)
			a.audit("account.delete", username, "fail", err.Error(), nil)
			return 1
		}
		current, stillExists, err := a.lookupUser(username)
		if err != nil || !stillExists || !user.SameAccountIdentity(pw, current) {
			if err == nil {
				err = fmt.Errorf("account identity changed during registry migration")
			}
			a.errorf("%s: %v", a.P.M(
				"旧版登记迁移期间账号身份发生变化；未清理授权、禁用或删除账号",
				"the account identity changed during legacy registry migration; no grant was cleaned and no account was disabled or deleted"), err)
			a.audit("account.delete", username, "fail", err.Error(), nil)
			return 1
		}
		rec, registered, pw = migrated, stillRegistered, current
	}

	// A pending row was written before useradd and is not ordinary deletion
	// authority; it may still carry the initial UID 0 or a later captured UID.
	// Releases before v2.9.2 could nevertheless retain that row
	// after capturing an exact pending-generation passwd identity. Permit recovery
	// only after a direct interactive --force/full-name confirmation and a complete
	// marker/Home/UID/GID shape match. The deletion transition below then strips the
	// generation and persists only a UID recovery witness before artifact cleanup.
	pendingRecovery := registered && rec.Pending && pendingRecoveryAuthorized(opts, stdinTTY) &&
		pendingCreationRecordMatchesPasswd(rec, pw)
	if registered && rec.Pending && !rec.DeletionStarted && !pendingRecovery {
		grantCleanupErr := errors.Join(a.removeSudoGrant(username), a.removeSSHDException(username))
		cleanupErr := errors.Join(grantCleanupErr, a.Scheduler.Cancel(username, rec.AutoUnit))
		a.errorf("%s", a.P.M(
			"该登记仍处于创建中的 pending 状态，不能直接证明当前同名账号的身份；已保留账号和登记。人工核查后，只能在交互终端运行 revoke --user "+username+" --force，并输入完整用户名；程序还会严格核对 pending 世代与账号形状。",
			"the registry row is still a pending creation intent and does not directly prove the current same-name identity; the account and registry record were retained. After manual inspection, recovery requires revoke --user "+username+" --force in an interactive terminal, the full username confirmation, and an exact pending-generation account-shape match."))
		if cleanupErr != nil {
			a.errorf("%s: %v", a.P.M("清理 pending 账号的遗留授权或任务未完整完成", "cleanup of grants or schedules for the pending account did not complete"), cleanupErr)
		}
		a.audit("account.delete", username, "fail", "pending creation identity is unverified", nil)
		return 1
	}

	// Strip the privilege grants FIRST — before the protection gate can refuse and
	// before anything else can fail. Both only ever touch this tool's own
	// name-scoped files, so doing it for a target that turns out to be protected is
	// safe (for a real account those files do not exist; if one does, it is an
	// orphan and removing it is exactly right). Ordering matters: when the gate
	// below refuses — which an invitee with sudo can force by rewriting its own
	// passwd entry — the account may survive, but it must not survive still holding
	// NOPASSWD sudo and an sshd exception.
	grantErr := errors.Join(a.removeSudoGrant(username), a.removeSSHDException(username))

	protected := user.IsProtectedRevokeEntry(username, pw, true, registered, rec.UID, rec.Generation, allowLegacy)
	if pendingRecovery {
		protected = false
	}
	manualOnlyRecovery := registered && rec.DeletionStarted &&
		(!rec.IdentityBound || !deletionRecordMatchesPasswd(rec, pw))
	if registered && rec.DeletionStarted && rec.IdentityBound && !deletionRecordMatchesPasswd(rec, pw) {
		protected = true
	}
	if registered && rec.DeletionStarted && rec.IdentityBound && deletionRecordMatchesPasswd(rec, pw) {
		protected = false
	}
	if registered && rec.DeletionStarted && !rec.IdentityBound && allowLegacy {
		protected = !uidOnlyDeletionCandidateMatches(rec, pw)
	}
	if protected {
		a.errorf("%s", a.P.M("拒绝删除受保护或系统用户："+username,
			"refusing to delete a protected or system user: "+username))
		if !rec.IdentityBound && user.IsLegacyManagedEntry(pw) {
			a.errorf("%s", a.P.M(
				"该账号使用旧版固定身份标记，无法证明它仍是原账号。请人工核查后在交互终端直接运行 revoke --user "+username+" --force，并输入完整用户名确认；为避免旧版自动任务获得删除授权，非交互调用始终拒绝删除此类账号。",
				"this account uses a legacy fixed identity marker and cannot be proved to be the original account. After manual inspection, invoke revoke --user "+username+" --force directly in an interactive terminal and type the full username; non-interactive deletion is always refused so a historical automatic task cannot gain this authority."))
		}
		if rec.DeletionStarted && !rec.IdentityBound {
			a.errorf("%s", a.P.M(
				"该账号只有 UID 删除恢复见证，不能证明当前同名账号就是原删除目标。自动任务、--yes 和卸载批量删除始终拒绝；请人工核查后在交互终端直接运行 revoke --user "+username+" --force，并输入完整用户名。",
				"this account has only a UID-bound deletion-recovery witness, which cannot prove that the current same-name account is the original deletion target. Automatic jobs, --yes, and uninstall bulk deletion always refuse it; after manual inspection, invoke revoke --user "+username+" --force directly in an interactive terminal and type the full username."))
		}
		// Name the tamper if that is why: an account that rewrote its own UID (most
		// dangerously to 0) is now protected by the very check meant to shield real
		// accounts, and the operator has to clean it up by hand.
		if rec.UID > 0 && pw.UID != rec.UID {
			a.errorf("%s", a.P.M(
				fmt.Sprintf("该账号的 UID 已被改动：创建时为 %d，现在是 %d。它已不再是本工具创建的那个账号，请手动核查后处理。", rec.UID, pw.UID),
				fmt.Sprintf("this account's UID was changed: it was created as %d and is now %d. It is no longer the account this tool made; inspect and remove it by hand.", rec.UID, pw.UID)))
		}
		if grantErr != nil {
			a.errorf("%s: %v", a.P.M("账号受保护且授权未完全移除", "the account is protected and its grants were not fully removed"), grantErr)
		}
		if manualOnlyRecovery {
			if a.Scheduler != nil {
				if err := a.cancelAccountSchedules(username, rec); err != nil {
					a.errorf("%s: %v", a.P.M("该恢复状态只允许人工处理，但自动删除任务未能完整解除；登记已保留，请立即人工清理任务",
						"this recovery state is manual-only, but its auto-delete task could not be fully cancelled; the registry witness was retained; remove the task manually"), err)
				} else {
					a.warnf("%s", a.P.M("该恢复状态只允许人工处理；自动删除任务已解除，登记已保留。",
						"this recovery state is manual-only; its auto-delete task was cancelled and the registry witness was retained."))
				}
			}
		} else {
			a.warnf("%s", a.P.M("自动删除任务保留；systemd 任务会按策略重试，at 和旧的一次性任务需人工核查。",
				"the auto-delete task is retained; systemd jobs retry by policy, while at and legacy one-shot jobs require manual inspection."))
		}
		a.audit("account.delete", username, "fail", "protected target; grants stripped", nil)
		return 1
	}

	if rec.QuarantineUntil != "" {
		deadline, parseErr := time.Parse(time.RFC3339, rec.QuarantineUntil)
		if parseErr != nil {
			a.errorf("%s: %v", a.P.M("隔离删除截止时间损坏，拒绝继续", "quarantine deletion deadline is corrupt; refusing to continue"), parseErr)
			return 1
		}
		if a.Now().Before(deadline) && !opts.synchronousFinalization {
			// An old expiry task may race the new quarantine finalizer. Reassert the
			// access gates, but never release the name or UID before the durable deadline.
			err := errors.Join(a.removeSudoGrant(username), a.removeSSHDException(username), a.Users.DisableLogin(username))
			if err != nil {
				a.errorf("%s: %v", a.P.M("账号处于身份隔离期，但无法重新确认全部访问门已关闭", "the account is quarantined, but not every access gate could be reconfirmed closed"), err)
				return 1
			}
			a.info(a.P.M("账号访问已撤销，用户名和 UID 隔离保留至：", "account access is revoked; name and UID remain quarantined until: ") + deadline.Local().Format("2006-01-02 15:04:05 MST"))
			return 0
		}
		if a.Now().Before(deadline) {
			a.info(a.P.M(
				"卸载必须在移除命令前完成账号删除；将同步等待一个任务轮询周期后释放隔离身份。",
				"uninstall must finish account deletion before removing the command; waiting one deferred-job polling cycle before releasing the quarantined identity."))
		}
	}

	// Removing grants and reloading sshd can take long enough for an out-of-band
	// administrator to replace the account. Do not disable one generation, signal
	// another UID, and then userdel a third. New accounts can ignore concurrent
	// edits to user-changeable GECOS/shell fields only while their trailing
	// generation witness and stable numeric/Home identity remain exact.
	current, stillExists, identityErr := a.lookupUser(username)
	if identityErr != nil || !stillExists || !user.SameAccountIdentity(pw, current) {
		if identityErr == nil {
			identityErr = fmt.Errorf("account identity changed during revoke")
		}
		a.errorf("%s: %v", a.P.M("撤销期间账号身份发生变化，已移除可确认的授权但拒绝禁用、清场或删除账号",
			"the account identity changed during revoke; confirmed grants were stripped, but login disable, process termination, and deletion were refused"), identityErr)
		a.audit("account.delete", username, "fail", identityErr.Error(), nil)
		return 1
	}
	pw = current

	var artifactErr error
	expectedHome, homeErr := user.DefaultHome(username)
	switch {
	case homeErr != nil:
		artifactErr = fmt.Errorf("determine managed home: %w", homeErr)
	case pw.Home != expectedHome:
		artifactErr = fmt.Errorf("account home %q differs from managed path %q", pw.Home, expectedHome)
	}

	preDeleteErr := errors.Join(grantErr, artifactErr)
	if preDeleteErr != nil {
		// Do not free the username while a name-scoped privilege file survives or
		// while an account artifact cannot be removed under its captured identity.
		// The stable passwd identity was just re-checked, so disable this exact
		// account before retaining it for operator recovery.
		disableErr := a.Users.DisableLogin(username)
		if disableErr == nil {
			identityErr := a.revokeAccountStillMatches(username, pw)
			if identityErr != nil {
				combined := errors.Join(preDeleteErr, identityErr)
				a.errorf("%s: %v", a.P.M("删除前的授权或账号文件无法安全清理；账号身份在禁用登录后发生变化，拒绝按旧身份清理 cron/at 任务或终止进程",
					"a grant or account artifact could not be safely cleaned before deletion; the account identity changed after login disable, so cron/at cleanup and process termination under the old identity were refused"), combined)
				a.audit("account.delete", username, "fail", "pre-delete cleanup unsafe and identity changed after login disable: "+combined.Error(), nil)
				return 1
			}
			quiesceErr := a.quiesceScheduledAccountForRevoke(username, pw)
			combined := errors.Join(preDeleteErr, quiesceErr)
			a.errorf("%s: %v", a.P.M("删除前的授权或账号文件无法安全清理；账号已禁用但不会删除，账号和登记已保留供人工恢复",
				"a grant or account artifact could not be safely cleaned before deletion; the account was disabled but not deleted, and the account and registry witness were retained for manual recovery"), combined)
			a.audit("account.delete", username, "fail", "pre-delete cleanup unsafe; account disabled and retained: "+combined.Error(), nil)
		} else {
			combined := errors.Join(preDeleteErr, disableErr)
			a.errorf("%s: %v", a.P.M("删除前的授权或账号文件无法安全清理，且禁用登录也失败；账号和登记均已保留，请立即人工处理",
				"a grant or account artifact could not be safely cleaned before deletion, and disabling login also failed; the account and registry were retained for immediate manual recovery"), combined)
			a.audit("account.delete", username, "fail", "pre-delete cleanup unsafe and login disable incomplete: "+combined.Error(), nil)
		}
		return 1
	}

	// A completed generation-bound account can hand deletion to a persistent
	// systemd quarantine. The live but disabled passwd entry holds both its name and
	// numeric identity for one full deferred-job cycle, so the invoking terminal
	// does not have to wait. Legacy/pending recovery and hosts without reliable
	// systemd retain the synchronous fail-closed path below.
	if registered && rec.IdentityBound && !rec.DeletionStarted && (!rec.Pending || pendingRecovery) &&
		(opts.manualInvocation || opts.generation != "") {
		started, quarantineErr := a.beginIdentityQuarantine(rec, pw)
		if started {
			if quarantineErr != nil {
				a.warnf("%s: %v", a.P.M("身份隔离已建立，但持久化交接或旧自动删除任务清理未完整确认", "identity quarantine is active, but its durable handoff or cleanup of the old auto-delete task was not fully confirmed"), quarantineErr)
			}
			a.audit("account.quarantine", username, "ok", "access revoked; identity held for asynchronous deletion", nil)
			return 0
		}
		if quarantineErr != nil && !errors.Is(quarantineErr, errPersistentQuarantineUnavailable) {
			a.errorf("%s: %v", a.P.M("无法安全建立身份隔离；账号已禁用并保留", "cannot safely establish identity quarantine; the account is disabled and retained"), quarantineErr)
			return 1
		}
		if quarantineErr != nil {
			a.info(a.P.M("持久化身份隔离不可用；将同步等待约 65 秒后完成删除。", "persistent identity quarantine is unavailable; waiting about 65 seconds to finish deletion synchronously."))
		}
	}

	// Shut the door before taking the account apart. Until both expiry and password
	// locking land, the account may still be SSH-reachable: in particular, a failed
	// chage leaves public-key login open even when usermod -L succeeded. Never create
	// a scan-then-delete race by continuing from a partial disable.
	persistDeletion := func() error { return a.persistDeletionStarted(rec, registered, pw) }
	teardown := a.teardownLocalAccount
	if rec.QuarantineUntil != "" && !opts.synchronousFinalization {
		teardown = a.teardownQuarantinedAccount
	} else if rec.QuarantineUntil != "" {
		deadline, _ := time.Parse(time.RFC3339, rec.QuarantineUntil)
		if !a.Now().Before(deadline) {
			teardown = a.teardownQuarantinedAccount
		}
	}
	stage, teardownErr := teardown(username, pw, persistDeletion)
	switch stage {
	case revokeDisableLogin:
		a.errorf("%s: %v", a.P.M("无法完整禁用登录；保留账号、登记和自动删除任务，未终止进程或删除账号，请立即人工处理",
			"could not fully disable the login; the account, registry record, and auto-delete task were retained, and no processes were terminated or account deleted; inspect immediately"), teardownErr)
		a.audit("account.delete", username, "fail", "disable login incomplete: "+teardownErr.Error(), nil)
		return 1
	case revokeQuiesceAccount:
		a.errorf("%s: %v", a.P.M("无法确认该账号的 cron/at 任务及 UID 进程均已清空；账号已禁用，保留账号、登记和自动删除任务，避免任务或进程跨越身份复用",
			"could not confirm that the account's cron/at jobs and UID processes were empty; the account is disabled and its account, registry record, and auto-delete task were retained to prevent deferred work or processes crossing an identity reuse"), teardownErr)
		a.audit("account.delete", username, "fail", "account quiescence incomplete: "+teardownErr.Error(), nil)
		return 1
	case revokeDeleteAccount:
		a.errorf("%s: %v", a.P.M("删除用户失败", "delete user failed"), teardownErr)
		// The auto-revoke task is deliberately still armed: it is the fallback that
		// retries this deletion, and tearing it down on the way to a failure would
		// leave the account with nothing coming for it. The login is already
		// disabled, so the account cannot be used in the meantime.
		a.warnf("%s", a.P.M("登录已禁用；systemd 任务会按策略重试，at/旧任务需手动重试。",
			"the login is disabled; systemd jobs retry by policy, while at/legacy jobs require a manual retry."))
		a.audit("account.delete", username, "fail", teardownErr.Error(), nil)
		return 1
	case revokeAccountRemoved:
	}

	// Only now that the account is provably gone is the fallback safe to remove.
	if err := a.cancelAccountSchedules(username, rec); err != nil {
		a.errorf("%s: %v", a.P.M("用户已删除，但自动删除任务清理失败；保留登记", "user deleted, but schedule cleanup failed; keeping the registry record"), err)
		return 1
	}
	if err := a.releaseRegistryAfterCleanup(username); err != nil {
		a.errorf("%s: %v", a.P.M("用户已删除，但清理登记失败", "user deleted, but registry cleanup failed"), err)
		return 1
	}
	a.audit("account.delete", username, "ok", "", map[string]string{"force": ynStr(opts.force), "registered": ynStr(registered)})
	a.success(a.P.M("已撤销并删除用户："+username, "user revoked and deleted: "+username))
	return 0
}

// cancelAccountSchedules removes expiry and identity-quarantine tasks through
// their separate namespaces. This does not depend on Scheduler.New having added
// quarantine to its inventory prefixes, which keeps injected schedulers and
// recovery paths from accidentally stranding the finalizer.
func (a *App) cancelAccountSchedules(username string, rec registry.Record) error {
	if a.Scheduler == nil {
		return fmt.Errorf("scheduler is not configured")
	}
	return errors.Join(
		a.Scheduler.CancelAuto(username, rec.AutoUnit),
		a.Scheduler.CancelQuarantine(username, rec.QuarantineUnit),
	)
}

func quarantineDeadline(now time.Time) time.Time {
	target := now.Add(time.Duration(config.IdentityQuarantineSeconds) * time.Second).UTC()
	minute := target.Truncate(time.Minute)
	if target.Equal(minute) {
		return minute
	}
	return minute.Add(time.Minute)
}

// beginIdentityQuarantine performs the immediate access revocation, schedules a
// separate finalizer, and only then commits the quarantine row. The finalizer
// namespace can coexist with a currently-running expiry service, closing the
// schedule handoff crash window.
func (a *App) beginIdentityQuarantine(rec registry.Record, expected user.Passwd) (bool, error) {
	if a.Scheduler == nil || a.Scheduler.Sys == nil || !a.Scheduler.Sys.HasSystemctl() {
		return false, errPersistentQuarantineUnavailable
	}
	// The finalizer executes InstallPath, not this process. A standalone newer
	// binary may be running while that path is absent or still contains an older
	// release that cannot read the v5 quarantine row. Establish the same stable
	// command guarantee used before invite schedules auto-revoke; if it cannot be
	// proved, retain the foreground synchronous deletion path below.
	ensureCommand := a.ensureStableInstalled
	if a.EnsureScheduledCommand != nil {
		ensureCommand = a.EnsureScheduledCommand
	}
	if err := ensureCommand(); err != nil {
		return false, fmt.Errorf("%w: finalizer command is unavailable: %v", errPersistentQuarantineUnavailable, err)
	}
	if err := a.Users.DisableLogin(rec.User); err != nil {
		return false, err
	}
	if err := a.revokeAccountStillMatches(rec.User, expected); err != nil {
		return false, err
	}
	if err := a.quiesceScheduledAccountImmediateForRevoke(rec.User, expected); err != nil {
		return false, err
	}
	deadline := quarantineDeadline(a.Now())
	unit, err := a.Scheduler.ScheduleQuarantine(rec.User, expected.UID, rec.Generation, deadline)
	if err != nil {
		return false, fmt.Errorf("%w: %v", errPersistentQuarantineUnavailable, err)
	}
	beginQuarantine := a.Registry.BeginQuarantine
	if a.BeginQuarantine != nil {
		beginQuarantine = a.BeginQuarantine
	}
	var handoffErr error
	if err := beginQuarantine(rec.User, expected.UID, rec.Generation, deadline, unit); err != nil {
		var committed *fsutil.DurabilityError
		if !errors.As(err, &committed) {
			cancelErr := a.Scheduler.CancelQuarantine(rec.User, unit)
			return false, errors.Join(err, cancelErr)
		}
		// DurabilityError means the registry rename is already visible. Cancelling
		// the finalizer as if nothing committed would strand the disabled identity.
		// Prove the complete expected row before treating the handoff as active. If
		// the proof itself fails, preserve both the timer and registry evidence and
		// fail closed for operator recovery.
		if verifyErr := a.verifyCommittedQuarantine(rec, expected.UID, deadline, unit); verifyErr != nil {
			return false, errors.Join(err, fmt.Errorf("verify visible quarantine registry state: %w", verifyErr))
		}
		handoffErr = err
	}
	// The quarantine timer is now the durable retry path. Failure to remove an old
	// expiry task is non-fatal: an early duplicate invocation observes the deadline
	// and exits without releasing the identity.
	cleanupErr := a.Scheduler.CancelAuto(rec.User, rec.AutoUnit)
	a.success(a.P.M(
		"访问已撤销；账号身份隔离至 "+deadline.Local().Format("2006-01-02 15:04:05 MST")+"，届时自动完成删除。",
		"access revoked; account identity is quarantined until "+deadline.Local().Format("2006-01-02 15:04:05 MST")+" and will then be deleted automatically."))
	return true, errors.Join(handoffErr, cleanupErr)
}

func (a *App) verifyCommittedQuarantine(rec registry.Record, uid int, deadline time.Time, unit string) error {
	committed, found, err := a.Registry.Lookup(rec.User)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("registry quarantine row is absent")
	}
	want := rec
	want.UID = uid
	want.DeletionStarted = true
	want.QuarantineUntil = deadline.Format(time.RFC3339)
	want.QuarantineUnit = unit
	if committed != want {
		return fmt.Errorf("registry quarantine row does not match the committed handoff")
	}
	return nil
}

type revokeAccountStage uint8

const (
	revokeDisableLogin revokeAccountStage = iota
	revokeQuiesceAccount
	revokeDeleteAccount
	revokeAccountRemoved
)

// teardownLocalAccount preserves the ordering that makes UID reuse safe. A
// stage is returned with the error so revoke can explain precisely which recovery
// state was retained without repeating these security-sensitive calls.
func (a *App) teardownLocalAccount(username string, expected user.Passwd, persistDeletion func() error) (revokeAccountStage, error) {
	return a.teardownLocalAccountWith(username, expected, persistDeletion, a.revokeAccountStillMatches, a.Users.DeleteExpected)
}

func (a *App) teardownLocalAccountWith(
	username string,
	expected user.Passwd,
	persistDeletion func() error,
	stillMatches func(string, user.Passwd) error,
	deleteExpected func(string, user.Passwd, func() error) error,
) (revokeAccountStage, error) {
	if err := stillMatches(username, expected); err != nil {
		return revokeDisableLogin, err
	}
	if err := a.Users.DisableLogin(username); err != nil {
		return revokeDisableLogin, err
	}
	if err := stillMatches(username, expected); err != nil {
		return revokeQuiesceAccount, err
	}
	if err := a.quiesceScheduledAccountWith(username, expected, stillMatches); err != nil {
		return revokeQuiesceAccount, err
	}
	if err := stillMatches(username, expected); err != nil {
		return revokeDeleteAccount, err
	}
	// Persist recovery authority before controlled mail/Home cleanup begins. The
	// account can disappear out of band at any later syscall boundary; without this
	// witness, a failed post-disappearance mail fsync could be mistaken on retry for
	// an ordinary stale row and discarded without completing the narrow cleanup.
	if persistDeletion == nil {
		return revokeDeleteAccount, fmt.Errorf("deletion recovery persistence is not configured")
	}
	if err := persistDeletion(); err != nil {
		return revokeDeleteAccount, fmt.Errorf("persist deletion-started recovery state: %w", err)
	}
	if err := deleteExpected(username, expected, func() error {
		return a.finalScheduledAccountCheckWith(username, expected, stillMatches)
	}); err != nil {
		return revokeDeleteAccount, err
	}
	return revokeAccountRemoved, nil
}

func (a *App) teardownQuarantinedAccount(username string, expected user.Passwd, persistDeletion func() error) (revokeAccountStage, error) {
	if err := a.revokeAccountStillMatches(username, expected); err != nil {
		return revokeDisableLogin, err
	}
	if err := a.Users.DisableLogin(username); err != nil {
		return revokeDisableLogin, err
	}
	if err := a.quiesceScheduledAccountImmediateForRevoke(username, expected); err != nil {
		return revokeQuiesceAccount, err
	}
	if persistDeletion == nil {
		return revokeDeleteAccount, fmt.Errorf("deletion recovery persistence is not configured")
	}
	if err := persistDeletion(); err != nil {
		return revokeDeleteAccount, fmt.Errorf("persist deletion-started recovery state: %w", err)
	}
	if err := a.Users.DeleteExpected(username, expected, func() error {
		return a.finalScheduledAccountCheck(username, expected)
	}); err != nil {
		return revokeDeleteAccount, err
	}
	return revokeAccountRemoved, nil
}

// uidOnlyDeletionCandidateMatches is the final local-shape check before a
// legacy, unregistered, or rollback-pending account receives a UID-only deletion
// witness. It is intentionally not identity proof: UID and lifecycle markers can
// be reproduced. The interactive --force/full-name gate supplies the authority
// for a live recovery; this predicate only prevents that authority from reaching
// a reserved/root identity, an unsafe Home, or an account with no tool marker.
func uidOnlyDeletionCandidateMatches(rec registry.Record, pw user.Passwd) bool {
	if rec.User != pw.Name || user.IsReservedName(pw.Name) || !validate.AccountID(pw.UID) ||
		!validate.AccountID(pw.GID) || (rec.UID != 0 && rec.UID != pw.UID) ||
		!validate.ManagedHome(pw.Name, pw.Home) || pw.Shell == "" {
		return false
	}
	return user.HasLifecycleMarker(pw)
}

// deletionRecordMatchesPasswd is the exact identity predicate used before a
// deletion phase is persisted or resumed. Pending and completed markers are
// deliberately distinct; neither a bare managed-looking GECOS nor UID equality
// on its own is sufficient.
func deletionRecordMatchesPasswd(rec registry.Record, pw user.Passwd) bool {
	if rec.User != pw.Name || user.IsReservedName(rec.User) || !rec.IdentityBound || !validate.AccountID(rec.UID) ||
		rec.UID != pw.UID || !validate.AccountID(pw.GID) || !validate.Generation(rec.Generation) ||
		!validate.ManagedHome(rec.User, pw.Home) || pw.Shell == "" {
		return false
	}
	if rec.Pending {
		return user.MatchesPendingGeneration(pw, rec.Generation)
	}
	return user.MatchesManagedGeneration(pw, rec.Generation)
}

func pendingCreationRecordMatchesPasswd(rec registry.Record, pw user.Passwd) bool {
	if !rec.Pending || rec.DeletionStarted || !rec.IdentityBound ||
		(rec.UID != 0 && rec.UID != pw.UID) {
		return false
	}
	check := rec
	check.UID = pw.UID
	return deletionRecordMatchesPasswd(check, pw)
}

// persistDeletionStarted writes the mandatory pre-artifact-cleanup witness.
// Completed generation-bound accounts retain that exact generation; legacy,
// unregistered, and pending rollback paths deliberately receive only a UID
// witness. Any change between the policy decision and this transition stops
// before controlled mail/Home cleanup or userdel can release the name or UID.
func (a *App) persistDeletionStarted(rec registry.Record, registered bool, expected user.Passwd) error {
	if a.Registry == nil {
		return fmt.Errorf("registry is not configured")
	}
	if rec.User == "" {
		rec.User = expected.Name
	}
	if rec.User != expected.Name {
		return fmt.Errorf("deletion target changed before persistence")
	}
	current, found, err := a.Registry.Lookup(expected.Name)
	if err != nil {
		return fmt.Errorf("read current registry identity: %w", err)
	}
	if found != registered {
		return fmt.Errorf("registry identity changed before deletion")
	}
	generation := ""
	if registered {
		if current.User != rec.User || current.UID != rec.UID || current.Generation != rec.Generation ||
			current.IdentityBound != rec.IdentityBound || current.Pending != rec.Pending ||
			current.DeletionStarted != rec.DeletionStarted || current.SequentialID != rec.SequentialID ||
			current.QuarantineUntil != rec.QuarantineUntil || current.QuarantineUnit != rec.QuarantineUnit {
			return fmt.Errorf("registry identity changed before deletion")
		}
		if current.IdentityBound {
			check := current
			if check.Pending && check.UID == 0 {
				check.UID = expected.UID
			}
			if !deletionRecordMatchesPasswd(check, expected) {
				return fmt.Errorf("account no longer matches the registry deletion identity")
			}
			if !current.Pending || current.DeletionStarted {
				generation = current.Generation
			}
		} else if !uidOnlyDeletionCandidateMatches(current, expected) {
			return fmt.Errorf("account no longer matches the UID-only deletion candidate")
		}
	} else {
		candidate := registry.Record{User: expected.Name, UID: expected.UID}
		if !uidOnlyDeletionCandidateMatches(candidate, expected) {
			return fmt.Errorf("account no longer matches the unregistered deletion candidate")
		}
	}
	if err := a.Registry.BeginDeletion(expected.Name, expected.UID, generation); err != nil {
		return fmt.Errorf("write deletion-started registry state: %w", err)
	}
	return nil
}

// releaseRegistryAfterCleanup removes an ordinary stale row by name, but an
// in-progress deletion only through the exact identity transition. Looking up
// again also lets invite rollback use the durable phase written inside userdel's
// pre-delete callback rather than a stale in-memory copy of the record.
func (a *App) releaseRegistryAfterCleanup(username string) error {
	if a.Registry == nil {
		return fmt.Errorf("registry is not configured")
	}
	rec, found, err := a.Registry.Lookup(username)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if rec.DeletionStarted {
		return a.Registry.FinishDeletionRecovery(rec.User, rec.UID, rec.Generation)
	}
	return a.Registry.Remove(username)
}

// reconcileDeletionStarted performs the only artifact cleanup authorized after
// the passwd entry is gone: an owner-checked same-name mail spool sweep. Home is
// intentionally excluded. Ordinary absent rows never call this function.
func (a *App) reconcileDeletionStarted(rec registry.Record) error {
	if !rec.DeletionStarted || !validate.AccountID(rec.UID) ||
		(rec.IdentityBound != validate.Generation(rec.Generation)) {
		return fmt.Errorf("incomplete deletion-started registry state")
	}
	if rec.Pending && (rec.QuarantineUntil == "" || !rec.IdentityBound) {
		return fmt.Errorf("incomplete pending deletion quarantine")
	}
	if a.Users == nil {
		return fmt.Errorf("account manager is not configured")
	}
	return a.Users.ReconcileManagedMailAfterDeletion(rec.User, rec.UID)
}

// quiesceScheduledAccount reaches a fixed point before the numeric UID and
// username can be released. Each pass terminates processes before clearing jobs:
// otherwise a process can enqueue work after the inventory and before it dies,
// leaving that work behind as the last action of the pass. The drain interval
// lets cron/at daemons finish a due job they had already read, and the second pass
// terminates anything the daemon started before performing the authoritative job
// inventory. Transient first-pass failures are contained by the still-live,
// disabled account and must be resolved by the final verification.
func (a *App) quiesceScheduledAccount(username string, expected user.Passwd) error {
	return a.quiesceScheduledAccountWith(username, expected, a.accountStillMatches)
}

func (a *App) quiesceScheduledAccountForRevoke(username string, expected user.Passwd) error {
	return a.quiesceScheduledAccountWith(username, expected, a.revokeAccountStillMatches)
}

func (a *App) quiesceScheduledAccountWith(username string, expected user.Passwd, stillMatches func(string, user.Passwd) error) error {
	if err := stillMatches(username, expected); err != nil {
		return err
	}
	var firstPass []error
	if err := a.terminateProcesses(expected.UID); err != nil {
		firstPass = append(firstPass, fmt.Errorf("initial process termination: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(firstPass...), err)
	}
	if err := a.clearScheduledJobs(username, expected.UID); err != nil {
		firstPass = append(firstPass, fmt.Errorf("initial scheduled-job cleanup: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(firstPass...), err)
	}
	if err := a.drainScheduledJobs(); err != nil {
		return errors.Join(errors.Join(firstPass...), fmt.Errorf("drain deferred jobs: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(firstPass...), err)
	}
	var finalPass []error
	if err := a.terminateProcesses(expected.UID); err != nil {
		finalPass = append(finalPass, fmt.Errorf("final process termination: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(firstPass...), errors.Join(finalPass...), err)
	}
	if err := a.clearScheduledJobs(username, expected.UID); err != nil {
		finalPass = append(finalPass, fmt.Errorf("final scheduled-job cleanup: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(firstPass...), errors.Join(finalPass...), err)
	}
	if err := errors.Join(finalPass...); err != nil {
		return errors.Join(errors.Join(firstPass...), err)
	}
	return nil
}

// quiesceScheduledAccountImmediate closes process/job races without waiting for
// a daemon polling cycle. It is safe for a fresh monotonic identity and for the
// final pass after a live passwd entry has already held an old identity through
// the complete quarantine window.
func (a *App) quiesceScheduledAccountImmediate(username string, expected user.Passwd) error {
	return a.quiesceScheduledAccountImmediateWith(username, expected, a.accountStillMatches)
}

func (a *App) quiesceScheduledAccountImmediateForRevoke(username string, expected user.Passwd) error {
	return a.quiesceScheduledAccountImmediateWith(username, expected, a.revokeAccountStillMatches)
}

func (a *App) quiesceScheduledAccountImmediateWith(username string, expected user.Passwd, stillMatches func(string, user.Passwd) error) error {
	if err := stillMatches(username, expected); err != nil {
		return err
	}
	var errs []error
	if err := a.terminateProcesses(expected.UID); err != nil {
		errs = append(errs, fmt.Errorf("process termination: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(errs...), err)
	}
	if err := a.clearScheduledJobs(username, expected.UID); err != nil {
		errs = append(errs, fmt.Errorf("scheduled-job cleanup: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(errs...), err)
	}
	if err := a.terminateProcesses(expected.UID); err != nil {
		errs = append(errs, fmt.Errorf("final process termination: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(errs...), err)
	}
	if err := a.clearScheduledJobs(username, expected.UID); err != nil {
		errs = append(errs, fmt.Errorf("final scheduled-job cleanup: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// finalScheduledAccountCheck runs after controlled Home/mail cleanup and just
// before userdel. The earlier drain already waited out daemon-side cached work;
// this last pass terminates processes first, then closes jobs raced in during
// filesystem cleanup without imposing a second polling-cycle delay.
func (a *App) finalScheduledAccountCheck(username string, expected user.Passwd) error {
	return a.finalScheduledAccountCheckWith(username, expected, a.revokeAccountStillMatches)
}

func (a *App) finalScheduledAccountCheckWith(username string, expected user.Passwd, stillMatches func(string, user.Passwd) error) error {
	if err := stillMatches(username, expected); err != nil {
		return err
	}
	var errs []error
	if err := a.terminateProcesses(expected.UID); err != nil {
		errs = append(errs, fmt.Errorf("process termination: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		return errors.Join(errors.Join(errs...), err)
	}
	if err := a.clearScheduledJobs(username, expected.UID); err != nil {
		errs = append(errs, fmt.Errorf("scheduled-job cleanup: %w", err))
	}
	if err := stillMatches(username, expected); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// accountStillMatches keeps invite creation bound to the exact passwd snapshot it
// captured. Before activation, even an ordinarily user-changeable field moving is
// unexpected and must stop the transaction. Name-based helpers remain non-atomic.
func (a *App) accountStillMatches(username string, expected user.Passwd) error {
	current, exists, err := a.lookupUser(username)
	if err != nil {
		return fmt.Errorf("re-read account identity: %w", err)
	}
	if !exists || current != expected {
		return fmt.Errorf("account identity changed during the operation")
	}
	return nil
}

// revokeAccountStillMatches keeps destructive work bound to stable identity while
// allowing an activated invitee to change the passwd fields exposed by chfn/chsh.
// SameAccountIdentity remains byte-exact for older first-field-only identities.
func (a *App) revokeAccountStillMatches(username string, expected user.Passwd) error {
	current, exists, err := a.lookupUser(username)
	if err != nil {
		return fmt.Errorf("re-read account identity: %w", err)
	}
	if !exists || !user.SameAccountIdentity(expected, current) {
		return fmt.Errorf("account identity changed during the operation")
	}
	return nil
}

// removeSudoGrant deletes any NOPASSWD drop-in this tool wrote for username. Like
// removeSSHDException beside it, the path is derived from the username and the
// manager only ever touches its own managed file, so it is called blindly.
//
// A failure is reported and never silent, because of what surviving means here:
// the drop-in grants passwordless root the moment its username exists. Everything
// else in a revoke can fail and leave the host no worse than it was found; this
// one failing leaves a live grant behind, and it used to do so without a word.
func (a *App) removeSudoGrant(username string) error {
	if a.Sudoers == nil {
		return nil
	}
	if err := a.Sudoers.Remove(username); err != nil {
		a.errorf("%s: %v", a.P.M("无法移除 sudo 授权（该账号可能仍有免密 root，请手动删除该文件）",
			"could not remove the sudo grant (this account may still hold passwordless root; delete the file by hand)"), err)
		return err
	}
	return nil
}

// removeSSHDException deletes any per-account sshd drop-in this tool wrote for
// username and reloads sshd. Like the sudoers drop-in beside it, the path is
// derived from the username and the manager only ever touches its own managed
// file, so this is called blindly: revoke never has to know whether a grant was
// made, which means a grant can never be orphaned by a lost registry entry.
//
// A failure is reported and blocks account deletion. Remove can fail before the
// file is gone, and freeing the username while a name-scoped exception may still
// exist would let a replacement account inherit it.
func (a *App) removeSSHDException(username string) error {
	if a.SSHD == nil {
		return nil
	}
	if err := a.SSHD.Remove(username); err != nil {
		// Remove's own error already says precisely what happened — in the common
		// failure the file WAS deleted and only the reload was (deliberately) skipped
		// because the host's sshd config is invalid. Do not prepend a contradicting
		// "removal failed; delete it by hand", which would name a path that is already
		// gone and bury the real problem.
		a.warnf("%s: %v", a.P.M("sshd 例外", "sshd exception"), err)
		return err
	}
	return nil
}

// selectUser shows the registered accounts and reads a row number or a username.
// It is the `revoke` command's own picker, reached when no --user was given; the
// menu comes in through manageUsers, which has already chosen.
//
// It shows the same table, numbered the same way, because it used to print a bare
// list of names: you picked what to delete without seeing which account was about
// to expire anyway, which carried sudo, or which was already gone. Rows whose
// account is missing are listed too — revoke is what cleans up their registry
// entry and any grant they left behind, so leaving them unpickable only meant
// they could not be named.
//
// An unrecognized answer is returned verbatim for validate.Username to reject: a
// picker must not be the thing that decides what a legal username is.
//
// An empty registry still prompts. It says so and then asks anyway, because a
// registry with no rows is exactly the state `revoke --force` exists to dig out
// of — a tool-made account whose row was lost still has to be nameable, and the
// only way to name it here is to type it. (manageUsers takes the opposite branch
// on an empty list, but for a reason that does not apply here: it is reached from
// the menu, where a prompt nobody can answer would eat the next menu choice.)
func (a *App) selectUser() string {
	recs, err := a.Registry.List()
	if err != nil {
		a.warnf("%v", err)
	}
	if len(recs) == 0 {
		a.warnf("%s", a.P.M("没有已登记的临时用户；如需删除未登记账号，请输入完整用户名（配合 --force）。",
			"no registered temporary users; to delete an unregistered account, type its full username (with --force)."))
	} else {
		a.printf("%s", a.usersTable(recs, true).String())
	}
	choice := strings.TrimSpace(a.prompt(a.P.M("请输入编号或用户名: ", "enter a number or a username: ")))
	if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(recs) {
		return recs[n-1].User
	}
	return choice
}
