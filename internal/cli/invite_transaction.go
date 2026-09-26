package cli

import (
	"errors"
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/expiry"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"time"
)

// inviteTransaction keeps the durable and in-memory witnesses for a single
// account creation together. Phase methods must run in the order used by
// runInvite: later phases rely on the rollback gates and
// identity snapshots established by earlier ones.
type inviteTransaction struct {
	a *App
	invitePlan

	kp *sshkey.KeyPair
	// password is the issued login secret for a --password-login invite, kept as
	// bytes so rollback and the printer can clear it; a Go string could not be.
	password           []byte
	generation         string
	fingerprint        string
	permanent          bool
	createdAt          time.Time
	revokeDeadline     time.Time
	expiresDisplay     string
	expiresServerLocal string
	rec                registry.Record
	pw                 user.Passwd
	rollbackIdentity   user.Passwd
	groups             []string
	sshdDropIn         string
	sudoGranted        bool
	autoUnit           string
	autoScheduled      bool

	identityIsolationReady  bool
	sudoRemovalConfirmed    bool
	sshdRemovalConfirmed    bool
	accountCleanupConfirmed bool
	loginActivationStarted  bool
	cleanups                []func() error
}

func newInviteTransaction(a *App, plan invitePlan) *inviteTransaction {
	return &inviteTransaction{
		a: a, invitePlan: plan,
		sudoRemovalConfirmed:    true,
		sshdRemovalConfirmed:    true,
		accountCleanupConfirmed: true,
	}
}

// runInvite performs the mutating steps with rollback on any
// failure. generatedUsername controls whether the fresh-name isolation proof is
// available for the deferred-job cleanup policy.
func (a *App) runInvite(plan invitePlan) int {
	tx := newInviteTransaction(a, plan)
	// printInvite zeroes the credentials it renders, but nothing reached it on a
	// failure path. The interactive menu keeps one long-lived root process, so a
	// rolled-back invite left the unencrypted private key and the plaintext
	// password live in the heap for the rest of the session — through later
	// privileged actions and into any core dump, ptrace, swap or hibernation
	// image. clear() on an already-zeroed slice is harmless, so this is safe
	// alongside printInvite's own deferred clears.
	defer tx.clearSecrets()
	if !tx.preflightAndGenerateCredentials() {
		return 1
	}
	if !tx.clearReusedUsername() {
		return 1
	}
	if !tx.reserveAndCreatePendingIdentity() {
		return 1
	}
	if !tx.drainAndFinalizeIdentity() {
		return 1
	}
	if !tx.installCredentialsAndGrants() {
		return 1
	}
	return tx.scheduleActivateAndReport()
}

func (tx *inviteTransaction) preflightAndGenerateCredentials() bool {
	a := tx.a
	// Preflight the registry before creating anything, so a broken/unsafe
	// registry fails fast instead of leaving a stray account behind.
	if err := a.Registry.Init(); err != nil {
		a.errorf("%s: %v", a.P.M("初始化注册表失败", "registry init failed"), err)
		a.warnf("%s", a.P.M("请运行 linux-temp-admin doctor 查看安全恢复指引。",
			"run linux-temp-admin doctor for safe recovery guidance."))
		return false
	}

	// Both secrets are generated before anything is created, so a generation
	// failure cannot leave a half-made account behind. Exactly one is issued: a
	// key account has password authentication disabled, and a password account is
	// never given a key it could not use.
	if tx.login.password {
		p, err := a.RandPassword(passwordLen)
		if err != nil {
			a.errorf("%s: %v", a.P.M("生成密码失败", "password generation failed"), err)
			return false
		}
		tx.password = p
	} else {
		k, err := sshkey.GenerateEd25519(tx.username + "-" + config.ManagedTag)
		if err != nil {
			a.errorf("%s: %v", a.P.M("生成密钥失败", "key generation failed"), err)
			return false
		}
		tx.kp = k
	}
	generation, err := a.RandHex(16)
	if err != nil || !validate.Generation(generation) {
		if err == nil {
			err = fmt.Errorf("random source returned an invalid generation")
		}
		a.errorf("%s: %v", a.P.M("生成账号世代标识失败", "generating account generation failed"), err)
		return false
	}
	tx.generation = generation
	if tx.kp != nil {
		tx.fingerprint = tx.kp.Fingerprint
	}
	tx.permanent = !tx.wantAuto
	tx.createdAt = a.Now()
	tx.expiresDisplay = a.P.M("永久（不会过期，也不会自动删除）", "never (does not expire or auto-delete)")
	if !tx.permanent {
		tx.revokeDeadline = expiry.Deadline(tx.createdAt, tx.hours)
		tx.expiresDisplay = expiry.Display(tx.revokeDeadline)
		tx.expiresServerLocal = expiry.DisplayServerLocal(tx.revokeDeadline)
	}
	tx.rec = registry.Record{
		User:          tx.username,
		Created:       expiry.Display(tx.createdAt),
		Expires:       tx.expiresDisplay,
		Sudo:          tx.wantSudo,
		Host:          tx.host,
		Port:          tx.port,
		Fingerprint:   tx.fingerprint,
		AutoRevoke:    tx.wantAuto,
		Generation:    generation,
		IdentityBound: true,
		Pending:       true,
	}
	return true
}

func (tx *inviteTransaction) confirmSudoRemoved() error {
	err := tx.a.removeSudoGrant(tx.username)
	if err == nil {
		tx.sudoRemovalConfirmed = true
	}
	return err
}

func (tx *inviteTransaction) confirmSSHDRemoved() error {
	err := tx.a.removeSSHDException(tx.username)
	if err == nil {
		tx.sshdRemovalConfirmed = true
	}
	return err
}

// clearSecrets zeroes every credential this transaction generated. It is
// idempotent: printInvite clears the same backing arrays on the success path.
func (tx *inviteTransaction) clearSecrets() {
	if tx == nil {
		return
	}
	if tx.kp != nil {
		clear(tx.kp.PrivatePEM)
	}
	clear(tx.password)
}

func (tx *inviteTransaction) rollback() error {
	tx.a.warnf("%s", tx.a.P.M("创建失败，正在回滚："+tx.username, "creation failed; rolling back: "+tx.username))
	if tx.a.stableCommandReplaced {
		// Not a cleanup step: the replaced bytes are gone. It belongs in the
		// rollback report because "the invite was rolled back" otherwise reads as
		// "the host is unchanged", and the root binary is not unchanged.
		tx.a.warnf("%s", tx.a.P.M(
			"注意：本次运行已替换 "+tx.a.InstallPath+" 上的稳定命令，回滚不会还原它。",
			"note: this run already replaced the stable command at "+tx.a.InstallPath+"; the rollback does not restore it."))
	}
	var rollbackErrs []error
	for i := len(tx.cleanups) - 1; i >= 0; i-- {
		if err := tx.cleanups[i](); err != nil {
			rollbackErrs = append(rollbackErrs, err)
		}
	}
	return errors.Join(rollbackErrs...)
}

func (tx *inviteTransaction) failf(format string, args ...any) bool {
	tx.a.errorf(format, args...)
	tx.a.audit("account.create", tx.username, "fail", fmt.Sprintf(format, args...), nil)
	if err := tx.rollback(); err != nil {
		tx.a.errorf("%s: %v", tx.a.P.M("回滚未完整完成，请立即人工核查", "rollback did not complete; inspect immediately"), err)
		tx.a.audit("account.rollback", tx.username, "fail", err.Error(), nil)
	}
	return false
}

func (tx *inviteTransaction) clearReusedUsername() bool {
	a := tx.a
	// A failed invite may delete the account only after every name-scoped privilege
	// grant is confirmed gone. Grant closes its gate before it can write anything;
	// only Manager.Remove returning success opens it again. Registry cleanup keys on
	// the same gates so a crash-recovery witness survives even if the account
	// disappears out of band.
	// The final chage call can make the credential usable before a helper reports
	// failure. From the instant that helper is invoked, rollback must tolerate the
	// account holder changing ordinary passwd fields or a partially successful
	// activation could let chfn/chsh hold cleanup open indefinitely.
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
	exists, lookupErr := user.NameInUse(tx.username)
	if lookupErr != nil {
		return tx.failf("%s: %v", a.P.M("读取本地/NSS 账号数据库失败", "reading the local/NSS account database failed"), lookupErr)
	}
	if exists {
		a.errorf("%s", a.P.M("本地或 NSS 中已存在同名账号，拒绝创建："+tx.username,
			"an account with this name already exists locally or in NSS; refusing creation: "+tx.username))
		return false
	}
	// A previous revoke/rollback may have reached userdel and left a durable
	// recovery witness. Never consume that witness as a side effect of creating a
	// replacement account: the operator must finish the old transaction through
	// revoke, where its recovery state is visible and auditable. In particular,
	// creating a new generation must not depend on an invite-time mail cleanup and
	// then overwrite the only evidence needed to retry it.
	_, staleRegistered, err := a.Registry.Lookup(tx.username)
	if err != nil {
		return tx.failf("%s: %v", a.P.M("读取同名账号的旧删除状态失败", "reading prior deletion state for this username failed"), err)
	}
	if staleRegistered {
		return tx.failf("%s", a.P.M(
			"同名账号仍有未结清的生命周期登记；拒绝复用用户名或覆盖身份见证。请先运行 linux-temp-admin revoke --user "+tx.username+" 完成清理。",
			"an unfinished lifecycle record exists for this username; refusing to reuse the name or overwrite its identity witness. Run linux-temp-admin revoke --user "+tx.username+" first to complete cleanup."))
	}
	if err := errors.Join(a.removeSudoGrant(tx.username), a.removeSSHDException(tx.username)); err != nil {
		return tx.failf("%s: %v", a.P.M("无法清除同名账号的遗留授权，拒绝创建", "cannot remove grants left by this username; refusing creation"), err)
	}
	// A stale scheduled command is name-keyed, so it must be gone before useradd
	// makes that name live again. No recorded unit id can accompany it: the Lookup
	// above already refused every username that still holds a registry row, and
	// Lookup scans that same row set, so it could only ever return "" here.
	// Cancel sweeps by name across every namespace, which is what actually clears
	// an older run's unit or at job.
	if err := a.Scheduler.Cancel(tx.username, ""); err != nil {
		return tx.failf("%s: %v", a.P.M("无法确认旧自动删除任务已清除", "cannot confirm stale auto-delete tasks were removed"), err)
	}
	// Cancel can remove queued work, but an older at/systemd command may already be
	// executing an old binary and waiting for this transaction's lifecycle lock. It
	// has no UID/generation arguments, so letting it resume after a same-name invite
	// would apply the old deletion intent to the new account. Refuse reuse while that
	// exact root-owned command is still visible. New binaries also make this legacy
	// command shape take a nonblocking shared barrier for the username; invite owns
	// the exclusive side, closing the start-after-scan interval without suppressing
	// revokes delayed by unrelated lifecycle work.
	legacyRevoke, err := a.runningLegacyRevoke(tx.username)
	if err != nil {
		return tx.failf("%s: %v", a.P.M("无法检查正在运行的旧版撤销任务，拒绝复用用户名", "cannot inspect running legacy revoke tasks; refusing username reuse"), err)
	}
	if legacyRevoke {
		return tx.failf("%s", a.P.M(
			"检测到该用户名的旧版无世代绑定撤销进程仍在运行；已拒绝复用，请等待其退出并重新运行。",
			"a legacy revoke process without a generation binding is still running for this username; reuse was refused; wait for it to exit and retry."))
	}
	return true
}

func (tx *inviteTransaction) reserveAndCreatePendingIdentity() bool {
	a := tx.a
	// Reserve and durably burn an identity above every currently allocated local UID
	// and GID. The registry sequence commits before useradd: a crash may waste a
	// number, but this tool never reuses it for another account generation.
	minimumID, maximumID, err := a.identityAllocationRange()
	if err != nil {
		return tx.failf("%s: %v", a.P.M("无法确定安全的 UID/GID 分配范围", "cannot determine a safe UID/GID allocation range"), err)
	}
	reservedID, identityIsolationReady, err := a.Registry.ReserveIdentity(minimumID, maximumID)
	if err != nil {
		return tx.failf("%s: %v", a.P.M("无法持久化预留 UID/GID", "cannot durably reserve a UID/GID"), err)
	}
	tx.identityIsolationReady = identityIsolationReady
	tx.rec.UID = reservedID
	tx.rec.SequentialID = true
	// Persist the account intent before useradd. A kill or power loss after account
	// creation must leave a registry witness even if no sudo/sshd/schedule artifact
	// exists. The reserved UID is already known and is verified against passwd as
	// soon as the helper returns.
	// A DurabilityError means AtomicWriteFileAt already renamed the new registry
	// into place and only the directory fsync failed: the row IS on disk while
	// Record reports failure. Adopting it before failing is what lets rollback
	// release it. Even a failed Record may have committed its pending row.
	// Every other module
	// that writes through this primitive handles the same case explicitly.
	recordErr := a.Registry.Record(tx.rec)
	if recordErr != nil {
		var committed *fsutil.DurabilityError
		if !errors.As(recordErr, &committed) {
			return tx.failf("%s: %v", a.P.M("登记账号创建意图失败", "recording account creation intent failed"), recordErr)
		}
	}
	// This cleanup was registered first, so reverse-order rollback runs it last,
	// after account deletion. If deletion failed, retain the row for recovery.
	tx.cleanups = append(tx.cleanups, func() error {
		var unconfirmed []error
		if !tx.sudoRemovalConfirmed {
			unconfirmed = append(unconfirmed, fmt.Errorf("sudo removal is unconfirmed; keeping registry record"))
		}
		if !tx.sshdRemovalConfirmed {
			unconfirmed = append(unconfirmed, fmt.Errorf("sshd removal is unconfirmed; keeping registry record"))
		}
		if !tx.accountCleanupConfirmed {
			unconfirmed = append(unconfirmed, fmt.Errorf("account artifact cleanup is unconfirmed; keeping registry record"))
		}
		if err := errors.Join(unconfirmed...); err != nil {
			return err
		}
		exists, err := user.Exists(tx.username)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("account still exists; keeping registry record")
		}
		if err := a.releaseRegistryAfterCleanup(tx.username); err != nil {
			return err
		}
		// Only now that the account is provably gone is the scheduled fallback safe
		// to remove, the same rule revoke states when it deliberately leaves the
		// task armed on a failed teardown. Cancelling earlier destroyed the one
		// mechanism that would have retried this cleanup: rollbackInviteAccount may
		// only delete when both grant removals are confirmed, so a rollback that
		// retains a disabled account used to leave it with a stale sudo drop-in and
		// nothing scheduled to come back for it.
		if tx.autoScheduled {
			return a.Scheduler.Cancel(tx.username, tx.autoUnit)
		}
		return nil
	})
	if recordErr != nil {
		// Committed but not durable. The row and its release cleanup are registered
		// above, so rollback can now let it go; the transaction still fails, because
		// a registry this tool cannot prove is on stable storage is not a witness it
		// may rely on for anything that follows.
		return tx.failf("%s: %v", a.P.M("登记账号创建意图失败", "recording account creation intent failed"), recordErr)
	}

	// useradd can create the account before reporting an error. Close the
	// registry-removal gate before invoking it. CreatePendingIdentityWithID returns a
	// nonzero passwd snapshot with errors that happen after it has proved the full
	// pending identity, allowing this transaction to attempt the same fail-closed
	// rollback instead of discarding evidence it already captured.
	tx.accountCleanupConfirmed = false
	pw, err := a.Users.CreatePendingIdentityWithID(tx.username, resolveShell(), tx.generation, reservedID)
	if err != nil && errors.Is(err, user.ErrAccountCreationNotStarted) {
		// No account helper ran, so there is no ambiguous partial account identity to
		// recover. The last registry cleanup still confirms local absence before it
		// releases the creation-intent row.
		tx.accountCleanupConfirmed = true
		return tx.failf("%s: %v", a.P.M("创建用户失败", "create user failed"), err)
	}
	if err != nil && pw.Name == "" {
		// useradd ran but no passwd identity survived. It may still have committed
		// the reserved private group or subordinate-ID ranges, so convert the durable
		// pending intent into deletion recovery before touching those artifacts.
		cleanupErr := a.reconcileAbsentSequentialCreation(tx.rec)
		if cleanupErr == nil {
			tx.accountCleanupConfirmed = true
		}
		return tx.failf("%s: %v", a.P.M("创建用户失败", "create user failed"), errors.Join(err, cleanupErr))
	}
	// Keep a separately named rollback witness. A failed MarkManagedExpected call
	// may return a zero Passwd even after usermod partially ran; overwriting this
	// value would discard the last complete identity that this transaction proved.
	tx.pw = pw
	tx.rollbackIdentity = pw
	tx.cleanups = append(tx.cleanups, func() error {
		var causes []error
		if !tx.sudoRemovalConfirmed {
			causes = append(causes, fmt.Errorf("sudo removal is unconfirmed; account disabled and retained"))
		}
		if !tx.sshdRemovalConfirmed {
			causes = append(causes, fmt.Errorf("sshd removal is unconfirmed; account disabled and retained"))
		}
		mayDelete := tx.sudoRemovalConfirmed && tx.sshdRemovalConfirmed
		cleanupErr := errors.Join(errors.Join(causes...), a.rollbackInviteAccount(tx.username, tx.rec, tx.rollbackIdentity, mayDelete, tx.loginActivationStarted))
		if cleanupErr == nil {
			tx.accountCleanupConfirmed = true
		}
		return cleanupErr
	})
	if err != nil {
		return tx.failf("%s: %v", a.P.M("创建用户失败", "create user failed"), err)
	}

	tx.rec.UID = tx.pw.UID
	// Persist the UID while the passwd entry still carries PendingGECOS. An older
	// binary ignores the appended Pending field, but it does understand that this
	// is not the managed marker and therefore refuses deletion. Once this write is
	// durable, changing the marker is safe even for that older binary.
	if err := a.Registry.Record(tx.rec); err != nil {
		return tx.failf("%s: %v", a.P.M("登记新账号身份失败", "recording the new account identity failed"), err)
	}
	// Put an account-level login gate in place before any deferred work is
	// drained, the pending marker is promoted, or a credential is installed.
	// useradd's initial password lock is not enough for a key-based account: a
	// public key bypasses that lock, while an account expiry is enforced for both
	// key and password authentication. If this process is killed at any later
	// setup boundary, the account therefore remains unusable until a subsequent
	// successful invite installs its requested lifetime below.
	if err := a.Users.DisableLogin(tx.username); err != nil {
		return tx.failf("%s: %v", a.P.M("建立新账号的安全失效状态失败", "establishing the new account's fail-closed login state failed"), err)
	}
	return true
}

func (tx *inviteTransaction) drainAndFinalizeIdentity() bool {
	a := tx.a
	// Generated names combine a fresh random suffix with the monotonic UID/GID pair,
	// so neither name nor numeric identity is being reused by this tool. Clear and
	// verify once without the old polling-cycle delay. Explicit operator-selected
	// names retain the full drain because they may intentionally reuse a historical
	// name even though their numeric identity is fresh.
	quiesce := a.quiesceScheduledAccount
	if tx.generatedUsername && tx.rec.SequentialID && tx.identityIsolationReady {
		quiesce = a.quiesceScheduledAccountImmediate
	} else if tx.generatedUsername {
		a.info(a.P.M(
			"登记刚从旧版迁移，历史已释放 UID 尚未跨过一次性隔离窗口；本次将同步等待约 65 秒，后续自动用户名创建不再等待。",
			"the registry was just migrated from an older release, so historically released UIDs have not crossed the one-time isolation window; this invite waits about 65 seconds, and later generated-name invites do not."))
	} else {
		a.info(a.P.M(
			"显式用户名可能复用历史名称；为防止旧 cron/at 缓存任务跨世代执行，将同步等待约 65 秒完成清场。",
			"an explicit username may reuse a historical name; waiting about 65 seconds to prevent cached cron/at work from crossing account generations."))
	}
	if err := quiesce(tx.username, tx.pw); err != nil {
		return tx.failf("%s: %v", a.P.M("无法清除同名账号或复用 UID 的遗留 cron/at 任务", "cannot clear cron/at work left by the reused username or UID"), err)
	}
	// The drain intentionally gives daemon-cached work a full polling cycle to
	// start. Re-scan now, while the account is still expired, password-locked,
	// credential-less, and marked pending. A legacy command found here triggers the
	// ordinary rollback before this identity can become usable.
	legacyRevoke, err := a.runningLegacyRevoke(tx.username)
	if err != nil {
		return tx.failf("%s: %v", a.P.M("任务清场后无法复查正在运行的旧版撤销任务", "cannot recheck running legacy revoke tasks after deferred-job cleanup"), err)
	}
	if legacyRevoke {
		return tx.failf("%s", a.P.M(
			"任务清场期间启动了该用户名的旧版无世代绑定撤销进程；已回滚新账号，请等待旧任务退出后重试。",
			"a legacy revoke process without a generation binding started during deferred-job cleanup; the new account was rolled back; wait for the old task to exit before retrying."))
	}
	// Delivery can recreate /var/mail/USER during the deliberate daemon drain even
	// though pending-account creation swept an older generation's spool. Run the
	// same identity-checked cleanup again while this account is still expired,
	// password-locked, pending, credential-less, and without a Home.
	if err := a.Users.ClearManagedMailExpected(tx.username, tx.pw); err != nil {
		return tx.failf("%s: %v", a.P.M(
			"任务清场后无法安全清除同名旧邮件，拒绝激活账号",
			"cannot safely clear same-name stale mail after deferred-job cleanup; refusing to activate the account"), err)
	}
	if err := a.accountStillMatches(tx.username, tx.pw); err != nil {
		return tx.failf("%s: %v", a.P.M(
			"创建账号目录前账号身份发生变化",
			"the account identity changed before creating its Home"), err)
	}
	// Keep the Home absent until every inherited cron/at job and residual process
	// has been drained. A previous account generation therefore has nowhere to
	// plant authorized_keys or shell startup files that the new identity can inherit.
	if err := a.Users.CreateManagedHomeExpected(tx.username, tx.pw); err != nil {
		return tx.failf("%s: %v", a.P.M(
			"任务清场后无法安全创建账号目录，拒绝激活账号",
			"cannot safely create the account Home after deferred-job cleanup; refusing to activate the account"), err)
	}
	if err := a.accountStillMatches(tx.username, tx.pw); err != nil {
		return tx.failf("%s: %v", a.P.M(
			"创建账号目录期间账号身份发生变化",
			"the account identity changed while creating its Home"), err)
	}
	// The requested lifetime starts only after the deliberate deferred-job drain;
	// otherwise that safety wait would shorten a nominal one-hour invite. Persist
	// the adjusted display and absolute target while the account is still pending.
	tx.createdAt = a.Now()
	tx.rec.Created = expiry.Display(tx.createdAt)
	if !tx.permanent {
		tx.revokeDeadline = expiry.Deadline(tx.createdAt, tx.hours)
		tx.expiresDisplay = expiry.Display(tx.revokeDeadline)
		tx.expiresServerLocal = expiry.DisplayServerLocal(tx.revokeDeadline)
		tx.rec.Expires = tx.expiresDisplay
	}
	if err := a.Registry.Record(tx.rec); err != nil {
		return tx.failf("%s: %v", a.P.M("登记任务清场后的账号时间失败", "recording the account time after deferred-job cleanup failed"), err)
	}
	managedIdentity, err := a.Users.MarkManagedExpected(tx.username, tx.generation, tx.pw)
	if err != nil {
		return tx.failf("%s: %v", a.P.M("完成新账号身份标记失败", "finalizing the new account identity marker failed"), err)
	}
	tx.pw = managedIdentity
	tx.rollbackIdentity = managedIdentity
	completed := tx.rec
	completed.Pending = false
	if err := a.Registry.Record(completed); err != nil {
		// Same committed-but-unsynced case: the completed row is already the one on
		// disk. Keeping tx.rec on the superseded Pending shape would desynchronize
		// this transaction from the registry, and persistDeletionStarted compares
		// the recorded fields strictly — so invite's own rollback would abort and
		// leave the live account behind.
		var committed *fsutil.DurabilityError
		if errors.As(err, &committed) {
			tx.rec = completed
		}
		return tx.failf("%s: %v", a.P.M("完成新账号身份登记失败", "finalizing the new account identity record failed"), err)
	}
	tx.rec = completed
	return true
}

func (tx *inviteTransaction) installCredentialsAndGrants() bool {
	a := tx.a

	// The preflight had to PREDICT this account's groups, because it ran before the
	// account existed. Now they are real — and sshd decides AllowGroups/DenyGroups
	// on exactly them. Re-run the same check against the real group set before
	// anything is printed: `useradd` only gives the account a group of its own
	// name when USERGROUPS_ENAB is on, and on a host that puts new accounts in a
	// shared group instead (openSUSE ships GROUP=100 "users"), a `DenyGroups users`
	// rule would block the credential while the invite claimed config verification.
	groups, groupsErr := user.Groups(tx.pw)
	if groupsErr != nil {
		return tx.failf("%s: %v", a.P.M("无法可靠读取新账号的用户组", "cannot reliably read the new account's groups"), groupsErr)
	}
	tx.groups = groups
	if err := a.accountStillMatches(tx.username, tx.pw); err != nil {
		return tx.failf("%s: %v", a.P.M("读取用户组期间账号身份发生变化", "the account identity changed while resolving its groups"), err)
	}
	if !a.confirmLogin(tx.username, tx.groups, &tx.login) {
		return tx.failf("%s", a.P.M("按该账号的真实用户组复核后，sshd 有效配置检查发现此凭据的阻碍",
			"re-checked against the account's real groups: the effective sshd config check found a blocker for this credential"))
	}
	if err := a.accountStillMatches(tx.username, tx.pw); err != nil {
		return tx.failf("%s: %v", a.P.M("复核 sshd 配置期间账号身份发生变化", "the account identity changed during the sshd configuration check"), err)
	}

	if tx.login.password {
		if err := a.Users.SetPassword(tx.username, tx.password); err != nil {
			return tx.failf("%s: %v", a.P.M("设置密码失败", "set password failed"), err)
		}
	} else {
		if err := a.Users.DisablePasswordForKeyLogin(tx.username); err != nil {
			return tx.failf("%s: %v", a.P.M("禁用密码登录失败", "disable password login failed"), err)
		}
		if err := sshkey.WriteAuthorizedKeys(tx.pw.Home, tx.pw.UID, tx.pw.GID, tx.kp.AuthorizedKey); err != nil {
			return tx.failf("%s: %v", a.P.M("写入 authorized_keys 失败", "write authorized_keys failed"), err)
		}
	}

	// The sshd exception goes in only once the account (and its key) exist, and it
	// is confirmed in the effective config against the account's real groups before
	// sshd is reloaded. Grant attempts its own rollback on failure; the CLI retries removal
	// independently before account rollback can free the username.
	if tx.login.fixSSHD {
		tx.sshdRemovalConfirmed = false
		res, err := a.SSHD.Grant(tx.username, tx.groups, tx.login.report)
		if err != nil {
			cleanupErr := tx.confirmSSHDRemoved()
			return tx.failf("%s: %v", a.P.M("为该账号开启 sshd 公钥登录失败", "enabling the sshd public-key login for this account failed"), errors.Join(err, cleanupErr))
		}
		tx.sshdDropIn = res.Path
		tx.cleanups = append(tx.cleanups, tx.confirmSSHDRemoved)
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
			tx.login.verified = false
			tx.login.unverified = "sshd could not be asked to re-read its configuration; reload it yourself"
			a.warnf("%s", a.P.M("未能通知正在运行的 sshd 重新读取配置。若 sshd 是常驻进程，请手动运行 `sshd -t && systemctl reload ssh`，使配置变更生效（socket 激活的 sshd 无需 reload）。",
				"could not ask the running sshd to re-read its configuration. If sshd is a long-running process, run `sshd -t && systemctl reload ssh` yourself so the configuration change takes effect (a socket-activated sshd needs no reload)."))
		case len(tx.login.report.Unverifiable) > 0:
			tx.login.verified = false
			tx.login.unverified = tx.login.report.Unverifiable[0]
		default:
			tx.login.verified = true
			tx.login.unverified = ""
		}
	}

	if tx.wantSudo {
		// Grant can make the drop-in live before a later verification step fails.
		// Close the deletion gate before calling it so both that partial failure and a
		// later transaction failure retain the username until removal is confirmed.
		tx.sudoRemovalConfirmed = false
		if err := a.Sudoers.Grant(tx.username); err != nil {
			// Grant may have written a live drop-in before its verification step
			// failed; remove it unconditionally so a failed grant can never leave an
			// unregistered NOPASSWD grant behind. Remove only ever touches the
			// managed-prefixed file for this user, so it is safe to call blindly.
			cleanupErr := tx.confirmSudoRemoved()
			return tx.failf("%s: %v", a.P.M("sudo 授权失败，已拒绝创建账号", "sudo grant failed; refusing to create the account"),
				errors.Join(err, cleanupErr))
		}
		tx.sudoGranted = true
		tx.cleanups = append(tx.cleanups, tx.confirmSudoRemoved)
	}

	// Whoever revokes this account later runs the binary at InstallPath — the
	// auto-revoke timer's ExecStart, and the revoke command printed in the invite.
	// If a grant was written that an older binary does not know how to remove (the
	// sshd exception), that binary would delete the account and leave the grant
	// behind forever. So refresh the installed command whenever this invite created
	// something that needs cleaning up, not only when a timer is being scheduled.
	if tx.wantAuto || tx.sshdDropIn != "" {
		if err := a.ensureStableInstalled(); err != nil {
			return tx.failf("%s: %v", a.P.M("无法安装或验证稳定命令", "cannot install or verify the stable command"), err)
		}
	}
	return true
}

func (tx *inviteTransaction) scheduleActivateAndReport() int {
	a := tx.a

	// Commit the final grant state before creating a scheduler task. For an
	// auto-revoke account this row is the durable identity intent the task checks.
	tx.rec.Sudo = tx.sudoGranted
	if err := a.Registry.Record(tx.rec); err != nil {
		tx.failf("%s: %v", a.P.M("登记注册表失败", "registry record failed"), err)
		return 1
	}

	if tx.wantAuto {
		// The auto-revoke task's ExecStart runs the installed stable command, so a
		// binary must be present at InstallPath (ensured above), otherwise the timer
		// would fire and fail on a non-installed run.
		if err := fsutil.RootSafeFile(a.InstallPath); err != nil {
			tx.failf("%s: %v", a.P.M("稳定命令不安全", "the stable command is unsafe"), err)
			return 1
		}
		unit, err := a.Scheduler.Schedule(tx.username, tx.pw.UID, tx.generation, tx.revokeDeadline)
		if err != nil {
			tx.failf("%s: %v", a.P.M("自动删除任务创建失败，已拒绝创建临时账号", "auto-delete scheduling failed; refusing to create the temporary account"), err)
			return 1
		}
		tx.autoUnit = unit
		tx.autoScheduled = true
		// No cleanup is registered here on purpose. Reverse-order rollback would run
		// it first, before the account teardown that decides whether the account can
		// be deleted at all. The cancellation is performed by the first-registered
		// cleanup instead, which runs last and only after every confirmation passes.
		tx.rec.AutoUnit = unit
		if err := a.Registry.Record(tx.rec); err != nil {
			tx.failf("%s: %v", a.P.M("登记自动删除任务失败", "recording the auto-delete task failed"), err)
			return 1
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
	tx.loginActivationStarted = true
	if tx.permanent {
		if err := a.Users.ClearExpiry(tx.username); err != nil {
			tx.failf("%s: %v", a.P.M("恢复永久账号的登录有效期失败", "restoring never-expire login state for the permanent account failed"), err)
			return 1
		}
	} else {
		if err := a.Users.SetExpiry(tx.username, expiry.Date(tx.revokeDeadline)); err != nil {
			tx.failf("%s: %v", a.P.M("设置到期失败", "set expiry failed"), err)
			return 1
		}
	}

	if err := a.printInvite(inviteBundle{
		user: tx.username, host: tx.host, port: tx.port,
		sudo: tx.sudoGranted, auto: tx.autoScheduled, autoUnit: tx.autoUnit,
		permanent: tx.permanent, expires: tx.expiresDisplay, expiresServerLocal: tx.expiresServerLocal,
		kp: tx.kp, password: tx.password,
		sshdDropIn: tx.sshdDropIn, verified: tx.login.verified, unverified: tx.login.unverified,
	}); err != nil {
		tx.failf("%s: %v", a.P.M("邀请凭据输出失败", "writing invite credentials failed"), err)
		return 1
	}
	a.audit("account.create", tx.username, "ok", "", map[string]string{
		"host":        tx.host,
		"port":        fmt.Sprintf("%d", tx.port),
		"sudo":        ynStr(tx.sudoGranted),
		"auto":        ynStr(tx.autoScheduled),
		"registered":  "yes",
		"fingerprint": tx.fingerprint,
		"login":       loginKind(tx.login),
		"sshd_dropin": orNone(tx.sshdDropIn),
	})
	a.success(a.P.M("临时账号已创建并登记："+tx.username, "temporary account created and registered: "+tx.username))
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
	if rec.SequentialID {
		deleteExpected = a.Users.DeleteExpectedExactSequential
	}
	if loginActivationStarted {
		identityMatches = user.SameAccountIdentity
		stillMatches = a.revokeAccountStillMatches
		deleteExpected = a.Users.DeleteExpected
		if rec.SequentialID {
			deleteExpected = a.Users.DeleteExpectedSequential
		}
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
		return fmt.Errorf("fail-closed account teardown stopped at stage %s: %w", stage, err)
	}
	return nil
}
