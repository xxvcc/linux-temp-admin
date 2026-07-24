package cli

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

func (a *App) revoke(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	return a.withLifecycleLock(func() int { return a.revokeLocked(args) })
}

// revokeLocked performs one complete revoke while the process-wide lifecycle
// lock is held. uninstall calls this form because it already holds that lock.
func (a *App) revokeLocked(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	userFlag := fs.String("user", "", "")
	confirmForce := fs.String("confirm-force", "", "")
	expectedUID := fs.Int("expected-uid", 0, "")
	generation := fs.String("generation", "", "")
	var fYes, fForce bool
	fs.BoolVar(&fYes, "yes", false, "")
	fs.BoolVar(&fYes, "y", false, "")
	fs.BoolVar(&fForce, "force", false, "")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() > 0 {
		a.errorf("%s %v", a.P.M("未知参数：", "unexpected arguments:"), fs.Args())
		return 1
	}

	username := *userFlag
	if username == "" {
		username = a.selectUser()
	}
	if !validate.Username(username) {
		a.errorf("%s", a.P.M("用户名不合法，拒绝删除："+username, "invalid username; refusing deletion: "+username))
		return 1
	}

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
	if *generation != "" || *expectedUID != 0 {
		if !validate.Generation(*generation) || *expectedUID < 1 {
			a.errorf("%s", a.P.M("自动撤销身份参数不完整或不合法", "invalid or incomplete auto-revoke identity"))
			return 1
		}
		if !registered || rec.Generation != *generation || rec.UID != *expectedUID {
			a.warnf("%s", a.P.M("陈旧的自动撤销任务已忽略：账号世代不再匹配", "ignored stale auto-revoke task: account generation no longer matches"))
			a.audit("account.delete", username, "skip", "stale scheduled generation", nil)
			return 0
		}
	}

	if !fForce && !registered {
		a.errorf("%s", a.P.M("拒绝删除未登记用户："+username+"（如确需删除请加 --force）",
			"refusing to delete an unregistered user: "+username+" (use --force if intended)"))
		return 1
	}
	if fForce && !registered && fYes && *confirmForce != username {
		a.errorf("%s", a.P.M("通过 --force --yes 删除未登记用户需同时传入 --confirm-force "+username,
			"deleting an unregistered user via --force --yes also requires --confirm-force "+username))
		return 1
	}

	pw, exists, err := user.Lookup(username)
	if err != nil {
		a.errorf("%s: %v", a.P.M("读取账号数据库失败，拒绝清理状态", "reading account database failed; refusing state cleanup"), err)
		return 1
	}
	if !exists {
		a.warnf("%s", a.P.M("用户不存在，清理登记/sudoers/sshd 例外/自动删除任务："+username,
			"user does not exist; cleaning up registry/sudoers/sshd exception/auto-delete task: "+username))
		var cleanupErrs []error
		if err := a.Scheduler.Cancel(username, rec.AutoUnit); err != nil {
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
		if err := a.Registry.Remove(username); err != nil {
			a.errorf("%s: %v", a.P.M("清理登记失败", "registry cleanup failed"), err)
			return 1
		}
		a.audit("account.cleanup", username, "ok", "user absent; cleaned registry/sudoers/sshd/schedule", nil)
		return 0
	}

	if !fYes {
		if fForce && !registered {
			a.warnf("%s", a.P.M("危险：用户 "+username+" 未登记，--force 将删除真实系统用户及其家目录。",
				"DANGER: "+username+" is not registered; --force will delete a real system user and its home directory."))
		}
		if a.prompt(a.P.M("请输入完整用户名 "+username+" 以确认删除: ",
			"type the full username "+username+" to confirm deletion: ")) != username {
			a.warnf("%s", a.P.M("确认不匹配，已取消", "confirmation mismatch; cancelled"))
			return 0
		}
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

	protected, protectErr := user.IsProtectedRevokeTarget(username, registered, rec.UID)
	if protectErr != nil {
		a.errorf("%s: %v", a.P.M("无法确认目标账号身份，拒绝删除", "cannot verify target account identity; refusing deletion"), protectErr)
		return 1
	}
	if protected {
		a.errorf("%s", a.P.M("拒绝删除受保护或系统用户："+username,
			"refusing to delete a protected or system user: "+username))
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
		a.warnf("%s", a.P.M("自动删除任务保留；请人工核查，旧的一次性任务不会自动重试。",
			"the auto-delete task is retained; inspect manually because legacy one-shot jobs do not retry."))
		a.audit("account.delete", username, "fail", "protected target; grants stripped", nil)
		return 1
	}

	if grantErr != nil {
		// Do not free the username while a name-scoped privilege file survives.
		disableErr := a.Users.DisableLogin(username)
		if disableErr == nil {
			user.TerminateProcesses(pw.UID)
			a.errorf("%s: %v", a.P.M("授权未完全移除；账号已禁用但不会删除，以免残留授权在用户名复用时重新生效",
				"grants were not fully removed; the account was disabled but not deleted so a surviving name-scoped grant cannot re-arm on reuse"), grantErr)
		} else {
			a.errorf("%s: %v", a.P.M("授权未完全移除，且禁用登录也失败；账号和登记均已保留，请立即人工处理",
				"grants were not fully removed and disabling login also failed; the account and registry were retained for immediate manual recovery"), errors.Join(grantErr, disableErr))
		}
		return 1
	}

	// Shut the door before taking the account apart. Until this lands the account
	// is still SSH-reachable, and a reconnect landing between the kill and the
	// delete is exactly what used to make the delete fail.
	if err := a.Users.DisableLogin(username); err != nil {
		a.warnf("%s: %v", a.P.M("禁用登录失败，仍继续删除", "could not disable the login; continuing to delete anyway"), err)
	}
	user.TerminateProcesses(pw.UID)
	if err := a.Users.Delete(username); err != nil {
		a.errorf("%s: %v", a.P.M("删除用户失败", "delete user failed"), err)
		// The auto-revoke task is deliberately still armed: it is the fallback that
		// retries this deletion, and tearing it down on the way to a failure would
		// leave the account with nothing coming for it. The login is already
		// disabled, so the account cannot be used in the meantime.
		a.warnf("%s", a.P.M("登录已禁用；systemd 任务会按策略重试，at/旧任务需手动重试。",
			"the login is disabled; systemd jobs retry by policy, while at/legacy jobs require a manual retry."))
		a.audit("account.delete", username, "fail", err.Error(), nil)
		return 1
	}

	// Only now that the account is provably gone is the fallback safe to remove.
	if err := a.Scheduler.Cancel(username, rec.AutoUnit); err != nil {
		a.errorf("%s: %v", a.P.M("用户已删除，但自动删除任务清理失败；保留登记", "user deleted, but schedule cleanup failed; keeping the registry record"), err)
		return 1
	}
	if err := a.Registry.Remove(username); err != nil {
		a.errorf("%s: %v", a.P.M("用户已删除，但清理登记失败", "user deleted, but registry cleanup failed"), err)
		return 1
	}
	a.audit("account.delete", username, "ok", "", map[string]string{"force": ynStr(fForce), "registered": ynStr(registered)})
	a.success(a.P.M("已撤销并删除用户："+username, "user revoked and deleted: "+username))
	return 0
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
