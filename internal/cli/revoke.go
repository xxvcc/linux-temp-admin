package cli

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

func (a *App) revoke(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	userFlag := fs.String("user", "", "")
	confirmForce := fs.String("confirm-force", "", "")
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

	// One read gives every fact this path acts on — registration, the recorded
	// creation UID (the immutable proof the account is ours), and the auto-revoke
	// unit — so they cannot disagree with each other.
	rec, registered, err := a.Registry.Lookup(username)
	if err != nil {
		a.warnf("%s: %v", a.P.M("读取注册表失败", "reading registry failed"), err)
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

	if !user.Exists(username) {
		a.warnf("%s", a.P.M("用户不存在，清理登记/sudoers/sshd 例外/自动删除任务："+username,
			"user does not exist; cleaning up registry/sudoers/sshd exception/auto-delete task: "+username))
		// Nothing to delete, so the auto-revoke fallback has no job left to do.
		a.Scheduler.Cancel(username, rec.AutoUnit)
		a.Sudoers.Remove(username)
		a.removeSSHDException(username)
		if err := a.Registry.Remove(username); err != nil {
			a.warnf("%s: %v", a.P.M("清理登记失败", "registry cleanup failed"), err)
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
	a.Sudoers.Remove(username)
	a.removeSSHDException(username)

	if user.IsProtectedRevokeTarget(username, registered, rec.UID) {
		a.errorf("%s", a.P.M("拒绝删除受保护或系统用户："+username,
			"refusing to delete a protected or system user: "+username))
		// Name the tamper if that is why: an account that rewrote its own UID (most
		// dangerously to 0) is now protected by the very check meant to shield real
		// accounts, and the operator has to clean it up by hand.
		if cur, tampered := user.UIDTampered(username, rec.UID); tampered {
			a.errorf("%s", a.P.M(
				fmt.Sprintf("该账号的 UID 已被改动：创建时为 %d，现在是 %d。它已不再是本工具创建的那个账号，请手动核查后处理。", rec.UID, cur),
				fmt.Sprintf("this account's UID was changed: it was created as %d and is now %d. It is no longer the account this tool made; inspect and remove it by hand.", rec.UID, cur)))
		}
		a.warnf("%s", a.P.M("已移除该账号的 sudo 授权与 sshd 例外；自动删除任务保留，以便到期重试。",
			"its sudo grant and sshd exception were removed; the auto-delete task is left armed so it retries at expiry."))
		a.audit("account.delete", username, "fail", "protected target; grants stripped", nil)
		return 1
	}

	// Shut the door before taking the account apart. Until this lands the account
	// is still SSH-reachable, and a reconnect landing between the kill and the
	// delete is exactly what used to make the delete fail.
	if err := a.Users.DisableLogin(username); err != nil {
		a.warnf("%s: %v", a.P.M("禁用登录失败，仍继续删除", "could not disable the login; continuing to delete anyway"), err)
	}
	if pw, ok := user.Lookup(username); ok {
		user.TerminateProcesses(pw.UID)
	}
	if err := a.Users.Delete(username); err != nil {
		a.errorf("%s: %v", a.P.M("删除用户失败", "delete user failed"), err)
		// The auto-revoke task is deliberately still armed: it is the fallback that
		// retries this deletion, and tearing it down on the way to a failure would
		// leave the account with nothing coming for it. The login is already
		// disabled, so the account cannot be used in the meantime.
		a.warnf("%s", a.P.M("登录已禁用，自动删除任务保留以便重试；请手动核查。",
			"the login is disabled and the auto-delete task is left armed to retry; please check by hand."))
		a.audit("account.delete", username, "fail", err.Error(), nil)
		return 1
	}

	// Only now that the account is provably gone is the fallback safe to remove.
	a.Scheduler.Cancel(username, rec.AutoUnit)
	if err := a.Registry.Remove(username); err != nil {
		a.warnf("%s: %v", a.P.M("用户已删除，但清理登记失败", "user deleted, but registry cleanup failed"), err)
	}
	a.audit("account.delete", username, "ok", "", map[string]string{"force": ynStr(fForce), "registered": ynStr(registered)})
	a.success(a.P.M("已撤销并删除用户："+username, "user revoked and deleted: "+username))
	return 0
}

// removeSSHDException deletes any per-account sshd drop-in this tool wrote for
// username and reloads sshd. Like the sudoers drop-in beside it, the path is
// derived from the username and the manager only ever touches its own managed
// file, so this is called blindly: revoke never has to know whether a grant was
// made, which means a grant can never be orphaned by a lost registry entry.
//
// A failure is reported but never blocks the revoke: the account itself going
// away is what matters most, and a leftover Match block for a user that no
// longer exists grants nobody anything.
func (a *App) removeSSHDException(username string) {
	if a.SSHD == nil {
		return
	}
	if err := a.SSHD.Remove(username); err != nil {
		// Remove's own error already says precisely what happened — in the common
		// failure the file WAS deleted and only the reload was (deliberately) skipped
		// because the host's sshd config is invalid. Do not prepend a contradicting
		// "removal failed; delete it by hand", which would name a path that is already
		// gone and bury the real problem.
		a.warnf("%s: %v", a.P.M("sshd 例外", "sshd exception"), err)
	}
}

// selectUser lists existing registered users and reads a choice or a username.
func (a *App) selectUser() string {
	recs, _ := a.Registry.List()
	var existing []string
	for _, r := range recs {
		if user.Exists(r.User) {
			existing = append(existing, r.User)
		}
	}
	for i, u := range existing {
		a.warnf("%2d) %s", i+1, u)
	}
	choice := a.prompt(a.P.M("请选择编号或输入用户名: ", "select a number or enter a username: "))
	if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(existing) {
		return existing[n-1]
	}
	return choice
}
