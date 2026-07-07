package cli

import (
	"flag"
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

	registered, err := a.Registry.Contains(username)
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
		a.warnf("%s", a.P.M("用户不存在，清理登记/sudoers/自动删除任务："+username,
			"user does not exist; cleaning up registry/sudoers/auto-delete task: "+username))
		a.Scheduler.Cancel(username)
		a.Sudoers.Remove(username)
		_ = a.Registry.Remove(username)
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

	if user.IsProtectedRevokeTarget(username, registered) {
		a.errorf("%s", a.P.M("拒绝删除受保护或系统用户："+username,
			"refusing to delete a protected or system user: "+username))
		return 1
	}

	a.Scheduler.Cancel(username)
	if pw, ok := user.Lookup(username); ok {
		user.TerminateProcesses(pw.UID)
	}
	a.Sudoers.Remove(username)
	if err := a.Users.Delete(username); err != nil {
		a.errorf("%s: %v", a.P.M("删除用户失败", "delete user failed"), err)
		return 1
	}
	if err := a.Registry.Remove(username); err != nil {
		a.warnf("%s: %v", a.P.M("用户已删除，但清理登记失败", "user deleted, but registry cleanup failed"), err)
	}
	a.success(a.P.M("已撤销并删除用户："+username, "user revoked and deleted: "+username))
	return 0
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
