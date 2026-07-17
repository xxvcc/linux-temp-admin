package cli

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/table"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// parseFlags parses fs and rejects trailing positional arguments (which the
// stdlib flag package would otherwise silently drop).
func (a *App) parseFlags(fs *flag.FlagSet, args []string) bool {
	if err := fs.Parse(args); err != nil {
		return false
	}
	if fs.NArg() > 0 {
		a.errorf("%s %v", a.P.M("未知参数：", "unexpected arguments:"), fs.Args())
		return false
	}
	return true
}

func (a *App) status(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	userFlag := fs.String("user", "", "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	if u := *userFlag; u != "" {
		if !validate.Username(u) {
			a.errorf("%s", a.P.M("用户名不合法："+u, "invalid username: "+u))
			return 1
		}
		pw, ok := user.Lookup(u)
		if !ok {
			a.errorf("%s", a.P.M("用户不存在："+u, "user does not exist: "+u))
			return 1
		}
		a.printf("user=%s uid=%d gid=%d home=%s shell=%s managed=%v",
			pw.Name, pw.UID, pw.GID, pw.Home, pw.Shell, user.IsManaged(u))
		if unit, _ := a.Registry.UnitFor(u); unit != "" {
			a.printf("auto-revoke unit=%s", unit)
		}
		return 0
	}

	a.info(a.P.M("已登记的临时用户：", "Registered temporary users:"))
	recs, err := a.Registry.List()
	if err != nil {
		a.warnf("%v", err)
	}
	if len(recs) == 0 {
		a.printf("  %s", a.P.M("（无）", "(none)"))
		return 0
	}
	a.printf("%s", a.usersTable(recs, false).String())
	return 0
}

// usersTable renders the registered accounts. It is the single view of that list:
// `cleanup-expired` used to print its own strictly-poorer version of the same
// rows (user/exists/expires/auto — every one of them a column here under a
// different name), which was two renderings of one truth waiting to disagree.
//
// numbered adds a leading # column, so the same table can also be the thing an
// operator picks a row from. Choosing what to delete used to mean reading a bare
// list of names, with no way to see which account was about to expire, which
// carried sudo, or which was already gone.
//
// The auto-revoke unit is deliberately not a column. It is 40-odd characters,
// mechanically derived from the username, and would double the table's width to
// tell the reader something they already know; `status --user <name>` still
// prints it for the one account being examined.
func (a *App) usersTable(recs []registry.Record, numbered bool) *table.Table {
	headers := []string{
		a.P.M("用户", "USER"),
		a.P.M("状态", "STATE"),
		a.P.M("SUDO", "SUDO"),
		a.P.M("自动删除", "AUTO-DELETE"),
		a.P.M("到期", "EXPIRES"),
		a.P.M("主机", "HOST"),
		a.P.M("端口", "PORT"),
	}
	if numbered {
		headers = append([]string{"#"}, headers...)
	}
	t := table.New(headers...)
	yn := func(b bool) string {
		return a.P.M(map[bool]string{true: "是", false: "否"}[b], map[bool]string{true: "yes", false: "no"}[b])
	}
	for i, r := range recs {
		state := a.P.M("缺失", "missing")
		if user.Exists(r.User) {
			state = a.P.M("在册", "active")
		}
		cells := []string{r.User, state, yn(r.Sudo), yn(r.AutoRevoke), r.Expires, r.Host, strconv.Itoa(r.Port)}
		if numbered {
			cells = append([]string{strconv.Itoa(i + 1)}, cells...)
		}
		t.Row(cells...)
	}
	return t
}

// manageUsers is the menu's one screen for the temporary accounts: it shows the
// table and offers the two things anyone does with it.
//
// The three menu entries this replaces were three views of one list. Revoke
// opened with a bare list of names — you chose what to delete without seeing
// which account was expiring or carried sudo. The list itself was the entry
// beside it. And the cleanup entry acted on precisely the rows this table marks
// "missing": a registry row whose account is gone is exactly what --compact
// prunes, so it was never a separate object, only a separate menu item.
//
// Looking is the default: a bare Enter leaves. Revoking still has to get past
// typing the account's full name, which is where that decision belongs — not in
// whether the list happens to be on screen.
func (a *App) manageUsers() int {
	recs, err := a.Registry.List()
	if err != nil {
		a.warnf("%v", err)
	}
	a.info(a.P.M("已登记的临时用户：", "Registered temporary users:"))
	if len(recs) == 0 {
		a.printf("  %s", a.P.M("（无）", "(none)"))
		return 0
	}
	a.printf("%s", a.usersTable(recs, true).String())

	choice := strings.TrimSpace(a.prompt(a.P.M(
		"输入编号或用户名撤销 · c 清理失效登记与孤儿授权 · 回车返回: ",
		"a number or username revokes it · c cleans up stale rows and orphaned grants · Enter returns: ")))
	switch {
	case choice == "":
		return 0
	case strings.EqualFold(choice, "c"):
		// compact() is the bare sweep, so the root gate the cleanup-expired
		// subcommand opens with has to be repeated here rather than inherited.
		if !a.requireRoot() {
			return 1
		}
		a.compact()
		return 0
	}
	// A row number is shorthand for its username; anything else is taken as a name
	// and validated downstream, exactly as `revoke --user` would.
	name := choice
	if n, err := strconv.Atoi(choice); err == nil {
		if n < 1 || n > len(recs) {
			a.warnf("%s", a.P.M("无效编号", "no such row"))
			return 1
		}
		name = recs[n-1].User
	}
	return a.revoke([]string{"--user", name})
}

func (a *App) cleanupExpired(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("cleanup-expired", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var compact bool
	fs.BoolVar(&compact, "compact", false, "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	a.warnf("%s", a.P.M("此命令不删除用户；账号请用 revoke，状态请用 status。",
		"This never deletes a user: revoke deletes accounts, status shows them."))
	// The account list is status's job — this used to print its own poorer copy of
	// it. Show it here too, but through the one renderer, so the two can never
	// drift apart.
	recs, _ := a.Registry.List()
	if len(recs) > 0 {
		a.printf("%s", a.usersTable(recs, false).String())
	}
	if compact {
		a.compact()
	}
	return 0
}

// compact is the sweep itself, with none of the framing the cleanup-expired
// subcommand wraps it in. It is split out for the manage screen, which has just
// drawn the table and is where revoke already lives: re-printing the list under a
// banner that sends the reader off to `revoke` and `status` would repeat what is
// already on screen and point away from where they are.
//
// The subcommand's root gate does NOT come with it. Every caller has to keep its
// own — this function sweeps.
func (a *App) compact() {
	// Sweep the live grants BEFORE the registry rows: compacting drops the rows
	// that name these accounts, and a grant nobody can name any more is a grant
	// nobody will ever find.
	if a.SSHD != nil {
		orphans, err := a.SSHD.Orphans(user.Exists)
		if err != nil {
			a.warnf("%v", err)
		}
		for _, u := range orphans {
			if err := a.SSHD.Remove(u); err != nil {
				// Remove's own error states what happened (in the usual case the file
				// was deleted and only the reload was skipped), so use a neutral prefix
				// that does not assert the removal failed.
				a.warnf("%s: %v", a.P.M("清理孤儿 sshd 例外时", "while cleaning up the orphaned sshd exception"), err)
				continue
			}
			a.info(a.P.M("已移除孤儿 sshd 例外："+a.SSHD.FilePath(u),
				"removed an orphaned sshd exception: "+a.SSHD.FilePath(u)))
		}
	}
	// An orphaned NOPASSWD drop-in is the worse of the two: it re-arms full root
	// the moment its username is reused.
	if a.Sudoers != nil {
		orphans, err := a.Sudoers.Orphans(user.Exists)
		if err != nil {
			a.warnf("%v", err)
		}
		for _, u := range orphans {
			a.Sudoers.Remove(u)
			a.info(a.P.M("已移除孤儿 sudo 授权："+a.Sudoers.FilePath(u),
				"removed an orphaned sudo grant: "+a.Sudoers.FilePath(u)))
		}
	}
	removed, err := a.Registry.Compact(user.Exists)
	if err != nil {
		a.warnf("%v", err)
	} else {
		a.info(fmt.Sprintf(a.P.M("已压实注册表：移除 %d 条指向已不存在用户的记录。",
			"Compacted the registry: removed %d entries for users that no longer exist."), removed))
	}
}

func (a *App) doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	if !a.parseFlags(fs, args) {
		return 1
	}
	rc := 0
	a.info(a.P.M("linux-temp-admin 诊断报告", "linux-temp-admin doctor report"))
	if a.Geteuid() == 0 {
		a.success(a.P.M("当前以 root 运行。", "running as root."))
	} else {
		a.warnf("%s", a.P.M("当前不是 root；invite/revoke 需要 root。", "not running as root; invite/revoke require root."))
	}
	for _, d := range sysinfo.RequiredDeps(true) {
		if d.Present {
			a.success(a.P.M("依赖存在：", "dependency found: ") + d.Label)
		} else {
			a.warnf("%s%s", a.P.M("缺少依赖：", "missing dependency: "), d.Label)
			if d.Label != "sudo" { // sudo is only needed for --sudo invites
				rc = 1
			}
		}
	}
	a.info(a.P.M("包管理器：", "package manager: ") + orNone(sysinfo.PackageManager()))
	a.info(a.P.M("init 系统：", "init system: ") + sysinfo.InitSystem())
	a.info(fmt.Sprintf(a.P.M("探测到 SSH 端口：%d", "detected SSH port: %d"), sysinfo.SSHPort()))
	// Probe with a name shaped like a fresh invite account: brand new, on no
	// whitelist, and in no group but its own. That is what an invite actually hits,
	// and reporting on it here is the only way an operator can learn that key logins
	// are off *before* they hand out an invite.
	//
	// The probe name is passed to SSHDConfig, not just to the check: `sshd -T` alone
	// cannot see `Match User` blocks, so asking the global view a per-user question
	// would let doctor contradict the invite it is meant to predict.
	probe := config.DefaultPrefix + "-doctor"
	if cfg, err := a.sshdConfig(probe); err != nil {
		a.warnf("%s (%v)", a.P.M("无法读取 sshd 有效配置；invite 无法验证公钥登录是否真的可用。",
			"cannot read the effective sshd config; invite cannot verify that a key login would work."), err)
	} else {
		rep := a.checkKeyLogin(cfg, probe, []string{probe})
		for _, w := range rep.Warnings {
			a.warnf("%s", w)
		}
		if rep.OK() {
			a.success(a.P.M("sshd 接受公钥登录。", "sshd accepts public-key logins."))
		} else {
			a.warnf("%s", a.P.M("sshd 不会接受新建临时账号的公钥登录：",
				"sshd would not accept a public-key login for a freshly created temporary account:"))
			a.reportBlockers(rep)
			if rep.Fixable() {
				a.warnf("%s", a.P.M("可用 `invite --fix-sshd` 只为该账号开启（不改动全局策略）。",
					"`invite --fix-sshd` can enable it for that one account, leaving the global policy untouched."))
			}
			rc = 1
		}
		for _, u := range rep.Unverifiable {
			a.warnf("%s", u)
		}
	}
	// An sshd exception that outlived its account is a standing loosening of the
	// host's policy, and it re-arms the moment the username is reused. Nothing else
	// looks for these, so doctor must.
	if a.SSHD != nil {
		if orphans, err := a.SSHD.Orphans(user.Exists); err == nil && len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿 sshd 例外（账号已不存在）：",
					"orphaned sshd exception (its account no longer exists): "), a.SSHD.FilePath(u))
			}
			a.warnf("%s", a.P.M("请用 `cleanup-expired --compact` 清理。",
				"remove them with `cleanup-expired --compact`."))
			rc = 1
		}
	}
	if err := fsutil.RootSafeDir("/etc/sudoers.d"); err == nil {
		a.success(a.P.M("/etc/sudoers.d 看起来安全。", "/etc/sudoers.d looks safe."))
	} else {
		a.warnf("%s (%v)", a.P.M("/etc/sudoers.d 不可用或不安全；NOPASSWD sudo 可能不可用。",
			"/etc/sudoers.d unavailable or unsafe; NOPASSWD sudo may be unavailable."), err)
	}
	// An orphaned NOPASSWD drop-in is the most dangerous leftover the tool can
	// produce — it re-arms full root the moment its username is reused — and the
	// directory being "safe" says nothing about what is in it. Report them the same
	// way the sshd exceptions are reported.
	if a.Sudoers != nil {
		if orphans, err := a.Sudoers.Orphans(user.Exists); err == nil && len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿 sudo 授权（账号已不存在，NOPASSWD:ALL 仍在）：",
					"orphaned sudo grant (its account is gone; NOPASSWD:ALL still on disk): "), a.Sudoers.FilePath(u))
			}
			a.warnf("%s", a.P.M("请用 `cleanup-expired --compact` 清理。",
				"remove them with `cleanup-expired --compact`."))
			rc = 1
		}
	}
	return rc
}

// menuItems are the interactive menu entries in order. An entry's position is
// both the digit shown and the action run, so a label can never drift away from
// the command it launches. A nil run means "leave the menu".
//
// `install` is deliberately absent. Reaching this menu means a binary is already
// running as root, so install either does nothing (it is the installed one, byte
// for byte) or is a one-time bootstrap better done from the shell as
// `sudo ./linux-temp-admin install`. Leaving it out makes `upgrade` the menu's
// single, signature-verified update path.
var menuItems = []struct {
	zh, en string
	run    func(*App) int
}{
	{"创建一次性临时管理员邀请", "Create one-time temp admin invite", func(a *App) int { return a.invite(nil) }},
	// One entry for the temporary accounts, because there was only ever one list.
	// It replaced three: revoke (which opened with a bare list of names to choose
	// from), the list itself, and a cleanup whose target — a registry row whose
	// account is gone — is a row of this very table, marked "missing".
	{"管理临时用户（查看 / 撤销 / 清理）", "Temporary users (list / revoke / clean up)", func(a *App) int { return a.manageUsers() }},
	{"系统诊断", "Run system doctor", func(a *App) int { return a.doctor(nil) }},
	{"从 GitHub 验签升级稳定命令", "Verify and upgrade the stable command from GitHub", func(a *App) int { return a.upgrade(nil) }},
	{"卸载稳定命令", "Uninstall stable command", func(a *App) int { return a.uninstall(nil) }},
	// Appended rather than slotted in beside the other settings-ish entries, so no
	// existing digit changes meaning. Inserting it earlier pushed Exit from 8 to 9,
	// which turned an old hand's reflexive "8" into "uninstall the stable command".
	// Here the only shifted key is Exit, and a stale "8" lands on this — harmless.
	{"切换语言 / Switch language", "Switch language / 切换语言", func(a *App) int { return a.switchLang() }},
	{"退出", "Exit", nil},
}

// switchLang re-asks the language and remembers the answer, so the one-time
// question at first run is not a one-way door. Its own label is bilingual: an
// operator who picked the wrong language must be able to find this entry in a
// menu they cannot read.
func (a *App) switchLang() int {
	a.printf("\nLanguage / 语言:\n  1) 中文\n  2) English")
	choice := a.prompt("选择 / select [1-2]: ")
	var lang i18n.Lang
	switch strings.TrimSpace(choice) {
	case "1":
		lang = i18n.ZH
	case "2":
		lang = i18n.EN
	default:
		a.warnf("%s", a.P.M("无效选择，语言未改变", "invalid choice; language unchanged"))
		return 1
	}
	// Apply to this session first: the confirmation below should already read in the
	// language just chosen, whether or not it can be persisted.
	a.P = i18n.Printer{Lang: lang}
	if err := prefs.SetLang(string(lang)); err != nil {
		a.warnf("%s: %v", a.P.M("已切换，但未能记住（下次仍会用旧设置）", "switched, but could not be remembered (the next run will use the old setting)"), err)
		return 1
	}
	a.success(a.P.M("语言已切换为中文，并已记住。", "language switched to English and remembered."))
	return 0
}

// menu drives the interactive loop. The menu is drawn on entry and only when
// asked for again (a blank line), never automatically after an action: redrawing
// eight lines on top of every result scrolled it out of view, and an invite
// bundle -- which carries the one-time private key -- suffered worst.
func (a *App) menu() int {
	if !a.requireRoot() {
		return 1
	}
	prompt := fmt.Sprintf(a.P.M("请选择 [1-%d]（回车显示菜单）: ", "select [1-%d] (Enter shows the menu): "), len(menuItems))
	draw := true
	for {
		if draw {
			a.printf("\n%s", a.P.M("Linux 临时管理员管理器", "Linux Temporary Admin Manager"))
			for i, it := range menuItems {
				a.printf("%2d) %s", i+1, a.P.M(it.zh, it.en))
			}
			draw = false
		}
		fmt.Fprint(a.Err, prompt)
		choice, ok := a.readLine()
		if !ok {
			return 0 // EOF
		}
		if choice == "" { // a blank line asks for the menu back
			draw = true
			continue
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(menuItems) {
			a.warnf("%s", a.P.M("无效选择", "invalid choice"))
			// Re-prompting only makes sense at a terminal. readLine returns ok=false
			// solely at EOF, so a non-TTY stream of invalid lines (`yes x | ...`) would
			// spin this loop forever, pinning a root process and flooding stderr. A
			// non-interactive run gets one complaint and exits, like every other prompt
			// in the tool.
			if !a.StdinIsTTY() {
				return 1
			}
			continue
		}
		if run := menuItems[n-1].run; run != nil {
			// Frame the result with blank lines. The leading one does not rely on
			// the terminal echoing the operator's Enter, so a piped or scripted run
			// reads the same as an interactive one.
			fmt.Fprintln(a.Out)
			run(a)
			fmt.Fprintln(a.Out)
		} else {
			return 0
		}
	}
}
