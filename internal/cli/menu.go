package cli

import (
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"strconv"
	"strings"
)

// menuItems are the interactive menu entries in order. An entry's position is
// both the digit shown and the action run, so a label can never drift away from
// the command it launches. A nil run means "leave the menu".
//
// `install` is deliberately absent. Reaching this menu means a binary is already
// running as root, so install either does nothing (it is the installed one, byte
// for byte) or is a one-time bootstrap better done from the shell as
// `sudo ./linux-temp-admin install`. Leaving it out makes `upgrade` the menu's
// single, signature-verified update path.
type menuItem struct {
	zh, en      string
	run         func(*App) commandResult
	exitOnApply bool
}

// commandResult separates a command's process status from whether it completed
// the terminal mutation the menu must stop running after. Cancellation and an
// already-current upgrade both succeed without applying anything.
type commandResult struct {
	status  int
	applied bool
}

func statusResult(status int) commandResult { return commandResult{status: status} }

var menuItems = []menuItem{
	{"创建临时管理员邀请", "Create temp admin invite", func(a *App) commandResult { return statusResult(a.invite(nil)) }, false},
	// One entry for the temporary accounts, because there was only ever one list.
	// It replaced three: revoke (which opened with a bare list of names to choose
	// from), the list itself, and a cleanup whose target — a registry row whose
	// account is gone — is a row of this very table, marked "missing".
	{"管理临时用户", "Manage temporary users", func(a *App) commandResult { return statusResult(a.manageUsers()) }, false},
	{"系统诊断", "Run system doctor", func(a *App) commandResult { return statusResult(a.doctor(nil)) }, false},
	// Just 升级, like 卸载 below: the old label spelled out "verify-signed, from
	// GitHub, the stable command" — the whole mechanism — where the entry only needs
	// to name the act. The command itself still shows "will download, verify, and
	// upgrade from <url>" and asks for YES before touching anything, so the
	// signature-verified part is stated where it matters, at the point of action,
	// not carried as ballast in a menu line.
	{"升级", "Upgrade", func(a *App) commandResult { return a.upgradeResult(nil) }, true},
	// It says 卸载 with nothing qualifying it because it finally earns the word: it
	// removes the accounts, their grants, their auto-delete tasks, the state and the
	// command. The old label had to say "the stable command" — an opaque phrase for
	// "the copy at the install path" — precisely because the object was the only
	// honest part: uninstall deleted one file and left everything else on the host.
	{"卸载", "Uninstall", func(a *App) commandResult { return a.uninstallResult(nil) }, true},
	// Kept next to last, in front of Exit. When this entry was added it was appended
	// for a stronger reason — that appending changed no existing digit's meaning,
	// where slotting it in earlier would have pushed Exit from 8 to 9 and turned an
	// old hand's reflexive "8" into "uninstall the stable command". That property is
	// gone: merging the three account entries into one renumbered everything below
	// 2 anyway, which is the cost the v2.5.0 CHANGELOG entry owns rather than hides.
	// The habit it teaches survives its own arithmetic — a digit's meaning is the
	// interface, so moving one is a real cost to weigh, not a free tidy-up.
	{"语言 / Language", "Language / 语言", func(a *App) commandResult { return statusResult(a.switchLang()) }, false},
	{"退出", "Exit", nil, false},
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
	return a.withLifecycleLock(func() int {
		// Apply to this session first: any persistence error and the confirmation
		// should already read in the language just chosen.
		a.P = i18n.Printer{Lang: lang}
		if err := prefs.SetLang(string(lang)); err != nil {
			a.warnf("%s: %v", a.P.M("已切换，但未能记住（下次仍会用旧设置）", "switched, but could not be remembered (the next run will use the old setting)"), err)
			return 1
		}
		a.success(a.P.M("语言已切换为中文，并已记住。", "language switched to English and remembered."))
		return 0
	})
}

// menu drives the interactive loop. The menu is drawn on entry and only when
// asked for again (a blank line), never automatically after an action: redrawing
// eight lines on top of every result scrolled it out of view, and an invite
// bundle -- which carries the one-time private key -- suffered worst.
func (a *App) menu() int {
	if !a.requireRoot() {
		return 1
	}
	draw := true
	status := 0
	for {
		if draw {
			a.printf("\n%s", a.P.M("Linux 临时管理员管理器", "Linux Temporary Admin Manager"))
			for i, it := range menuItems {
				a.printf("%2d) %s", i+1, a.P.M(it.zh, it.en))
			}
			draw = false
		}
		// The language can change inside this loop, so resolve the prompt for every
		// iteration instead of retaining the language that was active on entry.
		fmt.Fprintf(a.Err, a.P.M("请选择 [1-%d]（回车显示菜单）: ", "select [1-%d] (Enter shows the menu): "), len(menuItems))
		choice, ok := a.readLine()
		if !ok {
			return status // EOF
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
		item := menuItems[n-1]
		if item.run != nil {
			// Frame the result with blank lines. The leading one does not rely on
			// the terminal echoing the operator's Enter, so a piped or scripted run
			// reads the same as an interactive one.
			fmt.Fprintln(a.Out)
			result := item.run(a)
			if result.status != 0 {
				status = result.status
			}
			fmt.Fprintln(a.Out)
			// A completed upgrade replaced the executable, and a completed uninstall
			// removed it. Do not continue servicing privileged actions from the old,
			// now untracked process image. Cancellation and a no-op upgrade stay here.
			if item.exitOnApply && result.applied {
				return status
			}
		} else {
			return status
		}
	}
}
