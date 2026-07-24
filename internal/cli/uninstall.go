package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/table"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// witness is a place that names an account, and the reason the teardown believes
// the account is this tool's to remove.
//
// The registry is the obvious one and the weakest: it is a file, and every way it
// goes wrong (hand-edited, truncated, restored from an old backup, lost with the
// disk) makes accounts VANISH from it rather than announce themselves. So the
// inventory is a union of witnesses, and the load-bearing ones are the tool's own
// namespaced files. An account can be hidden from the registry; it cannot be
// hidden from the sudo grant that is the whole reason it is worth hiding.
//
// The managed GECOS marker is deliberately NOT a witness. It is the one signal an
// account can write to itself: `usermod -c 'linux-temp-admin temporary admin'
// realadmin` would enlist a real administrator's account — and their home
// directory — into a teardown. It is reported (see gecosOnly) and never acted on.
type witness string

const (
	witnessRegistry witness = "registry"
	witnessV1       witness = "v1-registry"
	witnessSudoers  witness = "sudo-grant"
	witnessSSHD     witness = "sshd-exception"
	witnessUnit     witness = "auto-delete-task"
)

// hasArtifactWitness reports whether the account is named by a filesystem
// artifact that carries privilege — a sudo grant, an sshd exception, or an
// auto-delete unit — as opposed to only a registry row. A row is a record; an
// artifact is a live loosening of policy. The residual-block after teardown keys
// on this so a stale row never blocks, but a surviving grant always does.
func hasArtifactWitness(acc teardownAccount) bool {
	for _, w := range acc.witnesses {
		if w == witnessSudoers || w == witnessSSHD || w == witnessUnit {
			return true
		}
	}
	return false
}

// teardownAccount is one account the uninstall has to get rid of, and why it
// thinks so.
type teardownAccount struct {
	name      string
	exists    bool
	witnesses []witness
}

// teardownPlan is what an uninstall would do, gathered before anything is
// touched. It is built first and shown first: everything it reports is something
// the operator can act on BEFORE it is too late to act on it.
type teardownPlan struct {
	accounts []teardownAccount

	stateDir  string
	auditPath string
	auditKept bool

	binaryPath string
	// binaryBlocker is why the binary cannot be removed, discovered now rather
	// than in the last step after everything else is already destroyed.
	binaryBlocker string

	// inventoryErr is set when a source that should have been readable was not.
	// It is fatal rather than advisory: every way of failing to read a witness
	// makes accounts VANISH from the inventory, and an inventory that under-reports
	// is precisely how a teardown removes the binary and strands the accounts it
	// never saw. An absent registry is NOT this — it reads as zero rows, which on a
	// host that never made an account is the truth.
	inventoryErr error
}

func (p teardownPlan) names() []string {
	out := make([]string, 0, len(p.accounts))
	for _, acc := range p.accounts {
		out = append(out, acc.name)
	}
	return out
}

// teardownPlan gathers every account any witness names, plus the footprint.
func (a *App) teardownPlan(purgeAudit, force bool) teardownPlan {
	found := map[string][]witness{}
	add := func(name string, w witness) {
		if name == "" || !validate.Username(name) {
			return
		}
		for _, have := range found[name] {
			if have == w {
				return
			}
		}
		found[name] = append(found[name], w)
	}

	var inventoryErr error
	addInventoryErr := func(err error) { inventoryErr = errors.Join(inventoryErr, err) }
	if recs, err := a.Registry.List(); err != nil {
		addInventoryErr(fmt.Errorf("%s: %w", a.P.M("读取注册表失败", "reading the registry failed"), err))
	} else {
		for _, r := range recs {
			add(r.User, witnessRegistry)
		}
	}
	if users, err := a.v1RegistryUsers(); err != nil {
		addInventoryErr(fmt.Errorf("%s: %w", a.P.M("读取 v1 注册表失败", "reading the v1 registry failed"), err))
	} else {
		for _, u := range users {
			add(u, witnessV1)
		}
	}
	if a.Sudoers != nil {
		if users, err := a.Sudoers.All(); err != nil {
			addInventoryErr(fmt.Errorf("%s: %w", a.P.M("扫描 sudo 授权失败", "scanning sudo grants failed"), err))
		} else {
			for _, u := range users {
				add(u, witnessSudoers)
			}
		}
	}
	if a.SSHD != nil {
		if users, err := a.SSHD.All(); err != nil {
			addInventoryErr(fmt.Errorf("%s: %w", a.P.M("扫描 sshd 例外失败", "scanning sshd exceptions failed"), err))
		} else {
			for _, u := range users {
				add(u, witnessSSHD)
			}
		}
	}
	if a.Scheduler != nil {
		if users, err := a.Scheduler.ScheduledUsers(); err != nil {
			addInventoryErr(fmt.Errorf("%s: %w", a.P.M("扫描自动删除任务失败", "scanning auto-delete tasks failed"), err))
		} else {
			for _, u := range users {
				add(u, witnessUnit)
			}
		}
	}

	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)

	plan := teardownPlan{
		stateDir:   a.StateDir,
		auditPath:  filepath.Join(a.AuditLogDir, filepath.Base(config.AuditLogFile)),
		auditKept:  !purgeAudit,
		binaryPath: a.InstallPath,
	}
	for _, n := range names {
		ws := found[n]
		sort.Slice(ws, func(i, j int) bool { return ws[i] < ws[j] })
		exists, err := user.Exists(n)
		if err != nil {
			addInventoryErr(fmt.Errorf("%s %s: %w", a.P.M("读取账号失败", "reading account"), n, err))
		}
		plan.accounts = append(plan.accounts, teardownAccount{name: n, exists: exists, witnesses: ws})
	}
	plan.binaryBlocker = a.binaryBlocker(force)
	plan.inventoryErr = inventoryErr
	return plan
}

// binaryBlocker reports why the installed binary could not be removed, or "" if
// it can be. It is probed during the inventory on purpose: the binary is removed
// LAST, so a refusal discovered there would land after every account is deleted
// and the state is gone, with nothing left to do but hand the operator --force.
// A symlinked install path is ordinary on a host with a versioned or Nix-style
// layout, and it is refused (fsutil.RootSafeFile), so this is not a rare corner.
func (a *App) binaryBlocker(force bool) string {
	fi, err := os.Lstat(a.InstallPath)
	if os.IsNotExist(err) {
		return "" // nothing to remove is not a blocker
	}
	if err != nil {
		return err.Error()
	}
	// --force is exactly what makes an unsafe path removable (Selfmanage.Uninstall
	// skips the RootSafeFile check under force), so with it set there is no blocker
	// to report — saying "needs --force" while --force is present is just wrong.
	if force {
		return ""
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return a.P.M("是符号链接（需 --force）", "is a symlink (needs --force)")
	}
	if err := fsutil.RootSafeFile(a.InstallPath); err != nil {
		return err.Error()
	}
	return ""
}

// v1RegistryUsers reads the account names out of v1's registry.
//
// v1 is the shell implementation this tool replaced. Its registry is not litter
// to be deleted along with the rest of the state directory: it is an inventory,
// and on an upgraded host it may be the only thing naming an account v1 made
// without a sudo grant. v1's install path was identical to v2's, so its
// auto-delete timer invokes the binary running this code — remove that binary
// with a v1 account still live and it strands exactly as a v2 one would.
//
// The format is v1's: tab-separated, username first (its own removal pass keyed
// on `awk -F '\t' '$1 != u'`). A malformed non-empty row is an error: this file
// may be the only witness naming an account v1 created without a sudo grant.
//
// It distinguishes absent from unreadable, and the caller treats the two
// differently. Absent is the normal case — nothing was upgraded from v1 — and
// returns no error. But a file that EXISTS and cannot be read (a permission
// error, a mid-read I/O failure) must not collapse into "no v1 accounts": that is
// the exact silent under-report the inventory's fatal-error gate exists to catch,
// and this is the one witness the code itself calls the only record of an account
// v1 made without a sudo grant. So a present-but-unreadable registry is an error.
func (a *App) v1RegistryUsers() ([]string, error) {
	f, err := os.Open(filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var users []string
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, _ := strings.Cut(line, "\t")
		if !validate.Username(name) {
			return nil, fmt.Errorf("v1 registry line %d has invalid username %q", lineNo, name)
		}
		users = append(users, name)
	}
	if err := sc.Err(); err != nil {
		// A partial read already yielded some names; returning them AND the error
		// would let the caller act on an inventory it was just told is incomplete.
		return nil, err
	}
	return users, nil
}

// printTeardownPlan shows what is about to happen while it can still be stopped.
func (a *App) printTeardownPlan(p teardownPlan) {
	a.info(a.P.M("卸载将移除：", "The uninstall will remove:"))

	if len(p.accounts) == 0 {
		a.printf("  %s", a.P.M("临时账号：（无）", "temporary accounts: (none)"))
	} else {
		t := table.New(
			a.P.M("账号", "ACCOUNT"),
			a.P.M("状态", "STATE"),
			a.P.M("依据", "NAMED BY"),
		)
		for _, acc := range p.accounts {
			state := a.P.M("缺失（仅剩痕迹）", "gone (leftovers only)")
			if acc.exists {
				state = a.P.M("在册（连同家目录删除）", "live (deleted with its home)")
			}
			ws := make([]string, 0, len(acc.witnesses))
			for _, w := range acc.witnesses {
				ws = append(ws, string(w))
			}
			t.Row(acc.name, state, strings.Join(ws, " "))
		}
		a.printf("%s", t.String())
	}

	a.printf("  %s %s", a.P.M("状态目录：", "state directory:"), p.stateDir)
	a.printf("  %s %s", a.P.M("已安装的命令：", "installed command:"), p.binaryPath)
	if p.binaryBlocker != "" {
		a.warnf("%s %s（%s）", a.P.M("无法移除：", "cannot be removed:"), p.binaryPath, p.binaryBlocker)
	}
	if p.auditKept {
		a.info(fmt.Sprintf(a.P.M("审计日志保留在 %s —— 它记录了谁开过、谁删过 root 级账号，卸载不会替你抹掉它。要一并删除请加 --purge-audit。",
			"the audit log is KEPT at %s — it records who opened and closed root-capable accounts, and an uninstall does not erase that for you. Pass --purge-audit to remove it too."), p.auditPath))
	} else {
		a.warnf("%s %s", a.P.M("审计日志将被删除：", "the audit log will be DELETED:"), p.auditPath)
	}
}

// callerAccount names the account that invoked this command, or "" if nothing
// says. SUDO_USER is the only identity signal this tool has ever had.
//
// It is an interlock for the honest operator, NOT a security boundary, and the
// difference matters enough to say out loud: `sudo su -` drops SUDO_USER, so
// anyone who wants past this walks past it. That is acceptable because the thing
// on the other side is not a privilege — an invitee who can run this already has
// the sudo to `rm` the binary directly. What it buys is that a temp admin who
// uninstalls from their own session gets told, instead of having the teardown
// reap the sudo front-end relaying its own signals and leave the box half taken
// apart.
func callerAccount() string { return os.Getenv("SUDO_USER") }

func (a *App) uninstall(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var force, yes, removeUsers, purgeAudit bool
	fs.BoolVar(&force, "force", false, "")
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	fs.BoolVar(&removeUsers, "remove-users", false, "")
	fs.BoolVar(&purgeAudit, "purge-audit", false, "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	return a.withLifecycleLock(func() int {
		return a.uninstallLocked(force, yes, removeUsers, purgeAudit)
	})
}

func (a *App) uninstallLocked(force, yes, removeUsers, purgeAudit bool) int {
	plan := a.teardownPlan(purgeAudit, force)

	// A witness that could not be read is fatal, not advisory. Every way of failing
	// to read one makes accounts vanish from the inventory rather than announce
	// themselves, and an inventory that under-reports is how a teardown deletes the
	// binary and strands every account it never saw — the exact shape this redesign
	// exists to close. Refuse while that is still something the operator can act on.
	// (The pre-teardown uninstall refused on this too; its test is what caught the
	// regression when this was first written as a warning.)
	if plan.inventoryErr != nil {
		a.errorf("%s: %v", a.P.M("无法确定这台机器上有哪些账号，拒绝卸载",
			"cannot determine which accounts are on this host; refusing to uninstall"), plan.inventoryErr)
		a.warnf("%s", a.P.M(
			"清单不全就卸载，会删掉命令、留下它没看见的账号——而它们的自动删除任务执行的正是这个命令。请先修好上面的问题再重试。",
			"uninstalling on a partial inventory removes the command and leaves behind accounts it never saw. Repair the account database or managed state before retrying."))
		return 1
	}

	a.printTeardownPlan(plan)

	// If the binary itself cannot be removed, refuse NOW — before a single account
	// or grant is torn down. binaryBlocker is force-aware (empty under --force), so
	// a non-empty value means the path is unsafe AND the operator did not opt in.
	// The whole point of computing it during the inventory is that the alternative —
	// discovering it in the last step, after every account and the state dir are
	// already gone — leaves the operator with a half-uninstalled host and only
	// --force to finish, which is the footgun this design removes. Not a gate until
	// now: it was printed as a warning and nothing acted on it.
	if plan.binaryBlocker != "" {
		a.errorf("%s：%s（%s）", a.P.M("拒绝卸载：无法移除已安装的命令", "refusing to uninstall: the installed command cannot be removed"),
			plan.binaryPath, plan.binaryBlocker)
		a.warnf("%s", a.P.M("先处理该路径（或用 --force 明确接受），再重试——否则卸载会删光账号与状态却卡在最后一步。",
			"resolve that path (or pass --force to accept it explicitly) and retry — otherwise the uninstall would remove every account and all state, then stop at the last step."))
		return 1
	}

	// Refuse before anything is touched, not partway through.
	if who := callerAccount(); who != "" {
		for _, acc := range plan.accounts {
			if acc.name == who && acc.exists {
				a.errorf("%s", a.P.M(
					"你正以临时账号 "+who+" 的身份运行卸载，而卸载会删除这个账号。请改用 root 或其他管理员登录后重试。",
					"you are running this as the temporary account "+who+", which the uninstall would delete. Log in as root or another administrator and retry."))
				return 1
			}
		}
	}

	if len(plan.accounts) > 0 && !removeUsers {
		// Mirrors --fix-sshd: a non-interactive run never does the irreversible thing
		// implicitly, and the flag is what says it out loud. The analogy is not exact
		// and the difference is worth admitting: this tool's other --yes gates
		// (--confirm-sudo, --confirm-force) make you retype the USERNAME, which a
		// bare bool cannot do because there is no single username here. The printed
		// count is the compensation, not an equal.
		if yes || !a.StdinIsTTY() {
			a.errorf("%s", a.P.M(
				fmt.Sprintf("非交互模式不会删除账号。这台机器上有 %d 个由本工具管理的账号，卸载必须先删除它们；确认请加 --remove-users。", len(plan.accounts)),
				fmt.Sprintf("a non-interactive run will not delete accounts. This host has %d managed by this tool, and the uninstall must remove them first; pass --remove-users to say so.", len(plan.accounts))))
			a.warnf("%s", a.P.M("（不能只卸载命令、留下账号：它们的自动删除任务执行的就是这个命令，删掉命令它们就再也不会过期。）",
				"(uninstalling the command and keeping the accounts is not an option: their auto-delete tasks invoke this very command, so removing it means they never expire.)"))
			return 1
		}
	}

	if !yes {
		if a.prompt(a.P.M("确认卸载请输入 YES: ", "type YES to uninstall: ")) != "YES" {
			a.warnf("%s", a.P.M("已取消", "cancelled"))
			return 0
		}
	}

	return a.teardown(plan, force, purgeAudit)
}

// teardown executes the plan. Order is the whole design: every step leaves the
// host no worse than it found it, and the binary goes last because everything
// that could still need a manager needs the manager to exist.
func (a *App) teardown(plan teardownPlan, force, purgeAudit bool) int {
	// Each account goes through the ordinary revoke — the same path, the same
	// protections, the same audit trail. Nothing here reimplements deletion.
	//
	// --yes, because the operator already confirmed this whole teardown once
	// against the printed plan; asking again per account would be N prompts for a
	// decision already made, on a shared stdin.
	//
	// --force, and this is load-bearing rather than incidental: the inventory is a
	// union of witnesses precisely to catch an account with NO registry row — one
	// whose row was lost, a v1 account, one named only by its sudo grant. Bare
	// revoke REFUSES an unregistered account ("use --force"), so without this the
	// teardown would turn away exactly the account the inventory worked hardest to
	// find, and then — correctly — refuse to remove the binary while that account
	// survived, so the uninstall could never complete. --confirm-force is the token
	// bare revoke also demands for an unregistered --force --yes; here the operator
	// confirmed the whole named plan once, which is the same assurance per account.
	// revoke's protections (protected targets, the UID proof) are UNaffected by
	// --force and still refuse a real non-managed account — that is what the
	// survivor check below is for.
	for _, acc := range plan.accounts {
		a.revokeLocked([]string{"--user", acc.name, "--yes", "--force", "--confirm-force", acc.name})
	}

	// Re-inventory from scratch, do not trust the plan or revoke's rc. Two things
	// the point-in-time plan and a user.Exists check both miss:
	//   - an artifact revoke could not remove — a NOPASSWD grant wedged with
	//     chattr +i, an EPERM, a path swapped for a non-empty dir. The account is
	//     gone, so user.Exists reports no survivor, but the passwordless-root file
	//     re-arms the instant the name is reused. sudoers.Remove returns its error
	//     precisely so this cannot be called done; the fresh Sudoers.All witness is
	//     what observes it.
	//   - an account created by a concurrent invite between the plan and now, whose
	//     auto-revoke task points at the binary we are about to remove.
	// A witness that names ANYTHING — an account, a grant, an exception, a unit —
	// blocks the binary, exactly as a surviving account does. An unreadable witness
	// blocks too: we cannot prove nothing is left.
	residual := a.teardownPlan(purgeAudit, force)
	if residual.inventoryErr != nil {
		a.errorf("%s: %v", a.P.M("无法确认账号与授权已全部清除，卸载中止（命令与状态已保留）",
			"cannot confirm every account and grant is gone; the uninstall stopped (command and state kept)"), residual.inventoryErr)
		a.audit("uninstall", "", "fail", "re-inventory error: "+residual.inventoryErr.Error(), nil)
		return 1
	}
	// Block only on residue that carries privilege: a live account, or a leftover
	// grant / exception / unit. A residual entry named ONLY by a registry row whose
	// account no longer exists carries none — it is a stale row (a v1 users.tsv
	// leftover is the common one; revoke prunes v2 rows but never touches v1's), and
	// removeStateDir just below deletes it. Blocking on it would false-block the
	// uninstall forever on any v1-upgraded host, which is strictly worse than the
	// user.Exists-only check this re-inventory replaced.
	var blocking []teardownAccount
	for _, acc := range residual.accounts {
		if acc.exists || hasArtifactWitness(acc) {
			blocking = append(blocking, acc)
		}
	}
	if len(blocking) > 0 {
		residual.accounts = blocking
		a.errorf("%s", a.P.M(
			"以下项未能清除（账号、sudo 授权、sshd 例外或自动删除任务仍在）：",
			"these could not be cleared (an account, a sudo grant, an sshd exception, or an auto-delete task remains):"))
		for _, acc := range residual.accounts {
			ws := make([]string, 0, len(acc.witnesses))
			for _, w := range acc.witnesses {
				ws = append(ws, string(w))
			}
			a.printf("  %s (%s)", acc.name, strings.Join(ws, " "))
		}
		a.errorf("%s", a.P.M(
			"已保留已安装的命令和状态目录，卸载中止。留着一个带 sudo 的授权却删掉唯一能清理它的命令，比不卸载更糟。请先手动处理，再重试。",
			"the installed command and the state directory were kept, and the uninstall stopped. Leaving a sudo grant behind while deleting the only thing that can clean it up is worse than not uninstalling. Deal with these by hand and retry."))
		a.audit("uninstall", "", "fail", "residual: "+strings.Join(residual.names(), " "), nil)
		return 1
	}

	// Nothing is left, so removal is safe. Purge the audit log only AFTER a final
	// record of the teardown — the record precedes the purge, or "purge" would
	// recreate the file it deleted and quietly mean "leave exactly one line".
	if purgeAudit {
		a.audit("uninstall", "", "ok", a.InstallPath, map[string]string{"accounts": fmt.Sprint(len(plan.accounts)), "purged": "yes"})
		if err := os.RemoveAll(a.AuditLogDir); err != nil {
			a.warnf("%s: %v", a.P.M("删除审计日志失败", "removing the audit log failed"), err)
		} else {
			a.info(a.P.M("已删除审计日志："+a.AuditLogDir, "removed the audit log: "+a.AuditLogDir))
		}
		a.Audit = nil // nothing may audit after this: a.Audit would recreate the dir
	}

	stateGone := true
	if err := a.removeStateDir(force); err != nil {
		stateGone = false
		a.warnf("%s: %v", a.P.M("删除状态目录失败（账号已全部移除，命令仍将卸载）",
			"removing the state directory failed (every account is gone, so the command is still uninstalled)"), err)
	} else {
		a.info(a.P.M("已删除状态目录："+a.StateDir, "removed the state directory: "+a.StateDir))
	}

	// The binary is the last thing removed and the first that can still fail here
	// (a symlinked path without --force). The "ok" audit is written only once it is
	// actually gone, so the log never records success for a teardown that failed at
	// its defining step.
	if err := a.Selfmanage.Uninstall(force); err != nil {
		a.errorf("%v", err)
		a.audit("uninstall", "", "fail", "binary removal failed: "+err.Error(), nil)
		return 1
	}
	if !purgeAudit {
		a.audit("uninstall", "", "ok", a.InstallPath, map[string]string{"accounts": fmt.Sprint(len(plan.accounts)), "purged": "no"})
	}

	if stateGone {
		a.success(a.P.M("已卸载：临时账号、授权、自动删除任务、状态与命令均已移除。",
			"uninstalled: the temporary accounts, their grants, their auto-delete tasks, the state and the command are gone."))
	} else {
		a.success(a.P.M("已卸载命令，账号与授权已清除；但状态目录未能删除（见上），请手动清理 "+a.StateDir,
			"uninstalled the command; accounts and grants are gone, but the state directory could not be removed (see above) — remove "+a.StateDir+" by hand."))
	}
	return 0
}

// removeStateDir deletes everything this tool kept under /var/lib, v1's files
// included. It is only ever reached once no managed account survives.
//
// The symlink check is the same discipline the rest of the tool writes with: the
// directory is root-owned by construction, so anything else standing at that path
// is not ours to delete recursively.
func (a *App) removeStateDir(force bool) error {
	if a.StateDir == "" {
		return fmt.Errorf("no state directory configured")
	}
	if _, err := os.Lstat(a.StateDir); os.IsNotExist(err) {
		return nil
	}
	if !force {
		if err := fsutil.RootSafeDir(a.StateDir); err != nil {
			return fmt.Errorf("refusing to remove an unsafe state directory: %w", err)
		}
	}
	return os.RemoveAll(a.StateDir)
}
