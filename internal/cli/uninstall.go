package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/mountinfo"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/table"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
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
// A passwd GECOS marker is deliberately only a block-only witness. It is the one
// signal an account can write to itself: `usermod -c 'linux-temp-admin temporary
// admin' realadmin` must never enlist that account or its home for deletion. But
// ignoring the marker entirely can strand a permanent no-sudo/no-timer account if
// its registry row is lost. The marker therefore keeps the command and state in
// place for manual recovery; only a completed registry+UID+generation+passwd
// identity can authorize automatic deletion.
type witness string

const (
	witnessRegistry witness = "registry"
	witnessV1       witness = "v1-registry"
	witnessSudoers  witness = "sudo-grant"
	witnessSSHD     witness = "sshd-exception"
	witnessUnit     witness = "auto-delete-task"
	witnessMarker   witness = "passwd-marker-block-only"
)

func hasRegistryWitness(acc teardownAccount) bool {
	for _, w := range acc.witnesses {
		if w == witnessRegistry {
			return true
		}
	}
	return false
}

// markerOnlyForeignAccount reports whether acc is named ONLY by a passwd GECOS
// lifecycle marker — no registry row, no v1 row, and no privilege-carrying
// artifact.
//
// This is the one witness an unprivileged account can forge. The legacy fixed
// marker contains no '=', ',' or ':', so both shadow's and util-linux's chfn
// accept it in the user-writable full-name field, and any local user can make
// their own account name itself as this tool's. That block is correct by default
// — the marker may also be the last trace of a permanent no-sudo/no-timer
// account whose registry row was lost — but without an override it let any
// unprivileged user refuse every uninstall forever.
//
// The override is safe to offer precisely for this shape and no other: an
// account with anything left to clean up (a sudo grant, an sshd exception, an
// auto-delete unit, a registry row) carries a second witness and still blocks.
// Ignoring one of these never deletes it; it only stops it from blocking.
func markerOnlyForeignAccount(acc teardownAccount) bool {
	return !acc.registryFound && len(acc.witnesses) == 1 && acc.witnesses[0] == witnessMarker
}

// uninstallOptions is the operator's intent for one teardown. It is a struct so
// the authorization and execution steps cannot be handed the flags in the wrong
// order as the list grows.
type uninstallOptions struct {
	force                bool
	yes                  bool
	removeUsers          bool
	purgeAudit           bool
	ignoreForeignMarkers bool
}

// ignoredForeignMarkers lists the accounts opts excuses from blocking.
func (p teardownPlan) ignoredForeignMarkers(opts uninstallOptions) []string {
	if !opts.ignoreForeignMarkers {
		return nil
	}
	var out []string
	for _, acc := range p.accounts {
		if markerOnlyForeignAccount(acc) {
			out = append(out, acc.name)
		}
	}
	return out
}

func (p teardownPlan) ignores(opts uninstallOptions, acc teardownAccount) bool {
	return opts.ignoreForeignMarkers && markerOnlyForeignAccount(acc)
}

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
	name           string
	exists         bool
	witnesses      []witness
	recovery       deletionRecoveryState
	registryFound  bool
	registryRecord registry.Record
	passwd         user.Passwd
}

type deletionRecoveryState uint8

const (
	noDeletionRecovery deletionRecoveryState = iota
	absentDeletionRecovery
	boundDeletionRecovery
	manualDeletionRecovery
)

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
	records := map[string]registry.Record{}
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
			records[r.User] = r
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
	if users, err := a.listMarkerAccounts(); err != nil {
		addInventoryErr(fmt.Errorf("%s: %w", a.P.M("扫描账号生命周期标记失败", "scanning account lifecycle markers failed"), err))
	} else {
		for _, u := range users {
			add(u, witnessMarker)
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
		pw, exists, err := a.lookupUser(n)
		if err != nil {
			addInventoryErr(fmt.Errorf("%s %s: %w", a.P.M("读取账号失败", "reading account"), n, err))
		}
		rec, registered := records[n]
		recovery := noDeletionRecovery
		if registered && rec.DeletionStarted && err == nil {
			switch {
			case !exists:
				recovery = absentDeletionRecovery
			case rec.IdentityBound && deletionRecordMatchesPasswd(rec, pw):
				recovery = boundDeletionRecovery
			default:
				recovery = manualDeletionRecovery
			}
		}
		plan.accounts = append(plan.accounts, teardownAccount{
			name: n, exists: exists, witnesses: ws, recovery: recovery,
			registryFound: registered, registryRecord: rec, passwd: pw,
		})
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
	// Even --force only authorizes unlinking an unsafe file-like entry (for
	// example a symlink). A directory is not an installed command, and a non-empty
	// one would fail only after accounts and state had already been destroyed.
	if fi.IsDir() {
		return a.P.M("是目录；请先人工处理", "is a directory; remove or relocate it manually")
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
const maxV1RegistryBytes = int64(16 << 20)

func (a *App) v1RegistryUsers() ([]string, error) {
	path := filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile))
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("v1 registry %s is not a regular file", path)
	}
	if fi.Size() > maxV1RegistryBytes {
		return nil, fmt.Errorf("v1 registry exceeds %d-byte limit", maxV1RegistryBytes)
	}
	var users []string
	limited := &io.LimitedReader{R: f, N: maxV1RegistryBytes + 1}
	sc := bufio.NewScanner(limited)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, tabSeparated := strings.Cut(line, "\t")
		if !tabSeparated {
			return nil, fmt.Errorf("v1 registry line %d is not tab-separated", lineNo)
		}
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
	if limited.N == 0 {
		return nil, fmt.Errorf("v1 registry exceeds %d-byte limit", maxV1RegistryBytes)
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
			switch acc.recovery {
			case absentDeletionRecovery:
				state = a.P.M("缺失（删除恢复待完成）", "gone (deletion recovery pending)")
			case boundDeletionRecovery:
				state = a.P.M("存在（删除世代已绑定）", "live (deletion generation bound)")
			case manualDeletionRecovery:
				state = a.P.M("存在（删除恢复需人工）", "live (manual deletion recovery required)")
			case noDeletionRecovery:
				if acc.exists {
					state = a.P.M("存在（身份核验后尝试撤销）", "live (revoke after identity checks)")
				}
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
		a.info(fmt.Sprintf(a.P.M("审计日志保留在 %s —— 其中保留了成功写入的 root 级账号操作记录，卸载不会替你抹掉它。要一并删除请加 --purge-audit。",
			"the audit log is KEPT at %s — it retains successfully written records of root-capable account operations, and an uninstall does not erase them for you. Pass --purge-audit to remove it too."), p.auditPath))
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
	return a.uninstallResult(args).status
}

func (a *App) uninstallResult(args []string) commandResult {
	if !a.requireRoot() {
		return statusResult(1)
	}
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var opts uninstallOptions
	fs.BoolVar(&opts.force, "force", false, "")
	fs.BoolVar(&opts.yes, "yes", false, "")
	fs.BoolVar(&opts.yes, "y", false, "")
	fs.BoolVar(&opts.removeUsers, "remove-users", false, "")
	fs.BoolVar(&opts.purgeAudit, "purge-audit", false, "")
	fs.BoolVar(&opts.ignoreForeignMarkers, "ignore-foreign-markers", false, "")
	if !a.parseFlags(fs, args) {
		return statusResult(1)
	}
	purgeAudit, force, yes := opts.purgeAudit, opts.force, opts.yes
	plan := a.teardownPlan(purgeAudit, force)
	if !a.authorizeUninstall(plan, opts) {
		return statusResult(1)
	}
	if !yes {
		if a.prompt(a.P.M("确认卸载请输入 YES: ", "type YES to uninstall: ")) != "YES" {
			a.warnf("%s", a.P.M("已取消", "cancelled"))
			return statusResult(0)
		}
	}
	result := commandResult{}
	result.status = a.withLifecycleLockAllowUninstalled(func() int {
		current := a.teardownPlan(purgeAudit, force)
		if current.inventoryErr != nil {
			a.errorf("%s: %v", a.P.M("确认后无法重新读取完整卸载清单，拒绝执行",
				"cannot rebuild a complete uninstall inventory after confirmation; refusing to proceed"), current.inventoryErr)
			return 1
		}
		if !sameTeardownPlan(plan, current) {
			a.errorf("%s", a.P.M("确认后卸载清单发生变化；未修改主机，请重新运行并确认最新清单",
				"the uninstall inventory changed after confirmation; the host was not modified; rerun and confirm the current inventory"))
			a.audit("uninstall", "", "fail", "inventory changed after confirmation", nil)
			return 1
		}
		status := a.teardown(current, opts)
		result = commandResult{status: status, applied: status == 0}
		return status
	})
	return result
}

func (a *App) authorizeUninstall(plan teardownPlan, opts uninstallOptions) bool {
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
			"清单不全就卸载，会删掉命令、留下它没看见的账号或授权，并使已有自动删除任务无法执行。请先修好上面的问题再重试。",
			"uninstalling on a partial inventory can leave unseen accounts or grants behind and prevent any existing auto-delete task from running. Repair the account database or managed state before retrying."))
		return false
	}

	a.printTeardownPlan(plan)

	if ignored := plan.ignoredForeignMarkers(opts); len(ignored) > 0 {
		a.warnf("%s %s", a.P.M(
			"--ignore-foreign-markers：以下账号只由 passwd GECOS 标记指认，没有登记行，也没有本工具的 sudo 授权、sshd 例外或自动删除任务。卸载不会删除它们，也不会再因它们中止；如果其中有你的临时账号，请先取消卸载并人工处理：",
			"--ignore-foreign-markers: these accounts are named only by a passwd GECOS marker, with no registry row and none of this tool's sudo grants, sshd exceptions, or auto-delete tasks. The uninstall will neither delete them nor stop for them; if any of them is really yours, cancel and deal with it by hand first:"),
			strings.Join(ignored, " "))
	}

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
		return false
	}

	// A live UID-only (or mismatched) deletion witness proves only that a prior
	// operator reached the userdel boundary; it does not prove that today's
	// same-name account is the one they approved. Bulk uninstall is unattended per
	// account, so refuse the whole operation before touching any host state. The
	// operator must recover it through an interactive revoke --force confirmation.
	for _, acc := range plan.accounts {
		if acc.recovery != manualDeletionRecovery {
			continue
		}
		a.errorf("%s %s", a.P.M(
			"拒绝卸载：活账号的删除恢复见证未绑定当前世代；已保留账号、命令和状态。请先人工核查并交互执行 linux-temp-admin revoke --force：",
			"refusing to uninstall: a live account has a deletion-recovery witness that is not bound to its current generation; the account, command, and state were kept. Inspect it and complete an interactive linux-temp-admin revoke --force first:"), acc.name)
		return false
	}

	// Validate every other live account from the displayed, immutable snapshot
	// before the lifecycle lock is entered and before teardown can revoke the first
	// account. Without this whole-plan preflight, a valid alphabetically earlier
	// account could be deleted before a later marker-only, pending, legacy, or
	// identity-mismatched account made the same bulk operation fail. The plan is
	// rebuilt and compared under the lock before teardown, and revoke still repeats
	// its identity checks immediately before each mutation.
	for _, acc := range plan.accounts {
		if !acc.exists || liveTeardownAccountAuthorized(acc) || plan.ignores(opts, acc) {
			continue
		}
		a.errorf("%s %s", a.P.M("拒绝卸载：无法在缺少当前世代绑定身份登记时自动删除活账号；在删除任何账号前已停止：",
			"refusing to uninstall: cannot auto-delete a live account without a current generation-bound identity record; stopped before deleting any account:"), acc.name)
		if markerOnlyForeignAccount(acc) {
			// Say which witness is doing the blocking and how to clear it. This shape
			// is reachable by any local user running chfn on their own account, so an
			// operator who cannot see the cause has no way to finish an uninstall.
			a.warnf("%s", a.P.M(
				"该账号只由 passwd GECOS 生命周期标记指认（没有登记行，也没有本工具的授权或任务）。任何本机用户都能用 chfn 给自己写上这个标记。确认它不是本工具创建的账号后，可用 `usermod -c '' "+acc.name+"` 清除标记，或用 --ignore-foreign-markers 明确跳过。",
				"this account is named only by a passwd GECOS lifecycle marker (no registry row, and none of this tool's grants or tasks). Any local user can write that marker onto their own account with chfn. Once you have confirmed it is not an account this tool created, clear it with `usermod -c '' "+acc.name+"`, or skip it explicitly with --ignore-foreign-markers."))
		}
		return false
	}

	// Refuse before anything is touched, not partway through. An explicitly
	// ignored foreign marker is exempt: the teardown will not delete that account,
	// so warning that it would is simply untrue.
	if who := callerAccount(); who != "" {
		for _, acc := range plan.accounts {
			if acc.name == who && acc.exists && !plan.ignores(opts, acc) {
				a.errorf("%s", a.P.M(
					"你正以临时账号 "+who+" 的身份运行卸载，而卸载会删除这个账号。请改用 root 或其他管理员登录后重试。",
					"you are running this as the temporary account "+who+", which the uninstall would delete. Log in as root or another administrator and retry."))
				return false
			}
		}
	}

	// Count only the accounts this teardown would actually act on. An explicitly
	// ignored foreign marker is left alone, so demanding --remove-users for it
	// would name a deletion that is not going to happen.
	pending := 0
	for _, acc := range plan.accounts {
		if !plan.ignores(opts, acc) {
			pending++
		}
	}
	if pending > 0 && !opts.removeUsers {
		// Mirrors --fix-sshd: a non-interactive run never does the irreversible thing
		// implicitly, and the flag is what says it out loud. The analogy is not exact
		// and the difference is worth admitting: this tool's other --yes gates
		// (--confirm-sudo, --confirm-force) make you retype the USERNAME, which a
		// bare bool cannot do because there is no single username here. The printed
		// count is the compensation, not an equal.
		if opts.yes || !a.StdinIsTTY() {
			a.errorf("%s", a.P.M(
				fmt.Sprintf("非交互模式不会删除账号。这台机器上有 %d 个由本工具管理的账号，卸载必须先删除它们；确认请加 --remove-users。", pending),
				fmt.Sprintf("a non-interactive run will not delete accounts. This host has %d managed by this tool, and the uninstall must remove them first; pass --remove-users to say so.", pending)))
			a.warnf("%s", a.P.M("（不能只卸载命令、留下受管账号：这会让工具失去撤销这些账号、清理授权和执行已有自动删除任务的能力。）",
				"(uninstalling the command while keeping managed accounts is not an option: it removes the ability to revoke those accounts, clean their grants, and run any auto-delete tasks already scheduled.)"))
			return false
		}
	}
	return true
}

func liveTeardownAccountAuthorized(acc teardownAccount) bool {
	if !acc.exists || !acc.registryFound || !hasRegistryWitness(acc) {
		return false
	}
	state := classifyRegisteredAccount(acc.registryRecord, acc.passwd, true, nil)
	return state == registeredActive || state == registeredFirstFieldWitness || state == registeredQuarantine || state == registeredRecoveryBound
}

func sameTeardownPlan(a, b teardownPlan) bool {
	if a.stateDir != b.stateDir || a.auditPath != b.auditPath || a.auditKept != b.auditKept ||
		a.binaryPath != b.binaryPath || a.binaryBlocker != b.binaryBlocker || len(a.accounts) != len(b.accounts) {
		return false
	}
	for i := range a.accounts {
		left, right := a.accounts[i], b.accounts[i]
		if left.name != right.name || left.exists != right.exists || left.recovery != right.recovery ||
			left.registryFound != right.registryFound || left.registryRecord != right.registryRecord ||
			!user.SameAccountIdentity(left.passwd, right.passwd) || len(left.witnesses) != len(right.witnesses) {
			return false
		}
		for j := range left.witnesses {
			if left.witnesses[j] != right.witnesses[j] {
				return false
			}
		}
	}
	return true
}

// teardown executes the plan. Order is the whole design: every step leaves the
// host no worse than it found it, and the binary goes last because everything
// that could still need a manager needs the manager to exist.
func (a *App) teardown(plan teardownPlan, opts uninstallOptions) int {
	force, purgeAudit := opts.force, opts.purgeAudit
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
	var failedRevokes []string
	for _, acc := range plan.accounts {
		if plan.ignores(opts, acc) {
			// Explicitly excused by --ignore-foreign-markers, and authorizeUninstall
			// already named it. Nothing is deleted for it and nothing is cleaned up:
			// this shape has no registry row and no artifact of ours to remove.
			continue
		}
		// A passwd marker, v1 row, or name-scoped artifact can make a live account
		// block uninstall, but none can authorize its deletion. Require the current
		// registry witness before even entering the destructive revoke path; the
		// completedAccountIdentity check below then binds UID, generation, home, and
		// the exact marker on one passwd snapshot.
		if acc.exists && !hasRegistryWitness(acc) {
			a.errorf("%s %s", a.P.M("缺少当前世代绑定身份登记，拒绝自动删除活账号：",
				"refusing to auto-delete a live account without a current generation-bound identity record:"), acc.name)
			failedRevokes = append(failedRevokes, acc.name)
			continue
		}
		ours, live, identityErr := a.completedAccountIdentity(acc.name)
		if identityErr != nil {
			a.errorf("%s %s: %v", a.P.M("无法重新验证活账号身份，拒绝自动删除：",
				"cannot re-verify the live account identity; refusing automatic deletion:"), acc.name, identityErr)
			failedRevokes = append(failedRevokes, acc.name)
			continue
		}
		if live && !ours {
			// Every filesystem artifact and v1 row is name-scoped: it proves that this
			// tool once managed the name, not that today's account is the same account
			// generation. A pending/legacy v2 row is not identity either, and the GECOS
			// marker is user-writable. Bulk uninstall therefore requires a completed,
			// generation-bound identity and the same passwd snapshot to match its UID and
			// marker; an operator can inspect and revoke an unverifiable account explicitly.
			a.errorf("%s %s", a.P.M("缺少当前世代绑定身份登记，拒绝自动删除活账号：",
				"refusing to auto-delete a live account without a current generation-bound identity record:"), acc.name)
			failedRevokes = append(failedRevokes, acc.name)
			continue
		}
		if rc := a.revokeLocked([]string{"--user", acc.name, "--yes", "--force", "--confirm-force", acc.name}); rc != 0 {
			failedRevokes = append(failedRevokes, acc.name)
		}
	}

	// Re-inventory from scratch and also retain every revoke failure. Two things
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
	// blocks too. So does a failed revoke even when no disk artifact remains: a
	// systemd timer can remain active in manager memory after its unit file vanished.
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
		// An explicitly ignored foreign marker is still expected to be here — that is
		// what ignoring it meant. It is only excused while it still carries nothing
		// but that marker: if a grant, exception, unit, or registry row has appeared
		// for the name since the plan was approved, it blocks like anything else.
		if residual.ignores(opts, acc) {
			continue
		}
		if acc.exists || hasArtifactWitness(acc) {
			blocking = append(blocking, acc)
		}
	}
	if len(blocking) > 0 || len(failedRevokes) > 0 {
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
		if len(failedRevokes) > 0 {
			a.errorf("%s %s", a.P.M("以下账号的撤销操作失败：", "revoke failed for these accounts:"), strings.Join(failedRevokes, " "))
		}
		a.errorf("%s", a.P.M(
			"已保留已安装的命令和状态目录，卸载中止。留着一个带 sudo 的授权却删掉唯一能清理它的命令，比不卸载更糟。请先手动处理，再重试。",
			"the installed command and the state directory were kept, and the uninstall stopped. Leaving a sudo grant behind while deleting the only thing that can clean it up is worse than not uninstalling. Deal with these by hand and retry."))
		a.audit("uninstall", "", "fail", "residual: "+strings.Join(residual.names(), " ")+"; failed revokes: "+strings.Join(failedRevokes, " "), nil)
		return 1
	}

	// Releases before the persistent-timer cleanup fix could leave an inert
	// stamp after both the account and its unit files were gone. There is no
	// username witness left to feed through revoke, so sweep this tool's timer
	// namespaces only after the fresh inventory above proved that no managed task
	// remains live. A failure keeps the command and state available for a retry.
	if a.Scheduler != nil {
		if err := a.Scheduler.CleanupTimerStamps(); err != nil {
			a.errorf("%s: %v", a.P.M("无法清除旧版 systemd 定时器时间戳，卸载中止（命令与状态已保留）",
				"cannot remove legacy systemd timer timestamps; the uninstall stopped (command and state kept)"), err)
			a.audit("uninstall", "", "fail", "timer timestamp cleanup failed: "+err.Error(), nil)
			return 1
		}
	}

	if a.Lifecycle != nil {
		if err := a.Lifecycle.MarkUninstalled(); err != nil {
			a.errorf("%s: %v", a.P.M("无法写入卸载状态标记；状态与命令均已保留，以阻止排队中的旧进程重新启用工具",
				"cannot record the uninstall-state marker; state and command were kept so a queued older process cannot re-enable the tool"), err)
			a.audit("uninstall", "", "fail", "uninstall marker write failed: "+err.Error(), nil)
			return 1
		}
	}
	if err := a.removeStateDir(force); err != nil {
		a.errorf("%s: %v", a.P.M("删除状态目录失败；工具已标记为卸载并保留命令，以便修复后重试",
			"removing the state directory failed; the tool is marked uninstalled and the command was kept so uninstall can be retried after repair"), err)
		a.audit("uninstall", "", "fail", "state directory cleanup failed: "+err.Error(), nil)
		return 1
	}
	a.info(a.P.M("已删除状态目录："+a.StateDir, "removed the state directory: "+a.StateDir))

	// The binary is the last thing removed and the first that can still fail here
	// (a symlinked path without --force). The "ok" audit is written only once it is
	// actually gone, so the log never records success for a teardown that failed at
	// its defining step.
	if err := a.Selfmanage.Uninstall(force); err != nil {
		a.errorf("%v", err)
		a.audit("uninstall", "", "fail", "binary removal failed: "+err.Error(), nil)
		return 1
	}
	if purgeAudit {
		// Record the complete outcome before purging; logging after a successful
		// purge would recreate the directory and turn "purge" into "keep one line".
		a.audit("uninstall", "", "pending", "core teardown complete; audit purge pending",
			map[string]string{"accounts": fmt.Sprint(len(plan.accounts)), "purged": "requested"})
		if err := a.removeAuditDir(force); err != nil {
			a.errorf("%s: %v", a.P.M("删除审计日志失败；命令已卸载但清理未完整完成",
				"removing the audit log failed; the command is uninstalled but cleanup is incomplete"), err)
			// Keep the logger live. A failed recursive removal may be partial, and this
			// failure is exactly the event the surviving/recreated log must retain.
			a.audit("uninstall", "", "fail", "audit purge failed: "+err.Error(), nil)
			return 1
		}
		a.info(a.P.M("已删除审计日志："+a.AuditLogDir, "removed the audit log: "+a.AuditLogDir))
		a.Audit = nil
	} else {
		a.audit("uninstall", "", "ok", a.InstallPath, map[string]string{"accounts": fmt.Sprint(len(plan.accounts)), "purged": "no"})
	}

	a.success(a.P.M("已卸载：临时账号、授权、自动删除任务、状态与命令均已移除。",
		"uninstalled: the temporary accounts, their grants, their auto-delete tasks, the state and the command are gone."))
	return 0
}

// removeStateDir deletes everything this tool kept under /var/lib, v1's files
// included. It is only ever reached once no managed account survives.
//
// Ancestor symlinks are always refused so the mount inventory and removal name the
// same tree. Without --force, the managed leaf must also be a root-safe directory;
// force relaxes only that leaf check (for example, to unlink a symlink at the
// managed name), never the ancestor or mount boundaries.
func (a *App) removeStateDir(force bool) error {
	if err := safeRecursiveRemovalPath(a.StateDir); err != nil {
		return fmt.Errorf("unsafe state directory: %w", err)
	}
	if err := refuseSymlinkedRemovalParent(a.StateDir); err != nil {
		return fmt.Errorf("unsafe state directory: %w", err)
	}
	if _, err := os.Lstat(a.StateDir); os.IsNotExist(err) {
		// A previous recursive removal can have made the name disappear and then
		// failed to sync its parent. Route the retry through removeAll so it
		// finishes that durability step instead of treating visibility as durable.
		return a.removeAll(a.StateDir)
	} else if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if err := refuseMountedRemoval(a.StateDir); err != nil {
		return err
	}
	if !force {
		if err := fsutil.RootSafeDir(a.StateDir); err != nil {
			return fmt.Errorf("refusing to remove an unsafe state directory: %w", err)
		}
	}
	return a.removeAll(a.StateDir)
}

func (a *App) removeAuditDir(force bool) error {
	if err := safeRecursiveRemovalPath(a.AuditLogDir); err != nil {
		return fmt.Errorf("unsafe audit directory: %w", err)
	}
	if err := refuseSymlinkedRemovalParent(a.AuditLogDir); err != nil {
		return fmt.Errorf("unsafe audit directory: %w", err)
	}
	if _, err := os.Lstat(a.AuditLogDir); os.IsNotExist(err) {
		return a.removeAll(a.AuditLogDir)
	} else if err != nil {
		return fmt.Errorf("inspect audit directory: %w", err)
	}
	if err := refuseMountedRemoval(a.AuditLogDir); err != nil {
		return err
	}
	if !force {
		if err := fsutil.RootSafeDir(a.AuditLogDir); err != nil {
			return fmt.Errorf("refusing to remove an unsafe audit directory: %w", err)
		}
	}
	return a.removeAll(a.AuditLogDir)
}

func safeRecursiveRemovalPath(path string) error {
	clean := filepath.Clean(path)
	if path == "" || !filepath.IsAbs(path) || clean != path || clean == string(filepath.Separator) {
		return fmt.Errorf("refusing recursive removal of %q", path)
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) < 3 {
		return fmt.Errorf("refusing recursive removal of broad path %q", path)
	}
	return nil
}

// refuseSymlinkedRemovalParent keeps the lexical path checked against mountinfo
// identical to the path os.RemoveAll will traverse. A symlink in an ancestor
// could otherwise redirect removal to a different tree whose mounts were never
// inspected. The final entry is intentionally not resolved: --force may safely
// unlink a symlink at the managed name because RemoveAll does not follow it.
func refuseSymlinkedRemovalParent(path string) error {
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("resolve recursive-removal parent %s: %w", parent, err)
	}
	if resolved != parent {
		return fmt.Errorf("refusing recursive removal through symlinked parent %s (resolves to %s)", parent, resolved)
	}
	return nil
}

// refuseMountedRemoval prevents os.RemoveAll from crossing into a bind mount or
// child filesystem. Mount ownership is independent of pathname ownership, and a
// dedicated tool directory can be used as a mountpoint for unrelated data. This
// check is intentionally not bypassed by --force.
func refuseMountedRemoval(path string) error {
	return mountinfo.RefuseUnder(filepath.Clean(path))
}

func rejectMountsUnder(r io.Reader, root string) error {
	return mountinfo.RejectUnder(r, root)
}

// syncRecursiveRemovalParent is indirected so tests can exercise a retry after
// the recursive removal became visible but the parent fsync failed.
var syncRecursiveRemovalParent = func(parent *os.File) error { return parent.Sync() }

func (a *App) removeAll(path string) error {
	var err error
	if a.RemoveAll != nil {
		err = a.RemoveAll(path)
	} else {
		err = os.RemoveAll(path)
	}
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		if err == nil {
			return fmt.Errorf("recursive removal reported success but %s still exists", path)
		}
		return fmt.Errorf("verify recursive removal of %s: %w", path, err)
	}
	parent, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// If another actor removed the whole parent tree, there is no remaining
		// directory entry for this function to make durable.
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open recursive-removal parent: %w", err)
	}
	defer parent.Close()
	if err := syncRecursiveRemovalParent(parent); err != nil {
		return &fsutil.DurabilityError{Operation: "recursive removal", Err: err}
	}
	return nil
}
