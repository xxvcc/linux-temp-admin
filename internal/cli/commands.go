package cli

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
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
		rec, found, err := a.Registry.Lookup(u)
		if err != nil {
			a.errorf("%s: %v", a.P.M("读取注册表失败", "reading registry failed"), err)
			return 1
		}
		pw, ok, err := a.lookupUser(u)
		if err != nil {
			a.errorf("%s: %v", a.P.M("读取账号数据库失败", "reading account database failed"), err)
			return 1
		}
		if !ok {
			if found && rec.DeletionStarted {
				a.printf("user=%s uid=%d exists=false managed=false identity=deletion-recovery-absent", rec.User, rec.UID)
				if rec.AutoUnit != "" {
					a.printf("auto-revoke unit=%s", rec.AutoUnit)
				}
				if rec.QuarantineUntil != "" {
					a.printf("quarantine-until=%s unit=%s", rec.QuarantineUntil, rec.QuarantineUnit)
				}
				return 0
			}
			a.errorf("%s", a.P.M("用户不存在："+u, "user does not exist: "+u))
			return 1
		}
		managed := false
		identity := "unregistered"
		if found {
			switch classifyRegisteredAccount(rec, pw, true, nil) {
			case registeredActive:
				managed, identity = true, "generation-bound"
			case registeredFirstFieldWitness:
				managed, identity = true, "generation-bound-first-field-compat"
			case registeredRecoveryBound:
				identity = "deletion-recovery-bound"
			case registeredQuarantine:
				identity = "quarantined"
			case registeredRecoveryManual:
				identity = "deletion-recovery-manual"
			case registeredLegacyIdentity:
				identity = "legacy-unverified"
			case registeredPending:
				identity = "pending"
			case registeredUIDMismatch:
				identity = "uid-mismatch"
			case registeredMarkerMismatch:
				identity = "generation-marker-mismatch"
			case registeredHomeMismatch:
				identity = "home-mismatch"
			default:
				identity = "unverified"
			}
		}
		a.printf("user=%s uid=%d gid=%d home=%s shell=%s managed=%v identity=%s",
			pw.Name, pw.UID, pw.GID, pw.Home, pw.Shell, managed, identity)
		if found && rec.AutoUnit != "" {
			a.printf("auto-revoke unit=%s", rec.AutoUnit)
		}
		if found && rec.QuarantineUntil != "" {
			a.printf("quarantine-until=%s unit=%s", rec.QuarantineUntil, rec.QuarantineUnit)
		}
		return 0
	}

	a.info(a.P.M("已登记的临时用户：", "Registered temporary users:"))
	recs, err := a.Registry.List()
	if err != nil {
		a.warnf("%v", err)
		return 1
	}
	if len(recs) == 0 {
		a.printf("  %s", a.P.M("（无）", "(none)"))
		return 0
	}
	a.printf("%s", a.usersView(recs, false))
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
	for i, r := range recs {
		cells := a.userCells(r)
		if numbered {
			cells = append([]string{strconv.Itoa(i + 1)}, cells...)
		}
		t.Row(cells...)
	}
	return t
}

func (a *App) userCells(r registry.Record) []string {
	yn := func(value bool) string {
		return a.P.M(map[bool]string{true: "是", false: "否"}[value], map[bool]string{true: "yes", false: "no"}[value])
	}
	pw, exists, err := a.lookupUser(r.User)
	var state string
	switch classifyRegisteredAccount(r, pw, exists, err) {
	case registeredActive:
		state = a.P.M("在册", "active")
	case registeredFirstFieldWitness:
		state = a.P.M("在册（旧首字段见证）", "active (legacy first-field witness)")
	case registeredRecoveryAbsent:
		state = a.P.M("删除后恢复", "post-delete recovery")
	case registeredRecoveryBound:
		state = a.P.M("删除恢复（可续删）", "deletion recovery (bound retry)")
	case registeredQuarantine:
		state = a.P.M("已撤权，隔离待删", "access revoked; quarantined")
	case registeredRecoveryManual:
		state = a.P.M("删除恢复（需人工）", "deletion recovery (manual)")
	case registeredPending:
		state = a.P.M("创建未完成", "pending")
	case registeredIdentityUnverified:
		state = a.P.M("身份未验证", "identity unverified")
	case registeredLegacyIdentity:
		state = a.P.M("旧版身份未验证", "legacy identity unverified")
	case registeredUIDMismatch:
		state = a.P.M("UID 不匹配", "UID mismatch")
	case registeredMarkerMismatch:
		state = a.P.M("标记不匹配", "marker mismatch")
	case registeredHomeMismatch:
		state = a.P.M("家目录不匹配", "home mismatch")
	case registeredUnknown:
		state = a.P.M("未知", "unknown")
	default:
		state = a.P.M("缺失", "missing")
	}
	return []string{r.User, state, yn(r.Sudo), yn(r.AutoRevoke), r.Expires, r.Host, strconv.Itoa(r.Port)}
}

// usersView keeps the comparison table on ordinary terminals and switches to a
// vertical record view when the table would be wider than the actual terminal.
func (a *App) usersView(recs []registry.Record, numbered bool) string {
	full := a.usersTable(recs, numbered).String()
	width := 0
	if a.TerminalWidth != nil {
		width = a.TerminalWidth()
	}
	if width <= 0 || widestLine(full) <= width {
		return full
	}

	labels := []string{
		a.P.M("状态", "state"),
		"sudo",
		a.P.M("自动删除", "auto-delete"),
		a.P.M("到期", "expires"),
		a.P.M("主机", "host"),
		a.P.M("端口", "port"),
	}
	var out strings.Builder
	for i, rec := range recs {
		cells := a.userCells(rec)
		prefix := "- "
		if numbered {
			prefix = fmt.Sprintf("%d) ", i+1)
		}
		appendWrappedLine(&out, width, prefix, cells[0])
		for field := 1; field < len(cells); field++ {
			appendWrappedLine(&out, width, "   "+labels[field-1]+"=", cells[field])
		}
		if i+1 < len(recs) {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func widestLine(value string) int {
	widest := 0
	for _, line := range strings.Split(value, "\n") {
		if width := table.Width(line); width > widest {
			widest = width
		}
	}
	return widest
}

func appendWrappedLine(out *strings.Builder, maxWidth int, prefix, value string) {
	for {
		available := maxWidth - table.Width(prefix)
		if available < 1 {
			available = 1
		}
		part, rest := takeDisplayWidth(value, available)
		out.WriteString(prefix)
		out.WriteString(part)
		out.WriteByte('\n')
		if rest == "" {
			return
		}
		value = rest
		prefix = "   "
	}
}

func takeDisplayWidth(value string, maxWidth int) (string, string) {
	width, end := 0, 0
	for offset, r := range value {
		runeWidth := table.Width(string(r))
		if width+runeWidth > maxWidth && end > 0 {
			break
		}
		width += runeWidth
		end = offset + len(string(r))
		if width >= maxWidth {
			break
		}
	}
	if end == 0 && value != "" {
		_, size := utf8.DecodeRuneInString(value)
		end = size
	}
	return value[:end], value[end:]
}

type registeredAccountState uint8

const (
	registeredMissing registeredAccountState = iota
	registeredUnknown
	registeredRecoveryAbsent
	registeredRecoveryBound
	registeredQuarantine
	registeredRecoveryManual
	registeredPending
	registeredIdentityUnverified
	registeredLegacyIdentity
	registeredUIDMismatch
	registeredMarkerMismatch
	registeredHomeMismatch
	registeredFirstFieldWitness
	registeredActive
)

func classifyRegisteredAccount(rec registry.Record, pw user.Passwd, exists bool, lookupErr error) registeredAccountState {
	switch {
	case lookupErr != nil:
		return registeredUnknown
	case rec.DeletionStarted && !exists:
		return registeredRecoveryAbsent
	case rec.QuarantineUntil != "" && rec.DeletionStarted && rec.IdentityBound && deletionRecordMatchesPasswd(rec, pw):
		return registeredQuarantine
	case rec.DeletionStarted && rec.IdentityBound && deletionRecordMatchesPasswd(rec, pw):
		return registeredRecoveryBound
	case rec.DeletionStarted:
		return registeredRecoveryManual
	case !exists:
		return registeredMissing
	case !validate.AccountID(pw.UID) || !validate.AccountID(pw.GID):
		return registeredIdentityUnverified
	case rec.Pending:
		return registeredPending
	case !validate.AccountID(rec.UID):
		return registeredIdentityUnverified
	case pw.UID != rec.UID:
		return registeredUIDMismatch
	case !rec.IdentityBound:
		if user.IsLegacyManagedEntry(pw) {
			return registeredLegacyIdentity
		}
		return registeredMarkerMismatch
	case !user.MatchesManagedGeneration(pw, rec.Generation):
		return registeredMarkerMismatch
	case !validate.ManagedHome(rec.User, pw.Home):
		return registeredHomeMismatch
	case !user.HasTrailingGenerationWitness(pw, rec.Generation):
		return registeredFirstFieldWitness
	default:
		return registeredActive
	}
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
// Looking is the default: a bare Enter leaves.
//
// What a number does depends on the row's state, and the difference is worth
// stating exactly rather than summarising as "a number revokes":
//
//   - 在册/active — a real account. revoke deletes it, and that has to get past
//     typing the account's full name, which is where that decision belongs and
//     not in whether the list happens to be on screen.
//   - 缺失/missing — the account is already gone; only a registry row and any
//     grant it left behind remain. revoke sweeps those, with no prompt: there is
//     no account to lose, and `c` on this same screen sweeps every such row
//     without asking, so demanding a name for one of them and not for all of
//     them would be ceremony, not safety.
//
// The pickers deliberately list missing rows (revoke's picker used to filter them
// out). Being unpickable never made them safer — the same cleanup was always one
// typed name away — it only meant the one command that tidies them could not
// offer them.
func (a *App) manageUsers() int {
	recs, err := a.Registry.List()
	if err != nil {
		a.warnf("%v", err)
		return 1
	}
	orphans, orphanErr := a.orphanArtifacts(recs)
	if orphanErr != nil {
		a.warnf("%s: %v", a.P.M("扫描孤儿残留失败", "scanning for orphaned leftovers failed"), orphanErr)
	}

	a.info(a.P.M("已登记的临时用户：", "Registered temporary users:"))
	if len(recs) == 0 {
		a.printf("  %s", a.P.M("（无）", "(none)"))
	} else {
		a.printf("%s", a.usersView(recs, true))
	}

	// Orphans have no registry row, so the table above cannot show them — this is
	// where `doctor` and this screen used to disagree: doctor globs the filesystem
	// and sees a leftover grant/exception/unit; the table reads only the registry.
	// Surface them here, on the very screen whose `c` sweeps them, so the cleanup is
	// discoverable instead of something you only learn about from doctor.
	if len(orphans) > 0 {
		a.warnf("%s", a.P.M("另有无登记行的孤儿残留（账号不存在或身份无法验证；按 c 清理）：",
			"orphaned leftovers with no registry row (the account is absent or its identity is unverified; press c to clean):"))
		for _, o := range orphans {
			a.printf("  %s (%s)", o.name, strings.Join(o.kinds, " "))
		}
	}

	// Only truly empty — no rows AND no orphans — is a dead end. When orphans exist
	// with an empty registry (a host where every account expired, leaving fired
	// auto-revoke .service files behind), the old early return said "(none)" and
	// walked away without ever offering `c`, so the leftovers could not be cleaned
	// from here at all.
	if len(recs) == 0 && len(orphans) == 0 {
		if orphanErr != nil {
			return 1
		}
		return 0
	}

	choice := strings.TrimSpace(a.prompt(a.P.M(
		"输入编号或用户名撤销 · c 清理失效登记与孤儿授权 · 回车返回: ",
		"a number or username revokes it · c cleans up stale rows and orphaned grants · Enter returns: ")))
	switch {
	case choice == "":
		if orphanErr != nil {
			return 1
		}
		return 0
	case strings.EqualFold(choice, "c"):
		// compact() is the bare sweep, so the root gate the cleanup-expired
		// subcommand opens with has to be repeated here rather than inherited.
		if !a.requireRoot() {
			return 1
		}
		return a.compact()
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
	args := []string{"--user", name}
	if rec, found, err := a.Registry.Lookup(name); err == nil && found && rec.Pending {
		// Pending recovery is still protected by the direct TTY, full-name prompt,
		// generation/GECOS/UID/Home checks, and manual-invocation gate. Supplying
		// --force here makes the menu's advertised revoke action usable without
		// weakening any of those checks.
		args = append(args, "--force")
	}
	return a.revoke(args)
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
	recs, err := a.Registry.List()
	if err != nil {
		a.warnf("%s: %v", a.P.M("读取注册表失败", "reading registry failed"), err)
		return 1
	}
	if len(recs) > 0 {
		a.printf("%s", a.usersView(recs, false))
	}
	if compact {
		return a.compact()
	}
	return 0
}

// accountIsOursAndLive reports whether name is still associated with a live
// registry row for orphan-scanning purposes. Generation-bound identities must
// match exactly. A migrated v2 row with its fixed legacy marker is also treated
// as live here so cleanup does not silently cancel a genuine legacy account's
// grants and timer; destructive paths still refuse that weaker identity.
//
// It is the predicate the orphan sweeps use instead of a bare user.Exists,
// because a grant/exception/unit outlives its account in TWO ways, not one: the
// account is gone, OR a different, unmanaged account has since taken the name. In
// the second case a bare user.Exists reports the name as present and the sweeps
// treat the leftover as live — while the name-keyed sudoers drop-in hands OUR
// passwordless root to an account we never granted it to, invisible to doctor and
// cleanup. Requiring the account to be provably ours closes that: a name taken
// over by something that is not ours makes the leftover an orphan again.
//
// A managed account whose marker was erased, whose row was lost, or whose UID no
// longer matches is intentionally treated as unverifiable. That may require
// operator recovery, but it cannot transfer a name-scoped privilege to an
// unrelated replacement account.
func (a *App) accountIsOursAndLive(name string) (bool, error) {
	if a.Registry == nil {
		return false, fmt.Errorf("no registry available to verify %s", name)
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil || !found {
		return false, err
	}
	pw, exists, err := a.lookupUser(name)
	if err != nil {
		return false, err
	}
	state := classifyRegisteredAccount(rec, pw, exists, nil)
	return state == registeredActive || state == registeredFirstFieldWitness || state == registeredQuarantine || state == registeredLegacyIdentity, nil
}

// accountNeedsAutoRevoke reports whether a managed auto-revoke task must be
// retained. An absent recovery row needs its retry path for owner-checked mail
// cleanup, and an exactly bound live recovery may safely retry deletion. A legacy
// identity and a live UID-only or generation-mismatched recovery are manual-only,
// so their old unattended tasks are stale and must be swept while the registry
// witness remains.
func (a *App) accountNeedsAutoRevoke(name string) (bool, error) {
	if a.Registry == nil {
		return false, fmt.Errorf("no registry available to verify %s", name)
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil || !found {
		return false, err
	}
	pw, exists, err := a.lookupUser(name)
	if err != nil {
		return false, err
	}
	state := classifyRegisteredAccount(rec, pw, exists, nil)
	return state == registeredActive || state == registeredFirstFieldWitness || state == registeredQuarantine || state == registeredRecoveryAbsent ||
		state == registeredRecoveryBound, nil
}

// completedAccountIdentity returns whether name currently resolves to the
// completed v2 identity recorded by this tool, and whether a local account with
// that name exists at all. The UID and marker are checked on the same passwd
// snapshot; splitting them across two lookups would let a concurrent name reuse
// splice facts from two different accounts into one apparent identity.
func (a *App) completedAccountIdentity(name string) (ours, live bool, err error) {
	if a.Registry == nil {
		return false, false, fmt.Errorf("no registry available to verify %s", name)
	}
	rec, found, err := a.Registry.Lookup(name)
	if err != nil {
		return false, false, err
	}
	pw, exists, err := a.lookupUser(name)
	if err != nil {
		return false, false, err
	}
	if !exists {
		return false, false, nil
	}
	if !found {
		return false, true, nil
	}
	state := classifyRegisteredAccount(rec, pw, true, nil)
	return state == registeredActive || state == registeredFirstFieldWitness || state == registeredQuarantine || state == registeredRecoveryBound, true, nil
}

// installedCommandVersion best-effort reads the version of the binary at
// InstallPath — the one the auto-revoke timer runs, which can differ from this
// process. It returns (version, "ok") when it read one, and ("", state) where
// state is "absent" (nothing installed), "unreadable" (present but the version
// could not be obtained), or "" (nothing to check, e.g. no InstallPath set).
//
// It execs the installed binary, so it refuses to run anything at an unsafe path
// (RootSafeFile) — never exec a symlink or a non-root-owned file — and bounds the
// call with a timeout so a wedged binary cannot hang the report.
func (a *App) installedCommandVersion() (string, string) {
	if a.InstallPath == "" {
		return "", ""
	}
	m := a.Selfmanage
	if m == nil {
		m = selfmanage.New(a.InstallPath, 0)
	}
	v, err := m.InstalledVersion()
	if errors.Is(err, selfmanage.ErrNotInstalled) {
		return "", "absent"
	}
	if err != nil {
		return "", "unreadable"
	}
	return v, "ok"
}

// orphanArtifact is a leftover the tool wrote for a name with no registry row —
// a sudo grant, an sshd exception, or an auto-delete unit whose account is gone.
type orphanArtifact struct {
	name  string
	kinds []string
}

// orphanArtifacts returns the leftovers `c`/compact would sweep that the registry
// table cannot show: managed grants/exceptions/units whose account is not a live
// account of ours AND whose name has no registry row (rows are already in the
// table, marked 缺失). It is the same union of sweeps compact() acts on and doctor
// reports, so the three views agree.
func (a *App) orphanArtifacts(recs []registry.Record) ([]orphanArtifact, error) {
	inRegistry := make(map[string]bool, len(recs))
	for _, r := range recs {
		inRegistry[r.User] = true
	}
	kinds := map[string][]string{}
	var scanErrs []error
	addKind := func(users []string, label string) {
		for _, u := range users {
			if !inRegistry[u] {
				kinds[u] = append(kinds[u], label)
			}
		}
	}
	if a.Sudoers != nil {
		if o, err := a.Sudoers.Orphans(a.accountIsOursAndLive); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("sudoers: %w", err))
		} else {
			addKind(o, a.P.M("sudo 授权", "sudo grant"))
		}
	}
	if a.SSHD != nil {
		if o, err := a.SSHD.Orphans(a.accountIsOursAndLive); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("sshd: %w", err))
		} else {
			addKind(o, a.P.M("sshd 例外", "sshd exception"))
		}
	}
	if a.Scheduler != nil {
		if o, err := a.Scheduler.Orphans(a.accountNeedsAutoRevoke); err != nil {
			scanErrs = append(scanErrs, fmt.Errorf("scheduler: %w", err))
		} else {
			addKind(o, a.P.M("自动删除任务", "auto-delete task"))
		}
	}
	names := make([]string, 0, len(kinds))
	for n := range kinds {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]orphanArtifact, 0, len(names))
	for _, n := range names {
		out = append(out, orphanArtifact{name: n, kinds: kinds[n]})
	}
	return out, errors.Join(scanErrs...)
}

// compact is the sweep itself, with none of the framing the cleanup-expired
// subcommand wraps it in. It is split out for the manage screen, which has just
// drawn the table and is where revoke already lives: re-printing the list under a
// banner that sends the reader off to `revoke` and `status` would repeat what is
// already on screen and point away from where they are.
//
// The subcommand's root gate does NOT come with it. Every caller has to keep its
// own — this function sweeps.
func (a *App) compact() int {
	return a.withLifecycleLock(a.compactLocked)
}

func (a *App) compactLocked() int {
	rc := 0
	// Sweep the live grants BEFORE the registry rows: compacting drops the rows
	// that name these accounts, and a grant nobody can name any more is a grant
	// nobody will ever find.
	if a.SSHD != nil {
		orphans, err := a.SSHD.Orphans(a.accountIsOursAndLive)
		if err != nil {
			a.warnf("%v", err)
			rc = 1
		}
		for _, u := range orphans {
			if err := a.SSHD.Remove(u); err != nil {
				// Remove's own error states what happened (in the usual case the file
				// was deleted and only the reload was skipped), so use a neutral prefix
				// that does not assert the removal failed.
				a.warnf("%s: %v", a.P.M("清理孤儿 sshd 例外时", "while cleaning up the orphaned sshd exception"), err)
				rc = 1
				continue
			}
			a.info(a.P.M("已移除孤儿 sshd 例外："+a.SSHD.FilePath(u),
				"removed an orphaned sshd exception: "+a.SSHD.FilePath(u)))
			a.audit("sshd.cleanup", u, "ok", "orphaned sshd exception removed", nil)
		}
	}
	// An orphaned NOPASSWD drop-in is the worse of the two: it re-arms full root
	// the moment its username is reused.
	if a.Sudoers != nil {
		orphans, err := a.Sudoers.Orphans(a.accountIsOursAndLive)
		if err != nil {
			a.warnf("%v", err)
			rc = 1
		}
		for _, u := range orphans {
			// Announce the removal only once it happened: this used to print "removed"
			// whatever the outcome, which is the worst possible lie about a file that
			// hands out passwordless root.
			if err := a.Sudoers.Remove(u); err != nil {
				a.errorf("%s: %v", a.P.M("无法移除孤儿 sudo 授权（该文件仍会在用户名被复用时立即生效，请手动删除）",
					"could not remove an orphaned sudo grant (it re-arms the instant its username is reused; delete it by hand)"), err)
				rc = 1
				continue
			}
			a.info(a.P.M("已移除孤儿 sudo 授权："+a.Sudoers.FilePath(u),
				"removed an orphaned sudo grant: "+a.Sudoers.FilePath(u)))
			a.audit("grant.cleanup", u, "ok", "orphaned sudo drop-in removed", nil)
		}
	}
	// An orphaned auto-revoke unit is the third leftover, and until now the only one
	// with no sweep: its ExecStart runs the installed binary, so a unit whose
	// account is gone fires forever and fails forever (and against a REMOVED binary
	// after an uninstall). Scheduler.Orphans mirrors the two sweeps above, and
	// globs the v1 prefix too.
	if a.Scheduler != nil {
		orphans, err := a.Scheduler.Orphans(a.accountNeedsAutoRevoke)
		if err != nil {
			a.warnf("%v", err)
			rc = 1
		}
		for _, u := range orphans {
			if err := a.Scheduler.Cancel(u, ""); err != nil {
				a.warnf("%s: %v", a.P.M("无法移除孤儿自动删除任务", "could not remove orphaned auto-delete task"), err)
				rc = 1
				continue
			}
			a.info(a.P.M("已移除孤儿自动删除任务："+u, "removed an orphaned auto-delete task: "+u))
			a.audit("schedule.cleanup", u, "ok", "orphaned auto-revoke unit removed", nil)
		}
	}
	if rc != 0 {
		a.warnf("%s", a.P.M("孤儿扫描或清理未完整成功；为保留恢复线索，本次不压缩注册表。",
			"orphan scanning or cleanup did not complete; the registry was not compacted so recovery evidence is retained."))
		return rc
	}
	removed, err := a.Registry.Compact(func(rec registry.Record) (bool, error) {
		return user.Exists(rec.User)
	})
	if err != nil {
		a.warnf("%v", err)
		rc = 1
	} else {
		a.info(fmt.Sprintf(a.P.M("已压实注册表：移除 %d 条指向已不存在用户的记录。",
			"Compacted the registry: removed %d entries for users that no longer exist."), removed))
		if removed > 0 {
			a.audit("registry.compact", "", "ok", fmt.Sprintf("removed %d stale rows", removed), nil)
		}
	}
	return rc
}

func (a *App) doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	if !a.parseFlags(fs, args) {
		return 1
	}
	rc := 0
	a.info(a.P.M("linux-temp-admin 诊断报告", "linux-temp-admin doctor report"))
	a.info(fmt.Sprintf(a.P.M("运行版本：%s", "running version: %s"), buildinfo.Version))
	// The version that matters most is not this process's but the one installed at
	// InstallPath: the auto-revoke timer's ExecStart runs THAT binary, so a stale or
	// missing installed copy is a real diagnostic concern. Surface it, and flag a
	// mismatch — this whole tool just spent a release closing installed-vs-running
	// divergences.
	switch v, state := a.installedCommandVersion(); state {
	case "absent":
		a.warnf("%s", a.P.M("已安装命令：未安装（自动删除任务需要它）",
			"installed command: not installed (the auto-delete task needs it)"))
		rc = 1
	case "unreadable":
		a.warnf("%s%s", a.P.M("无法读取已安装命令的版本：", "could not read the installed command's version: "), a.InstallPath)
		rc = 1
	case "ok":
		if v == buildinfo.Version {
			a.success(fmt.Sprintf(a.P.M("已安装命令版本：%s", "installed command version: %s"), v))
		} else {
			a.warnf("%s", fmt.Sprintf(a.P.M("已安装命令版本 %s 与运行中的 %s 不一致（自动删除任务执行的是已安装的那份，可用 upgrade 或 install 对齐）",
				"installed command version %s differs from the running %s (the auto-delete task runs the installed one; align with upgrade or install)"), v, buildinfo.Version))
			rc = 1
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
		rc = 1
	} else {
		a.success(a.P.M("pidfd 进程撤销能力可用。", "pidfd process revocation is available."))
	}
	for _, d := range sysinfo.RequiredDeps(true, true) {
		if d.Present {
			a.success(a.P.M("依赖存在：", "dependency found: ") + d.Label)
		} else {
			a.warnf("%s%s", a.P.M("缺少依赖：", "missing dependency: "), d.Label)
			if doctorDependencyIsFatal(d.Label) {
				rc = 1
			}
		}
	}
	a.info(a.P.M("包管理器：", "package manager: ") + orNone(sysinfo.PackageManager()))
	a.info(a.P.M("init 系统：", "init system: ") + sysinfo.InitSystem())
	a.info(fmt.Sprintf(a.P.M("探测到 SSH 端口：%d", "detected SSH port: %d"), sysinfo.SSHPort()))
	// Probe with a name shaped like a fresh invite account: brand new, on no
	// whitelist, and in no group but its own. That is what an invite actually hits,
	// and reporting on it here lets an operator see effective-configuration blockers
	// before handing out an invite.
	//
	// The probe name is passed to SSHDConfig, not just to the check: `sshd -T` alone
	// cannot see `Match User` blocks, so asking the global view a per-user question
	// would let doctor contradict the invite it is meant to predict.
	probe := config.DefaultPrefix + "-doctor"
	if cfg, err := a.sshdConfig(probe); err != nil {
		a.warnf("%s (%v)", a.P.M("无法读取 sshd 有效配置；无法运行新邀请的公钥凭据检查。",
			"cannot read the effective sshd config; cannot run the public-key credential check for a new invite."), err)
		rc = 1
	} else {
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
			rc = 1
		} else {
			a.warnf("%s", a.P.M("sshd 有效配置检查发现新建临时账号公钥凭据的阻碍：",
				"the effective sshd config check found a blocker for a freshly created temporary account's key credential:"))
			a.reportBlockers(rep)
			if rep.Fixable() {
				a.warnf("%s", a.P.M("可用 `invite --fix-sshd` 只为该账号移除已知配置阻碍（不改动全局策略）。",
					"`invite --fix-sshd` can remove the known configuration blocker for that account only, leaving the global policy untouched."))
			}
			rc = 1
		}
		for _, u := range rep.Unverifiable {
			a.warnf("%s", u)
		}
	}
	// Read the registry once and inspect the account identity recorded in every
	// row. A pending or legacy row is recovery evidence, not authority to delete a
	// live account; a UID/GECOS mismatch means the name now resolves to something
	// other than the completed identity this tool recorded.
	var registryRecords []registry.Record
	registryReadable := a.Registry == nil
	if a.Registry != nil {
		var err error
		registryRecords, err = a.Registry.List()
		if err != nil {
			a.warnf("%s: %v", a.P.M("无法读取注册表", "cannot read registry"), err)
			rc = 1
		} else {
			registryReadable = true
			for _, rec := range registryRecords {
				pw, exists, lookupErr := a.lookupUser(rec.User)
				if lookupErr != nil {
					a.warnf("%s %s: %v", a.P.M("无法验证登记账号身份：", "cannot verify registered account identity:"), rec.User, lookupErr)
					rc = 1
					continue
				}
				switch classifyRegisteredAccount(rec, pw, exists, nil) {
				case registeredRecoveryAbsent:
					a.warnf("%s%s", a.P.M(
						"删除事务已持久化且账号已不存在；见证只允许重试按 UID 校验所属者的邮件清扫，请运行 revoke 完成恢复：",
						"deletion was durably started and the account is absent; the witness authorizes only an owner-checked UID-bound mail cleanup retry. Run revoke to finish recovery: "), rec.User)
					rc = 1
				case registeredRecoveryBound:
					a.warnf("%s%s", a.P.M(
						"活账号与已持久化的删除世代精确匹配；这是可重试的中断删除，请运行 revoke 完成：",
						"the live account exactly matches a durably started deletion generation; this interrupted deletion can be retried with revoke: "), rec.User)
					rc = 1
				case registeredQuarantine:
					a.info(a.P.M(
						"账号访问已撤销，用户名和 UID 正隔离至 "+rec.QuarantineUntil+"，之后由持久化任务完成删除：",
						"account access is revoked; its name and UID are quarantined until "+rec.QuarantineUntil+" and a persistent task will then finish deletion: ") + rec.User)
				case registeredRecoveryManual:
					a.warnf("%s%s", a.P.M(
						"活账号的删除恢复见证未绑定当前世代或已不匹配；自动删除、--yes 和卸载批量删除均被拒绝。人工核查后，请直接运行 revoke --force 并输入完整用户名：",
						"the live account's deletion-recovery witness is unbound to the current generation or no longer matches; automatic deletion, --yes, and uninstall bulk deletion are refused. Inspect it, then invoke revoke --force directly and type the full username: "), rec.User)
					rc = 1
				case registeredPending:
					a.warnf("%s%s", a.P.M("登记仍是未完成的 pending 创建意图，不能证明当前账号身份：",
						"registry row is still an incomplete pending creation intent and cannot prove the current account identity: "), rec.User)
					rc = 1
				case registeredMissing:
					a.warnf("%s%s", a.P.M("登记指向已不存在的账号（可用 cleanup-expired --compact 清理）：",
						"registry row points to an absent account (remove it with cleanup-expired --compact): "), rec.User)
					rc = 1
				case registeredIdentityUnverified:
					a.warnf("%s%s", a.P.M("活账号或登记没有安全的非 root UID/GID，不能证明身份：",
						"live account or registry row has no safe non-root UID/GID and cannot prove identity: "), rec.User)
					rc = 1
				case registeredUIDMismatch:
					a.warnf("%s", fmt.Sprintf(a.P.M("登记账号 %s 的 UID 不匹配：记录为 %d，当前为 %d；拒绝自动删除。",
						"registered account %s has a UID mismatch: recorded %d, current %d; automatic deletion is refused."), rec.User, rec.UID, pw.UID))
					rc = 1
				case registeredLegacyIdentity:
					a.warnf("%s%s", a.P.M("登记账号来自旧版固定身份标记，无法排除同名/同 UID 重用；自动和批量删除已禁用，请人工核查后用 revoke --force 处理：",
						"registered account uses a legacy fixed identity marker, so same-name/same-UID reuse cannot be excluded; automatic and bulk deletion are disabled; inspect it and use revoke --force: "), rec.User)
					rc = 1
				case registeredMarkerMismatch:
					a.warnf("%s%s", a.P.M("登记账号缺少与登记世代精确匹配的受管身份标记，可能已被替换或篡改：",
						"registered account lacks a managed identity marker matching its recorded generation and may have been replaced or modified: "), rec.User)
					rc = 1
				case registeredHomeMismatch:
					a.warnf("%s%s", a.P.M("登记账号的家目录不是本工具使用的确定路径；自动删除已禁用：",
						"registered account home is not the deterministic path used by this tool; automatic deletion is disabled: "), rec.User)
					rc = 1
				case registeredFirstFieldWitness:
					a.warnf("%s%s", a.P.M(
						"登记账号仍使用 v2.9.3 及更早版本的 GECOS 首字段世代见证；当前精确标记仍可安全撤销，但允许普通用户修改 full-name 的主机可在撤销前丢失该见证。请尽快撤销并按当前版本重新邀请：",
						"registered account still uses the v2.9.3-and-earlier generation witness in the GECOS full-name field. Its currently exact marker remains revocable, but a host that lets regular users change full-name can lose this witness before revoke. Revoke it promptly and issue a new invite with the current version: "), rec.User)
					rc = 1
				}
			}
		}
	}
	// A lifecycle marker is deliberately weaker than identity proof, but it is
	// still the only durable witness for a permanent no-sudo/no-timer account
	// after its registry row is lost. Compare markers only after a complete,
	// successful registry read: an unreadable registry is already a failure and
	// cannot support a meaningful missing-row comparison.
	if a.Registry != nil && registryReadable {
		registered := make(map[string]struct{}, len(registryRecords))
		for _, rec := range registryRecords {
			registered[rec.User] = struct{}{}
		}
		markerAccounts, err := a.listMarkerAccounts()
		if err != nil {
			a.warnf("%s: %v", a.P.M("无法扫描账号生命周期标记", "cannot scan account lifecycle markers"), err)
			rc = 1
		} else {
			for _, name := range markerAccounts {
				if _, ok := registered[name]; ok {
					continue
				}
				a.warnf("%s%s", a.P.M("账号带有本工具的生命周期标记，但登记表中没有对应记录；该标记只能用于发现异常，不能授权自动或批量删除：",
					"account carries this tool's lifecycle marker but has no registry row; the marker is discovery evidence only and cannot authorize automatic or bulk deletion: "), name)
				rc = 1
			}
		}
	}

	// An sshd exception that outlived its account is a standing loosening of the
	// host's policy, and it re-arms the moment the username is reused. Nothing else
	// looks for these, so doctor must.
	if a.SSHD != nil {
		if orphans, err := a.SSHD.Orphans(a.accountIsOursAndLive); err != nil {
			a.warnf("%s: %v", a.P.M("无法扫描孤儿 sshd 例外", "cannot scan for orphaned sshd exceptions"), err)
			rc = 1
		} else if len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿 sshd 例外（账号不存在或身份无法验证）：",
					"orphaned sshd exception (the account is absent or its identity is unverified): "), a.SSHD.FilePath(u))
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
		if orphans, err := a.Sudoers.Orphans(a.accountIsOursAndLive); err != nil {
			a.warnf("%s: %v", a.P.M("无法扫描孤儿 sudo 授权", "cannot scan for orphaned sudo grants"), err)
			rc = 1
		} else if len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿 sudo 授权（账号不存在或身份无法验证，NOPASSWD:ALL 仍在）：",
					"orphaned sudo grant (the account is absent or its identity is unverified; NOPASSWD:ALL is still on disk): "), a.Sudoers.FilePath(u))
			}
			a.warnf("%s", a.P.M("请用 `cleanup-expired --compact` 清理。",
				"remove them with `cleanup-expired --compact`."))
			rc = 1
		}
	}
	// The auto-revoke unit is the third leftover to report. Its account being gone
	// means it fires against a name nothing will recreate — or, after an uninstall,
	// against a binary that no longer exists — so it belongs in the same health list
	// the two grants are in.
	if a.Scheduler != nil {
		if orphans, err := a.Scheduler.Orphans(a.accountNeedsAutoRevoke); err != nil {
			a.warnf("%s: %v", a.P.M("无法扫描孤儿自动删除任务", "cannot scan for orphaned auto-delete tasks"), err)
			rc = 1
		} else if len(orphans) > 0 {
			for _, u := range orphans {
				a.warnf("%s%s", a.P.M("孤儿自动删除任务（账号不存在或身份无法验证）：",
					"orphaned auto-delete task (the account is absent or its identity is unverified): "), u)
			}
			a.warnf("%s", a.P.M("请用 `cleanup-expired --compact` 清理。",
				"remove them with `cleanup-expired --compact`."))
			rc = 1
		}
	}
	// The other direction: prove that every live account marked for auto-revoke has
	// the exact task recorded for its UID and generation. A matching username alone
	// is not health: a stale unit/job can target another account generation, and a
	// modified service body can run something else entirely.
	if a.Scheduler != nil && a.Registry != nil && registryReadable {
		var strandedAuto, strandedQuarantine []string
		for _, r := range registryRecords {
			_, exists, existsErr := a.lookupUser(r.User)
			if existsErr != nil {
				a.warnf("%s %s: %v", a.P.M("无法确认账号状态：", "cannot determine account state:"), r.User, existsErr)
				rc = 1
				continue
			}
			if r.QuarantineUntil != "" && exists {
				deadline, parseErr := time.Parse(time.RFC3339, r.QuarantineUntil)
				if parseErr != nil {
					a.warnf("%s %s: %v", a.P.M("无法验证身份隔离任务：", "cannot verify identity-quarantine task:"), r.User, parseErr)
					rc = 1
					continue
				}
				valid, err := a.Scheduler.ValidQuarantine(r.User, r.UID, r.Generation, r.QuarantineUnit, deadline)
				if err != nil {
					a.warnf("%s %s: %v", a.P.M("无法验证身份隔离任务：", "cannot verify identity-quarantine task:"), r.User, err)
					rc = 1
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
			valid, err := a.Scheduler.ValidSchedule(r.User, r.UID, r.Generation, r.AutoUnit)
			if err != nil {
				a.warnf("%s %s: %v", a.P.M("无法验证自动删除任务：", "cannot verify auto-delete task:"), r.User, err)
				rc = 1
				continue
			}
			if !valid {
				strandedAuto = append(strandedAuto, r.User)
			}
		}
		if len(strandedAuto) > 0 {
			for _, u := range strandedAuto {
				a.warnf("%s%s", a.P.M("账号设置了自动删除但已无可验证的对应任务（任务必须匹配 UID、世代、记录的 unit 和正文；chage 仅提供按天粒度的较晚兜底锁定）：",
					"account set to auto-delete but has no valid task left to do it (the UID, generation, recorded unit, and body must all match; chage only provides a later, day-granularity lockout backstop): "), u)
			}
			a.warnf("%s", a.P.M("到期后请用 `revoke --user <名>` 手动删除。",
				"remove them with `revoke --user <name>` once expired."))
			rc = 1
		}
		if len(strandedQuarantine) > 0 {
			for _, u := range strandedQuarantine {
				a.warnf("%s%s", a.P.M(
					"账号访问已撤销且身份仍在隔离，但已无可验证的后台终删任务（任务必须匹配 UID、世代、隔离截止时间、记录的 unit 和正文）：",
					"account access is revoked and its identity remains quarantined, but no valid background finalizer remains (the UID, generation, quarantine deadline, recorded unit, and body must all match): "), u)
			}
			a.warnf("%s", a.P.M(
				"请运行 `revoke --user <名>`；隔离截止时间已到时会立即续删，尚未到时会确认账号仍保持禁用。",
				"run `revoke --user <name>`; after the quarantine deadline it resumes deletion immediately, and before the deadline it reconfirms that access remains disabled."))
			rc = 1
		}
	}
	return rc
}

// sudo and visudo are mandatory only for --sudo invites. chpasswd is mandatory
// only for password invites. Missing optional-feature helpers do not make the
// base key-only doctor verdict fail.
func doctorDependencyIsFatal(label string) bool {
	return label != "sudo" && label != "visudo" && label != "chpasswd"
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
