package cli

import (
	"errors"
	"flag"
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/table"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"strconv"
	"strings"
	"unicode/utf8"
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
			case registeredGIDMismatch:
				identity = "gid-mismatch"
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
func (a *App) usersTable(rows [][]string, numbered bool) *table.Table {
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
	for i, cells := range rows {
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
	case registeredGIDMismatch:
		state = a.P.M("GID 不匹配", "GID mismatch")
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
	// Use one observation per account for this render. A later refresh or a
	// mutating command must obtain its own current account state.
	rows := make([][]string, len(recs))
	for i, rec := range recs {
		rows[i] = a.userCells(rec)
	}
	full := a.usersTable(rows, numbered).String()
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
	for i, cells := range rows {
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
	if maxWidth < 1 {
		maxWidth = 1
	}
	prefixWidth := table.Width(prefix)
	if prefixWidth > maxWidth || (value != "" && prefixWidth == maxWidth) {
		meaningfulPrefix := strings.TrimLeft(prefix, " ")
		wrote := appendWrappedChunks(out, maxWidth, meaningfulPrefix)
		wrote = appendWrappedChunks(out, maxWidth, value) || wrote
		if !wrote {
			out.WriteByte('\n')
		}
		return
	}

	for {
		available := maxWidth - prefixWidth
		part, rest := takeDisplayWidth(value, available)
		out.WriteString(prefix)
		out.WriteString(part)
		out.WriteByte('\n')
		if rest == "" {
			return
		}
		value = rest
		if table.Width("   ") < maxWidth {
			prefix = "   "
		} else {
			prefix = ""
		}
		prefixWidth = table.Width(prefix)
	}
}

func appendWrappedChunks(out *strings.Builder, maxWidth int, value string) bool {
	wrote := false
	for value != "" {
		part, rest := takeDisplayWidth(value, maxWidth)
		out.WriteString(part)
		out.WriteByte('\n')
		value = rest
		wrote = true
	}
	return wrote
}

func takeDisplayWidth(value string, maxWidth int) (string, string) {
	if maxWidth < 1 {
		maxWidth = 1
	}
	width, end := 0, 0
	for end < len(value) {
		r, size := utf8.DecodeRuneInString(value[end:])
		runeWidth := table.Width(string(r))
		if width+runeWidth > maxWidth {
			if end == 0 {
				return "?", value[size:]
			}
			break
		}
		width += runeWidth
		end += size
		if width >= maxWidth {
			break
		}
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
	registeredGIDMismatch
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
	case !rec.IdentityBound && user.IsLegacyManagedEntry(pw):
		return registeredLegacyIdentity
	case !validate.AccountID(rec.UID):
		return registeredIdentityUnverified
	case pw.UID != rec.UID:
		return registeredUIDMismatch
	case rec.SequentialID && pw.GID != rec.UID:
		return registeredGIDMismatch
	case !rec.IdentityBound:
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
	if rec, found, err := a.Registry.Lookup(name); err == nil && found && (rec.Pending || !rec.IdentityBound) {
		// Pending, legacy, and UID-only recovery are still protected by the direct
		// TTY, full-name prompt, identity/Home checks, and manual-invocation gate.
		// Supplying --force here makes the menu's advertised revoke action usable
		// without weakening any of those checks.
		args = append(args, "--force")
	}
	return a.revoke(args)
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
