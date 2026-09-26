package cli

import (
	"errors"
	"flag"
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"os"
	"sort"
)

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
	a.warnf("%s", a.P.M("此命令不删除用户；账号请用 linux-temp-admin revoke，状态请用 linux-temp-admin status。",
		"This never deletes a user: linux-temp-admin revoke deletes accounts; linux-temp-admin status shows them."))
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
// match exactly. A migrated v2 row with its fixed legacy marker is treated as
// live only when its recorded UID still matches, so cleanup preserves a genuine
// legacy account's grants without letting a nine-field or UID-mismatched row
// transfer name-scoped privilege; destructive paths still refuse that weaker
// identity.
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
	if state == registeredLegacyIdentity {
		return validate.AccountID(rec.UID) && rec.UID == pw.UID, nil
	}
	return state == registeredActive || state == registeredFirstFieldWitness || state == registeredQuarantine, nil
}

// accountNeedsAutoRevoke reports whether a managed auto-revoke task must be
// retained. An absent recovery row needs its retry path for owner-checked mail
// cleanup, and an exactly bound live recovery may safely retry deletion. A live
// UID-only or generation-mismatched recovery is manual-only, so its old unattended
// task is stale and must be swept while the registry witness remains.
//
// A live legacy identity is NOT such a recovery state: classifyRegisteredAccount
// only reaches registeredLegacyIdentity when DeletionStarted is false, so the row
// is a live account with a pending expiry rather than a deletion retry. Its task
// is the mechanism that strips this tool's grants at expiry — an exactly matching
// v2-shaped unit reaches revokeLegacyScheduledAccess, whose first act is to remove
// the sudo grant and sshd exception, and a name-only v1-shaped unit reaches
// stripGrantsAndCheckProtection, which removes the same two before refusing
// deletion. accountIsOursAndLive deliberately preserves that account's grants, so
// this predicate must preserve the task that removes them on the same terms;
// cancelling it while keeping the grant is the one combination that turns a
// time-limited sudo grant into a permanent one.
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
	if state == registeredLegacyIdentity {
		return validate.AccountID(rec.UID) && rec.UID == pw.UID, nil
	}
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
	// A grant this sweep could not enumerate or could not remove must keep its
	// auto-revoke task: cancelling the task is what leaves an orphaned NOPASSWD
	// drop-in with nothing left to remove it.
	grantSweepIncomplete := false
	grantStillPresent := map[string]bool{}
	// For sudoers, disappearance of the file removes the grant. SSH exceptions
	// additionally require a confirmed daemon reload; a failed Remove must keep
	// its retry task even when the drop-in was already unlinked.
	pinIfStillOnDisk := func(user, path string) {
		if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
			grantStillPresent[user] = true
		}
	}
	// Sweep the live grants BEFORE the registry rows: compacting drops the rows
	// that name these accounts, and a grant nobody can name any more is a grant
	// nobody will ever find.
	if a.SSHD != nil {
		orphans, err := a.SSHD.Orphans(a.accountIsOursAndLive)
		if err != nil {
			a.warnf("%v", err)
			rc = 1
			grantSweepIncomplete = true
		}
		for _, u := range orphans {
			if err := a.SSHD.Remove(u); err != nil {
				// Remove's own error states what happened (in the usual case the file
				// was deleted and only the reload was skipped), so use a neutral prefix
				// that does not assert the removal failed.
				a.warnf("%s: %v", a.P.M("清理孤儿 sshd 例外时", "while cleaning up the orphaned sshd exception"), err)
				rc = 1
				grantStillPresent[u] = true
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
			grantSweepIncomplete = true
		}
		for _, u := range orphans {
			// Announce the removal only once it happened: this used to print "removed"
			// whatever the outcome, which is the worst possible lie about a file that
			// hands out passwordless root.
			if err := a.Sudoers.Remove(u); err != nil {
				a.errorf("%s: %v", a.P.M("无法移除孤儿 sudo 授权（该文件仍会在用户名被复用时立即生效，请手动删除）",
					"could not remove an orphaned sudo grant (it re-arms the instant its username is reused; delete it by hand)"), err)
				rc = 1
				pinIfStillOnDisk(u, a.Sudoers.FilePath(u))
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
			if grantSweepIncomplete || grantStillPresent[u] {
				// Keep the task. It is the only remaining mechanism that would strip a
				// grant this run could not confirm gone.
				a.warnf("%s%s", a.P.M(
					"保留自动删除任务，因为本次未能确认该账号的授权已清除：",
					"keeping the auto-delete task because this run could not confirm the account's grants were removed: "), u)
				rc = 1
				continue
			}
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
		// Use the injected snapshot source, like every other identity read in this
		// package. Compact holds the registry lock while this runs, so it must not
		// re-enter Store; these probes only read the account databases.
		_, exists, err := a.lookupUser(rec.User)
		if err != nil || exists {
			return exists, err
		}
		if a.Users == nil {
			return false, fmt.Errorf("verify absent account database for %s: user manager is unavailable", rec.User)
		}
		if err := a.Users.VerifyAccountDatabaseAfterExternalDeletion(rec.User, rec.UID, rec.UID, rec.SequentialID); err != nil {
			return false, fmt.Errorf("verify absent account database for %s: %w", rec.User, err)
		}
		return false, nil
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
