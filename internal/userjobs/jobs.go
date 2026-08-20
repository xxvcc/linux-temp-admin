// Package userjobs removes deferred work owned by an account before its UID or
// username can be released. Login expiry and process termination do not cancel a
// personal crontab or at/batch jobs, and shadow-utils userdel does not guarantee
// that cleanup unless an optional distribution hook is configured.
package userjobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/atqueue"
	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

const (
	commandTimeout     = 15 * time.Second
	atInventoryTimeout = 30 * time.Second
	queueOutputLimit   = int64(4 << 20)
	atOwnerProbeLimit  = int64(64 << 10)
	spoolReadBatch     = 256
	procStatusLimit    = int64(64 << 10)
)

var (
	lookPath       = exec.LookPath
	combinedOutput = executil.CombinedOutput
	output         = executil.Output

	cronSpoolDirectories = []string{
		"/var/spool/cron/crontabs", // Debian, Alpine
		"/var/spool/cron",          // Cronie
		"/var/spool/cron/tabs",     // openSUSE
	}
	atSpoolDirectories = []string{
		"/var/spool/cron/atjobs", // Debian
		"/var/spool/at",          // Cronie
		"/var/spool/atjobs",      // other at implementations
	}
)

func commandOptions(maxOutput int64) executil.Options {
	return executil.Options{
		Timeout: commandTimeout, MaxOutput: maxOutput,
		ExtraEnv: []string{"LC_ALL=C", "LANG=C"},
	}
}

var (
	drainSleep          = time.Sleep
	drainProcRoot       = "/proc"
	drainExecutableInfo = processExecutableInfo
)

type executableInfo struct {
	target   string
	mode     os.FileMode
	uid, gid uint32
}

// WaitForDrain leaves the disabled account and UID allocated for longer than one
// cron/at polling cycle. A daemon may already have read a due job before Clear
// removed its spool entry but not forked it yet; callers clear and terminate once
// more after this wait. Tests replace the sleeper, never the production duration.
func WaitForDrain() error {
	toolingPresent := commandAvailable("crontab") || commandAvailable("at") ||
		commandAvailable("atq") || commandAvailable("atrm") || commandAvailable("atd") ||
		commandAvailable("batch") || commandAvailable("cron") || commandAvailable("crond")
	if !toolingPresent {
		daemonPresent, scanErr := cronAtDaemonPresent(drainProcRoot)
		// An unreadable process inventory cannot prove that no daemon has already
		// cached a due job. Waiting is the conservative outcome and costs only the
		// same bounded delay used when a known footprint exists.
		if scanErr == nil && !daemonPresent {
			return nil
		}
	}
	drainSleep(65 * time.Second)
	return nil
}

func cronAtDaemonPresent(procRoot string) (bool, error) {
	proc, err := os.Open(procRoot)
	if err != nil {
		return false, fmt.Errorf("open process inventory: %w", err)
	}
	defer proc.Close()

	for {
		entries, readErr := proc.Readdirnames(spoolReadBatch)
		for _, entry := range entries {
			pid, parseErr := strconv.ParseUint(entry, 10, 31)
			if parseErr != nil || pid == 0 {
				continue
			}
			commPath := filepath.Join(procRoot, entry, "comm")
			nameBody, nameErr := readProcEntry(commPath, 64)
			if nameErr != nil {
				if errors.Is(nameErr, os.ErrNotExist) {
					continue
				}
				return false, fmt.Errorf("read process name %s: %w", commPath, nameErr)
			}
			name := strings.TrimSpace(string(nameBody))
			switch name {
			case "cron", "crond", "atd":
			default:
				continue
			}

			statusPath := filepath.Join(procRoot, entry, "status")
			rootProcess, statusErr := processRunsAsRoot(statusPath)
			if statusErr != nil {
				if errors.Is(statusErr, os.ErrNotExist) {
					continue
				}
				return false, fmt.Errorf("verify process credentials %s: %w", statusPath, statusErr)
			}
			if !rootProcess {
				continue
			}

			executable, executableErr := drainExecutableInfo(procRoot, entry)
			if executableErr != nil {
				if errors.Is(executableErr, os.ErrNotExist) {
					continue
				}
				return false, fmt.Errorf("verify process executable %s: %w", filepath.Join(procRoot, entry, "exe"), executableErr)
			}
			if !trustedDaemonExecutable(name, executable) {
				return false, fmt.Errorf("root-owned %s candidate has untrusted executable %q", name, executable.target)
			}
			return true, nil
		}
		if errors.Is(readErr, io.EOF) {
			return false, nil
		}
		if readErr != nil {
			return false, fmt.Errorf("read process inventory: %w", readErr)
		}
	}
}

func readProcEntry(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(f, maxBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("content exceeds %d-byte limit", maxBytes)
	}
	return body, nil
}

func processRunsAsRoot(statusPath string) (bool, error) {
	body, err := readProcEntry(statusPath, procStatusLimit)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Uid:" {
			continue
		}
		if len(fields) != 5 {
			return false, fmt.Errorf("malformed Uid line")
		}
		hasRoot, hasNonRoot := false, false
		for _, raw := range fields[1:] {
			uid, parseErr := strconv.ParseUint(raw, 10, 32)
			if parseErr != nil {
				return false, fmt.Errorf("malformed Uid value %q", raw)
			}
			if uid == 0 {
				hasRoot = true
			} else {
				hasNonRoot = true
			}
		}
		if hasRoot && hasNonRoot {
			return false, fmt.Errorf("mixed root and non-root process credentials")
		}
		return hasRoot, nil
	}
	return false, fmt.Errorf("status has no Uid line")
}

func processExecutableInfo(procRoot, pid string) (executableInfo, error) {
	exePath := filepath.Join(procRoot, pid, "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		return executableInfo{}, err
	}
	f, err := os.Open(exePath)
	if err != nil {
		return executableInfo{}, err
	}
	fi, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil {
		return executableInfo{}, statErr
	}
	if closeErr != nil {
		return executableInfo{}, closeErr
	}
	stat, ok := fi.Sys().(*unix.Stat_t)
	if !ok {
		return executableInfo{}, fmt.Errorf("executable metadata is unavailable")
	}
	return executableInfo{target: target, mode: fi.Mode(), uid: stat.Uid, gid: stat.Gid}, nil
}

func trustedDaemonExecutable(name string, executable executableInfo) bool {
	if !filepath.IsAbs(executable.target) || !executable.mode.IsRegular() || executable.mode.Perm()&0o111 == 0 ||
		executable.mode.Perm()&0o022 != 0 || executable.uid != 0 || executable.gid != 0 {
		return false
	}
	base := filepath.Base(executable.target)
	if base == name {
		return true
	}
	return base == "busybox" && (name == "cron" || name == "crond")
}

// Clear removes and verifies the absence of a personal crontab and every
// queued at/batch job whose generated owner header carries uid. Callers repeat
// this around process termination so a process racing to enqueue new work does
// not survive the fixed-point check.
func Clear(name string, uid int) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	if !validate.AccountID(uid) {
		return fmt.Errorf("invalid Linux account UID %d", uid)
	}
	kernelUID := uint32(uid) // #nosec G115 -- AccountID proved uid is in 1..MaxUint32-1.
	return errors.Join(clearCrontab(name), clearAtJobs(kernelUID))
}

func clearCrontab(name string) error {
	if _, err := lookPath("crontab"); err == nil {
		// The final inventory is authoritative. crontab -r commonly reports an
		// error when the file was already absent, and a failed response can also
		// follow a removal that did commit.
		_, _ = combinedOutput("crontab", []string{"-u", name, "-r"}, commandOptions(queueOutputLimit))
		absent, err := crontabAbsent(name)
		if err != nil {
			return err
		}
		if !absent {
			return fmt.Errorf("personal crontab for %s still exists after removal", name)
		}
	}
	artifacts, err := namedSpoolArtifacts(cronSpoolDirectories, name)
	if err != nil {
		return fmt.Errorf("inspect cron spool: %w", err)
	}
	if len(artifacts) != 0 {
		return fmt.Errorf("personal crontab artifacts remain for %s: %v", name, artifacts)
	}
	return nil
}

func crontabAbsent(name string) (bool, error) {
	// crontab implementations write their normal "no crontab" diagnostic to
	// stderr. Keep both streams bounded, but retain stderr so absence can be
	// distinguished from an inventory failure.
	out, err := combinedOutput("crontab", []string{"-u", name, "-l"}, commandOptions(queueOutputLimit))
	if err == nil {
		return false, nil
	}
	message := strings.TrimSpace(string(out))
	if message == "no crontab for "+name ||
		message == "crontab: no crontab for "+name ||
		message == "crontab: can't open '"+name+"': No such file or directory" {
		return true, nil
	}
	return false, fmt.Errorf("inventory personal crontab for %s: %w: %s", name, err, message)
}

func clearAtJobs(uid uint32) error {
	hasAt := commandAvailable("at")
	hasAtq := commandAvailable("atq")
	hasAtrm := commandAvailable("atrm")
	hasAtd := commandAvailable("atd")
	hasBatch := commandAvailable("batch")
	if hasAt || hasAtq || hasAtrm || hasAtd || hasBatch {
		if !hasAt || !hasAtq || !hasAtrm {
			return fmt.Errorf("partial at installation cannot safely inventory and remove jobs (at=%t atq=%t atrm=%t atd=%t batch=%t)", hasAt, hasAtq, hasAtrm, hasAtd, hasBatch)
		}
		ctx, cancel := context.WithTimeout(context.Background(), atInventoryTimeout)
		defer cancel()
		jobs, err := inventoryAtJobs(ctx)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			if job.uid != uid {
				continue
			}
			if err := removeAtJob(ctx, job.id, job.uid); err != nil {
				return err
			}
		}
		jobs, err = inventoryAtJobs(ctx)
		if err != nil {
			return fmt.Errorf("verify at jobs after removal: %w", err)
		}
		for _, job := range jobs {
			if job.uid == uid {
				return fmt.Errorf("at job %s for UID %d still exists after removal", job.id, uid)
			}
		}
	}
	artifacts, err := ownedSpoolArtifacts(atSpoolDirectories, uid)
	if err != nil {
		return fmt.Errorf("inspect at spool: %w", err)
	}
	if len(artifacts) != 0 {
		return fmt.Errorf("at job artifacts remain for UID %d: %v", uid, artifacts)
	}
	return nil
}

func commandAvailable(name string) bool {
	_, err := lookPath(name)
	return err == nil
}

type atJob struct {
	id  string
	uid uint32
}

func inventoryAtJobs(ctx context.Context) ([]atJob, error) {
	ids, err := queuedAtJobIDs(ctx)
	if err != nil {
		return nil, err
	}
	jobs := make([]atJob, 0, len(ids))
	for _, id := range ids {
		owner, present, err := readAtJobOwner(ctx, id)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		jobs = append(jobs, atJob{id: id, uid: owner})
	}
	return jobs, nil
}

func queuedAtJobIDs(ctx context.Context) ([]string, error) {
	opts := commandOptions(queueOutputLimit)
	opts.Context = ctx
	out, err := output("atq", nil, opts)
	if err != nil {
		return nil, fmt.Errorf("atq: %w", err)
	}
	return atqueue.ParseInventory(out, int(queueOutputLimit))
}

func removeAtJob(ctx context.Context, id string, expectedUID uint32) error {
	if !atqueue.ValidJobID(id) {
		return fmt.Errorf("invalid at job id %q", id)
	}
	if expectedUID == ^uint32(0) {
		return fmt.Errorf("invalid expected owner for at job %s", id)
	}
	opts := commandOptions(queueOutputLimit)
	opts.Context = ctx
	// Inventory is only a snapshot and at job IDs are eventually reusable. Bind
	// deletion to a fresh owner-header read immediately before atrm. If the old
	// job fired and the ID now names another UID's job, the target job is already
	// gone and the replacement must be left untouched.
	owner, present, err := readAtJobOwner(ctx, id)
	if err != nil {
		return fmt.Errorf("revalidate at job %s before removal: %w", id, err)
	}
	if !present {
		return nil
	}
	if owner != expectedUID {
		return nil
	}
	if out, err := combinedOutput("atrm", []string{id}, opts); err != nil {
		owner, present, inspectErr := readAtJobOwner(ctx, id)
		if inspectErr != nil {
			return errors.Join(
				fmt.Errorf("remove at job %s: %w: %s", id, err, strings.TrimSpace(string(out))),
				fmt.Errorf("recheck at job %s: %w", id, inspectErr),
			)
		}
		if !present {
			return nil
		}
		if owner != expectedUID {
			return nil
		}
		return fmt.Errorf("remove at job %s: %w: %s", id, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// readAtJobOwner reads only the root-controlled prologue emitted by at -c. A
// local user may submit an arbitrarily large command body, but the first atrun
// owner header appears near the start and is all UID-based cleanup needs.
func readAtJobOwner(ctx context.Context, id string) (uint32, bool, error) {
	if !atqueue.ValidJobID(id) {
		return 0, false, fmt.Errorf("invalid at job id %q", id)
	}
	opts := commandOptions(atOwnerProbeLimit)
	opts.Context = ctx
	prefix, err := output("at", []string{"-c", id}, opts)
	if err == nil || errors.Is(err, executil.ErrOutputLimit) {
		owner, ownerErr := atqueue.ParseOwner(prefix, int(atOwnerProbeLimit))
		if ownerErr == nil {
			return owner, true, nil
		}
		if err != nil {
			return 0, false, errors.Join(
				fmt.Errorf("read owner probe for at job %s: %w", id, err),
				fmt.Errorf("parse owner of at job %s: %w", id, ownerErr),
			)
		}
		return 0, false, fmt.Errorf("parse owner of at job %s: %w", id, ownerErr)
	}
	queued, queueErr := atJobQueued(ctx, id)
	if queueErr != nil {
		return 0, false, errors.Join(
			fmt.Errorf("read at job %s: %w", id, err),
			fmt.Errorf("recheck at job %s: %w", id, queueErr),
		)
	}
	if !queued {
		return 0, false, nil
	}
	return 0, false, fmt.Errorf("read at job %s: %w", id, err)
}

func atJobQueued(ctx context.Context, id string) (bool, error) {
	ids, err := queuedAtJobIDs(ctx)
	if err != nil {
		return false, err
	}
	for _, queued := range ids {
		if queued == id {
			return true, nil
		}
	}
	return false, nil
}

func namedSpoolArtifacts(directories []string, name string) ([]string, error) {
	var artifacts []string
	for _, directory := range directories {
		fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", directory, err)
		}
		var st unix.Stat_t
		err = unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		closeErr := unix.Close(fd)
		if err == nil {
			artifacts = append(artifacts, filepath.Join(directory, name))
		} else if !errors.Is(err, unix.ENOENT) {
			inspectErr := fmt.Errorf("inspect %s: %w", filepath.Join(directory, name), err)
			if closeErr != nil {
				return nil, errors.Join(inspectErr, fmt.Errorf("close %s: %w", directory, closeErr))
			}
			return nil, inspectErr
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", directory, closeErr)
		}
	}
	return artifacts, nil
}

func ownedSpoolArtifacts(directories []string, uid uint32) ([]string, error) {
	var artifacts []string
	for _, directory := range directories {
		fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", directory, err)
		}
		dir := os.NewFile(uintptr(fd), directory)
		if dir == nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("adopt directory descriptor for %s", directory)
		}
		count := 0
		for {
			entries, readErr := dir.ReadDir(spoolReadBatch)
			for _, entry := range entries {
				count++
				if count > atqueue.MaxJobs+1 {
					_ = dir.Close()
					return nil, fmt.Errorf("spool %s contains more than %d inspectable entries", directory, atqueue.MaxJobs+1)
				}
				name := entry.Name()
				if name == "" || filepath.Base(name) != name {
					_ = dir.Close()
					return nil, fmt.Errorf("unsafe spool entry name %q in %s", name, directory)
				}
				var st unix.Stat_t
				if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
					continue
				} else if err != nil {
					_ = dir.Close()
					return nil, fmt.Errorf("inspect %s: %w", filepath.Join(directory, name), err)
				}
				if st.Uid == uid {
					artifacts = append(artifacts, filepath.Join(directory, name))
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = dir.Close()
				return nil, fmt.Errorf("read %s: %w", directory, readErr)
			}
			if len(entries) == 0 {
				_ = dir.Close()
				return nil, fmt.Errorf("read %s made no progress", directory)
			}
		}
		if err := dir.Close(); err != nil {
			return nil, fmt.Errorf("close %s: %w", directory, err)
		}
	}
	return artifacts, nil
}
