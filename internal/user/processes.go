package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

var (
	procRoot          = "/proc"
	readProcDirectory = os.ReadDir
	pidfdOpen         = unix.PidfdOpen
	pidfdSendSignal   = unix.PidfdSendSignal
	closeFD           = unix.Close
	terminateSleep    = time.Sleep
	processScanSleep  = time.Sleep
)

// terminateSweeps bounds the SIGKILL retry loop. A handful of passes clears any
// realistic fork loop; the bound keeps a process that cannot be killed at all (an
// uninterruptible-sleep task) from spinning here forever while holding up revoke.
const terminateSweeps = 5

const (
	// processScanAttempts bounds retries when a numeric /proc entry disappears
	// between the directory snapshot and its credential read. Such a task may have
	// forked a child that was not present in the old snapshot, so an unstable empty
	// scan cannot prove that a UID is free.
	processScanAttempts = 10

	// A PID can exit, fork a child, and be reused before its status is read. The
	// replacement then makes one old directory snapshot look stable even though the
	// child was not listed in it. A second stable empty scan catches that descendant.
	processEmptyConfirmations = 2
	processScanRetryDelay     = time.Millisecond
)

// CheckPidfd verifies that this kernel and sandbox allow pidfd operations. The
// revoke path relies on pidfds so a PID reused between inspection and signalling
// can never redirect a root-issued signal at an unrelated process.
func CheckPidfd() error {
	fd, err := pidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd is unavailable (Linux 5.3+ and permission from the process sandbox are required): %w", err)
	}
	signalErr := pidfdSendSignal(fd, 0, nil, 0)
	closeErr := closeFD(fd)
	var errs []error
	if signalErr != nil {
		errs = append(errs, fmt.Errorf("pidfd signalling is unavailable (permission from the process sandbox is required): %w", signalErr))
	}
	if closeErr != nil {
		errs = append(errs, fmt.Errorf("close pidfd capability probe: %w", closeErr))
	}
	return errors.Join(errs...)
}

// TerminateProcesses signals SIGTERM then, after a grace period, SIGKILL to every
// process owned by uid. It no-ops for a non-positive uid (never root/all). Done
// natively via /proc (no pkill dependency).
//
// The SIGKILL pass repeats until stable scans find nothing left (or the bound is hit),
// because one snapshot-then-signal pass loses to a process that is actively
// forking: a child created after the scan is never in the list, and would survive
// the revoke as an orphan owned by a uid that is about to be recycled. Re-scanning
// after each kill reaches newly visible descendants; a lineage that keeps escaping
// the bounded sweeps makes revoke fail closed instead of releasing the UID.
func TerminateProcesses(uid int) error {
	if uid < 1 {
		return nil
	}
	if !validate.AccountID(uid) {
		return fmt.Errorf("refusing invalid Linux UID %d", uid)
	}
	var errs []error
	pids, err := signalUID(unix.SIGTERM, uid)
	if err != nil {
		errs = append(errs, fmt.Errorf("signal UID %d processes with SIGTERM: %w", uid, err))
	}
	if len(pids) != 0 {
		terminateSleep(2 * time.Second)
	}
	var survivors []int
	for i := 0; i < terminateSweeps; i++ {
		_, err = signalUID(unix.SIGKILL, uid)
		if err != nil {
			errs = append(errs, fmt.Errorf("signal UID %d processes with SIGKILL: %w", uid, err))
		}
		// signalUID reports only tasks reached from its directory snapshot. A task
		// can fork and exit between that snapshot and pidfdOpen, leaving no signalled
		// PID while its child was never in the snapshot. Only consecutive stable
		// per-thread credential scans can confirm that the UID is now empty.
		survivors, err = processesForUID(uid)
		if err != nil {
			errs = append(errs, fmt.Errorf("scan for UID %d after SIGKILL: %w", uid, err))
		} else if len(survivors) == 0 {
			return errors.Join(errs...)
		}
		if i+1 < terminateSweeps {
			terminateSleep(100 * time.Millisecond)
		}
	}
	if len(survivors) != 0 {
		errs = append(errs, fmt.Errorf("UID %d still has surviving processes %v after SIGKILL", uid, survivors))
	}
	return errors.Join(errs...)
}

// signalUID first filters every live thread by credentials, then opens a pidfd for
// its thread-group leader and rechecks the group before signalling through the
// descriptor. Linux credentials are per-thread, and a leader can be a zombie while
// another thread still runs. The first filter avoids requiring pidfd access to
// every unrelated host process; the second check plus the pidfd prevents PID reuse
// from redirecting a signal at an unrelated process.
func signalUID(sig unix.Signal, uid int) ([]int, error) {
	entries, err := readProcDirectory(procRoot)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", procRoot, err)
	}
	var signalled []int
	var errs []error
	for _, e := range entries {
		tgid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		matched, _, inspectErr := processGroupHasUID(tgid, uid)
		if inspectErr != nil {
			errs = append(errs, fmt.Errorf("read thread credentials for process %d: %w", tgid, inspectErr))
			continue
		}
		if !matched {
			continue
		}
		fd, err := pidfdOpen(tgid, 0)
		if err == unix.ESRCH || err == unix.ENOENT {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("open pidfd for process %d: %w", tgid, err))
			continue
		}
		matched, _, inspectErr = processGroupHasUID(tgid, uid)
		if inspectErr != nil {
			errs = append(errs, fmt.Errorf("recheck thread credentials for process %d: %w", tgid, inspectErr))
			if closeErr := closeFD(fd); closeErr != nil {
				errs = append(errs, fmt.Errorf("close pidfd for process %d: %w", tgid, closeErr))
			}
			continue
		}
		if !matched {
			if closeErr := closeFD(fd); closeErr != nil {
				errs = append(errs, fmt.Errorf("close pidfd for process %d: %w", tgid, closeErr))
			}
			continue
		}
		signalErr := pidfdSendSignal(fd, sig, nil, 0)
		closeErr := closeFD(fd)
		if signalErr == nil {
			signalled = append(signalled, tgid)
		} else if signalErr != unix.ESRCH {
			errs = append(errs, fmt.Errorf("signal process %d: %w", tgid, signalErr))
		}
		if closeErr != nil {
			errs = append(errs, fmt.Errorf("close pidfd for process %d: %w", tgid, closeErr))
		}
	}
	sort.Ints(signalled)
	return signalled, errors.Join(errs...)
}

func processesForUID(uid int) ([]int, error) {
	stableEmpty := 0
	disturbed := 0
	for attempt := 0; attempt < processScanAttempts; attempt++ {
		pids, stable, err := processSnapshotForUID(uid)
		if err != nil {
			return nil, err
		}
		// Finding even one live task is conclusive. Empty results need consecutive
		// stable scans because PID reuse can hide an old snapshotted parent without
		// producing ENOENT while its new child was absent from that old snapshot.
		if len(pids) != 0 {
			return pids, nil
		}
		if !stable {
			stableEmpty = 0
			disturbed++
		} else {
			stableEmpty++
			if stableEmpty == processEmptyConfirmations {
				return nil, nil
			}
		}
		// Give short-lived background activity time to settle without exhausting
		// every retry in one burst. Sustained unclassified churn fails closed.
		if attempt+1 < processScanAttempts {
			processScanSleep(processScanRetryDelay)
		}
	}
	// Name the cause. Every attempt reporting a disturbance means the snapshot kept
	// racing process activity this scan could not rule out, which is host state
	// rather than a fault in the account being revoked. Without this the operator
	// sees only a bare refusal and cannot tell an attributable problem from a busy
	// or deliberately churning host.
	return nil, fmt.Errorf("scan %s: no consecutive stable empty process snapshots after %d attempts (%d disturbed by process activity this scan could not attribute to another account; a busy host, or a local account forking continuously, can cause this)",
		procRoot, processScanAttempts, disturbed)
}

func processSnapshotForUID(uid int) ([]int, bool, error) {
	entries, err := readProcDirectory(procRoot)
	if err != nil {
		return nil, false, fmt.Errorf("scan %s: %w", procRoot, err)
	}
	// /proc directory ownership reflects effective credentials (or root for a
	// non-dumpable process), not every real/effective/saved/filesystem UID of every
	// thread. A foreign-owned group may therefore still carry the target UID. Read
	// credentials directly, without a separate stat pass that both adds a race
	// window and cannot establish that a disappearing group was unrelated.
	var pids []int
	stable := true
	for _, entry := range entries {
		tgid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil {
			continue
		}
		matched, groupStable, err := processGroupHasUID(tgid, uid)
		if err != nil {
			return nil, false, fmt.Errorf("read thread credentials for process %d: %w", tgid, err)
		}
		if !groupStable {
			stable = false
		}
		if matched {
			pids = append(pids, tgid)
		}
	}
	sort.Ints(pids)
	return pids, stable, nil
}

// processGroupHasUID inspects every thread because Linux credentials are
// per-thread and the thread-group leader may already be a zombie while workers
// remain executable. It reports an unstable snapshot when a listed group or task
// disappears before its status can be read; callers may act on a positive match,
// but must never use an unstable negative result as proof that the UID is absent.
func processGroupHasUID(tgid, uid int) (matched, stable bool, err error) {
	taskRoot := filepath.Join(procRoot, strconv.Itoa(tgid), "task")
	entries, err := readProcDirectory(taskRoot)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("scan %s: %w", taskRoot, err)
	}
	stable = true
	numericTasks := 0
	for _, entry := range entries {
		tid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil {
			continue
		}
		numericTasks++
		status, readErr := readProcTaskStatus(tgid, tid)
		if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, unix.ESRCH) {
			stable = false
			continue
		}
		if readErr != nil {
			return false, false, fmt.Errorf("read credentials for task %d/%d: %w", tgid, tid, readErr)
		}
		// Zombie/dead threads cannot execute or fork. A zombie leader does not make
		// the group inactive: another task entry may still describe a live worker.
		if !status.inactive && containsUID(status.uids, uid) {
			return true, stable, nil
		}
	}
	if numericTasks == 0 {
		stable = false
	}
	return false, stable, nil
}

func containsUID(uids [4]int, uid int) bool {
	for _, candidate := range uids {
		if candidate == uid {
			return true
		}
	}
	return false
}

type processStatus struct {
	uids     [4]int
	inactive bool
}

// readProcTaskStatus returns Linux's real, effective, saved-set, and filesystem
// UIDs and whether one task is already a zombie/dead thread awaiting reaping.
func readProcTaskStatus(tgid, tid int) (processStatus, error) {
	// Whole-file read: a scanner that errored before the Uid: line would drop this
	// task from the SIGKILL sweep silently. /proc/<tgid>/task/<tid>/status is tiny.
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(tgid), "task", strconv.Itoa(tid), "status"))
	if err != nil {
		return processStatus{}, err
	}
	var status processStatus
	foundUID := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "State:"):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return processStatus{}, fmt.Errorf("malformed State line")
			}
			status.inactive = fields[1] == "Z" || fields[1] == "X"
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			if len(fields) != 5 {
				return processStatus{}, fmt.Errorf("malformed Uid line")
			}
			for i := range status.uids {
				parsed, err := strconv.Atoi(fields[i+1])
				if err != nil || !validate.KernelID(parsed) {
					return processStatus{}, fmt.Errorf("malformed Uid value %q", fields[i+1])
				}
				status.uids[i] = parsed
			}
			foundUID = true
		}
	}
	if !foundUID {
		return processStatus{}, fmt.Errorf("status has no Uid line")
	}
	return status, nil
}
