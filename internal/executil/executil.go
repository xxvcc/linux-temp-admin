// Package executil runs bounded local helper commands. Privileged workflows must
// not let a stuck helper, an inherited pipe held by a descendant, or unbounded
// diagnostic output hold the global lifecycle lock forever.
package executil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	DefaultTimeout   = 30 * time.Second
	DefaultMaxOutput = int64(1 << 20)
	defaultWaitDelay = time.Second
	// HelperWorkingDir is a directory that always exists and that this tool never
	// removes, so nothing a helper persists can depend on the caller's CWD. It is
	// exported so the at-job inventory can tell a job pinned here from one that
	// still carries a pre-upgrade caller CWD.
	HelperWorkingDir = "/"
	// maxErrorDetail bounds how much captured stderr is folded into an error.
	maxErrorDetail = 400
)

// Options controls one helper invocation. Helpers receive a minimal environment
// rather than caller-controlled values preserved by `sudo -E`; ExtraEnv adds
// purpose-specific values such as a stable locale. PATH is the process PATH: the
// production CLI pins it to trusted system directories before any root dispatch.
type Options struct {
	Context   context.Context
	Timeout   time.Duration
	MaxOutput int64
	Stdin     io.Reader
	ExtraEnv  []string
}

var ErrOutputLimit = errors.New("command output limit exceeded")

// CombinedOutput mirrors exec.Cmd.CombinedOutput with bounded resources.
func CombinedOutput(name string, args []string, opts Options) ([]byte, error) {
	return run(name, args, opts, true)
}

// Output mirrors exec.Cmd.Output. Stderr is drained under the same independent
// bound so a noisy failing helper cannot block even though only stdout is returned.
func Output(name string, args []string, opts Options) ([]byte, error) {
	return run(name, args, opts, false)
}

// Run executes a command while still draining and bounding both output streams.
func Run(name string, args []string, opts Options) error {
	_, err := run(name, args, opts, true)
	return err
}

func run(name string, args []string, opts Options, combined bool) ([]byte, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxOutput := opts.MaxOutput
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutput
	}
	parent := opts.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = defaultWaitDelay
	cmd.Stdin = opts.Stdin
	cmd.Env = append(helperEnvironment(), opts.ExtraEnv...)
	// Pin the working directory the same way the environment is pinned. at(1)
	// persists getcwd() into the queued job as a hard `cd <dir> || exit 1`
	// prologue, so an inherited caller CWD that later disappears turns the
	// one-shot auto-revoke into a no-op that never reaches revoke.
	cmd.Dir = HelperWorkingDir

	stdout := &boundedBuffer{max: maxOutput, cancel: cancel}
	stderr := stdout
	if !combined {
		stderr = &boundedBuffer{max: maxOutput, cancel: cancel}
	}
	err := runWithProcessGroup(ctx, cmd, stdout, stderr)
	if stdout.exceededLimit() || stderr.exceededLimit() {
		return stdout.bytes(), fmt.Errorf("%w (%d bytes)", ErrOutputLimit, maxOutput)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return stdout.bytes(), fmt.Errorf("command timed out after %s: %w", timeout, context.DeadlineExceeded)
	}
	if err != nil && !combined {
		if detail := firstLines(stderr.bytes()); detail != "" {
			return stdout.bytes(), fmt.Errorf("%w: %s", err, detail)
		}
	}
	return stdout.bytes(), err
}

// runWithProcessGroup keeps the group leader waitable until output has drained
// or exceptional completion has killed the group. Killing after cmd.Wait is not
// safe: Wait reaps the leader, allowing its numeric PID/PGID to be reused.
func runWithProcessGroup(ctx context.Context, cmd *exec.Cmd, stdout, stderr io.Writer) error {
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer outRead.Close()
	defer outWrite.Close()
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer errRead.Close()
	defer errWrite.Close()
	cmd.Stdout, cmd.Stderr = outWrite, errWrite
	if stdout == stderr {
		// Preserve CombinedOutput's ordering by giving both descriptors the
		// same pipe, rather than racing independent stdout/stderr readers.
		cmd.Stderr = outWrite
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = outWrite.Close()
	_ = errWrite.Close()
	streamErrors := make(chan error, 2)
	var pumps sync.WaitGroup
	pumps.Add(2)
	for _, stream := range []struct {
		dst io.Writer
		src *os.File
	}{{stdout, outRead}, {stderr, errRead}} {
		go func() {
			defer pumps.Done()
			_, err := io.Copy(stream.dst, stream.src)
			streamErrors <- err
		}()
	}
	drained := make(chan struct{})
	go func() { pumps.Wait(); close(drained) }()
	type exitObservation struct {
		success bool
		err     error
	}
	exited := make(chan exitObservation, 1)
	go func() {
		var info unix.Siginfo
		var err error
		for {
			err = unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		// Linux SIGCHLD's union begins at pointer alignment after the three
		// common int32 fields; pid and uid precede si_status. x/sys exposes
		// the union as padding, so read only this ABI-defined status field.
		type childInfo struct {
			header [3]int32
			align  [unsafe.Sizeof(uintptr(0)) - 4]byte
			pid    int32
			uid    uint32
			status int32
		}
		status := (*childInfo)(unsafe.Pointer(&info)).status
		exited <- exitObservation{success: err == nil && info.Code == 1 && status == 0, err: err}
	}()
	killGroup := func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	var cause, killErr error
	groupOwned := true
	select {
	case observed := <-exited:
		if observed.err != nil {
			cause = fmt.Errorf("observe helper exit: %w", observed.err)
			// ECHILD means another reaper already took ownership; never signal
			// a numeric group that can now name a different process.
			groupOwned = !errors.Is(observed.err, unix.ECHILD)
			if groupOwned {
				killErr = killGroup()
			}
		} else if !observed.success {
			killErr = killGroup()
		} else {
			timer := time.NewTimer(defaultWaitDelay)
			select {
			case <-drained:
			case <-ctx.Done():
				cause, killErr = ctx.Err(), killGroup()
			case <-timer.C:
				cause, killErr = exec.ErrWaitDelay, killGroup()
			}
			timer.Stop()
		}
	case <-ctx.Done():
		cause, killErr = ctx.Err(), killGroup()
		observed := <-exited
		if observed.err != nil {
			cause = errors.Join(cause, observed.err)
		}
	}
	// A helper can deliberately leave the group/session. Bound pipe cleanup
	// even then; the security boundary is this command's original process group.
	timer := time.NewTimer(defaultWaitDelay)
	select {
	case <-drained:
	case <-timer.C:
		_ = outRead.Close()
		_ = errRead.Close()
		<-drained
		cause = errors.Join(cause, exec.ErrWaitDelay)
	}
	timer.Stop()
	if copyErr := errors.Join(<-streamErrors, <-streamErrors); copyErr != nil && cause == nil {
		cause = fmt.Errorf("read helper output: %w", copyErr)
		if groupOwned {
			killErr = errors.Join(killErr, killGroup())
		}
	}
	// Drained output and cancellation can become ready together. Selecting the
	// drain does not turn an output-limit/timeout failure into success: finish
	// checking cancellation while the leader still pins this numeric PGID.
	if ctxErr := ctx.Err(); ctxErr != nil {
		cause = errors.Join(cause, ctxErr)
		if groupOwned {
			killErr = errors.Join(killErr, killGroup())
		}
	}
	return errors.Join(cmd.Wait(), cause, killErr)
}

// firstLines condenses captured stderr into a single bounded line suitable for an
// error message. Helpers such as sshd -T name the offending file and line there,
// and dropping it left the operator with nothing but an exit status.
func firstLines(b []byte) string {
	text := strings.TrimSpace(string(b))
	if text == "" {
		return ""
	}
	fields := strings.Fields(strings.ReplaceAll(text, "\n", " "))
	text = strings.Join(fields, " ")
	if len(text) > maxErrorDetail {
		text = strings.TrimSpace(text[:maxErrorDetail]) + "..."
	}
	return text
}

func helperEnvironment() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"SHELL=/bin/sh",
		"TERM=dumb",
	}
}

type boundedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	max      int64
	exceeded bool
	cancel   context.CancelFunc
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	remaining := b.max - int64(b.buf.Len())
	if remaining > 0 {
		keep := int64(len(p))
		if keep > remaining {
			keep = remaining
		}
		_, _ = b.buf.Write(p[:keep])
	}
	if int64(len(p)) > remaining {
		b.exceeded = true
	}
	exceeded := b.exceeded
	b.mu.Unlock()
	if exceeded && b.cancel != nil {
		b.cancel()
	}
	// Report the full write as consumed. Cancellation kills the process group;
	// returning a short write alone can leave a child that ignores SIGPIPE alive.
	return len(p), nil
}

func (b *boundedBuffer) exceededLimit() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

func (b *boundedBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}
