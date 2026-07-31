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
	"sync"
	"syscall"
	"time"
)

const (
	DefaultTimeout   = 30 * time.Second
	DefaultMaxOutput = int64(1 << 20)
	defaultWaitDelay = time.Second
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

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	cmd.WaitDelay = defaultWaitDelay
	cmd.Stdin = opts.Stdin
	cmd.Env = append(helperEnvironment(), opts.ExtraEnv...)

	stdout := &boundedBuffer{max: maxOutput, cancel: cancel}
	stderr := stdout
	if !combined {
		stderr = &boundedBuffer{max: maxOutput, cancel: cancel}
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.exceededLimit() || stderr.exceededLimit() {
		return stdout.bytes(), fmt.Errorf("%w (%d bytes)", ErrOutputLimit, maxOutput)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.bytes(), fmt.Errorf("command timed out after %s: %w", timeout, context.DeadlineExceeded)
	}
	return stdout.bytes(), err
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
