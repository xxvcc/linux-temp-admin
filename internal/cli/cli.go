// Package cli wires the internal packages into the command-line program: it
// resolves the UI language, dispatches subcommands, and orchestrates invite and
// revoke. Dependencies (managers, clock, randomness, IO) hang off App so the
// commands are testable.
package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/lifecycle"
	"github.com/xxvcc/linux-temp-admin/internal/netdetect"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/userjobs"
	"golang.org/x/term"
)

// App holds the program's collaborators. Fields are exported/injectable so tests
// can substitute fakes and temp paths.
type App struct {
	Out io.Writer
	Err io.Writer
	In  io.Reader

	P i18n.Printer

	Users      *user.Manager
	Sudoers    *sudoers.Manager
	SSHD       *sshdconf.Manager
	Scheduler  *schedule.Scheduler
	Registry   *registry.Store
	Detector   *netdetect.Detector
	Selfmanage *selfmanage.Manager
	Audit      *audit.Logger
	Lifecycle  *lifecycle.Lock

	// SSHDConfig reads sshd's effective configuration for a user; injectable so a
	// test's verdict comes from a fixture, not from the test host's own sshd.
	SSHDConfig func(user string) (*sysinfo.SSHDConfig, error)
	// SSHDHasUnverifiableMatch covers the part of sshd policy that a user-only
	// effective-config probe cannot evaluate in the current account phase. Keep it
	// beside SSHDConfig so tests can source the complete policy verdict from
	// fixtures instead of the host.
	SSHDHasUnverifiableMatch func(accountExists bool) bool

	InstallPath string
	// StateDir and AuditLogDir are the paths an uninstall removes RECURSIVELY, so
	// they are fields for the same reason InstallPath is: a test that ran the
	// teardown against the constants would delete the real ones. CI runs the
	// integration suite as root, so that is not a hypothetical — it would happen on
	// every push, to the runner and to whatever box a developer ran it on.
	StateDir      string
	AuditLogDir   string
	Now           func() time.Time
	RandHex       func(nBytes int) (string, error)
	RandPassword  func(nChars int) (string, error)
	StdoutIsTTY   func() bool
	StdinIsTTY    func() bool
	TerminalWidth func() int
	Geteuid       func() int
	// Executable is a test hook. Production leaves it nil and reads /proc/self/exe,
	// which remains bound to the running inode if its original pathname is replaced.
	Executable func() (string, error)
	// RemoveAll is a test hook for recursive teardown. Production uses
	// os.RemoveAll; nil also falls back to os.RemoveAll for direct test Apps.
	RemoveAll func(string) error
	// TerminateProcesses is injectable so revoke's fail-closed handling can be
	// exercised without signalling real processes in tests.
	TerminateProcesses func(int) error
	// ClearScheduledJobs removes personal cron and at/batch work before an account
	// identity can be released. DrainScheduledJobs waits out a daemon that may have
	// read a due job before its spool entry disappeared. Both are injected together
	// in tests so no host queue is inspected or delayed accidentally.
	ClearScheduledJobs func(string, int) error
	DrainScheduledJobs func() error
	// LookupUser is the single passwd snapshot source for identity-sensitive CLI
	// operations. Production uses user.Lookup; tests inject account replacement
	// sequences without modifying the host account database.
	LookupUser func(string) (user.Passwd, bool, error)
	// ListMarkerAccounts discovers exact pending/legacy/generation passwd markers
	// for uninstall's fail-closed inventory. Marker presence is only a blocker and
	// must never be used as identity proof for automatic deletion.
	ListMarkerAccounts func() ([]string, error)
	// RunningLegacyRevoke detects an already-started name-only revoke command from
	// an older release before invite reuses the username. Production scans /proc;
	// tests inject the process inventory they intend to exercise.
	RunningLegacyRevoke func(installPath, username string) (bool, error)
	// IdentityAllocationRange is the local UID/GID allocation policy probe.
	// Production scans passwd, group, and login.defs; tests inject a deterministic
	// range so their account helper and registry sequence agree.
	IdentityAllocationRange func() (minimum, maximum int, err error)
	// EnsureScheduledCommand is a test hook for the stable-command preflight used
	// before a revoke hands final deletion to systemd. Production leaves it nil and
	// installs or verifies the running binary through ensureStableInstalled.
	EnsureScheduledCommand func() error

	inReader *bufio.Reader // lazily wraps In; reused so buffered stdin isn't lost between prompts
}

// NewApp builds an App with real collaborators and the resolved language.
func NewApp(lang i18n.Lang) *App {
	return &App{
		Out:                      os.Stdout,
		Err:                      os.Stderr,
		In:                       os.Stdin,
		P:                        i18n.Printer{Lang: lang},
		Users:                    user.New(),
		Sudoers:                  sudoers.New(),
		SSHD:                     sshdconf.New(),
		Scheduler:                schedule.New(),
		Registry:                 registry.Default(),
		Detector:                 netdetect.New(),
		Selfmanage:               selfmanage.New(config.InstallPath, config.MaxUpgradeBytes),
		Audit:                    audit.Default(),
		Lifecycle:                lifecycle.New(config.LifecycleLockFile),
		SSHDConfig:               sysinfo.SSHDEffective,
		SSHDHasUnverifiableMatch: sysinfo.HasUnverifiableMatch,
		InstallPath:              config.InstallPath,
		StateDir:                 config.StateDir,
		AuditLogDir:              config.AuditLogDir,
		Now:                      time.Now,
		RandHex:                  randHex,
		RandPassword:             randPassword,
		StdoutIsTTY:              func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		StdinIsTTY:               func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		TerminalWidth: func() int {
			width, _, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil {
				return 0
			}
			return width
		},
		Geteuid:            os.Geteuid,
		RemoveAll:          os.RemoveAll,
		TerminateProcesses: user.TerminateProcesses,
		ClearScheduledJobs: userjobs.Clear,
		DrainScheduledJobs: userjobs.WaitForDrain,
		LookupUser:         user.Lookup,
		ListMarkerAccounts: user.LifecycleMarkerAccounts,
		RunningLegacyRevoke: func(installPath, username string) (bool, error) {
			return runningLegacyRevokeProcess("/proc", installPath, username)
		},
		IdentityAllocationRange: user.IdentityAllocationRange,
	}
}

func (a *App) lookupUser(name string) (user.Passwd, bool, error) {
	if a.LookupUser != nil {
		return a.LookupUser(name)
	}
	return user.Lookup(name)
}

func (a *App) listMarkerAccounts() ([]string, error) {
	if a.ListMarkerAccounts != nil {
		return a.ListMarkerAccounts()
	}
	return user.LifecycleMarkerAccounts()
}

func (a *App) runningLegacyRevoke(username string) (bool, error) {
	if a.RunningLegacyRevoke != nil {
		return a.RunningLegacyRevoke(a.InstallPath, username)
	}
	return runningLegacyRevokeProcess("/proc", a.InstallPath, username)
}

func (a *App) identityAllocationRange() (int, int, error) {
	if a.IdentityAllocationRange != nil {
		return a.IdentityAllocationRange()
	}
	return user.IdentityAllocationRange()
}

func (a *App) terminateProcesses(uid int) error {
	if a.TerminateProcesses != nil {
		return a.TerminateProcesses(uid)
	}
	return user.TerminateProcesses(uid)
}

func (a *App) clearScheduledJobs(name string, uid int) error {
	if a.ClearScheduledJobs == nil {
		return fmt.Errorf("scheduled-job cleanup is not configured")
	}
	return a.ClearScheduledJobs(name, uid)
}

func (a *App) drainScheduledJobs() error {
	if a.DrainScheduledJobs == nil {
		return fmt.Errorf("scheduled-job drain is not configured")
	}
	return a.DrainScheduledJobs()
}

func randHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// passwordAlphabet is deliberately alphanumeric: the password travels through a
// chpasswd line, an SSH prompt, and a chat message, and a character that any one
// of those three would mangle costs far more than the ~6 bits of entropy it adds.
// At 24 characters this is ~142 bits, which no online guessing attack reaches.
const passwordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// passwordLen is the length of a --password-login password.
const passwordLen = 24

// randPassword returns a uniformly random password. Rejection sampling keeps the
// distribution flat: taking a raw byte modulo 62 would quietly favour the first
// few letters of the alphabet.
func randPassword(nChars int) (string, error) {
	out := make([]byte, 0, nChars)
	buf := make([]byte, 1)
	const limit = 256 - (256 % len(passwordAlphabet)) // 248: the unbiased range
	for len(out) < nChars {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= limit {
			continue
		}
		out = append(out, passwordAlphabet[int(buf[0])%len(passwordAlphabet)])
	}
	return string(out), nil
}

// EnvLang overrides the language for one run without changing what is
// remembered. sudo scrubs the environment by default, so it needs `sudo -E`.
const EnvLang = "LINUX_TEMP_ADMIN_LANG"

// Run is the process entry point: it resolves the language, then dispatches.
func Run(args []string) int {
	syscall.Umask(0o077)
	if err := setTrustedRootPath(os.Geteuid, os.Setenv); err != nil {
		fmt.Fprintf(os.Stderr, "cannot set trusted PATH: %v\n", err)
		return 1
	}
	lang, rest, err := extractLang(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resolved, remember, proceed := resolveLangChoice(lang, os.Getenv(EnvLang), rest)
	if !proceed {
		return 0
	}
	app := NewApp(resolved)
	if remember {
		app.rememberLangChoice(resolved)
	}
	return app.Dispatch(rest)
}

const trustedRootPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// setTrustedRootPath prevents a root invocation from resolving privileged
// helper commands through a caller-controlled directory. Non-root invocations
// keep their environment unchanged; their mutating commands are rejected by
// requireRoot before any helper is run.
func setTrustedRootPath(geteuid func() int, setenv func(string, string) error) error {
	if geteuid() != 0 {
		return nil
	}
	return setenv("PATH", trustedRootPath)
}

// resolveLang picks the UI language: an explicit --lang, then the env override,
// then what the operator chose last time, then — on a terminal that has never
// been asked — the question itself, and finally Chinese.
//
// The host's locale is deliberately NOT consulted. It used to be, which meant a
// server with LANG=en_US.UTF-8 silently overrode the project's own default and
// the operator had to discover --lang to get Chinese back. The language of the
// box says little about the language of the person holding the invite, so the
// tool asks that person once and remembers the answer instead of guessing from
// the environment.
func resolveLang(flag, env string, rest []string) i18n.Lang {
	lang, _, _ := resolveLangChoice(flag, env, rest)
	return lang
}

func resolveLangChoice(flag, env string, rest []string) (i18n.Lang, bool, bool) {
	return resolveLangChoiceWith(flag, env, rest, askLang)
}

func resolveLangChoiceWith(flag, env string, rest []string, ask func([]string) (i18n.Lang, bool, bool)) (i18n.Lang, bool, bool) {
	for _, v := range []string{flag, env, prefs.Lang()} {
		if l, ok := i18n.Parse(v); ok {
			return l, false, true
		}
	}
	if l, ok, prompted := ask(rest); prompted {
		if !ok {
			return i18n.ZH, false, false
		}
		return l, true, true
	}
	return i18n.ZH, false, true
}

// askLang puts the language question to an operator who has never answered it.
// Persistence happens later, under the lifecycle lock and uninstall marker gate.
// prompted is false whenever asking would be wrong:
// no terminal to ask at (a script, a cron-fired auto-revoke), or a run that
// explicitly asked not to be prompted. Those get the default and stay silent.
// When prompted is true but ok is false, the operator ended the prompt with EOF
// and the whole interactive run should be cancelled.
func askLang(rest []string) (lang i18n.Lang, ok, prompted bool) {
	if !shouldAskLang(rest,
		term.IsTerminal(int(os.Stdin.Fd())),
		term.IsTerminal(int(os.Stderr.Fd())),
		term.IsTerminal(int(os.Stdout.Fd()))) {
		return "", false, false
	}
	lang, ok = askLangInput(os.Stdin, os.Stderr)
	return lang, ok, true
}

func shouldAskLang(rest []string, stdinTTY, stderrTTY, stdoutTTY bool) bool {
	if !stdinTTY || !stderrTTY {
		return false
	}
	for _, arg := range rest {
		if arg == "--yes" || arg == "-y" { // an unattended run must not be stopped by a question
			return false
		}
	}
	if len(rest) == 0 || (rest[0] != "invite" && rest[0] != "create") || stdoutTTY {
		return true
	}
	for _, arg := range rest[1:] {
		if arg == "--allow-non-tty-private-key-output" {
			return true
		}
	}
	// invite will refuse this run before any of its own prompts. Do not make a
	// first-run language question the side effect that happens before that refusal.
	return false
}

// askLangInput contains the line-oriented part of the first-run language
// prompt. Keep one buffered reader for the whole exchange: constructing a new
// reader after invalid input could discard later lines it had already buffered.
func askLangInput(in io.Reader, out io.Writer) (i18n.Lang, bool) {
	reader := bufio.NewReader(in)
	for {
		fmt.Fprint(out, "\nLanguage / 语言:\n  1) 中文 (默认)\n  2) English\n选择 / select [1-2]: ")
		line, ok, err := readInteractiveLine(reader)
		if errors.Is(err, errInteractiveLineTooLong) {
			fmt.Fprintln(out, "输入过长，请重新输入 / input is too long; try again")
			continue
		}
		if err != nil || !ok { // EOF cancels the interactive run.
			return "", false
		}
		switch strings.TrimSpace(line) {
		case "", "1":
			return i18n.ZH, true
		case "2":
			return i18n.EN, true
		default:
			fmt.Fprintln(out, "无效选择，请输入 1 或 2 / invalid choice; enter 1 or 2")
		}
	}
}

// rememberLangChoice writes a convenience preference only while holding the
// same lifecycle lock as every privileged mutation. A completed uninstall owns
// the state namespace; in that state a language prompt must not recreate it.
func (a *App) rememberLangChoice(lang i18n.Lang) {
	if a.Lifecycle == nil {
		if err := prefs.SetLang(string(lang)); err != nil {
			a.warnf("%s: %v", a.P.M("未能记住语言选择", "could not remember the language choice"), err)
		}
		return
	}
	release, err := a.Lifecycle.Acquire()
	if err != nil {
		a.warnf("%s: %v", a.P.M("未能锁定语言偏好", "could not lock the language preference"), err)
		return
	}
	defer func() {
		if err := release(); err != nil {
			a.warnf("%s: %v", a.P.M("无法释放生命周期锁", "cannot release the lifecycle lock"), err)
		}
	}()
	uninstalled, err := a.Lifecycle.IsUninstalled()
	if err != nil {
		a.warnf("%s: %v", a.P.M("无法验证卸载状态，未保存语言选择", "could not verify uninstall state; the language choice was not saved"), err)
		return
	}
	if uninstalled {
		return
	}
	if err := prefs.SetLang(string(lang)); err != nil {
		a.warnf("%s: %v", a.P.M("未能记住语言选择", "could not remember the language choice"), err)
	}
}

// extractLang pulls --lang/--lang=VAL from anywhere in args (an explicit flag
// value), returning the selector and the remaining args.
func extractLang(args []string) (lang string, rest []string, err error) {
	sawLang := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--lang":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return "", nil, fmt.Errorf("--lang requires a value: zh or en")
			}
			sawLang = true
			lang = args[i+1]
			i++
		case strings.HasPrefix(a, "--lang="):
			sawLang = true
			lang = strings.TrimPrefix(a, "--lang=")
		default:
			rest = append(rest, a)
		}
	}
	if sawLang { // validate even for an empty --lang= value
		if _, ok := i18n.Parse(lang); !ok {
			return "", nil, fmt.Errorf("--lang only supports zh or en: %s", lang)
		}
	}
	return lang, rest, nil
}

// Dispatch routes a command (language already stripped).
func (a *App) Dispatch(args []string) int {
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(a.Out, buildinfo.Version)
		return 0
	case "help", "-h", "--help":
		a.usage()
		return 0
	case "invite", "create":
		return a.invite(args)
	case "revoke", "delete-user", "remove":
		return a.revoke(args)
	case "status":
		return a.status(args)
	case "cleanup-expired", "expiry-status":
		return a.cleanupExpired(args)
	case "doctor", "check":
		return a.doctor(args)
	case "install":
		return a.install(args)
	case "upgrade", "update":
		return a.upgrade(args)
	case "uninstall":
		return a.uninstall(args)
	case "":
		return a.menu()
	default:
		a.errorf("%s", a.P.M("未知命令："+cmd, "unknown command: "+cmd))
		a.usage()
		return 1
	}
}

// --- small output/prompt/permission helpers ---

func (a *App) printf(format string, args ...any) { fmt.Fprintf(a.Out, format+"\n", args...) }
func (a *App) errorf(format string, args ...any) {
	fmt.Fprintf(a.Err, a.P.M("[错误] ", "[ERROR] ")+format+"\n", args...)
}
func (a *App) warnf(format string, args ...any) {
	fmt.Fprintf(a.Err, a.P.M("[警告] ", "[WARN] ")+format+"\n", args...)
}
func (a *App) info(s string)    { fmt.Fprintln(a.Out, a.P.M("[信息] ", "[INFO] ")+s) }
func (a *App) success(s string) { fmt.Fprintln(a.Out, a.P.M("[完成] ", "[OK] ")+s) }

// audit records a privileged operation to the audit log. Best-effort: a write
// failure is reported but never blocks or fails the operation itself.
func (a *App) audit(action, target, result, detail string, fields map[string]string) {
	if a.Audit == nil {
		return
	}
	if err := a.Audit.Log(audit.Event{Action: action, Target: target, Result: result, Detail: detail, Fields: fields}); err != nil {
		a.warnf("%s: %v", a.P.M("写入审计日志失败", "audit log write failed"), err)
	}
}

// requireRoot returns false (and reports) if not effectively root.
func (a *App) requireRoot() bool {
	if a.Geteuid() != 0 {
		a.errorf("%s", a.P.M("请使用 root 运行", "please run as root"))
		return false
	}
	return true
}

// withLifecycleLock serializes complete privileged state transitions. Tests that
// construct App directly may leave Lifecycle nil; production NewApp never does.
func (a *App) withLifecycleLock(fn func() int) int {
	return a.withLifecycleLockMode(false, fn)
}

// withLifecycleLockAllowUninstalled is reserved for explicit install and
// uninstall retry. Every other mutation must stop at a completed uninstall.
func (a *App) withLifecycleLockAllowUninstalled(fn func() int) int {
	return a.withLifecycleLockMode(true, fn)
}

func (a *App) withLifecycleLockMode(allowUninstalled bool, fn func() int) int {
	if a.Lifecycle == nil {
		return fn()
	}
	release, err := a.Lifecycle.Acquire()
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法获取生命周期锁", "cannot acquire the lifecycle lock"), err)
		return 1
	}
	return a.withAcquiredLifecycleLock(allowUninstalled, release, fn)
}

func (a *App) withAcquiredLifecycleLock(allowUninstalled bool, release func() error, fn func() int) int {
	if !allowUninstalled {
		uninstalled, markerErr := a.Lifecycle.IsUninstalled()
		if markerErr != nil {
			_ = release()
			a.errorf("%s: %v", a.P.M("无法验证卸载状态，拒绝修改主机", "cannot verify uninstall state; refusing to mutate the host"), markerErr)
			return 1
		}
		if uninstalled {
			_ = release()
			a.errorf("%s", a.P.M("本工具已卸载；如需重新启用，请先显式运行 install",
				"this tool is uninstalled; run install explicitly before re-enabling mutations"))
			return 1
		}
	}
	rc := fn()
	if err := release(); err != nil {
		a.errorf("%s: %v", a.P.M("无法释放生命周期锁", "cannot release the lifecycle lock"), err)
		return 1
	}
	return rc
}

// accountLifecycleLock is a per-username reader/writer barrier adjacent to the
// global lifecycle lock. Account locks are always acquired before the global
// lock: invite is the exclusive writer, while revoke is a shared reader whose
// actual mutation remains serialized by the global lock.
func (a *App) accountLifecycleLock(username string) *lifecycle.Lock {
	if a.Lifecycle == nil || a.Lifecycle.Path == "" {
		return nil
	}
	return lifecycle.New(a.Lifecycle.Path + ".account-" + username)
}

func (a *App) withAccountExclusiveLock(username string, fn func() int) int {
	lock := a.accountLifecycleLock(username)
	if lock == nil {
		return fn()
	}
	release, err := lock.Acquire()
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法获取账号生命周期锁", "cannot acquire the account lifecycle lock"), err)
		return 1
	}
	return a.withAcquiredAccountLock(release, fn)
}

func (a *App) withAccountSharedLock(username string, fn func() int) int {
	lock := a.accountLifecycleLock(username)
	if lock == nil {
		return fn()
	}
	release, err := lock.AcquireShared()
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法获取账号生命周期锁", "cannot acquire the account lifecycle lock"), err)
		return 1
	}
	return a.withAcquiredAccountLock(release, fn)
}

// withAccountTrySharedLock distinguishes contention from an acquisition error.
// A legacy name-only revoke may be abandoned only when an invite already owns
// the exclusive barrier for that same username; unrelated lifecycle work still
// queues normally under the global lock.
func (a *App) withAccountTrySharedLock(username string, fn func() int) (rc int, busy bool) {
	lock := a.accountLifecycleLock(username)
	if lock == nil {
		return fn(), false
	}
	release, err := lock.TryAcquireShared()
	if errors.Is(err, lifecycle.ErrBusy) {
		return 0, true
	}
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法获取账号生命周期锁", "cannot acquire the account lifecycle lock"), err)
		return 1, false
	}
	return a.withAcquiredAccountLock(release, fn), false
}

func (a *App) withAcquiredAccountLock(release func() error, fn func() int) int {
	rc := fn()
	if err := release(); err != nil {
		a.errorf("%s: %v", a.P.M("无法释放账号生命周期锁", "cannot release the account lifecycle lock"), err)
		return 1
	}
	return rc
}

const (
	maxInteractiveLineBytes = 64 << 10
	rejectedInteractiveLine = "\x00"
)

var errInteractiveLineTooLong = errors.New("interactive input line is too long")

// prompt reads a single line, printing the message to stderr first.
// readLine reads one trimmed line. ok is false only at EOF with no data, letting
// callers tell a blank Enter apart from end-of-input.
func (a *App) readLine() (line string, ok bool) {
	if a.inReader == nil {
		a.inReader = bufio.NewReader(a.In)
	}
	s, ok, err := readInteractiveLine(a.inReader)
	if err != nil {
		if errors.Is(err, errInteractiveLineTooLong) {
			a.warnf("%s", a.P.M("输入行过长，已拒绝", "input line is too long and was rejected"))
		} else {
			a.warnf("%s: %v", a.P.M("读取输入失败", "reading input failed"), err)
		}
		return rejectedInteractiveLine, ok
	}
	return strings.TrimSpace(s), ok
}

// readInteractiveLine consumes exactly one line while retaining at most a fixed
// amount of it. Once the limit is crossed it drains the rest of that same line,
// so a following answer remains aligned with its next prompt.
func readInteractiveLine(reader *bufio.Reader) (string, bool, error) {
	var line strings.Builder
	gotInput := false
	tooLong := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			gotInput = true
			if fragment[len(fragment)-1] == '\n' {
				fragment = fragment[:len(fragment)-1]
			}
			if !tooLong {
				remaining := maxInteractiveLineBytes - line.Len()
				if len(fragment) > remaining {
					tooLong = true
				} else {
					line.Write(fragment)
				}
			}
		}
		switch {
		case err == nil:
			if tooLong {
				return "", true, errInteractiveLineTooLong
			}
			return line.String(), true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if !gotInput {
				return "", false, nil
			}
			if tooLong {
				return "", true, errInteractiveLineTooLong
			}
			return line.String(), true, nil
		default:
			return "", gotInput, err
		}
	}
}

func (a *App) prompt(msg string) string {
	fmt.Fprint(a.Err, msg)
	s, _ := a.readLine()
	return s
}

func (a *App) usage() {
	fmt.Fprintf(a.Out, "%s v%s\n\n%s\n", config.ManagedTag, buildinfo.Version,
		a.P.M("用法： invite | revoke | status | cleanup-expired | doctor | install | upgrade | uninstall | version | help  （无参数进入菜单；--lang zh|en）",
			"Usage: invite | revoke | status | cleanup-expired | doctor | install | upgrade | uninstall | version | help  (no args = menu; --lang zh|en)"))
}
