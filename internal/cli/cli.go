// Package cli wires the internal packages into the command-line program: it
// resolves the UI language, dispatches subcommands, and orchestrates invite and
// revoke. Dependencies (managers, clock, randomness, IO) hang off App so the
// commands are testable.
package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/xxvcc/linux-temp-admin/internal/netdetect"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
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

	// SSHDConfig reads sshd's effective configuration for a user; injectable so a
	// test's verdict comes from a fixture, not from the test host's own sshd.
	SSHDConfig func(user string) (*sysinfo.SSHDConfig, error)

	InstallPath  string
	Now          func() time.Time
	RandHex      func(nBytes int) (string, error)
	RandPassword func(nChars int) (string, error)
	StdoutIsTTY  func() bool
	StdinIsTTY   func() bool
	Geteuid      func() int

	inReader *bufio.Reader // lazily wraps In; reused so buffered stdin isn't lost between prompts
}

// NewApp builds an App with real collaborators and the resolved language.
func NewApp(lang i18n.Lang) *App {
	return &App{
		Out:          os.Stdout,
		Err:          os.Stderr,
		In:           os.Stdin,
		P:            i18n.Printer{Lang: lang},
		Users:        user.New(),
		Sudoers:      sudoers.New(),
		SSHD:         sshdconf.New(),
		Scheduler:    schedule.New(),
		Registry:     registry.Default(),
		Detector:     netdetect.New(),
		Selfmanage:   selfmanage.New(config.InstallPath, config.MaxUpgradeBytes),
		Audit:        audit.Default(),
		SSHDConfig:   sysinfo.SSHDEffective,
		InstallPath:  config.InstallPath,
		Now:          time.Now,
		RandHex:      randHex,
		RandPassword: randPassword,
		StdoutIsTTY:  func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		StdinIsTTY:   func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		Geteuid:      os.Geteuid,
	}
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
	lang, rest, err := extractLang(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	app := NewApp(resolveLang(lang, os.Getenv(EnvLang), rest))
	return app.Dispatch(rest)
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
	for _, v := range []string{flag, env, prefs.Lang()} {
		if l, ok := i18n.Parse(v); ok {
			return l
		}
	}
	if l, ok := askLang(rest); ok {
		return l
	}
	return i18n.ZH
}

// askLang puts the language question to an operator who has never answered it,
// and remembers the answer. It returns ok=false whenever asking would be wrong:
// no terminal to ask at (a script, a cron-fired auto-revoke), or a run that
// explicitly asked not to be prompted. Those get the default, and stay silent.
func askLang(rest []string) (i18n.Lang, bool) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return "", false
	}
	for _, a := range rest {
		if a == "--yes" || a == "-y" { // an unattended run must not be stopped by a question
			return "", false
		}
	}
	fmt.Fprint(os.Stderr, "\nLanguage / 语言:\n  1) 中文 (默认)\n  2) English\n选择 / select [1-2]: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" { // EOF: take the default rather than hang
		return "", false
	}
	lang := i18n.ZH
	if strings.TrimSpace(line) == "2" {
		lang = i18n.EN
	}
	// Remembering is a convenience: if it cannot be saved the run still proceeds in
	// the chosen language, it will just ask again next time.
	if err := prefs.SetLang(string(lang)); err != nil {
		fmt.Fprintf(os.Stderr, "（未能记住语言选择 / could not remember the language choice: %v）\n", err)
	}
	return lang, true
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

// prompt reads a single line, printing the message to stderr first.
// readLine reads one trimmed line. ok is false only at EOF with no data, letting
// callers tell a blank Enter apart from end-of-input.
func (a *App) readLine() (line string, ok bool) {
	if a.inReader == nil {
		a.inReader = bufio.NewReader(a.In)
	}
	s, err := a.inReader.ReadString('\n')
	if err != nil && s == "" {
		return "", false
	}
	return strings.TrimSpace(s), true
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
