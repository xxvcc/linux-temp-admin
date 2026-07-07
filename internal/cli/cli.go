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

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/netdetect"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
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

	Users     *user.Manager
	Sudoers   *sudoers.Manager
	Scheduler *schedule.Scheduler
	Registry  *registry.Store
	Detector  *netdetect.Detector

	InstallPath string
	Now         func() time.Time
	RandHex     func(nBytes int) (string, error)
	StdoutIsTTY func() bool
	StdinIsTTY  func() bool
	Geteuid     func() int
}

// NewApp builds an App with real collaborators and the resolved language.
func NewApp(lang i18n.Lang) *App {
	return &App{
		Out:         os.Stdout,
		Err:         os.Stderr,
		In:          os.Stdin,
		P:           i18n.Printer{Lang: lang},
		Users:       user.New(),
		Sudoers:     sudoers.New(),
		Scheduler:   schedule.New(),
		Registry:    registry.Default(),
		Detector:    netdetect.New(),
		InstallPath: config.InstallPath,
		Now:         time.Now,
		RandHex:     randHex,
		StdoutIsTTY: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		StdinIsTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		Geteuid:     os.Geteuid,
	}
}

func randHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Run is the process entry point: it resolves the language, then dispatches.
func Run(args []string) int {
	syscall.Umask(0o077)
	lang, rest, err := extractLang(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resolved := i18n.Resolve(lang, os.Getenv("LINUX_TEMP_ADMIN_LANG"), callerLocale())
	app := NewApp(resolved)
	return app.Dispatch(rest)
}

func callerLocale() string {
	if v := os.Getenv("LC_ALL"); v != "" {
		return v
	}
	return os.Getenv("LANG")
}

// extractLang pulls --lang/--lang=VAL from anywhere in args (an explicit flag
// value), returning the selector and the remaining args.
func extractLang(args []string) (lang string, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--lang":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return "", nil, fmt.Errorf("--lang requires a value: zh or en")
			}
			lang = args[i+1]
			i++
		case strings.HasPrefix(a, "--lang="):
			lang = strings.TrimPrefix(a, "--lang=")
		default:
			rest = append(rest, a)
		}
	}
	if lang != "" {
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

// requireRoot returns false (and reports) if not effectively root.
func (a *App) requireRoot() bool {
	if a.Geteuid() != 0 {
		a.errorf("%s", a.P.M("请使用 root 运行", "please run as root"))
		return false
	}
	return true
}

// prompt reads a single line, printing the message to stderr first.
func (a *App) prompt(msg string) string {
	fmt.Fprint(a.Err, msg)
	sc := bufio.NewScanner(a.In)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}

func (a *App) usage() {
	fmt.Fprintf(a.Out, "%s v%s\n\n%s\n", config.ManagedTag, buildinfo.Version,
		a.P.M("用法： invite | revoke | status | cleanup-expired | doctor | version | help  （--lang zh|en）",
			"Usage: invite | revoke | status | cleanup-expired | doctor | version | help  (--lang zh|en)"))
}
