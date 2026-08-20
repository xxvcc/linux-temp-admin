// Package sysinfo detects the host's package manager, init system, SSH port, and
// account-management dependencies. It invokes bounded external helpers for
// package installation and effective sshd configuration probes.
package sysinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"golang.org/x/sys/unix"
)

// sshdConfigPath is overridable in tests.
var sshdConfigPath = "/etc/ssh/sshd_config"

const (
	maxSSHDConfigLine  = 1 << 20
	maxSSHDConfigBytes = int64(16 << 20)
)

var packageCommandOptions = executil.Options{
	Timeout:   30 * time.Minute,
	MaxOutput: 8 << 20,
	ExtraEnv: []string{
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C",
		"LANG=C",
	},
}

func has(name string) bool { _, err := exec.LookPath(name); return err == nil }

// PackageManager returns the detected package manager, or "" if none is found.
func PackageManager() string {
	switch {
	case has("apt-get"):
		return "apt"
	case has("dnf"):
		return "dnf"
	case has("yum"):
		return "yum"
	case has("apk"):
		return "apk"
	case has("pacman"):
		return "pacman"
	default:
		return ""
	}
}

// InitSystem returns "systemd", "openrc", "sysvinit", or "unknown".
func InitSystem() string {
	switch {
	case has("systemctl"):
		return "systemd"
	case has("rc-service"):
		return "openrc"
	case has("service"):
		return "sysvinit"
	default:
		return "unknown"
	}
}

// Dep describes a required external capability and its executable alternatives.
type Dep struct {
	Label   string
	Names   []string
	Present bool
}

// RequiredDeps returns the external account-management tools the tool needs.
// needPassword adds chpasswd; needSudo adds both sudo and its mandatory policy
// validator, visudo.
func RequiredDeps(needSudo, needPassword bool) []Dep {
	deps := []Dep{
		{Label: "id", Names: []string{"id"}, Present: has("id")},
		{Label: "useradd", Names: []string{"useradd"}, Present: has("useradd")},
		{Label: "usermod", Names: []string{"usermod"}, Present: has("usermod")},
		{Label: "chage", Names: []string{"chage"}, Present: has("chage")},
		{Label: "userdel", Names: []string{"userdel"}, Present: has("userdel")},
		{Label: "groupdel", Names: []string{"groupdel"}, Present: has("groupdel")},
	}
	if needPassword {
		deps = append(deps, Dep{Label: "chpasswd", Names: []string{"chpasswd"}, Present: has("chpasswd")})
	}
	if needSudo {
		deps = append(deps,
			Dep{Label: "sudo", Names: []string{"sudo"}, Present: has("sudo")},
			Dep{Label: "visudo", Names: []string{"visudo"}, Present: has("visudo")},
		)
	}
	return deps
}

// MissingDeps returns the labels of required tools that are absent.
func MissingDeps(needSudo, needPassword bool) []string {
	var missing []string
	for _, d := range RequiredDeps(needSudo, needPassword) {
		if !d.Present {
			missing = append(missing, d.Label)
		}
	}
	return missing
}

// PackageCandidate maps a tool label to the install package for a package
// manager, or "" if unknown.
func PackageCandidate(label, pm string) string {
	switch label {
	case "useradd", "usermod", "userdel", "groupdel", "chage", "chpasswd":
		switch pm {
		case "apt":
			return "passwd"
		case "dnf", "yum":
			return "shadow-utils"
		case "apk", "pacman":
			return "shadow"
		}
	case "id":
		return "coreutils"
	case "sudo", "visudo":
		return "sudo"
	}
	return ""
}

// InstallPackages installs pkgs using the given package manager. APT refresh
// and installation are both attempted so the operator gets every actionable
// diagnostic, but success requires both phases to succeed: packages may have
// been installed from an old cache even when a non-nil update error is returned.
func InstallPackages(pm string, pkgs []string) error {
	var name string
	var args []string
	var updateErr error
	switch pm {
	case "apt":
		out, err := executil.CombinedOutput("apt-get", []string{"update"}, packageCommandOptions)
		if err != nil {
			updateErr = packageCommandError("apt-get update", out, err)
		}
		name, args = "apt-get", append([]string{"install", "-y"}, pkgs...)
	case "dnf":
		name, args = "dnf", append([]string{"install", "-y"}, pkgs...)
	case "yum":
		name, args = "yum", append([]string{"install", "-y"}, pkgs...)
	case "apk":
		name, args = "apk", append([]string{"add", "--no-cache"}, pkgs...)
	case "pacman":
		// Arch supports only full system upgrades. `pacman -S` can create a partial
		// upgrade when the sync database is newer than installed packages, while
		// `pacman -Syu` would let an account-invite command upgrade the whole host
		// unattended. Neither is an acceptable implicit dependency action.
		return fmt.Errorf("automatic pacman installation is disabled because Arch does not support partial upgrades; run a deliberate full system upgrade and install the required packages first")
	default:
		return fmt.Errorf("unsupported package manager: %q", pm)
	}
	out, installErr := executil.CombinedOutput(name, args, packageCommandOptions)
	if installErr != nil {
		return errors.Join(updateErr, packageCommandError(name+" "+args[0], out, installErr))
	}
	return updateErr
}

func packageCommandError(action string, out []byte, err error) error {
	diagnostic := strings.TrimSpace(string(out))
	if diagnostic == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, diagnostic)
}

// DetectSSHPort returns the configured SSH port, preferring `sshd -T`, then
// sshd_config, and finally 22 when neither source is available. The returned
// port remains a bounded best-effort hint when err is non-nil; callers must
// surface that diagnostic instead of presenting the fallback as authoritative.
func DetectSSHPort() (int, error) {
	var effectiveErr error
	if has(sshdCommand) {
		if p, err := sshPortFromSshdT(); err == nil {
			return p, nil
		} else {
			effectiveErr = err
		}
	}

	p, ok, configErr := sshPortFromConfig(sshdConfigPath)
	if configErr == nil {
		if ok {
			if effectiveErr != nil {
				return p, fmt.Errorf("effective SSH port probe failed; static sshd_config suggests port %d: %w", p, effectiveErr)
			}
			return p, nil
		}
		if effectiveErr != nil {
			return 22, fmt.Errorf("effective SSH port probe failed; defaulting to port 22: %w", effectiveErr)
		}
		return 22, nil
	}

	// An absent config is the documented default case when sshd is not installed.
	// Any other read or parse failure must remain visible to the caller.
	if errors.Is(configErr, os.ErrNotExist) && effectiveErr == nil {
		return 22, nil
	}
	configErr = fmt.Errorf("read SSH port from %s: %w", sshdConfigPath, configErr)
	if effectiveErr != nil {
		return 22, errors.Join(effectiveErr, configErr)
	}
	return 22, configErr
}

func sshPortFromSshdT() (int, error) {
	cfg, err := SSHDEffective("")
	if err != nil {
		return 0, err
	}
	raw := cfg.First("port")
	p, err := strconv.Atoi(raw)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("sshd -T returned invalid port %q", raw)
	}
	return p, nil
}

func sshPortFromConfig(path string) (int, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, false, err
	}
	if !fi.Mode().IsRegular() {
		return 0, false, fmt.Errorf("sshd config %s is not a regular non-symlink file", path)
	}
	if fi.Size() > maxSSHDConfigBytes {
		return 0, false, fmt.Errorf("sshd config %s exceeds %d-byte limit", path, maxSSHDConfigBytes)
	}
	limited := &io.LimitedReader{R: f, N: maxSSHDConfigBytes + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 64<<10), maxSSHDConfigLine)
	var port int
	found, hasInclude := false, false
	for sc.Scan() {
		keyword, args, complete := parseSSHDDirective(sc.Text())
		if !complete {
			return 0, false, fmt.Errorf("sshd config %s contains a directive the static port fallback cannot parse", path)
		}
		if keyword == "" {
			continue
		}
		if strings.EqualFold(keyword, "include") {
			if len(args) == 0 {
				return 0, false, fmt.Errorf("sshd config %s contains Include without a value", path)
			}
			hasInclude = true
			continue
		}
		if !strings.EqualFold(keyword, "port") {
			continue
		}
		if len(args) != 1 {
			return 0, false, fmt.Errorf("sshd config %s contains Port without exactly one value", path)
		}
		p, err := strconv.Atoi(args[0])
		if err != nil || p < 1 || p > 65535 {
			return 0, false, fmt.Errorf("sshd config %s contains invalid Port value %q", path, args[0])
		}
		if !found {
			// First Port wins: sshd listens on every Port directive, and
			// sshPortFromSshdT returns the first, so the config fallback matches it
			// for a consistent hint (rather than the bash awk's last-wins).
			port, found = p, true
		}
	}
	if err := sc.Err(); err != nil {
		return 0, false, fmt.Errorf("scan sshd config %s: %w", path, err)
	}
	if limited.N == 0 {
		return 0, false, fmt.Errorf("sshd config %s exceeds %d-byte limit", path, maxSSHDConfigBytes)
	}
	if !found && hasInclude {
		return 0, false, fmt.Errorf("sshd config %s has active Include directives but no direct Port; static port detection is incomplete", path)
	}
	return port, found, nil
}
