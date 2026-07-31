// Package sysinfo detects the host's package manager, init system, SSH port, and
// account-management dependencies. It invokes bounded external helpers for
// package installation and effective sshd configuration probes.
package sysinfo

import (
	"bufio"
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
	case "useradd", "usermod", "userdel", "chage", "chpasswd":
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

// InstallPackages installs pkgs using the given package manager.
func InstallPackages(pm string, pkgs []string) error {
	var name string
	var args []string
	switch pm {
	case "apt":
		_ = executil.Run("apt-get", []string{"update"}, packageCommandOptions)
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
	if out, err := executil.CombinedOutput(name, args, packageCommandOptions); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SSHPort returns the configured SSH port, preferring `sshd -T`, then
// sshd_config, defaulting to 22.
func SSHPort() int {
	if p, ok := sshPortFromSshdT(); ok {
		return p
	}
	if p, ok, _ := sshPortFromConfig(sshdConfigPath); ok {
		return p
	}
	return 22
}

func sshPortFromSshdT() (int, bool) {
	cfg, err := SSHDEffective("")
	if err != nil {
		return 0, false
	}
	if p, err := strconv.Atoi(cfg.First("port")); err == nil && p >= 1 && p <= 65535 {
		return p, true
	}
	return 0, false
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
	found := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if !found && len(fields) >= 2 && strings.EqualFold(fields[0], "port") {
			if p, err := strconv.Atoi(fields[1]); err == nil && p >= 1 && p <= 65535 {
				// First Port wins: sshd listens on every Port directive, and
				// sshPortFromSshdT returns the first, so the config fallback matches it
				// for a consistent hint (rather than the bash awk's last-wins).
				port, found = p, true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, false, fmt.Errorf("scan sshd config %s: %w", path, err)
	}
	if limited.N == 0 {
		return 0, false, fmt.Errorf("sshd config %s exceeds %d-byte limit", path, maxSSHDConfigBytes)
	}
	return port, found, nil
}
