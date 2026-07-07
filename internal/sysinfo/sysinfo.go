// Package sysinfo detects the host's package manager, init system, SSH port, and
// which external tools the tool still depends on. The Go rewrite needs far fewer
// external commands than the bash version (ssh-keygen, curl/wget, date, getent,
// install, flock, pkill are all done natively), leaving only the account tools.
package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// sshdConfigPath is overridable in tests.
var sshdConfigPath = "/etc/ssh/sshd_config"

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

// Dep describes a required external tool (Any means one of Names suffices).
type Dep struct {
	Label   string
	Names   []string
	Present bool
}

// RequiredDeps returns the external account-management tools the tool needs.
// needSudo adds sudo. Everything else the bash version required is now native.
func RequiredDeps(needSudo bool) []Dep {
	deps := []Dep{
		{Label: "useradd/adduser", Names: []string{"useradd", "adduser"}},
		{Label: "usermod", Names: []string{"usermod"}},
		{Label: "chage", Names: []string{"chage"}},
		{Label: "userdel/deluser", Names: []string{"userdel", "deluser"}},
	}
	if needSudo {
		deps = append(deps, Dep{Label: "sudo", Names: []string{"sudo"}})
	}
	for i := range deps {
		for _, n := range deps[i].Names {
			if has(n) {
				deps[i].Present = true
				break
			}
		}
	}
	return deps
}

// MissingDeps returns the labels of required tools that are absent.
func MissingDeps(needSudo bool) []string {
	var missing []string
	for _, d := range RequiredDeps(needSudo) {
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
	case "useradd/adduser", "usermod", "userdel/deluser", "chage":
		switch pm {
		case "apt":
			return "passwd"
		case "dnf", "yum":
			return "shadow-utils"
		case "apk", "pacman":
			return "shadow"
		}
	case "sudo":
		return "sudo"
	}
	return ""
}

// InstallPackages installs pkgs using the given package manager.
func InstallPackages(pm string, pkgs []string) error {
	var cmd *exec.Cmd
	switch pm {
	case "apt":
		_ = exec.Command("apt-get", "update").Run()
		cmd = exec.Command("apt-get", append([]string{"install", "-y"}, pkgs...)...)
	case "dnf":
		cmd = exec.Command("dnf", append([]string{"install", "-y"}, pkgs...)...)
	case "yum":
		cmd = exec.Command("yum", append([]string{"install", "-y"}, pkgs...)...)
	case "apk":
		cmd = exec.Command("apk", append([]string{"add", "--no-cache"}, pkgs...)...)
	case "pacman":
		cmd = exec.Command("pacman", append([]string{"-Syu", "--noconfirm", "--needed"}, pkgs...)...)
	default:
		return fmt.Errorf("unsupported package manager: %q", pm)
	}
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SSHPort returns the configured SSH port, preferring `sshd -T`, then
// sshd_config, defaulting to 22.
func SSHPort() int {
	if p, ok := sshPortFromSshdT(); ok {
		return p
	}
	if p, ok := sshPortFromConfig(sshdConfigPath); ok {
		return p
	}
	return 22
}

func sshPortFromSshdT() (int, bool) {
	if !has("sshd") {
		return 0, false
	}
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.EqualFold(fields[0], "port") {
			if p, err := strconv.Atoi(fields[1]); err == nil && p >= 1 && p <= 65535 {
				return p, true
			}
		}
	}
	return 0, false
}

func sshPortFromConfig(path string) (int, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	port := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "port") {
			if p, err := strconv.Atoi(fields[1]); err == nil && p >= 1 && p <= 65535 {
				port = p // last wins, matching the bash awk
			}
		}
	}
	if port != 0 {
		return port, true
	}
	return 0, false
}
