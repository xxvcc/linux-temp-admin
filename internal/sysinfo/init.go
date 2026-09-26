package sysinfo

import (
	"fmt"
	"os"
	"strings"
)

// SystemdBooted distinguishes evidence of systemd from an installed systemctl.
// An error means the host could not be classified: scheduling must not treat it
// as permission to fall back to another backend.
func SystemdBooted() (bool, error) {
	return systemdBooted("/run/systemd/system", "/proc/1/comm")
}

func systemdBooted(bootMarker, initComm string) (bool, error) {
	if _, err := os.Stat(bootMarker); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("inspect systemd boot marker: %w", err)
	}
	comm, err := os.ReadFile(initComm)
	if err != nil {
		return false, fmt.Errorf("read PID 1 name: %w", err)
	}
	name := strings.TrimSpace(string(comm))
	if name == "" {
		return false, fmt.Errorf("PID 1 name is empty")
	}
	return name == "systemd", nil
}
