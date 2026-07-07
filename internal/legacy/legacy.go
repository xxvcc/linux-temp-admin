// Package legacy detects artifacts left by the v1 (bash) tool. v2 makes a clean
// break — it does not adopt v1 state — so on a box that ran v1 this reports the
// leftover registry and systemd units (which are distinguishable from v2's) and
// tells the operator how to clean them up. It never modifies them.
package legacy

import (
	"os"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
)

// Detector locates v1 artifacts. Paths are fields for tests.
type Detector struct {
	V1RegistryFile string // v1: /var/lib/linux-temp-admin/users.tsv
	SystemdDir     string // /etc/systemd/system
}

// New returns a Detector for the real system paths.
func New() *Detector {
	return &Detector{
		V1RegistryFile: "/var/lib/linux-temp-admin/users.tsv",
		SystemdDir:     config.SystemdDir,
	}
}

// v1UnitPrefix is what the bash tool named its units; v2 inserts "-v2-".
const v1UnitPrefix = config.ManagedTag + "-revoke-"

// Findings returns human-readable notices about detected v1 artifacts. An empty
// result means none were found. The strings are advisory; nothing is changed.
func (d *Detector) Findings() []string {
	var out []string
	if fi, err := os.Lstat(d.V1RegistryFile); err == nil && fi.Mode().IsRegular() {
		out = append(out, "legacy v1 registry present: "+d.V1RegistryFile+
			" (drain accounts with the v1 tool, then remove it)")
	}
	if units := d.legacyUnits(); len(units) > 0 {
		out = append(out, "legacy v1 systemd auto-revoke units present: "+strings.Join(units, ", ")+
			" (disable/remove them with the v1 tool)")
	}
	return out
}

// legacyUnits lists v1 (not v2) auto-revoke unit files in SystemdDir.
func (d *Detector) legacyUnits() []string {
	entries, err := os.ReadDir(d.SystemdDir)
	if err != nil {
		return nil
	}
	var units []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, v1UnitPrefix) {
			continue
		}
		if strings.HasPrefix(name, config.AutoRevokeUnitPrefix) { // v2 (…-v2-revoke-…)
			continue
		}
		if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".timer") {
			units = append(units, name)
		}
	}
	return units
}
