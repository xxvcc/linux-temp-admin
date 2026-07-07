// Package config holds the shared constants ported from the bash tool's header.
// v2 makes a clean break from v1 state: distinct registry directory and systemd
// unit namespace so a v2 binary never touches v1 (bash-era) artifacts.
package config

const (
	// DefaultPrefix is the default temporary-username prefix.
	DefaultPrefix = "xxvcc"
	// DefaultExpireHours is the default account lifetime.
	DefaultExpireHours = 24
	// MaxExpireHours caps --hours (one year).
	MaxExpireHours = 8760
	// MaxUpgradeBytes caps a downloaded upgrade payload (1 MiB).
	MaxUpgradeBytes = 1 << 20
	// DefaultShell is the preferred login shell for created accounts.
	DefaultShell = "/bin/bash"

	// ManagedTag marks tool-managed accounts.
	ManagedTag = "linux-temp-admin"
	// ManagedGECOS is the exact GECOS an invite sets; account_is_managed
	// requires this full string, not a bare ManagedTag substring.
	ManagedGECOS = ManagedTag + " temporary admin"

	// --- v2 clean-break paths / namespaces (distinct from v1) ---

	// RegistryDir is the v2 registry directory (v1 used /var/lib/linux-temp-admin).
	RegistryDir = "/var/lib/linux-temp-admin/v2"
	// RegistryFile is the v2 registry file.
	RegistryFile = RegistryDir + "/registry.tsv"
	// RegistryLockFile is the flock file for registry mutations.
	RegistryLockFile = RegistryDir + "/registry.lock"
	// RegistrySchema is written as the registry header's version marker.
	RegistrySchema = 2

	// InstallPath is where the stable command is installed.
	InstallPath = "/usr/local/sbin/linux-temp-admin"
	// SystemdDir holds generated auto-revoke units.
	SystemdDir = "/etc/systemd/system"
	// AutoRevokeUnitPrefix namespaces v2 systemd units (v1 used
	// "linux-temp-admin-revoke-"), so v2 and v1 units never collide.
	AutoRevokeUnitPrefix = ManagedTag + "-v2-revoke-"

	// ReleaseBaseURL is where signed release binaries are published; the upgrade
	// binary is ReleaseBaseURL + BinaryAssetPrefix + GOARCH and its detached
	// signature is that URL + ".sig".
	ReleaseBaseURL    = "https://github.com/xxvcc/linux-temp-admin/releases/latest/download/"
	BinaryAssetPrefix = ManagedTag + "-linux-"
)
