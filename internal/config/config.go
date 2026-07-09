// Package config holds the constants shared across the tool: account defaults,
// the managed-account markers, and the on-disk paths and systemd unit namespace
// it owns.
package config

const (
	// DefaultPrefix is the default temporary-username prefix.
	DefaultPrefix = "xxvcc"
	// DefaultExpireHours is the default account lifetime.
	DefaultExpireHours = 24
	// MaxExpireHours caps --hours (one year).
	MaxExpireHours = 8760
	// MaxUpgradeBytes caps a downloaded upgrade payload (64 MiB), leaving headroom
	// over the ~7 MiB static release binaries.
	MaxUpgradeBytes = 64 << 20
	// DefaultShell is the preferred login shell for created accounts.
	DefaultShell = "/bin/bash"

	// ManagedTag marks tool-managed accounts.
	ManagedTag = "linux-temp-admin"
	// ManagedGECOS is the exact GECOS an invite sets; user.IsManaged requires this
	// full string, not a bare ManagedTag substring.
	ManagedGECOS = ManagedTag + " temporary admin"

	// --- owned paths and namespaces ---

	// RegistryDir is the registry directory. The "/v2" leaf is baked into deployed
	// hosts' on-disk state; changing it would strand their registries.
	RegistryDir = "/var/lib/linux-temp-admin/v2"
	// RegistryFile is the registry file.
	RegistryFile = RegistryDir + "/registry.tsv"
	// RegistryLockFile is the flock file for registry mutations.
	RegistryLockFile = RegistryDir + "/registry.lock"
	// RegistrySchema is written as the registry header's version marker.
	RegistrySchema = 2

	// AuditLogDir holds the append-only operation audit log (root:root, 0700).
	AuditLogDir = "/var/log/" + ManagedTag
	// AuditLogFile is the audit log; one JSON object per line.
	AuditLogFile = AuditLogDir + "/audit.log"

	// InstallPath is where the stable command is installed.
	InstallPath = "/usr/local/sbin/linux-temp-admin"
	// SystemdDir holds generated auto-revoke units.
	SystemdDir = "/etc/systemd/system"
	// AutoRevokeUnitPrefix namespaces generated systemd units. The "-v2-" infix is
	// load-bearing: it is baked into the unit filenames already written on
	// deployed hosts, so changing it would orphan their auto-revoke timers.
	AutoRevokeUnitPrefix = ManagedTag + "-v2-revoke-"

	// ReleaseBaseURL is where signed release binaries are published; the upgrade
	// binary is ReleaseBaseURL + BinaryAssetPrefix + GOARCH and its detached
	// signature is that URL + ".sig".
	ReleaseBaseURL    = "https://github.com/xxvcc/linux-temp-admin/releases/latest/download/"
	BinaryAssetPrefix = ManagedTag + "-linux-"
)
