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

	// StateDir is everything this tool owns under /var/lib: the v2 registry in its
	// "/v2" leaf, and the v1-era files beside it. It is the unit of removal for an
	// uninstall, which is why it is named separately from RegistryDir.
	StateDir = "/var/lib/" + ManagedTag
	// RegistryDir is the registry directory. The "/v2" leaf is baked into deployed
	// hosts' on-disk state; changing it would strand their registries.
	RegistryDir = StateDir + "/v2"

	// --- v1-era artifacts ---
	//
	// v1 was the shell implementation (temp-admin.sh). v2 does not read or write
	// any of this and never has; it is named here only so an uninstall can find it,
	// because on an upgraded host these are not litter — V1RegistryFile is v1's
	// account registry, the only record naming the accounts v1 created.
	//
	// This matters more than it looks: v1's INSTALL_PATH was byte-identical to v2's
	// (/usr/local/sbin/linux-temp-admin), so a v1 auto-revoke timer still on disk
	// invokes THIS binary — with an argv v2 parses perfectly. Remove the binary and
	// a v1 account is stranded exactly as a v2 one would be.

	// V1RegistryFile is v1's account registry.
	V1RegistryFile = StateDir + "/users.tsv"
	// V1RegistryLockFile is v1's registry lock.
	V1RegistryLockFile = StateDir + "/users.lock"
	// V1AutoRevokeUnitPrefix namespaced v1's generated units. It has no "-v2-"
	// infix, so AutoRevokeUnitPrefix does NOT match it and a sweep that globs only
	// the v2 prefix walks straight past every v1 unit on the host.
	V1AutoRevokeUnitPrefix = ManagedTag + "-revoke-"
	// RegistryFile is the registry file.
	RegistryFile = RegistryDir + "/registry.tsv"
	// RegistryLockFile is the flock file for registry mutations.
	RegistryLockFile = RegistryDir + "/registry.lock"
	// PrefsFile holds the operator's remembered UI choices (currently just the
	// language). It shares the tool's state directory rather than /etc: it is a
	// convenience the tool wrote for itself, not configuration an operator is
	// expected to hand-edit or ship in a config-management repo.
	PrefsFile = RegistryDir + "/prefs"
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
