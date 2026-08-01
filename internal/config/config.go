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
	// full string for legacy accounts, not a bare ManagedTag substring.
	ManagedGECOS = ManagedTag + " temporary admin"
	// ManagedGenerationGECOSPrefix begins the generation-bound marker written for
	// every newly completed account. The 128-bit generation follows immediately.
	ManagedGenerationGECOSPrefix = ManagedGECOS + " generation="
	// PendingGECOS is used only between useradd and durable UID registration. It
	// deliberately does not match ManagedGECOS, so an older binary that ignores a
	// newer registry Pending field still treats the incomplete account as protected.
	PendingGECOS = ManagedTag + " pending account"
	// PendingGenerationGECOSPrefix binds even the incomplete passwd entry to the
	// creation intent that preceded it.
	PendingGenerationGECOSPrefix = PendingGECOS + " generation="

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
	// IdentitySequenceFile stores the highest numeric UID/GID reserved by the
	// monotonic allocator. Once the registry is migrated to the matching schema,
	// this file is mandatory: recreating it from only the currently-live accounts
	// could reuse an identity that was retired after the last registry compaction.
	IdentitySequenceFile = RegistryDir + "/identity-sequence"
	// PrefsFile holds the operator's remembered UI choices (currently just the
	// language). It shares the tool's state directory rather than /etc: it is a
	// convenience the tool wrote for itself, not configuration an operator is
	// expected to hand-edit or ship in a config-management repo.
	PrefsFile = RegistryDir + "/prefs"
	// RegistrySchema is written as the registry header's version marker.
	RegistrySchema = 5

	// AuditLogDir holds the best-effort JSONL operation audit log (root:root, 0700).
	AuditLogDir = "/var/log/" + ManagedTag
	// AuditLogFile is the audit log; one JSON object per line.
	AuditLogFile = AuditLogDir + "/audit.log"

	// InstallPath is where the stable command is installed.
	InstallPath = "/usr/local/sbin/linux-temp-admin"
	// LifecycleLockFile serializes every account/install mutation. It deliberately
	// lives outside StateDir because uninstall removes StateDir while holding it.
	LifecycleLockFile = "/run/" + ManagedTag + ".lock"
	// SystemdDir holds generated auto-revoke units.
	SystemdDir = "/etc/systemd/system"
	// SystemdTimerStateDir holds Persistent=true timer timestamps. systemd does
	// not remove these when a timer unit is disabled or deleted.
	SystemdTimerStateDir = "/var/lib/systemd/timers"
	// AutoRevokeUnitPrefix namespaces generated systemd units. The "-v2-" infix is
	// load-bearing: it is baked into the unit filenames already written on
	// deployed hosts, so changing it would orphan their auto-revoke timers.
	AutoRevokeUnitPrefix = ManagedTag + "-v2-revoke-"
	// QuarantineUnitPrefix names the short-lived persistent timers that finish an
	// already-disabled account deletion after the identity-reuse quarantine.
	QuarantineUnitPrefix = ManagedTag + "-v2-quarantine-"
	// IdentityQuarantineSeconds covers one complete cron/at polling cycle plus a
	// small margin. Normal creation avoids this delay with monotonic UID/GID
	// allocation; revoke holds the disabled passwd identity for this interval and
	// completes deletion asynchronously when systemd is available.
	IdentityQuarantineSeconds = 65

	// ReleaseMirrorBaseURL is the official mirror used for normal installation and
	// upgrades. latest.json selects one immutable version directory below it.
	ReleaseMirrorBaseURL     = "https://dl.ll.cd/linux-temp-admin"
	ReleaseMirrorManifestURL = ReleaseMirrorBaseURL + "/latest.json"
	// GitHub remains a transport-only fallback. A valid mirror manifest pins the
	// fallback to the same tag instead of consulting a potentially newer Latest.
	GitHubReleaseRoot          = "https://github.com/xxvcc/linux-temp-admin/releases"
	GitHubLatestReleaseBaseURL = GitHubReleaseRoot + "/latest/download"
	BinaryAssetPrefix          = ManagedTag + "-linux-"
)
