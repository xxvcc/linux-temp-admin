package user

import (
	"fmt"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// IsManagedEntry recognizes both deployed fixed markers and well-formed dynamic
// markers. It is suitable for display and explicitly confirmed recovery only;
// registry-backed identity decisions must use MatchesManagedGeneration.
func IsManagedEntry(pw Passwd) bool {
	return IsLegacyManagedEntry(pw) || hasManagedGenerationMarker(pw)
}

func hasManagedGenerationMarker(pw Passwd) bool {
	return hasGenerationMarker(pw.GECOS, config.ManagedGenerationGECOSPrefix, config.ManagedGenerationGECOSWitnessPrefix)
}

// HasLifecycleMarker recognizes exact pending, legacy managed, and
// generation-bound managed markers. It is intentionally weaker than identity:
// use it to notice an account that must block cleanup, never to authorize delete.
func HasLifecycleMarker(pw Passwd) bool {
	if IsManagedEntry(pw) {
		return true
	}
	return hasPendingGenerationMarker(pw)
}

func hasPendingGenerationMarker(pw Passwd) bool {
	return hasGenerationMarker(pw.GECOS, config.PendingGenerationGECOSPrefix, config.PendingGenerationGECOSWitnessPrefix)
}

// IsLegacyManagedEntry reports whether pw has the fixed marker used by released
// versions that could not bind the passwd entry to a registry generation.
func IsLegacyManagedEntry(pw Passwd) bool {
	return gecosFullName(pw.GECOS) == config.ManagedGECOS
}

// MatchesManagedGeneration requires the exact dynamic marker for generation.
// New accounts place a compact phase-specific witness in the trailing GECOS
// field, which supported shadow/util-linux chfn implementations preserve when ordinary users
// change full-name, room, or phone fields. The first-field fallback is retained
// only for accounts created by already-deployed releases.
func MatchesManagedGeneration(pw Passwd, generation string) bool {
	return matchesGenerationMarker(pw.GECOS, config.ManagedGenerationGECOSPrefix, config.ManagedGenerationGECOSWitnessPrefix, generation)
}

// MatchesPendingGeneration is the pending-account counterpart of
// MatchesManagedGeneration. It is exported because invite rollback and pending
// recovery must use exactly the same old/new GECOS compatibility policy as
// ordinary revoke.
func MatchesPendingGeneration(pw Passwd, generation string) bool {
	return matchesGenerationMarker(pw.GECOS, config.PendingGenerationGECOSPrefix, config.PendingGenerationGECOSWitnessPrefix, generation)
}

// HasTrailingGenerationWitness reports whether the trailing GECOS field carries
// the exact completed-generation marker. Supported ordinary-user account tools
// cannot overwrite that field. A false result can still be a valid account
// created by v2.9.3 or earlier, when the exact marker is present only in the
// user-changeable full-name field.
func HasTrailingGenerationWitness(pw Passwd, generation string) bool {
	if !validate.Generation(generation) {
		return false
	}
	return gecosTrailingInfo(pw.GECOS) == config.ManagedGenerationGECOSWitnessPrefix+generation
}

// SameAccountIdentity compares passwd snapshots across a multi-stage lifecycle
// operation. Accounts from older releases have only a user-changeable first-field
// marker, so every field must remain byte-for-byte identical. For a new account,
// an exact trailing lifecycle witness lets ordinary chfn/chsh changes proceed
// without indefinitely postponing revoke: name, UID, GID, Home, and the trailing
// witness still have to match, while earlier GECOS fields and a non-empty shell
// may change.
func SameAccountIdentity(expected, current Passwd) bool {
	if expected == current {
		return true
	}
	witness, protected := trailingLifecycleWitness(expected.GECOS)
	if !protected || gecosTrailingInfo(current.GECOS) != witness {
		return false
	}
	return current.Name == expected.Name && current.UID == expected.UID && current.GID == expected.GID &&
		current.Home == expected.Home && expected.Shell != "" && current.Shell != ""
}

// ManagedGECOSForGeneration returns the exact completed marker for generation.
func ManagedGECOSForGeneration(generation string) (string, error) {
	return generationGECOS(config.ManagedGenerationGECOSWitnessPrefix, generation)
}

func pendingGECOSForGeneration(generation string) (string, error) {
	return generationGECOS(config.PendingGenerationGECOSWitnessPrefix, generation)
}

func generationGECOS(prefix, generation string) (string, error) {
	if !validate.Generation(generation) {
		return "", fmt.Errorf("invalid account generation %q", generation)
	}
	marker := prefix + generation
	// Keep the user-changeable fields empty and place a compact identity only in the
	// fifth field. The deployed long marker leaves no portable room under chfn's
	// bounded GECOS length once a user fills earlier fields. An older binary sees an
	// empty full-name marker and safely refuses deletion; the current binary uses the
	// trailing witness, for which supported helpers expose no ordinary-user
	// overwrite path.
	return ",,,," + marker, nil
}

// gecosFullName returns the first comma-separated GECOS subfield. Account tools
// may pad the remaining office/phone fields with commas.
func gecosFullName(gecos string) string {
	name := gecos
	if i := strings.IndexByte(gecos, ','); i >= 0 {
		name = gecos[:i]
	}
	return name
}

// gecosTrailingInfo returns the fifth GECOS subfield. SplitN deliberately keeps
// every comma after the fourth inside this final value so a malformed extra field
// cannot be normalized into a valid witness.
func gecosTrailingInfo(gecos string) string {
	fields := strings.SplitN(gecos, ",", 5)
	if len(fields) != 5 {
		return ""
	}
	return fields[4]
}

func hasGenerationMarker(gecos, deployedPrefix, witnessPrefix string) bool {
	deployedGeneration, deployed := strings.CutPrefix(gecosFullName(gecos), deployedPrefix)
	witnessGeneration, witnessed := strings.CutPrefix(gecosTrailingInfo(gecos), witnessPrefix)
	return (deployed && validate.Generation(deployedGeneration)) ||
		(witnessed && validate.Generation(witnessGeneration))
}

// hasAuthoritativeGenerationMarker is the deletion-authority form of
// hasGenerationMarker. The two differ deliberately, because the same question
// has opposite safe answers in the two places it is asked:
//
//   - HasLifecycleMarker only ever BLOCKS work, so recognizing a marker in either
//     GECOS position is the conservative reading there.
//   - IsProtectedRevokeEntry turns a marker into permission to delete an
//     unregistered account, so the root-only trailing field must win once it
//     carries any value at all. Otherwise a user-writable full-name copy could
//     re-establish deletion evidence that the trailing witness contradicts.
//
// This mirrors matchesGenerationMarker's precedence without pinning the result
// to one specific recorded generation.
func hasAuthoritativeGenerationMarker(gecos, deployedPrefix, witnessPrefix string) bool {
	if trailing := gecosTrailingInfo(gecos); trailing != "" {
		generation, witnessed := strings.CutPrefix(trailing, witnessPrefix)
		return witnessed && validate.Generation(generation)
	}
	generation, deployed := strings.CutPrefix(gecosFullName(gecos), deployedPrefix)
	return deployed && validate.Generation(generation)
}

func hasAuthoritativeManagedGenerationMarker(pw Passwd) bool {
	return hasAuthoritativeGenerationMarker(pw.GECOS,
		config.ManagedGenerationGECOSPrefix, config.ManagedGenerationGECOSWitnessPrefix)
}

func trailingLifecycleWitness(gecos string) (string, bool) {
	marker := gecosTrailingInfo(gecos)
	for _, prefix := range []string{config.ManagedGenerationGECOSWitnessPrefix, config.PendingGenerationGECOSWitnessPrefix} {
		generation, found := strings.CutPrefix(marker, prefix)
		if found && validate.Generation(generation) {
			return marker, true
		}
	}
	return "", false
}

func matchesGenerationMarker(gecos, deployedPrefix, witnessPrefix, generation string) bool {
	if !validate.Generation(generation) {
		return false
	}
	wantWitness := witnessPrefix + generation
	trailing := gecosTrailingInfo(gecos)
	if trailing != "" {
		// Once a trailing value exists it is authoritative. Refuse a contradictory
		// value even when the user-changeable full-name copy still looks right.
		return trailing == wantWitness
	}
	// Compatibility for v2.9.3 and earlier generation-bound accounts.
	return gecosFullName(gecos) == deployedPrefix+generation
}

// protectedNames are never deletable regardless of registration.
var protectedNames = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true, "list": true,
	"irc": true, "gnats": true, "nobody": true, "dbus": true, "sshd": true, "polkitd": true,
}

// IsReservedName reports whether name falls in a namespace the tool must never
// touch based on its shape alone — a well-known system account name or the
// reserved "systemd-" prefix — independent of any /etc/passwd lookup. It is the
// single source of truth shared by both sides: the revoke path refuses to delete
// these, and the create path (invite) refuses to create them, so the tool can
// never mint an account it would later be unable to revoke.
func IsReservedName(name string) bool {
	return protectedNames[name] || strings.HasPrefix(name, "systemd-")
}

func validateMutationName(name string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	if IsReservedName(name) {
		return fmt.Errorf("refusing reserved username %q", name)
	}
	return nil
}

// RevokeIdentity is the registry evidence a revoke decision may use. IdentityBound
// is deliberately separate from RecordedGeneration: released legacy rows can
// carry a generation-shaped value without proving that it was embedded in the
// account's passwd marker.
type RevokeIdentity struct {
	Registered         bool
	RecordedUID        int
	RecordedGeneration string
	IdentityBound      bool
}

// IsProtectedRevokeEntry applies the revoke policy to one already-read passwd
// snapshot. Destructive callers must not splice the UID from one lookup together
// with the marker or name from another lookup while an account is being replaced.
// Reserved names and UID 0 are always protected. A system-range UID requires a
// registered generation-bound identity; a higher UID still requires the managed
// marker or explicitly authorized legacy recovery. A matching recorded UID is
// only a contradiction check, never proof against name/UID reuse on its own.
func IsProtectedRevokeEntry(name string, pw Passwd, exists bool, identity RevokeIdentity, allowLegacy bool) bool {
	if IsReservedName(name) {
		return true
	}
	if !exists {
		return !identity.Registered
	}
	if pw.UID == 0 {
		return true
	}
	if identity.Registered {
		if identity.RecordedUID > 0 && pw.UID != identity.RecordedUID {
			return true
		}
		// A legacy row is explicitly unbound even when it carries both a UID and a
		// generation-shaped column. Never turn that value into deletion authority by
		// comparing it with passwd. Only the direct interactive recovery gate may
		// authorize the exact fixed legacy marker, and never for a system-range UID.
		if !identity.IdentityBound {
			return pw.UID < minAllocatableID || !allowLegacy || !IsLegacyManagedEntry(pw)
		}
		if identity.RecordedUID < 1 {
			return true
		}
	}
	// A fixed legacy marker can be reproduced and is therefore only recovery
	// evidence. It becomes deletion authority solely when the caller obtained the
	// explicit legacy confirmation, including when the registry row was lost. A
	// random generation marker may still support explicit unregistered recovery,
	// but only in its authoritative form: once the root-only trailing GECOS field
	// holds a value it decides, so a user-changeable full-name copy can never
	// re-establish a marker that field contradicts. Registered accounts must match
	// their exact recorded generation below.
	managed := hasAuthoritativeManagedGenerationMarker(pw) || (allowLegacy && IsLegacyManagedEntry(pw))
	if identity.Registered {
		managed = identity.IdentityBound && MatchesManagedGeneration(pw, identity.RecordedGeneration)
	}
	if pw.UID < minAllocatableID {
		return !(identity.Registered && identity.IdentityBound && managed)
	}
	// UIDs are reusable. Even a matching recorded UID cannot prove that this is the
	// same account generation after an out-of-band deletion and recreation. Require
	// the per-account marker as well; ambiguity is safer to leave for an operator.
	return !managed
}

func (m *Manager) verifyExpectedIdentity(name string, expected Passwd, phase string) error {
	current, exists, err := m.lookup(name)
	if err != nil {
		return fmt.Errorf("verify account identity %s: %w", phase, err)
	}
	if !exists {
		return fmt.Errorf("account %s disappeared %s", name, phase)
	}
	if current != expected {
		return fmt.Errorf("account identity changed %s", phase)
	}
	return nil
}
