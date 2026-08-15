// Package user manages the lifecycle of temporary local accounts: creating,
// locking, expiring, and deleting them, plus the protection checks that keep the
// tool from ever touching a system or real account. Account mutations shell out
// to the distro's shadow tools (useradd/usermod/chage/userdel) via an injectable
// runner, so argv is unit-testable; passwd
// lookups and process termination are done natively (no getent/pkill).
package user

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/mountinfo"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

// passwdPath is the account database; overridable in tests.
var passwdPath = "/etc/passwd"
var groupPath = "/etc/group"
var loginDefsPath = "/etc/login.defs"

const maxLocalPasswdBytes = 64 << 20
const maxLocalGroupBytes = 64 << 20
const maxLoginDefsBytes = 1 << 20

var (
	// ErrAccountCreationNotStarted marks failures that happened before useradd was
	// invoked. A transaction may release its creation-intent witness for this
	// class after independently confirming that the account name is still absent.
	ErrAccountCreationNotStarted = errors.New("account creation was not started")
	nssCommandOptions            = executil.Options{
		Timeout:   10 * time.Second,
		MaxOutput: 256 << 10,
		ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
	}
	accountCommandOptions = executil.Options{
		Timeout:   2 * time.Minute,
		MaxOutput: 1 << 20,
		ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
	}
)

// Passwd is one /etc/passwd entry.
type Passwd struct {
	Name  string
	UID   int
	GID   int
	GECOS string
	Home  string
	Shell string
}

// Lookup returns the passwd entry for name (local accounts only; no NSS).
// A caller must distinguish a confirmed absence from an unreadable or malformed
// account database; destructive lifecycle operations fail closed on err.
func Lookup(name string) (Passwd, bool, error) {
	// Read the complete bounded file, not a bufio.Scanner: a scanner ignores a
	// mid-file read error and stops early, which would make an account later in the
	// file look absent. Lookup backs destructive existence checks, so partial or
	// oversized input must fail closed rather than masquerade as EOF.
	data, err := readPasswdDatabase(passwdPath, maxLocalPasswdBytes)
	if err != nil {
		return Passwd{}, false, fmt.Errorf("read passwd database: %w", err)
	}
	var found *Passwd
	for _, line := range strings.Split(string(data), "\n") {
		// strings.Split always yields at least one element, so indexing [0] is safe
		// even for the empty trailing line produced by a final newline.
		if strings.Split(line, ":")[0] != name {
			continue
		}
		if found != nil {
			return Passwd{}, false, fmt.Errorf("duplicate passwd entries for %s", name)
		}
		pw, err := parsePasswdEntry(line)
		if err != nil {
			return Passwd{}, false, err
		}
		found = &pw
	}
	if found != nil {
		return *found, true, nil
	}
	return Passwd{}, false, nil
}

func parsePasswdEntry(line string) (Passwd, error) {
	parts := strings.Split(line, ":")
	name := ""
	if len(parts) > 0 {
		name = parts[0]
	}
	if len(parts) != 7 {
		return Passwd{}, fmt.Errorf("malformed passwd entry for %s", name)
	}
	uid, err1 := strconv.Atoi(parts[2])
	gid, err2 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil || !validate.KernelID(uid) || !validate.KernelID(gid) {
		return Passwd{}, fmt.Errorf("malformed passwd entry for %s", name)
	}
	return Passwd{Name: name, UID: uid, GID: gid, GECOS: parts[4], Home: parts[5], Shell: parts[6]}, nil
}

func readPasswdDatabase(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	return b, nil
}

// IdentityAllocationRange returns the first numeric identity above every local
// UID and GID in the ordinary login.defs account range, plus that range's upper
// bound. The registry's durable high-water mark is applied separately, under its
// own lock, immediately before useradd.
func IdentityAllocationRange() (minimum, maximum int, err error) {
	uidMin, uidMax, gidMin, gidMax, err := loginIdentityBounds()
	if err != nil {
		return 0, 0, err
	}
	lower := uidMin
	if gidMin > lower {
		lower = gidMin
	}
	upper := uidMax
	if gidMax < upper {
		upper = gidMax
	}
	if !validate.AccountID(lower) || !validate.AccountID(upper) || lower > upper {
		return 0, 0, fmt.Errorf("UID/GID allocation ranges do not overlap safely")
	}
	highest := lower - 1
	passwd, err := readPasswdDatabase(passwdPath, maxLocalPasswdBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("read passwd database for identity allocation: %w", err)
	}
	for i, line := range strings.Split(string(passwd), "\n") {
		if line == "" {
			continue
		}
		pw, err := parsePasswdEntry(line)
		if err != nil {
			return 0, 0, fmt.Errorf("scan passwd identity at line %d: %w", i+1, err)
		}
		for _, id := range []int{pw.UID, pw.GID} {
			if id >= lower && id <= upper && id > highest {
				highest = id
			}
		}
	}
	groups, err := readPasswdDatabase(groupPath, maxLocalGroupBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("read group database for identity allocation: %w", err)
	}
	for i, line := range strings.Split(string(groups), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 || parts[0] == "" {
			return 0, 0, fmt.Errorf("malformed group entry at line %d", i+1)
		}
		gid, parseErr := strconv.Atoi(parts[2])
		if parseErr != nil || !validate.KernelID(gid) {
			return 0, 0, fmt.Errorf("malformed group GID at line %d", i+1)
		}
		if gid >= lower && gid <= upper && gid > highest {
			highest = gid
		}
	}
	if highest >= upper {
		return 0, 0, fmt.Errorf("UID/GID allocation range %d..%d is exhausted", lower, upper)
	}
	return highest + 1, upper, nil
}

func loginIdentityBounds() (uidMin, uidMax, gidMin, gidMax int, err error) {
	uidMin, uidMax, gidMin, gidMax = 1000, 60000, 1000, 60000
	b, err := readPasswdDatabase(loginDefsPath, maxLoginDefsBytes)
	if errors.Is(err, os.ErrNotExist) {
		// shadow's own useradd falls back to its compiled-in range when
		// /etc/login.defs is absent, and minimal images ship shadow without it. A
		// missing file must therefore not make every invite fail on a host whose
		// account tooling works. Every other error stays fail-closed: an unreadable,
		// oversized, or non-regular file could be hiding a narrower configured range,
		// and allocating outside it would collide with the administrator's policy.
		return uidMin, uidMax, gidMin, gidMax, nil
	}
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read login.defs: %w", err)
	}
	values := map[string]*int{
		"UID_MIN": &uidMin, "UID_MAX": &uidMax, "GID_MIN": &gidMin, "GID_MAX": &gidMax,
	}
	seen := make(map[string]bool)
	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dst, wanted := values[fields[0]]
		if !wanted {
			continue
		}
		if len(fields) != 2 || seen[fields[0]] {
			return 0, 0, 0, 0, fmt.Errorf("invalid or duplicate %s at login.defs line %d", fields[0], i+1)
		}
		value, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil || !validate.AccountID(value) {
			return 0, 0, 0, 0, fmt.Errorf("invalid %s at login.defs line %d", fields[0], i+1)
		}
		*dst = value
		seen[fields[0]] = true
	}
	return uidMin, uidMax, gidMin, gidMax, nil
}

// Exists reports whether name is a local account.
func Exists(name string) (bool, error) {
	_, ok, err := Lookup(name)
	return ok, err
}

// LifecycleMarkerAccounts returns local passwd names carrying an exact marker
// written during this tool's account lifecycle. The result is discovery evidence
// only: some GECOS subfields are user-writable and a marker alone must never
// authorize account deletion. Callers must bind a completed registry row, UID,
// generation, and passwd snapshot separately before performing destructive work.
func LifecycleMarkerAccounts() ([]string, error) {
	data, err := readPasswdDatabase(passwdPath, maxLocalPasswdBytes)
	if err != nil {
		return nil, fmt.Errorf("read passwd database: %w", err)
	}
	seen := make(map[string]bool)
	var names []string
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		pw, err := parsePasswdEntry(line)
		if err != nil {
			return nil, fmt.Errorf("scan account markers at passwd line %d: %w", i+1, err)
		}
		if seen[pw.Name] {
			return nil, fmt.Errorf("scan account markers: duplicate passwd entries for %s", pw.Name)
		}
		seen[pw.Name] = true
		if !HasLifecycleMarker(pw) {
			continue
		}
		// A marker on a name this tool could never have created is not evidence
		// about this tool: invite runs validateMutationName before useradd, so every
		// account it has ever made carries a validate.Username name. Skipping such an
		// entry is deliberate rather than fail-closed, because the marker lives in the
		// GECOS full-name field that any local user can set with chfn. Reporting it as
		// an inventory error instead let an unprivileged account with a non-conforming
		// name (uppercase, over 32 bytes) permanently refuse every uninstall, with no
		// operator override.
		if !validate.Username(pw.Name) {
			continue
		}
		names = append(names, pw.Name)
	}
	sort.Strings(names)
	return names, nil
}

// NameInUse reports whether either the local passwd database or the host's NSS
// resolver knows name. Account ownership still comes only from /etc/passwd, but
// invite must not create a local account that shadows an LDAP/SSSD identity.
func NameInUse(name string) (bool, error) {
	if !validate.Username(name) {
		return false, fmt.Errorf("refusing NSS query for invalid username %q", name)
	}
	local, err := Exists(name)
	if err != nil || local {
		return local, err
	}
	out, err := executil.CombinedOutput("id", []string{"-u", "--", name}, nssCommandOptions)
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && idReportsUnknownUser(name, out) {
		return false, nil
	}
	diagnostic := strings.TrimSpace(string(out))
	if diagnostic == "" {
		return false, fmt.Errorf("query NSS identity %s: %w", name, err)
	}
	return false, fmt.Errorf("query NSS identity %s: %w: %s", name, err, diagnostic)
}

// idReportsUnknownUser recognizes only the C-locale diagnostics emitted for a
// confirmed miss by the implementations on supported systems: GNU coreutils on
// glibc, GNU coreutils on Alpine/musl (which appends EINVAL), and BusyBox on
// Alpine. Other nonzero exits may be an NSS/LDAP/SSSD failure and must not
// authorize creation of a shadowing account.
func idReportsUnknownUser(name string, out []byte) bool {
	diagnostic := strings.TrimSpace(string(out))
	return diagnostic == fmt.Sprintf("id: '%s': no such user", name) ||
		diagnostic == fmt.Sprintf("id: '%s': no such user: Invalid argument", name) ||
		diagnostic == "id: unknown user "+name
}

// Groups returns pw's group names: its primary group, plus every group that
// lists it as a member. This is exactly the set sshd evaluates AllowGroups and
// DenyGroups against, so an invite can tell whether a whitelist would admit the
// account it is about to create.
func Groups(pw Passwd) ([]string, error) {
	// Use the system identity resolver rather than parsing /etc/group: sshd also
	// consults NSS, so LDAP/SSSD memberships must participate in DenyGroups.
	// "--" matches NameInUse's invocation: the name is already constrained to
	// [a-z_]-led characters, so this is consistency rather than a live defence.
	out, err := executil.Output("id", []string{"-Gn", "--", pw.Name}, nssCommandOptions)
	if err != nil {
		return nil, fmt.Errorf("resolve groups for %s: %w", pw.Name, err)
	}
	groups := strings.Fields(string(out))
	if len(groups) == 0 {
		return nil, fmt.Errorf("identity resolver returned no groups for %s", pw.Name)
	}
	return groups, nil
}

// IsManaged reports whether name's GECOS carries a syntactically exact legacy or
// generation-bound marker written by this tool. Identity-sensitive callers must
// additionally match the generation stored in the registry.
func IsManaged(name string) (bool, error) {
	pw, ok, err := Lookup(name)
	return ok && IsManagedEntry(pw), err
}

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

// IsProtectedRevokeTarget reports whether deleting name must be refused.
// registered says whether the tool's registry lists it, and recordedUID is the
// UID the registry recorded when it created the account (0 = not recorded, i.e.
// a row from a build before that field existed).
//
// A reserved (system/systemd-) name or a UID-0 account is always protected; a
// system-range UID (<1000) is protected unless it is a registered, managed temp
// account; a real UID>=1000 account is protected unless it can be proven to be
// one the tool made — so a real account that merely reuses the name of a
// since-deleted temp account is never touched, even if a stale registry entry
// still names it.
//
// A current managed GECOS marker proves the account is in this tool's namespace.
// A recorded UID is a contradiction detector, not a sufficient witness: Linux
// can reuse the same UID after an out-of-band deletion and recreation. If the
// recorded and current UIDs differ, deletion is refused; if they match, the
// marker is still required.
//
// An account that escalates itself to UID 0 stays protected: never auto-delete a
// root account. The caller is expected to report that tamper rather than retry —
// see UIDTampered.
func IsProtectedRevokeTarget(name string, registered bool, recordedUID int, recordedGeneration string, allowLegacy bool) (bool, error) {
	pw, ok, err := Lookup(name)
	if err != nil {
		return true, err
	}
	return IsProtectedRevokeEntry(name, pw, ok, registered, recordedUID, recordedGeneration, allowLegacy), nil
}

// IsProtectedRevokeEntry applies the revoke policy to one already-read passwd
// snapshot. Destructive callers must not splice the UID from one lookup together
// with the marker or name from another lookup while an account is being replaced.
func IsProtectedRevokeEntry(name string, pw Passwd, exists, registered bool, recordedUID int, recordedGeneration string, allowLegacy bool) bool {
	if IsReservedName(name) {
		return true
	}
	if !exists {
		return !registered
	}
	if pw.UID == 0 {
		return true
	}
	if registered {
		if recordedUID < 1 || pw.UID != recordedUID {
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
	if registered {
		managed = MatchesManagedGeneration(pw, recordedGeneration) || (allowLegacy && IsLegacyManagedEntry(pw))
	}
	if pw.UID < 1000 {
		return !(registered && managed)
	}
	// UIDs are reusable. Even a matching recorded UID cannot prove that this is the
	// same account generation after an out-of-band deletion and recreation. Require
	// the per-account marker as well; ambiguity is safer to leave for an operator.
	return !managed
}

// UIDTampered reports whether name's current UID differs from the one the
// registry recorded at creation — the signature of an account that rewrote its
// own /etc/passwd entry (most dangerously to UID 0, which makes it permanently
// root and permanently protected). It is advisory: the caller reports it so the
// operator knows automatic revocation cannot proceed and why. Returns false when
// nothing was recorded (an older row) or the account is gone.
func UIDTampered(name string, recordedUID int) (current int, tampered bool, err error) {
	if recordedUID <= 0 {
		return 0, false, nil
	}
	pw, ok, err := Lookup(name)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, nil
	}
	return pw.UID, pw.UID != recordedUID, nil
}

// Runner executes account-management commands; injectable for tests.
type Runner interface {
	Run(name string, args ...string) error
	// RunInput is Run with data on the command's stdin. It exists so a secret
	// (a password) is handed to chpasswd through a pipe and never as an argv
	// element, which every process on the host can read out of /proc.
	RunInput(stdin string, name string, args ...string) error
	Look(name string) bool
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) error {
	out, err := executil.CombinedOutput(name, args, accountCommandOptions)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execRunner) RunInput(stdin string, name string, args ...string) error {
	opts := accountCommandOptions
	opts.Stdin = strings.NewReader(stdin)
	err := executil.Run(name, args, opts)
	if err != nil {
		// A malicious or broken helper can echo stdin to either output stream. Do
		// not include any child output in this error: stdin holds the password.
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func (execRunner) Look(name string) bool { _, err := exec.LookPath(name); return err == nil }

// Manager performs account mutations via its Runner.
type Manager struct {
	Runner                   Runner
	LookupUser               func(string) (Passwd, bool, error)
	NameInUse                func(string) (bool, error)
	ValidateManagedMailRoots func() error
	PrepareManagedHome       func(string) error
	CreateManagedHome        func(Passwd) error
	ValidateManagedHome      func(Passwd) error
	RemoveManagedMail        func(Passwd) error
	RemoveManagedHome        func(Passwd) error
}

// New returns a Manager using real command execution.
func New() *Manager {
	return &Manager{
		Runner:                   execRunner{},
		LookupUser:               Lookup,
		NameInUse:                NameInUse,
		ValidateManagedMailRoots: validateManagedMailRoots,
		PrepareManagedHome:       prepareManagedHome,
		CreateManagedHome:        createManagedHome,
		ValidateManagedHome:      validateCreatedHome,
		RemoveManagedMail:        removeManagedMail,
		RemoveManagedHome:        removeManagedHome,
	}
}

// Create makes a new account with a generation-bound managed GECOS tag and an
// empty managed Home.
func (m *Manager) Create(name, shell, generation string) error {
	gecos, err := ManagedGECOSForGeneration(generation)
	if err != nil {
		return err
	}
	_, err = m.create(name, shell, gecos, true, 0)
	return err
}

// CreatePending makes an account and empty Home whose GECOS is intentionally not
// the managed marker. It preserves the original convenience API; invite uses
// CreatePendingIdentity so it can keep the Home absent while draining inherited
// work, then create it against the captured identity.
func (m *Manager) CreatePending(name, shell, generation string) error {
	gecos, err := pendingGECOSForGeneration(generation)
	if err != nil {
		return err
	}
	_, err = m.create(name, shell, gecos, true, 0)
	return err
}

// CreatePendingIdentity is CreatePending with the post-create passwd snapshot
// returned to the caller, except that it deliberately leaves the Home absent.
// The invite transaction must carry this exact identity forward and call
// CreateManagedHomeExpected only after inherited work has been drained.
func (m *Manager) CreatePendingIdentity(name, shell, generation string) (Passwd, error) {
	gecos, err := pendingGECOSForGeneration(generation)
	if err != nil {
		return Passwd{}, err
	}
	return m.create(name, shell, gecos, false, 0)
}

// CreatePendingIdentityWithID creates the pending account with an explicitly
// reserved UID/GID pair. -U makes the private group deterministic; the complete
// passwd snapshot is rejected unless both numeric identities equal reservedID.
func (m *Manager) CreatePendingIdentityWithID(name, shell, generation string, reservedID int) (Passwd, error) {
	if !validate.AccountID(reservedID) {
		return Passwd{}, fmt.Errorf("%w: invalid reserved UID/GID %d", ErrAccountCreationNotStarted, reservedID)
	}
	gecos, err := pendingGECOSForGeneration(generation)
	if err != nil {
		return Passwd{}, err
	}
	return m.create(name, shell, gecos, false, reservedID)
}

var managedHomeRoot = "/home"

func managedHome(name string) string { return filepath.Join(managedHomeRoot, name) }

var (
	syncCreatedHomeMetadata = func(home *os.File) error { return home.Sync() }
	syncCreatedHomeParent   = func(parent *os.File) error { return parent.Sync() }
)

// DefaultHome is the dedicated home path used for every newly created account.
func DefaultHome(name string) (string, error) {
	if !validate.Username(name) {
		return "", fmt.Errorf("invalid username %q", name)
	}
	return managedHome(name), nil
}

func (m *Manager) create(name, shell, gecos string, shouldCreateHome bool, reservedID int) (Passwd, error) {
	if err := validateMutationName(name); err != nil {
		return Passwd{}, fmt.Errorf("%w: %w", ErrAccountCreationNotStarted, err)
	}
	validateMailRoots := m.ValidateManagedMailRoots
	if validateMailRoots == nil {
		validateMailRoots = validateManagedMailRoots
	}
	// Mail-root metadata does not depend on the UID selected by useradd. Reject a
	// persistently unsafe layout before creating a pending account, then repeat the
	// same validation while doing the UID-bound cleanup below to close path races.
	if err := validateMailRoots(); err != nil {
		return Passwd{}, fmt.Errorf("%w: validate managed mail roots before account creation: %w", ErrAccountCreationNotStarted, err)
	}
	home := managedHome(name)
	prepare := m.PrepareManagedHome
	if prepare == nil {
		prepare = prepareManagedHome
	}
	if err := prepare(name); err != nil {
		return Passwd{}, fmt.Errorf("%w: prepare managed home: %w", ErrAccountCreationNotStarted, err)
	}
	var err error
	switch {
	case m.Runner.Look("useradd"):
		// Create only the account database entry here. The expired date and locked
		// hash are part of the same useradd transaction, so the pending name never
		// depends on a later chage/usermod call for its initial login gate. -M also
		// prevents /etc/skel (including any locally provisioned SSH credential) from
		// being copied before the selected UID has been proved idle.
		args := []string{"-M", "-d", home, "-s", shell, "-c", gecos,
			"-e", expiredDate, "-p", initialLockedPasswordHash}
		if reservedID > 0 {
			id := strconv.Itoa(reservedID)
			// Pin the private-group allocator to the same already-reserved number.
			// -U normally prefers UID==GID, but login.defs gaps and concurrent local
			// administration can otherwise make that an implementation detail. The
			// post-create passwd check remains authoritative.
			args = append(args, "-U", "-u", id, "-K", "GID_MIN="+id, "-K", "GID_MAX="+id)
		}
		args = append(args, name)
		err = m.Runner.Run("useradd", args...)
	default:
		return Passwd{}, fmt.Errorf("%w: useradd not available", ErrAccountCreationNotStarted)
	}
	if err != nil {
		pw, exists, lookupErr := m.lookup(name)
		if lookupErr != nil {
			return Passwd{}, errors.Join(err, fmt.Errorf("inspect account after failed useradd: %w", lookupErr))
		}
		if !exists {
			return Passwd{}, fmt.Errorf("%w: useradd failed without creating an account: %v", ErrAccountCreationNotStarted, err)
		}
		return pw, fmt.Errorf("useradd reported failure after creating an account: %w", err)
	}

	// useradd chooses a numeric UID automatically. A process left behind after an
	// out-of-band deletion may still carry that number. Check all four Linux
	// credential UIDs before creating a UID-owned Home or allowing the caller to use
	// the account. If the check is inconclusive or finds a residual process, retain
	// the expired, password-locked pending account without a Home: deleting it would
	// free the reused UID while that process still carries it.
	pw, ok, lookupErr := m.lookup(name)
	if lookupErr != nil {
		return Passwd{}, errors.Join(
			fmt.Errorf("look up newly created account: %w", lookupErr),
			fmt.Errorf("newly created account %s was retained without a verified identity", name),
		)
	}
	if !ok {
		return Passwd{}, fmt.Errorf("newly created account %s is absent from the local account database", name)
	}
	if !validate.AccountID(pw.UID) || !validate.AccountID(pw.GID) {
		return Passwd{}, errors.Join(
			fmt.Errorf("newly created account %s has no safe local UID/GID", name),
			fmt.Errorf("account was retained for manual recovery because identity %d:%d is unsafe", pw.UID, pw.GID),
		)
	}
	if reservedID > 0 && (pw.UID != reservedID || pw.GID != reservedID) {
		return pw, fmt.Errorf("newly created account received identity %d:%d, want reserved %d:%d; account retained for rollback or manual recovery",
			pw.UID, pw.GID, reservedID, reservedID)
	}
	if pw.Name != name || pw.Home != home || pw.Shell != shell || pw.GECOS != gecos {
		// Return the snapshot that was actually read, exactly as the reserved-identity
		// mismatch above does. It is the last complete identity this call proved, and
		// discarding it left the caller with a zero Passwd whose first rollback check
		// fails, so a benign distro quirk in one field turned into an account that
		// could only ever be recovered by hand. The rollback path re-verifies the
		// generation marker and every name-scoped grant before it may delete anything.
		return pw, fmt.Errorf("newly created account identity does not match the requested name, home, shell, and marker; account retained for rollback or manual recovery")
	}
	pids, scanErr := processesForUID(pw.UID)
	if scanErr != nil {
		return Passwd{}, fmt.Errorf("scan processes before using UID %d: %w; account retained to keep the UID occupied", pw.UID, scanErr)
	}
	if len(pids) != 0 {
		return Passwd{}, fmt.Errorf("refusing reused UID %d: residual processes %v already carry it; account retained to keep the UID occupied", pw.UID, pids)
	}
	// A previous account generation can leave a same-name mail spool behind even
	// when its Home is gone. The newly selected UID may be the same, so clear that
	// artifact while this identity is still expired, password-locked, and has no
	// credential. A different owner or special file fails closed and retains the
	// pending account to keep the name and UID occupied.
	if err := m.ClearManagedMailExpected(name, pw); err != nil {
		return pw, fmt.Errorf("clear mail spool before using account identity: %w; account retained for rollback or manual recovery", err)
	}
	if !shouldCreateHome {
		return pw, nil
	}
	if err := m.CreateManagedHomeExpected(name, pw); err != nil {
		return pw, fmt.Errorf("%w; account retained for rollback or manual recovery", err)
	}
	return pw, nil
}

// CreateManagedHomeExpected creates and validates an empty Home only while the
// complete passwd identity captured at useradd still exists unchanged. Invite
// calls this after draining inherited deferred work, so an old account generation
// has no writable Home during that drain.
func (m *Manager) CreateManagedHomeExpected(name string, expected Passwd) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) ||
		!validate.AccountID(expected.GID) || expected.Home != managedHome(name) ||
		expected.Shell == "" ||
		(!hasManagedGenerationMarker(expected) && !hasPendingGenerationMarker(expected)) {
		return fmt.Errorf("invalid expected account identity for managed Home creation")
	}
	if err := m.verifyExpectedIdentity(name, expected, "before managed Home creation"); err != nil {
		return err
	}
	createHome := m.CreateManagedHome
	if createHome == nil {
		createHome = createManagedHome
	}
	createErr := createHome(expected)
	identityErr := m.verifyExpectedIdentity(name, expected, "during managed Home creation")
	if createErr != nil || identityErr != nil {
		if createErr != nil {
			createErr = fmt.Errorf("create empty managed account Home: %w", createErr)
		}
		return errors.Join(createErr, identityErr)
	}
	inspect := m.ValidateManagedHome
	if inspect == nil {
		inspect = validateCreatedHome
	}
	inspectErr := inspect(expected)
	identityErr = m.verifyExpectedIdentity(name, expected, "during managed Home validation")
	if inspectErr != nil || identityErr != nil {
		if inspectErr != nil {
			inspectErr = fmt.Errorf("validate newly created account Home: %w", inspectErr)
		}
		return errors.Join(inspectErr, identityErr)
	}
	return nil
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

// MarkManaged changes a pending account to the exact managed marker only after
// its numeric UID has been durably recorded. usermod is a required dependency
// for both invite and fail-closed revoke, so there is no weaker fallback here.
func (m *Manager) MarkManaged(name, generation string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	gecos, err := ManagedGECOSForGeneration(generation)
	if err != nil {
		return err
	}
	if !m.Runner.Look("usermod") {
		return fmt.Errorf("usermod not available")
	}
	return m.Runner.Run("usermod", "-c", gecos, name)
}

// MarkManagedExpected changes only the pending identity captured at creation and
// verifies the complete passwd entry afterward. The underlying usermod remains a
// name-scoped system helper, so these checks detect and contain replacement; they
// cannot make the helper itself an atomic compare-and-swap.
func (m *Manager) MarkManagedExpected(name, generation string, expected Passwd) (Passwd, error) {
	pending, err := pendingGECOSForGeneration(generation)
	if err != nil {
		return Passwd{}, err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) || expected.Home != managedHome(name) || expected.Shell == "" || expected.GECOS != pending {
		return Passwd{}, fmt.Errorf("invalid pending account identity for %q", name)
	}
	if err := m.verifyExpectedIdentity(name, expected, "before marking it managed"); err != nil {
		return Passwd{}, fmt.Errorf("verify pending account before marking managed: %w", err)
	}
	if err := m.MarkManaged(name, generation); err != nil {
		return Passwd{}, err
	}
	current, exists, err := m.lookup(name)
	if err != nil {
		return Passwd{}, fmt.Errorf("verify managed account marker: %w", err)
	}
	want := expected
	want.GECOS, err = ManagedGECOSForGeneration(generation)
	if err != nil {
		return Passwd{}, err
	}
	if !exists || current != want {
		return Passwd{}, fmt.Errorf("account identity changed while marking it managed")
	}
	return current, nil
}

// keyOnlyPasswordHash is deliberately not a valid crypt(3) result. Traditional
// DES crypt output is exactly 13 bytes, while modern Linux schemes start with
// '$' (or '_' for BSD extended DES). No password can reproduce this longer,
// unmarked value. Unlike a shadow value beginning with '!' or '*', it also does
// not make OpenSSH on Alpine reject the entire account before public-key auth.
const keyOnlyPasswordHash = "linux-temp-admin-key-only-password-disabled"

// DisablePasswordForKeyLogin makes password authentication impossible without
// marking the whole account locked. This distinction is required on OpenSSH
// builds that reject a shadow-locked account even when its authorized key is
// valid (notably Alpine's default configuration).
func (m *Manager) DisablePasswordForKeyLogin(name string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("usermod", "-p", keyOnlyPasswordHash, name)
}

// LockPassword locks name during revocation. Revoke also expires the account,
// so rejecting every authentication method is intentional here.
func (m *Manager) LockPassword(name string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("usermod", "-L", name)
}

// SetPassword sets name's login password, for the --password-login invite on a
// host whose sshd will not take a key. The password goes to chpasswd on stdin,
// never in argv, so it cannot be read out of the process table.
func (m *Manager) SetPassword(name, password string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if !m.Runner.Look("chpasswd") {
		return fmt.Errorf("chpasswd not available")
	}
	if strings.ContainsAny(password, ":\n") {
		// chpasswd's line format is user:password — a colon or newline would split
		// the record and set a different password than the one we printed.
		return fmt.Errorf("refusing a password containing ':' or a newline")
	}
	return m.Runner.RunInput(name+":"+password+"\n", "chpasswd")
}

// SetExpiry sets the account expiry date (YYYY-MM-DD) via chage.
func (m *Manager) SetExpiry(name, date string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("chage", "-E", date, name)
}

// ClearExpiry restores a permanent account after the credential-less safety
// drain temporarily expired it. chage documents -1 as "never expires"; using a
// dedicated method keeps that sentinel out of ordinary date-setting call sites.
func (m *Manager) ClearExpiry(name string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	return m.Runner.Run("chage", "-E", "-1", name)
}

// expiredDate is a date safely in the past; chage -E it to make an account
// expired as of now. A literal date is used rather than "0" because chage's
// numeric form is days-since-epoch and reads ambiguously next to -E -1 ("never").
const expiredDate = "1970-01-01"

// initialLockedPasswordHash is passed to useradd as an encrypted hash. It is not
// a valid crypt(3) result, and the leading '!' has the conventional shadow meaning
// of a locked password. Account expiry remains the authentication-method-neutral
// gate; this value independently closes password authentication at creation.
const initialLockedPasswordHash = "!"

// DisableLogin shuts the account's door before revoke starts taking it apart:
// it expires the account (chage), which sshd and PAM both refuse regardless of
// how the invitee authenticates, and locks the password for good measure.
//
// This must happen BEFORE processes are killed and the account is deleted.
// Without it the account stays reachable throughout the revoke, so an invitee
// reconnecting in a loop can land a session in the window between the kill and
// the delete — which used to be enough to make userdel fail and leave the
// account alive. Expiry is the effective gate for a key-based account: locking
// the password alone would not stop a public-key login.
//
// Both steps are attempted and their errors are returned. Destructive callers
// must stop before process termination or deletion unless both doors were shut.
//
// Both steps are ATTEMPTED even if the first fails. They guard different auth
// vectors — expiry stops a key login, the lock stops a password login — so
// returning on the expiry error would skip the password lock, dropping a
// mitigation that might still have succeeded (chage missing does not imply
// usermod missing). The errors are joined so the caller sees every door that
// could not be shut, not just the first.
func (m *Manager) DisableLogin(name string) error {
	return errors.Join(m.SetExpiry(name, expiredDate), m.LockPassword(name))
}

// DeleteExpected removes name only while its stable passwd identity still
// matches expected. A protected trailing witness permits user-changeable
// GECOS/shell fields to move; old identities retain byte-for-byte comparison.
// The caller has already disabled login and reached an initial
// cron/at/process fixed point. beforeDelete is mandatory and runs after controlled
// Home/mail cleanup but immediately before the name-scoped account helper, so the
// caller can repeat its scheduled-work and process checks at the last point where
// the UID is still bound. System helpers are invoked without recursive Home/mail
// options. In particular, userdel must not receive -f: on shadow-utils that flag
// may delete the same-name group even while another account still uses it as a
// primary group. Distro deluser and arbitrary BusyBox builds are not fallbacks:
// their configuration and compiled account-database semantics cannot be proven
// equivalent to shadow-utils userdel.
func (m *Manager) DeleteExpected(name string, expected Passwd, beforeDelete func() error) error {
	return m.deleteExpected(name, expected, beforeDelete, SameAccountIdentity)
}

// DeleteExpectedExact is the pre-activation rollback counterpart of
// DeleteExpected. It requires the complete passwd snapshot to remain unchanged,
// even for a current trailing-witness identity that cannot yet be used by the
// invitee. Once login activation has been attempted, callers must use
// DeleteExpected because the helper may have taken effect before reporting an
// error and a live invitee must not be able to hold rollback open with chfn/chsh.
func (m *Manager) DeleteExpectedExact(name string, expected Passwd, beforeDelete func() error) error {
	return m.deleteExpected(name, expected, beforeDelete, func(expected, current Passwd) bool {
		return expected == current
	})
}

func (m *Manager) deleteExpected(name string, expected Passwd, beforeDelete func() error, identityMatches func(Passwd, Passwd) bool) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) || !isManagedHome(name, expected.Home) {
		return fmt.Errorf("invalid expected account identity for %q", name)
	}
	if beforeDelete == nil {
		return fmt.Errorf("final account quiescence check is not configured")
	}
	return m.delete(name, &expected, beforeDelete, identityMatches)
}

func (m *Manager) delete(name string, expected *Passwd, beforeDelete func() error, identityMatches func(Passwd, Passwd) bool) error {
	absent, err := m.deletionState(name, expected, identityMatches)
	if err != nil {
		return fmt.Errorf("verify account identity before deletion: %w", err)
	}
	if absent {
		// Once passwd no longer binds the name and UID, the captured snapshot cannot
		// authorize recursive Home removal: Linux may already have reused the UID and
		// a replacement could have populated the deterministic path. Mail cleanup is
		// narrower and independently owner-checked, so it remains recoverable. Sweep
		// twice around an absence recheck to catch an in-flight delivery without ever
		// touching Home, jobs, processes, or an account helper.
		for sweep := 1; sweep <= 2; sweep++ {
			if err := m.removeManagedMail(*expected); err != nil {
				return err
			}
			absent, err = m.deletionState(name, expected, identityMatches)
			if err != nil {
				return fmt.Errorf("verify account remained absent after artifact cleanup sweep %d: %w", sweep, err)
			}
			if !absent {
				return fmt.Errorf("account %s reappeared during artifact cleanup sweep %d", name, sweep)
			}
		}
		return nil
	}
	type helper struct {
		name string
		args []string
	}
	var helpers []helper
	if m.Runner.Look("userdel") {
		helpers = append(helpers, helper{name: "userdel", args: []string{"--", name}})
	}
	if len(helpers) == 0 {
		return fmt.Errorf("userdel not available")
	}
	// Keep the account and registry witness if artifact cleanup cannot be proved
	// safe. Once a helper removes the passwd entry, a later retry no longer has the
	// complete snapshot needed to validate an orphaned mail spool or home.
	if err := m.removeManagedMail(*expected); err != nil {
		return err
	}
	if err := m.removeManagedHome(*expected); err != nil {
		return err
	}
	if err := beforeDelete(); err != nil {
		return fmt.Errorf("final account quiescence check before userdel: %w", err)
	}
	var attemptErrs []error
	for _, helper := range helpers {
		absent, err := m.deletionState(name, expected, identityMatches)
		if err != nil {
			return errors.Join(errors.Join(attemptErrs...), fmt.Errorf("verify account before %s: %w", helper.name, err))
		}
		if absent {
			if err := m.removeManagedMail(*expected); err != nil {
				return fmt.Errorf("final managed mail cleanup after account disappearance: %w", err)
			}
			absent, err = m.deletionState(name, expected, identityMatches)
			if err != nil {
				return fmt.Errorf("verify account remained absent after account disappearance: %w", err)
			}
			if !absent {
				return fmt.Errorf("account %s reappeared during final managed mail cleanup", name)
			}
			return nil
		}
		runErr := m.Runner.Run(helper.name, helper.args...)
		absent, stateErr := m.deletionState(name, expected, identityMatches)
		if stateErr != nil {
			return errors.Join(errors.Join(attemptErrs...), runErr, fmt.Errorf("verify %s removed %s: %w", helper.name, name, stateErr))
		}
		if absent {
			// Mail can be recreated while the account still exists and controlled Home
			// cleanup is in progress. Once the helper has made the account absent, sweep
			// one final time before reporting success or releasing the registry witness.
			mailErr := m.removeManagedMail(*expected)
			stillAbsent, finalStateErr := m.deletionState(name, expected, identityMatches)
			if finalStateErr == nil && !stillAbsent {
				finalStateErr = fmt.Errorf("account %s reappeared during final managed mail cleanup", name)
			}
			if runErr != nil {
				return errors.Join(errors.Join(attemptErrs...),
					fmt.Errorf("%s removed the account but reported incomplete cleanup: %w", helper.name, runErr),
					mailErr,
					finalStateErr)
			}
			if finalErr := errors.Join(mailErr, finalStateErr); finalErr != nil {
				return errors.Join(errors.Join(attemptErrs...), fmt.Errorf("final cleanup after %s: %w", helper.name, finalErr))
			}
			return nil
		}
		if runErr != nil {
			attemptErrs = append(attemptErrs, fmt.Errorf("%s: %w", helper.name, runErr))
		} else {
			attemptErrs = append(attemptErrs, fmt.Errorf("%s reported success but account %s still exists", helper.name, name))
		}
	}
	return errors.Join(append(attemptErrs, fmt.Errorf("account %s still exists after every available deletion helper", name))...)
}

func (m *Manager) lookup(name string) (Passwd, bool, error) {
	lookup := m.LookupUser
	if lookup == nil {
		lookup = Lookup
	}
	return lookup(name)
}

func (m *Manager) removeManagedHome(expected Passwd) error {
	remove := m.RemoveManagedHome
	if remove == nil {
		remove = removeManagedHome
	}
	return remove(expected)
}

func (m *Manager) removeManagedMail(expected Passwd) error {
	remove := m.RemoveManagedMail
	if remove == nil {
		remove = removeManagedMail
	}
	return remove(expected)
}

// ClearManagedMailExpected removes a same-name spool only while the complete
// live passwd entry still matches expected. It is used during account creation,
// before credentials are installed, so a reused UID cannot inherit old mail.
func (m *Manager) ClearManagedMailExpected(name string, expected Passwd) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if expected.Name != name || !validate.AccountID(expected.UID) ||
		!validate.AccountID(expected.GID) || !isManagedHome(name, expected.Home) || expected.Shell == "" {
		return fmt.Errorf("invalid expected account identity for mail cleanup")
	}
	if err := m.verifyExpectedIdentity(name, expected, "before managed mail cleanup"); err != nil {
		return fmt.Errorf("verify account before managed mail cleanup: %w", err)
	}
	if err := m.removeManagedMail(expected); err != nil {
		return err
	}
	if err := m.verifyExpectedIdentity(name, expected, "after managed mail cleanup"); err != nil {
		return fmt.Errorf("verify account after managed mail cleanup: %w", err)
	}
	return nil
}

// ReconcileManagedMailAfterDeletion retries the final mail-only sweep after a
// deletion whose intent was durably recorded while the account still existed.
// The caller owns that authorization decision. This method independently requires
// the name to remain absent before and after cleanup; it never touches Home.
func (m *Manager) ReconcileManagedMailAfterDeletion(name string, uid int) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	if !validate.AccountID(uid) {
		return fmt.Errorf("invalid expected account UID for post-deletion mail cleanup")
	}
	absent, err := m.deletionState(name, nil, nil)
	if err != nil {
		return fmt.Errorf("verify account absence before managed mail cleanup: %w", err)
	}
	if !absent {
		return fmt.Errorf("account %s exists; refusing post-deletion mail cleanup", name)
	}
	if err := m.removeManagedMail(Passwd{Name: name, UID: uid}); err != nil {
		return err
	}
	absent, err = m.deletionState(name, nil, nil)
	if err != nil {
		return fmt.Errorf("verify account absence after managed mail cleanup: %w", err)
	}
	if !absent {
		return fmt.Errorf("account %s reappeared during post-deletion mail cleanup", name)
	}
	return nil
}

func validateHomeRemoval(expected Passwd) error {
	if !isManagedHome(expected.Name, expected.Home) {
		return fmt.Errorf("account home %q is not a dedicated managed path", expected.Home)
	}
	if err := fsutil.RootSafeDir(managedHomeRoot); err != nil {
		return fmt.Errorf("managed home parent is unsafe: %w", err)
	}
	fi, err := os.Lstat(expected.Home)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect account home %s: %w", expected.Home, err)
	}
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("account home %s is not a real directory", expected.Home)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int64(st.Uid) != int64(expected.UID) || int64(st.Gid) != int64(expected.GID) {
			return fmt.Errorf("account home %s owner does not match uid/gid %d:%d", expected.Home, expected.UID, expected.GID)
		}
	}
	if err := refuseMountsUnder(expected.Home); err != nil {
		return err
	}
	return nil
}

func isManagedHome(name, home string) bool {
	return validate.Username(name) && home == managedHome(name)
}

func prepareManagedHome(name string) error {
	if !validate.Username(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	if err := fsutil.RootSafeDir(managedHomeRoot); err != nil {
		return fmt.Errorf("managed home parent is unsafe: %w", err)
	}
	home := managedHome(name)
	if _, err := os.Lstat(home); err == nil {
		return fmt.Errorf("managed home %s already exists", home)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect managed home %s: %w", home, err)
	}
	return nil
}

// createManagedHome creates an empty deterministic Home only after the account's
// selected UID has been proved idle. It never copies /etc/skel: a host-local
// skeleton can contain authorized_keys or other authentication material that is
// inappropriate for a one-time account. All mutation is relative to a pinned,
// root-owned parent directory and metadata is applied through the opened fd.
func createManagedHome(expected Passwd) error {
	if !validate.Username(expected.Name) || !validate.AccountID(expected.UID) ||
		!validate.AccountID(expected.GID) || expected.Home != managedHome(expected.Name) {
		return fmt.Errorf("invalid managed account identity for Home creation")
	}
	parentFD, err := unix.Open(managedHomeRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open managed home parent %s: %w", managedHomeRoot, err)
	}
	parent := os.NewFile(uintptr(parentFD), managedHomeRoot)
	defer parent.Close()

	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return fmt.Errorf("stat managed home parent: %w", err)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Gid != 0 || parentStat.Mode&0o022 != 0 {
		return fmt.Errorf("managed home parent is not a root-owned non-writable directory")
	}
	var namedParent unix.Stat_t
	if err := unix.Lstat(managedHomeRoot, &namedParent); err != nil {
		return fmt.Errorf("recheck managed home parent: %w", err)
	}
	if namedParent.Dev != parentStat.Dev || namedParent.Ino != parentStat.Ino || namedParent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home parent was replaced during account creation")
	}

	if err := unix.Mkdirat(parentFD, expected.Name, 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("managed home %s already exists", expected.Home)
		}
		return fmt.Errorf("create managed home %s: %w", expected.Home, err)
	}
	homeFD, err := unix.Openat(parentFD, expected.Name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open newly created managed home: %w", err)
	}
	home := os.NewFile(uintptr(homeFD), expected.Home)
	defer home.Close()

	var initial unix.Stat_t
	if err := unix.Fstat(homeFD, &initial); err != nil {
		return fmt.Errorf("stat newly created managed home: %w", err)
	}
	if initial.Mode&unix.S_IFMT != unix.S_IFDIR || initial.Uid != 0 || initial.Gid != 0 {
		return fmt.Errorf("new managed home did not begin as a root-owned directory")
	}
	if err := home.Chown(expected.UID, expected.GID); err != nil {
		return fmt.Errorf("set managed home owner: %w", err)
	}
	if err := home.Chmod(0o700); err != nil {
		return fmt.Errorf("set managed home mode: %w", err)
	}
	if err := syncCreatedHomeMetadata(home); err != nil {
		return &fsutil.DurabilityError{Operation: "managed home metadata update", Err: err}
	}
	if err := syncCreatedHomeParent(parent); err != nil {
		return &fsutil.DurabilityError{Operation: "managed home creation", Err: err}
	}

	var final, namedHome, finalParent unix.Stat_t
	if err := unix.Fstat(homeFD, &final); err != nil {
		return fmt.Errorf("verify managed home metadata: %w", err)
	}
	if final.Mode&unix.S_IFMT != unix.S_IFDIR || int64(final.Uid) != int64(expected.UID) ||
		int64(final.Gid) != int64(expected.GID) || final.Mode&0o7777 != 0o700 {
		return fmt.Errorf("managed home metadata remains unsafe after creation")
	}
	if err := unix.Fstatat(parentFD, expected.Name, &namedHome, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck managed home entry: %w", err)
	}
	if namedHome.Dev != final.Dev || namedHome.Ino != final.Ino || namedHome.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home was replaced during account creation")
	}
	if err := unix.Lstat(managedHomeRoot, &finalParent); err != nil {
		return fmt.Errorf("final recheck of managed home parent: %w", err)
	}
	if finalParent.Dev != parentStat.Dev || finalParent.Ino != parentStat.Ino || finalParent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home parent was replaced during account creation")
	}
	return nil
}

func validateCreatedHome(expected Passwd) error {
	if !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) {
		return fmt.Errorf("invalid account owner %d:%d", expected.UID, expected.GID)
	}
	if err := validateHomeRemoval(expected); err != nil {
		return err
	}
	if _, err := os.Lstat(expected.Home); os.IsNotExist(err) {
		return fmt.Errorf("account home %s was not created", expected.Home)
	} else if err != nil {
		return fmt.Errorf("inspect account home %s: %w", expected.Home, err)
	}
	return nil
}

func removeManagedHome(expected Passwd) error {
	if err := validateHomeRemoval(expected); err != nil {
		return fmt.Errorf("refusing managed home cleanup: %w", err)
	}
	if err := removeHomeTree(expected); err != nil {
		return fmt.Errorf("remove managed home %s: %w", expected.Home, err)
	}
	return nil
}

var managedMailRoots = []string{"/var/mail", "/var/spool/mail"}

var syncRemovalDirectory = func(dir *os.File) error { return dir.Sync() }

// unlinkManagedMailAt is indirected so a unit test can force the stat/unlink
// disappearance race without relying on scheduler timing.
var unlinkManagedMailAt = unix.Unlinkat

func syncRemovalParent(dir *os.File, operation string) error {
	if err := syncRemovalDirectory(dir); err != nil {
		return &fsutil.DurabilityError{Operation: operation, Err: err}
	}
	return nil
}

func syncAndConfirmManagedMailAbsent(dir *os.File, root, name, operation string) error {
	if err := syncRemovalParent(dir, operation); err != nil {
		return err
	}
	var spool unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &spool, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err == nil {
			return fmt.Errorf("managed mail spool %s/%s reappeared during cleanup", root, name)
		}
		return fmt.Errorf("verify managed mail spool absence after directory sync %s/%s: %w", root, name, err)
	}
	return nil
}

// removeManagedMail removes only a conventional single-file system mailbox
// still owned by the captured account UID. Account helpers are intentionally
// invoked without recursive-home flags, so this preserves the mail-spool part of
// userdel -r without delegating Home traversal to a name-scoped helper.
func removeManagedMail(expected Passwd) error {
	if !validate.Username(expected.Name) || !validate.AccountID(expected.UID) {
		return fmt.Errorf("invalid expected account identity for mail cleanup")
	}
	return visitManagedMailRoots(func(root string) error {
		return removeManagedMailAt(root, expected)
	})
}

// validateManagedMailRoots checks directory metadata before useradd. The real
// cleanup opens and validates each root again while the selected UID is bound.
func validateManagedMailRoots() error {
	return visitManagedMailRoots(func(root string) error {
		dir, err := openManagedMailRoot(root)
		if err != nil {
			return err
		}
		return dir.Close()
	})
}

func visitManagedMailRoots(visit func(string) error) error {
	allowed := make(map[string]bool, len(managedMailRoots))
	for _, root := range managedMailRoots {
		clean := filepath.Clean(root)
		if root == "" || !filepath.IsAbs(root) || clean != root || clean == string(filepath.Separator) {
			return fmt.Errorf("unsafe managed mail root %q", root)
		}
		allowed[clean] = true
	}
	seen := make(map[string]bool, len(managedMailRoots))
	for _, root := range managedMailRoots {
		if _, err := os.Lstat(root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return fmt.Errorf("inspect managed mail root %s: %w", root, err)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return fmt.Errorf("resolve managed mail root %s: %w", root, err)
		}
		resolved = filepath.Clean(resolved)
		if !allowed[resolved] {
			return fmt.Errorf("managed mail root %s resolves outside the accepted spool directories", root)
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		if err := visit(resolved); err != nil {
			return err
		}
	}
	return nil
}

func openManagedMailRoot(root string) (*os.File, error) {
	dir, err := os.OpenFile(root, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open managed mail root %s: %w", root, err)
	}
	fi, err := dir.Stat()
	if err != nil {
		dir.Close()
		return nil, fmt.Errorf("stat managed mail root %s: %w", root, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	mode := fi.Mode()
	worldWritableWithoutSticky := mode.Perm()&0o002 != 0 && mode&os.ModeSticky == 0
	if !ok || !fi.IsDir() || st.Uid != 0 || mode&os.ModeSetuid != 0 || worldWritableWithoutSticky {
		dir.Close()
		return nil, fmt.Errorf("managed mail root %s is not a safe root-owned directory (world-writable roots require sticky protection and setuid is forbidden)", root)
	}
	return dir, nil
}

func removeManagedMailAt(root string, expected Passwd) error {
	dir, err := openManagedMailRoot(root)
	if err != nil {
		return err
	}
	defer dir.Close()

	var spool unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), expected.Name, &spool, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		// This can be a retry after unlink succeeded but the previous directory sync
		// failed. Re-sync the observed absence before allowing the UID to be released.
		return syncAndConfirmManagedMailAbsent(dir, root, expected.Name, "managed mail spool absence confirmation")
	}
	if err != nil {
		return fmt.Errorf("inspect managed mail spool %s/%s: %w", root, expected.Name, err)
	}
	if spool.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("managed mail spool %s/%s is not a regular file", root, expected.Name)
	}
	if int64(spool.Uid) != int64(expected.UID) {
		return fmt.Errorf("managed mail spool %s/%s owner does not match uid %d", root, expected.Name, expected.UID)
	}
	if err := unlinkManagedMailAt(int(dir.Fd()), expected.Name, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return syncAndConfirmManagedMailAbsent(dir, root, expected.Name, "managed mail spool absence confirmation")
		}
		return fmt.Errorf("remove managed mail spool %s/%s: %w", root, expected.Name, err)
	}
	if err := unix.Fstatat(int(dir.Fd()), expected.Name, &spool, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err == nil {
			return fmt.Errorf("managed mail spool %s/%s reappeared during cleanup", root, expected.Name)
		}
		return fmt.Errorf("verify managed mail spool removal %s/%s: %w", root, expected.Name, err)
	}
	return syncAndConfirmManagedMailAbsent(dir, root, expected.Name, "managed mail spool removal")
}

const (
	maxManagedHomeEntries     = 100_000
	maxManagedHomeDepth       = 128
	managedHomeRemovalTimeout = 2 * time.Minute
	managedHomeReadBatch      = 128
)

type homeRemovalBudget struct {
	remaining int
	maxDepth  int
	deadline  time.Time
	now       func() time.Time
	device    uint64
}

func (b *homeRemovalBudget) check(path string, depth int) error {
	now := b.now
	if now == nil {
		now = time.Now
	}
	if !now().Before(b.deadline) {
		return fmt.Errorf("managed home cleanup exceeded its time limit at %s", path)
	}
	if depth > b.maxDepth {
		return fmt.Errorf("managed home cleanup exceeded its depth limit at %s", path)
	}
	return nil
}

func (b *homeRemovalBudget) consume(path string, depth int) error {
	if err := b.check(path, depth); err != nil {
		return err
	}
	if b.remaining <= 0 {
		return fmt.Errorf("managed home cleanup exceeded its entry limit at %s", path)
	}
	b.remaining--
	return nil
}

// removeHomeTreeBounded removes a managed Home through directory-relative file
// descriptors. It never follows a symlink and checks fixed entry/depth limits and
// a cooperative deadline between filesystem calls. The deadline cannot interrupt
// one blocked call. A limit failure may leave a partially cleaned tree; callers
// retain the disabled account and registry witness, so a later retry can continue
// without freeing the UID or username.
func removeHomeTreeBounded(expected Passwd) error {
	budget := &homeRemovalBudget{
		remaining: maxManagedHomeEntries,
		maxDepth:  maxManagedHomeDepth,
		deadline:  time.Now().Add(managedHomeRemovalTimeout),
	}
	return removeHomeTreeWithin(expected, budget)
}

func removeHomeTreeWithin(expected Passwd, budget *homeRemovalBudget) error {
	if budget == nil || budget.remaining <= 0 || budget.maxDepth < 0 || budget.deadline.IsZero() {
		return fmt.Errorf("invalid managed home cleanup budget")
	}
	if !isManagedHome(expected.Name, expected.Home) || !validate.AccountID(expected.UID) || !validate.AccountID(expected.GID) {
		return fmt.Errorf("invalid expected account identity for managed home cleanup")
	}
	parentPath := filepath.Dir(expected.Home)
	if parentPath != managedHomeRoot || filepath.Base(expected.Home) != expected.Name {
		return fmt.Errorf("managed home %q is not directly beneath %q", expected.Home, managedHomeRoot)
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open managed home parent %s: %w", parentPath, err)
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	if parent == nil {
		_ = unix.Close(parentFD)
		return fmt.Errorf("adopt managed home parent descriptor")
	}
	defer parent.Close()

	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return fmt.Errorf("stat managed home parent %s: %w", parentPath, err)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Gid != 0 || parentStat.Mode&0o022 != 0 {
		return fmt.Errorf("managed home parent %s is not a root-owned, non-writable directory", parentPath)
	}
	if err := refuseMountsUnder(expected.Home); err != nil {
		return err
	}

	var rootStat unix.Stat_t
	err = unix.Fstatat(parentFD, expected.Name, &rootStat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		// A previous attempt may have removed the root but failed to sync /home.
		// Confirm the already-visible absence durably before account deletion.
		return syncRemovalParent(parent, "managed home absence confirmation")
	}
	if err != nil {
		return fmt.Errorf("inspect managed home %s: %w", expected.Home, err)
	}
	if rootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed home %s is not a real directory", expected.Home)
	}
	if int64(rootStat.Uid) != int64(expected.UID) || int64(rootStat.Gid) != int64(expected.GID) {
		return fmt.Errorf("managed home %s owner does not match uid/gid %d:%d", expected.Home, expected.UID, expected.GID)
	}
	budget.device = uint64(rootStat.Dev)
	if err := removeHomeEntryAt(parentFD, expected.Name, expected.Home, 0, rootStat, budget); err != nil {
		return err
	}
	return syncRemovalParent(parent, "managed home removal")
}

func removeHomeEntryAt(parentFD int, name, displayPath string, depth int, inspected unix.Stat_t, budget *homeRemovalBudget) error {
	if err := budget.consume(displayPath, depth); err != nil {
		return err
	}
	if uint64(inspected.Dev) != budget.device {
		return fmt.Errorf("refusing managed home cleanup across a filesystem boundary at %s", displayPath)
	}
	if inspected.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(parentFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove managed home entry %s: %w", displayPath, err)
		}
		return nil
	}

	dirFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open managed home directory %s: %w", displayPath, err)
	}
	dir := os.NewFile(uintptr(dirFD), displayPath)
	if dir == nil {
		_ = unix.Close(dirFD)
		return fmt.Errorf("adopt managed home directory descriptor for %s", displayPath)
	}

	var opened unix.Stat_t
	if err := unix.Fstat(dirFD, &opened); err != nil {
		_ = dir.Close()
		return fmt.Errorf("stat opened managed home directory %s: %w", displayPath, err)
	}
	if opened.Dev != inspected.Dev || opened.Ino != inspected.Ino {
		_ = dir.Close()
		return fmt.Errorf("managed home directory changed while opening %s", displayPath)
	}

	for {
		if err := budget.check(displayPath, depth); err != nil {
			_ = dir.Close()
			return err
		}
		entries, readErr := dir.ReadDir(managedHomeReadBatch)
		for _, entry := range entries {
			childName := entry.Name()
			if childName == "" || childName == "." || childName == ".." || filepath.Base(childName) != childName {
				_ = dir.Close()
				return fmt.Errorf("unsafe managed home entry name %q under %s", childName, displayPath)
			}
			var childStat unix.Stat_t
			if err := unix.Fstatat(dirFD, childName, &childStat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				_ = dir.Close()
				return fmt.Errorf("inspect managed home entry %s: %w", filepath.Join(displayPath, childName), err)
			}
			if err := removeHomeEntryAt(dirFD, childName, filepath.Join(displayPath, childName), depth+1, childStat, budget); err != nil {
				_ = dir.Close()
				return err
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = dir.Close()
			return fmt.Errorf("read managed home directory %s: %w", displayPath, readErr)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if len(entries) == 0 {
			_ = dir.Close()
			return fmt.Errorf("read managed home directory %s made no progress", displayPath)
		}
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close managed home directory %s: %w", displayPath, err)
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove managed home directory %s: %w", displayPath, err)
	}
	return nil
}

var (
	refuseMountsUnder = mountinfo.RefuseUnder
	removeHomeTree    = removeHomeTreeBounded
)

func (m *Manager) deletionState(name string, expected *Passwd, identityMatches func(Passwd, Passwd) bool) (absent bool, err error) {
	current, exists, err := m.lookup(name)
	if err != nil {
		return false, err
	}
	if !exists {
		nameInUse := m.NameInUse
		if nameInUse == nil {
			nameInUse = NameInUse
		}
		inUse, err := nameInUse(name)
		if err != nil {
			return false, fmt.Errorf("confirm account absence through NSS: %w", err)
		}
		if inUse {
			return false, fmt.Errorf("account name %s remains present through NSS after local account disappearance", name)
		}
		return true, nil
	}
	if expected != nil && (identityMatches == nil || !identityMatches(*expected, current)) {
		return false, fmt.Errorf("account identity changed during deletion; refusing a name-scoped fallback")
	}
	return false, nil
}

var (
	procRoot          = "/proc"
	readProcDirectory = os.ReadDir
	pidfdOpen         = unix.PidfdOpen
	pidfdSendSignal   = unix.PidfdSendSignal
	closeFD           = unix.Close
	terminateSleep    = time.Sleep
	processScanSleep  = time.Sleep
)

// terminateSweeps bounds the SIGKILL retry loop. A handful of passes clears any
// realistic fork loop; the bound keeps a process that cannot be killed at all (an
// uninterruptible-sleep task) from spinning here forever while holding up revoke.
const terminateSweeps = 5

const (
	// processScanAttempts bounds retries when a numeric /proc entry disappears
	// between the directory snapshot and its credential read. Such a task may have
	// forked a child that was not present in the old snapshot, so an unstable empty
	// scan cannot prove that a UID is free.
	processScanAttempts = 10

	// A PID can exit, fork a child, and be reused before its status is read. The
	// replacement then makes one old directory snapshot look stable even though the
	// child was not listed in it. A second stable empty scan catches that descendant.
	processEmptyConfirmations = 2
	processScanRetryDelay     = time.Millisecond
)

// CheckPidfd verifies that this kernel and sandbox allow pidfd operations. The
// revoke path relies on pidfds so a PID reused between inspection and signalling
// can never redirect a root-issued signal at an unrelated process.
func CheckPidfd() error {
	fd, err := pidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd is unavailable (Linux 5.3+ and permission from the process sandbox are required): %w", err)
	}
	signalErr := pidfdSendSignal(fd, 0, nil, 0)
	closeErr := closeFD(fd)
	var errs []error
	if signalErr != nil {
		errs = append(errs, fmt.Errorf("pidfd signalling is unavailable (permission from the process sandbox is required): %w", signalErr))
	}
	if closeErr != nil {
		errs = append(errs, fmt.Errorf("close pidfd capability probe: %w", closeErr))
	}
	return errors.Join(errs...)
}

// TerminateProcesses signals SIGTERM then, after a grace period, SIGKILL to every
// process owned by uid. It no-ops for a non-positive uid (never root/all). Done
// natively via /proc (no pkill dependency).
//
// The SIGKILL pass repeats until stable scans find nothing left (or the bound is hit),
// because one snapshot-then-signal pass loses to a process that is actively
// forking: a child created after the scan is never in the list, and would survive
// the revoke as an orphan owned by a uid that is about to be recycled. Re-scanning
// after each kill reaches newly visible descendants; a lineage that keeps escaping
// the bounded sweeps makes revoke fail closed instead of releasing the UID.
func TerminateProcesses(uid int) error {
	if uid < 1 {
		return nil
	}
	if !validate.AccountID(uid) {
		return fmt.Errorf("refusing invalid Linux UID %d", uid)
	}
	var errs []error
	pids, err := signalUID(unix.SIGTERM, uid)
	if err != nil {
		errs = append(errs, fmt.Errorf("signal UID %d processes with SIGTERM: %w", uid, err))
	}
	if len(pids) != 0 {
		terminateSleep(2 * time.Second)
	}
	var survivors []int
	for i := 0; i < terminateSweeps; i++ {
		_, err = signalUID(unix.SIGKILL, uid)
		if err != nil {
			errs = append(errs, fmt.Errorf("signal UID %d processes with SIGKILL: %w", uid, err))
		}
		// signalUID reports only tasks reached from its directory snapshot. A task
		// can fork and exit between that snapshot and pidfdOpen, leaving no signalled
		// PID while its child was never in the snapshot. Only consecutive stable
		// per-thread credential scans can confirm that the UID is now empty.
		survivors, err = processesForUID(uid)
		if err != nil {
			errs = append(errs, fmt.Errorf("scan for UID %d after SIGKILL: %w", uid, err))
		} else if len(survivors) == 0 {
			return errors.Join(errs...)
		}
		if i+1 < terminateSweeps {
			terminateSleep(100 * time.Millisecond)
		}
	}
	if len(survivors) != 0 {
		errs = append(errs, fmt.Errorf("UID %d still has surviving processes %v after SIGKILL", uid, survivors))
	}
	return errors.Join(errs...)
}

// signalUID first filters every live thread by credentials, then opens a pidfd for
// its thread-group leader and rechecks the group before signalling through the
// descriptor. Linux credentials are per-thread, and a leader can be a zombie while
// another thread still runs. The first filter avoids requiring pidfd access to
// every unrelated host process; the second check plus the pidfd prevents PID reuse
// from redirecting a signal at an unrelated process.
func signalUID(sig unix.Signal, uid int) ([]int, error) {
	entries, err := readProcDirectory(procRoot)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", procRoot, err)
	}
	var signalled []int
	var errs []error
	for _, e := range entries {
		tgid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		matched, _, inspectErr := processGroupHasUID(tgid, uid)
		if inspectErr != nil {
			errs = append(errs, fmt.Errorf("read thread credentials for process %d: %w", tgid, inspectErr))
			continue
		}
		if !matched {
			continue
		}
		fd, err := pidfdOpen(tgid, 0)
		if err == unix.ESRCH || err == unix.ENOENT {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("open pidfd for process %d: %w", tgid, err))
			continue
		}
		matched, _, inspectErr = processGroupHasUID(tgid, uid)
		if inspectErr != nil {
			errs = append(errs, fmt.Errorf("recheck thread credentials for process %d: %w", tgid, inspectErr))
			if closeErr := closeFD(fd); closeErr != nil {
				errs = append(errs, fmt.Errorf("close pidfd for process %d: %w", tgid, closeErr))
			}
			continue
		}
		if !matched {
			if closeErr := closeFD(fd); closeErr != nil {
				errs = append(errs, fmt.Errorf("close pidfd for process %d: %w", tgid, closeErr))
			}
			continue
		}
		signalErr := pidfdSendSignal(fd, sig, nil, 0)
		closeErr := closeFD(fd)
		if signalErr == nil {
			signalled = append(signalled, tgid)
		} else if signalErr != unix.ESRCH {
			errs = append(errs, fmt.Errorf("signal process %d: %w", tgid, signalErr))
		}
		if closeErr != nil {
			errs = append(errs, fmt.Errorf("close pidfd for process %d: %w", tgid, closeErr))
		}
	}
	sort.Ints(signalled)
	return signalled, errors.Join(errs...)
}

func processesForUID(uid int) ([]int, error) {
	stableEmpty := 0
	for attempt := 0; attempt < processScanAttempts; attempt++ {
		pids, stable, err := processSnapshotForUID(uid)
		if err != nil {
			return nil, err
		}
		// Finding even one live task is conclusive. Empty results need consecutive
		// stable scans because PID reuse can hide an old snapshotted parent without
		// producing ENOENT while its new child was absent from that old snapshot.
		if len(pids) != 0 {
			return pids, nil
		}
		if !stable {
			stableEmpty = 0
			continue
		}
		stableEmpty++
		if stableEmpty == processEmptyConfirmations {
			return nil, nil
		}
		processScanSleep(processScanRetryDelay)
	}
	return nil, fmt.Errorf("scan %s: no consecutive stable empty process snapshots after %d attempts", procRoot, processScanAttempts)
}

func processSnapshotForUID(uid int) ([]int, bool, error) {
	entries, err := readProcDirectory(procRoot)
	if err != nil {
		return nil, false, fmt.Errorf("scan %s: %w", procRoot, err)
	}
	var pids []int
	stable := true
	for _, entry := range entries {
		tgid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		matched, groupStable, err := processGroupHasUID(tgid, uid)
		if err != nil {
			return nil, false, fmt.Errorf("read thread credentials for process %d: %w", tgid, err)
		}
		if !groupStable {
			stable = false
		}
		if matched {
			pids = append(pids, tgid)
		}
	}
	sort.Ints(pids)
	return pids, stable, nil
}

// processGroupHasUID inspects every thread because Linux credentials are
// per-thread and the thread-group leader may already be a zombie while workers
// remain executable. It reports an unstable snapshot when a listed group or task
// disappears before its status can be read; callers may act on a positive match,
// but must never use an unstable negative result as proof that the UID is absent.
func processGroupHasUID(tgid, uid int) (matched, stable bool, err error) {
	taskRoot := filepath.Join(procRoot, strconv.Itoa(tgid), "task")
	entries, err := readProcDirectory(taskRoot)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("scan %s: %w", taskRoot, err)
	}
	stable = true
	numericTasks := 0
	for _, entry := range entries {
		tid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil {
			continue
		}
		numericTasks++
		status, readErr := readProcTaskStatus(tgid, tid)
		if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, unix.ESRCH) {
			stable = false
			continue
		}
		if readErr != nil {
			return false, false, fmt.Errorf("read credentials for task %d/%d: %w", tgid, tid, readErr)
		}
		// Zombie/dead threads cannot execute or fork. A zombie leader does not make
		// the group inactive: another task entry may still describe a live worker.
		if !status.inactive && containsUID(status.uids, uid) {
			return true, stable, nil
		}
	}
	if numericTasks == 0 {
		stable = false
	}
	return false, stable, nil
}

func containsUID(uids [4]int, uid int) bool {
	for _, candidate := range uids {
		if candidate == uid {
			return true
		}
	}
	return false
}

type processStatus struct {
	uids     [4]int
	inactive bool
}

// readProcTaskStatus returns Linux's real, effective, saved-set, and filesystem
// UIDs and whether one task is already a zombie/dead thread awaiting reaping.
func readProcTaskStatus(tgid, tid int) (processStatus, error) {
	// Whole-file read: a scanner that errored before the Uid: line would drop this
	// task from the SIGKILL sweep silently. /proc/<tgid>/task/<tid>/status is tiny.
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(tgid), "task", strconv.Itoa(tid), "status"))
	if err != nil {
		return processStatus{}, err
	}
	var status processStatus
	foundUID := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "State:"):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return processStatus{}, fmt.Errorf("malformed State line")
			}
			status.inactive = fields[1] == "Z" || fields[1] == "X"
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			if len(fields) != 5 {
				return processStatus{}, fmt.Errorf("malformed Uid line")
			}
			for i := range status.uids {
				parsed, err := strconv.Atoi(fields[i+1])
				if err != nil || !validate.KernelID(parsed) {
					return processStatus{}, fmt.Errorf("malformed Uid value %q", fields[i+1])
				}
				status.uids[i] = parsed
			}
			foundUID = true
		}
	}
	if !foundUID {
		return processStatus{}, fmt.Errorf("status has no Uid line")
	}
	return status, nil
}
