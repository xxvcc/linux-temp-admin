package user

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
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

// IdentityAllocationSnapshot is one bounded read of the local UID/GID allocation
// policy and account databases. Lower and Upper are the overlap of login.defs'
// ordinary UID and GID ranges. CurrentHighest is the greatest passwd UID/GID or
// group GID currently present inside that overlap; zero means none was observed.
//
// The snapshot deliberately remains valid when CurrentHighest == Upper. Callers
// diagnosing or repairing allocation state still need the observed bounds when
// no further identity can currently be allocated.
type IdentityAllocationSnapshot struct {
	Lower          int
	Upper          int
	CurrentHighest int
}

// InspectIdentityAllocation validates the local allocation policy and returns a
// complete bounded snapshot without deciding whether the range is exhausted.
func InspectIdentityAllocation() (IdentityAllocationSnapshot, error) {
	uidMin, uidMax, gidMin, gidMax, err := loginIdentityBounds()
	if err != nil {
		return IdentityAllocationSnapshot{}, err
	}
	lower := uidMin
	if gidMin > lower {
		lower = gidMin
	}
	// login.defs may configure a range that reaches below the protection boundary
	// (legacy RHEL-era hosts used UID_MIN 500, and an administrator can narrow it
	// further). Honour the administrator's range only where this tool can still
	// revoke what it creates.
	if lower < minAllocatableID {
		lower = minAllocatableID
	}
	upper := uidMax
	if gidMax < upper {
		upper = gidMax
	}
	if !validate.AccountID(lower) || !validate.AccountID(upper) || lower > upper {
		return IdentityAllocationSnapshot{}, fmt.Errorf("UID/GID allocation ranges do not overlap safely")
	}
	snapshot := IdentityAllocationSnapshot{Lower: lower, Upper: upper}
	passwd, err := readPasswdDatabase(passwdPath, maxLocalPasswdBytes)
	if err != nil {
		return IdentityAllocationSnapshot{}, fmt.Errorf("read passwd database for identity allocation: %w", err)
	}
	for i, line := range strings.Split(string(passwd), "\n") {
		// Skip exactly what glibc's nss_files skips. Refusing a comment or a NIS
		// compatibility entry here hard-failed every invite on a host that carries
		// one, and told the operator the database was malformed when the system
		// itself reads it fine. Genuinely malformed records still fail closed.
		if skipNonEntryLine(line) {
			continue
		}
		pw, err := parsePasswdEntry(line)
		if err != nil {
			return IdentityAllocationSnapshot{}, fmt.Errorf("scan passwd identity at line %d: %w", i+1, err)
		}
		for _, id := range []int{pw.UID, pw.GID} {
			if id >= lower && id <= upper && id > snapshot.CurrentHighest {
				snapshot.CurrentHighest = id
			}
		}
	}
	groups, err := readPasswdDatabase(groupPath, maxLocalGroupBytes)
	if err != nil {
		return IdentityAllocationSnapshot{}, fmt.Errorf("read group database for identity allocation: %w", err)
	}
	for i, line := range strings.Split(string(groups), "\n") {
		if skipNonEntryLine(line) {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 || parts[0] == "" {
			return IdentityAllocationSnapshot{}, fmt.Errorf("malformed group entry at line %d", i+1)
		}
		gid, parseErr := strconv.Atoi(parts[2])
		if parseErr != nil || !validate.KernelID(gid) {
			return IdentityAllocationSnapshot{}, fmt.Errorf("malformed group GID at line %d", i+1)
		}
		if gid >= lower && gid <= upper && gid > snapshot.CurrentHighest {
			snapshot.CurrentHighest = gid
		}
	}
	return snapshot, nil
}

// IdentityAllocationRange returns the first numeric identity above every local
// UID and GID in the ordinary login.defs account range, plus that range's upper
// bound. The registry's durable high-water mark is applied separately, under its
// own lock, immediately before useradd.
func IdentityAllocationRange() (minimum, maximum int, err error) {
	snapshot, err := InspectIdentityAllocation()
	if err != nil {
		return 0, 0, err
	}
	if snapshot.CurrentHighest >= snapshot.Upper {
		return 0, 0, fmt.Errorf("UID/GID allocation range %d..%d is exhausted", snapshot.Lower, snapshot.Upper)
	}
	minimum = snapshot.Lower
	if snapshot.CurrentHighest >= minimum {
		minimum = snapshot.CurrentHighest + 1
	}
	return minimum, snapshot.Upper, nil
}

// minAllocatableID is the lowest identity this tool may create. It is the same
// boundary the deletion protection uses for a system-range UID, and the two must
// not drift apart: below it, an account is protected unless its registry row is
// present, identity-bound, and marker-matched, so a lost or legacy-degraded row
// makes it permanently undeletable — while the identical situation above the
// boundary still has recovery paths. Minting an identity this tool could be
// unable to revoke is exactly what it exists to prevent.
const minAllocatableID = 1000

func loginIdentityBounds() (uidMin, uidMax, gidMin, gidMax int, err error) {
	uidMin, uidMax, gidMin, gidMax = minAllocatableID, 60000, minAllocatableID, 60000
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
		if skipNonEntryLine(line) {
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

func (m *Manager) lookup(name string) (Passwd, bool, error) {
	lookup := m.LookupUser
	if lookup == nil {
		lookup = Lookup
	}
	return lookup(name)
}

// ConfirmAccountAbsent performs the same local-plus-NSS absence proof used at
// post-deletion mutation boundaries without touching any account artifact.
func (m *Manager) ConfirmAccountAbsent(name string) error {
	if err := validateMutationName(name); err != nil {
		return err
	}
	absent, err := m.deletionState(name, nil, nil)
	if err != nil {
		return err
	}
	if !absent {
		return fmt.Errorf("account %s exists", name)
	}
	return nil
}
