// Package registry stores the tool-managed temporary accounts. This file defines
// the on-disk record format (a tab-separated line per account) and its
// parsing/formatting; the locked file store (flock, atomic rewrite, symlink
// guards) lives in store.go.
//
// The file opens with a schema header so a future format change is detectable.
package registry

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// Header is the current registry schema. v5 records monotonic identity
// allocation and the durable asynchronous deletion quarantine.
const Header = "# linux-temp-admin registry v5"

const legacyHeaderV2 = "# linux-temp-admin registry v2"
const legacyHeaderV3 = "# linux-temp-admin registry v3"
const legacyHeaderV4 = "# linux-temp-admin registry v4"

// Field indexes are append-only: deployed v2/v3/v4 rows are migrated by width,
// so inserting or reordering a column would reinterpret durable state.
const (
	userField = iota
	createdField
	expiresField
	sudoField
	hostField
	portField
	fingerprintField
	autoRevokeField
	autoUnitField
	uidField
	generationField
	pendingField
	identityBoundField
	deletionStartedField
	sequentialIDField
	quarantineUntilField
	quarantineUnitField
	currentFieldCount
)

const (
	legacyFieldCount    = uidField
	legacyMaxFieldCount = generationField + 1
	legacyV3FieldCount  = identityBoundField + 1
	legacyV4FieldCount  = deletionStartedField + 1
)

// Record is one managed temporary account.
type Record struct {
	User        string
	Created     string // creation timestamp (display)
	Expires     string // human-readable expiry (display)
	Sudo        bool
	Host        string
	Port        int
	Fingerprint string
	AutoRevoke  bool
	AutoUnit    string // systemd unit name, "at:<id>", or empty

	// UID is the account's UID as it was at creation. Revoke uses a mismatch as
	// evidence that the account was replaced or tampered with. A match is not
	// identity proof by itself because Linux can reuse a UID after deletion; the
	// current passwd entry must still carry the managed GECOS marker.
	//
	// 0 means "not recorded" — a row written by a build older than this field.
	// A real temporary account never has uid 0 (that is protected outright), so
	// 0 is unambiguous as the unknown marker.
	UID        int
	Generation string
	// IdentityBound is true only for an account created with Generation embedded
	// in its passwd GECOS marker. Migrated v2 rows remain false even when they have
	// a generation column: released v2 accounts used one shared fixed marker.
	IdentityBound bool
	// Pending marks both a creation intent written before useradd and the pending
	// generation marker left in passwd. It is normally cleared after creation. A
	// pending row alone cannot authorize unattended deletion; after a direct
	// interactive recovery proves its full account shape, BeginQuarantine may add a
	// deletion witness while retaining this bit so later retries verify the right
	// marker.
	Pending bool
	// DeletionStarted is written after the destructive identity policy and the
	// pre-artifact quiescence checks, before controlled mail/Home cleanup and
	// userdel. If the helper removes the account but the final mail-spool sweep
	// fails, this root-owned phase witness authorizes a later retry of that narrow
	// cleanup. A generation-bound row keeps
	// its exact identity; legacy, unregistered, and rollback-pending paths become
	// non-pending UID-only recovery rows. An ordinary stale row for an account
	// removed outside the tool leaves this false.
	DeletionStarted bool
	// SequentialID proves that this account received an explicitly reserved,
	// monotonically increasing UID/GID pair. Generated-name invites with this bit
	// can skip the daemon polling delay because neither numeric identity is reused.
	// A UID-only DeletionStarted recovery row may retain this historical proof for
	// cleaning up the matching private group after the account is gone; it does not
	// authorize unattended deletion of a live account.
	SequentialID bool
	// QuarantineUntil is the UTC RFC3339 deadline after which a disabled live
	// account may be removed without another cron/at polling delay. The account
	// itself holds both its name and numeric identity until that deadline.
	QuarantineUntil string
	// QuarantineUnit records the persistent systemd timer that finishes deletion.
	// It is separate from AutoUnit so the expiry task and the quarantine handoff
	// cannot overwrite one another during a crash.
	QuarantineUnit string
}

var fieldSanitizer = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ")

// sanitize flattens tab/CR/LF so a field value can never break the TSV layout.
func sanitize(s string) string { return fieldSanitizer.Replace(s) }

func boolYN(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// TSV renders the record as one tab-separated line (no trailing newline).
func (r Record) TSV() string {
	fields := make([]string, currentFieldCount)
	fields[userField] = sanitize(r.User)
	fields[createdField] = sanitize(r.Created)
	fields[expiresField] = sanitize(r.Expires)
	fields[sudoField] = boolYN(r.Sudo)
	fields[hostField] = sanitize(r.Host)
	fields[portField] = strconv.Itoa(r.Port)
	fields[fingerprintField] = sanitize(r.Fingerprint)
	fields[autoRevokeField] = boolYN(r.AutoRevoke)
	fields[autoUnitField] = sanitize(r.AutoUnit)
	fields[uidField] = strconv.Itoa(r.UID) // mandatory since v3; legacy v2 rows are migrated on load
	fields[generationField] = sanitize(r.Generation)
	fields[pendingField] = boolYN(r.Pending)
	fields[identityBoundField] = boolYN(r.IdentityBound)
	fields[deletionStartedField] = boolYN(r.DeletionStarted)
	fields[sequentialIDField] = boolYN(r.SequentialID)
	fields[quarantineUntilField] = sanitize(r.QuarantineUntil)
	fields[quarantineUnitField] = sanitize(r.QuarantineUnit)
	return strings.Join(fields, "\t")
}

// ParseLine parses a current-schema registry line. It returns ok=false only for
// the exact current header and blank lines. Every other non-empty line, including
// one beginning with '#', must be a valid 17-column record or is corruption.
func ParseLine(line string) (Record, bool, error) {
	if line == "" || line == Header {
		return Record{}, false, nil
	}
	return parseFields(line, currentFieldCount, currentFieldCount)
}

func parseLegacyV2Line(line string) (Record, bool, error) {
	if line == "" {
		return Record{}, false, nil
	}
	return parseFields(line, legacyFieldCount, legacyMaxFieldCount)
}

func parseLegacyV3Line(line string) (Record, bool, error) {
	if line == "" {
		return Record{}, false, nil
	}
	return parseFields(line, legacyV3FieldCount, legacyV3FieldCount)
}

func parseLegacyV4Line(line string) (Record, bool, error) {
	if line == "" {
		return Record{}, false, nil
	}
	return parseFields(line, legacyV4FieldCount, legacyV4FieldCount)
}

func parseFields(line string, minFields, maxFields int) (Record, bool, error) {
	if !utf8.ValidString(line) {
		return Record{}, false, fmt.Errorf("record is not valid UTF-8")
	}
	f := strings.Split(line, "\t")
	if len(f) < minFields || len(f) > maxFields {
		if minFields == maxFields {
			return Record{}, false, fmt.Errorf("record has %d fields, want exactly %d", len(f), minFields)
		}
		return Record{}, false, fmt.Errorf("record has %d fields, want %d..%d", len(f), minFields, maxFields)
	}
	if !validate.Username(f[userField]) {
		return Record{}, false, fmt.Errorf("invalid username %q", f[userField])
	}
	port, err := strconv.Atoi(f[portField])
	if err != nil {
		return Record{}, false, fmt.Errorf("invalid port %q", f[portField])
	}
	if (f[sudoField] != "yes" && f[sudoField] != "no") ||
		(f[autoRevokeField] != "yes" && f[autoRevokeField] != "no") {
		return Record{}, false, fmt.Errorf("invalid boolean field")
	}
	rec := Record{
		User:        f[userField],
		Created:     f[createdField],
		Expires:     f[expiresField],
		Sudo:        f[sudoField] == "yes",
		Host:        f[hostField],
		Port:        port,
		Fingerprint: f[fingerprintField],
		AutoRevoke:  f[autoRevokeField] == "yes",
		AutoUnit:    f[autoUnitField],
	}
	if len(f) > uidField {
		rec.UID, err = strconv.Atoi(f[uidField])
		if err != nil || !validate.KernelID(rec.UID) {
			return Record{}, false, fmt.Errorf("invalid uid %q", f[uidField])
		}
	}
	if len(f) > generationField {
		rec.Generation = f[generationField]
		if rec.Generation != "" && !validate.Generation(rec.Generation) {
			return Record{}, false, fmt.Errorf("invalid generation %q", rec.Generation)
		}
	}
	if len(f) > pendingField {
		if f[pendingField] != "yes" && f[pendingField] != "no" {
			return Record{}, false, fmt.Errorf("invalid pending field %q", f[pendingField])
		}
		rec.Pending = f[pendingField] == "yes"
	}
	if len(f) > identityBoundField {
		if f[identityBoundField] != "yes" && f[identityBoundField] != "no" {
			return Record{}, false, fmt.Errorf("invalid identity-bound field %q", f[identityBoundField])
		}
		rec.IdentityBound = f[identityBoundField] == "yes"
	}
	if len(f) > deletionStartedField {
		if f[deletionStartedField] != "yes" && f[deletionStartedField] != "no" {
			return Record{}, false, fmt.Errorf("invalid deletion-started field %q", f[deletionStartedField])
		}
		rec.DeletionStarted = f[deletionStartedField] == "yes"
	}
	if len(f) > sequentialIDField {
		if f[sequentialIDField] != "yes" && f[sequentialIDField] != "no" {
			return Record{}, false, fmt.Errorf("invalid sequential-id field %q", f[sequentialIDField])
		}
		rec.SequentialID = f[sequentialIDField] == "yes"
	}
	if len(f) > quarantineUntilField {
		rec.QuarantineUntil = f[quarantineUntilField]
	}
	if len(f) > quarantineUnitField {
		rec.QuarantineUnit = f[quarantineUnitField]
	}
	// UID-only recovery rows created for an unregistered account have no honest
	// endpoint metadata to preserve. Port 0 is reserved for exactly that state;
	// every ordinary and migrated account row still requires a real SSH port.
	if _, err := rec.lifecycleState(); err != nil {
		if err == errInvalidRecordPort {
			return Record{}, false, fmt.Errorf("invalid port %q", f[portField])
		}
		return Record{}, false, err
	}
	return rec, true, nil
}

type recordLifecycleState uint8

const (
	recordLegacyActive recordLifecycleState = iota + 1
	recordPending
	recordActive
	recordDeletingUIDOnly
	recordDeletingBound
	recordQuarantined
)

var errInvalidRecordPort = fmt.Errorf("invalid record port")

// lifecycleState is the single cross-field model for v5 state. The booleans
// remain on Record for on-disk compatibility, but no parser or writer should
// independently invent another set of allowed combinations.
func (r Record) lifecycleState() (recordLifecycleState, error) {
	// UID-only recovery rows created for an unregistered account have no honest
	// endpoint metadata to preserve. Port 0 is reserved for exactly that state;
	// every ordinary and migrated account row still requires a real SSH port.
	if !validate.Port(r.Port) && !(r.DeletionStarted && !r.IdentityBound && r.Port == 0) {
		return 0, errInvalidRecordPort
	}
	if r.IdentityBound && !validate.Generation(r.Generation) {
		return 0, fmt.Errorf("identity-bound record has no valid generation")
	}
	if r.IdentityBound && !r.Pending && !validate.AccountID(r.UID) {
		return 0, fmt.Errorf("completed identity-bound record has no valid uid")
	}
	if r.DeletionStarted && !validate.AccountID(r.UID) {
		return 0, fmt.Errorf("deletion-started record has no valid uid")
	}
	if r.DeletionStarted && !r.IdentityBound && r.Generation != "" {
		return 0, fmt.Errorf("uid-only deletion-started record carries a generation")
	}
	if r.SequentialID && (!validate.AccountID(r.UID) || (!r.IdentityBound && !r.DeletionStarted)) {
		return 0, fmt.Errorf("sequential identity record is neither safely identity-bound nor in deletion recovery")
	}
	if r.QuarantineUntil != "" {
		deadline, err := time.Parse(time.RFC3339, r.QuarantineUntil)
		if err != nil || deadline.Location() != time.UTC {
			return 0, fmt.Errorf("invalid quarantine deadline %q", r.QuarantineUntil)
		}
		if !r.DeletionStarted || !r.IdentityBound {
			return 0, fmt.Errorf("quarantine requires an identity-bound deletion row")
		}
		if r.QuarantineUnit == "" {
			return 0, fmt.Errorf("quarantine has no scheduled finalizer")
		}
		if r.QuarantineUnit != config.QuarantineUnitPrefix+r.User {
			return 0, fmt.Errorf("invalid quarantine unit %q", r.QuarantineUnit)
		}
		return recordQuarantined, nil
	}
	if r.QuarantineUnit != "" {
		return 0, fmt.Errorf("quarantine unit has no deadline")
	}
	if r.DeletionStarted && r.Pending {
		return 0, fmt.Errorf("pending deletion recovery requires a durable quarantine")
	}
	if r.DeletionStarted {
		if r.IdentityBound {
			return recordDeletingBound, nil
		}
		return recordDeletingUIDOnly, nil
	}
	if r.Pending {
		return recordPending, nil
	}
	if r.IdentityBound {
		return recordActive, nil
	}
	return recordLegacyActive, nil
}
