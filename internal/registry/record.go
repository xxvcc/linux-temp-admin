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

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// Header is the current registry schema. v5 records monotonic identity
// allocation and the durable asynchronous deletion quarantine.
const Header = "# linux-temp-admin registry v5"

const legacyHeaderV2 = "# linux-temp-admin registry v2"
const legacyHeaderV3 = "# linux-temp-admin registry v3"
const legacyHeaderV4 = "# linux-temp-admin registry v4"

const (
	legacyFieldCount    = 9
	legacyMaxFieldCount = 11
	legacyV3FieldCount  = 13
	legacyV4FieldCount  = 14
	currentFieldCount   = 17
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

// Column indexes are retained while migrating deployed v2/v3/v4 rows to v5.
const uidField = 9
const generationField = 10
const pendingField = 11
const identityBoundField = 12
const deletionStartedField = 13
const sequentialIDField = 14
const quarantineUntilField = 15
const quarantineUnitField = 16

// TSV renders the record as one tab-separated line (no trailing newline).
func (r Record) TSV() string {
	return strings.Join([]string{
		sanitize(r.User),
		sanitize(r.Created),
		sanitize(r.Expires),
		boolYN(r.Sudo),
		sanitize(r.Host),
		strconv.Itoa(r.Port),
		sanitize(r.Fingerprint),
		boolYN(r.AutoRevoke),
		sanitize(r.AutoUnit),
		strconv.Itoa(r.UID), // mandatory since v3; legacy v2 rows are migrated on load
		sanitize(r.Generation),
		boolYN(r.Pending),
		boolYN(r.IdentityBound),
		boolYN(r.DeletionStarted),
		boolYN(r.SequentialID),
		sanitize(r.QuarantineUntil),
		sanitize(r.QuarantineUnit),
	}, "\t")
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
	f := strings.Split(line, "\t")
	if len(f) < minFields || len(f) > maxFields {
		if minFields == maxFields {
			return Record{}, false, fmt.Errorf("record has %d fields, want exactly %d", len(f), minFields)
		}
		return Record{}, false, fmt.Errorf("record has %d fields, want %d..%d", len(f), minFields, maxFields)
	}
	if !validate.Username(f[0]) {
		return Record{}, false, fmt.Errorf("invalid username %q", f[0])
	}
	port, err := strconv.Atoi(f[5])
	if err != nil {
		return Record{}, false, fmt.Errorf("invalid port %q", f[5])
	}
	if (f[3] != "yes" && f[3] != "no") || (f[7] != "yes" && f[7] != "no") {
		return Record{}, false, fmt.Errorf("invalid boolean field")
	}
	rec := Record{
		User:        f[0],
		Created:     f[1],
		Expires:     f[2],
		Sudo:        f[3] == "yes",
		Host:        f[4],
		Port:        port,
		Fingerprint: f[6],
		AutoRevoke:  f[7] == "yes",
		AutoUnit:    f[8],
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
	if !validate.Port(rec.Port) && !(rec.DeletionStarted && !rec.IdentityBound && rec.Port == 0) {
		return Record{}, false, fmt.Errorf("invalid port %q", f[5])
	}
	if rec.IdentityBound && !validate.Generation(rec.Generation) {
		return Record{}, false, fmt.Errorf("identity-bound record has no valid generation")
	}
	if rec.IdentityBound && !rec.Pending && !validate.AccountID(rec.UID) {
		return Record{}, false, fmt.Errorf("completed identity-bound record has no valid uid")
	}
	if rec.DeletionStarted && !validate.AccountID(rec.UID) {
		return Record{}, false, fmt.Errorf("deletion-started record has no valid uid")
	}
	if rec.DeletionStarted && !rec.IdentityBound && rec.Generation != "" {
		return Record{}, false, fmt.Errorf("uid-only deletion-started record carries a generation")
	}
	if rec.SequentialID && (!rec.IdentityBound || !validate.AccountID(rec.UID)) {
		return Record{}, false, fmt.Errorf("sequential identity record is not safely identity-bound")
	}
	if rec.QuarantineUntil != "" {
		deadline, err := time.Parse(time.RFC3339, rec.QuarantineUntil)
		if err != nil || deadline.Location() != time.UTC {
			return Record{}, false, fmt.Errorf("invalid quarantine deadline %q", rec.QuarantineUntil)
		}
		if !rec.DeletionStarted || !rec.IdentityBound {
			return Record{}, false, fmt.Errorf("quarantine requires an identity-bound deletion row")
		}
		if rec.QuarantineUnit == "" {
			return Record{}, false, fmt.Errorf("quarantine has no scheduled finalizer")
		}
		if rec.QuarantineUnit != config.QuarantineUnitPrefix+rec.User {
			return Record{}, false, fmt.Errorf("invalid quarantine unit %q", rec.QuarantineUnit)
		}
	} else if rec.QuarantineUnit != "" {
		return Record{}, false, fmt.Errorf("quarantine unit has no deadline")
	} else if rec.DeletionStarted && rec.Pending {
		return Record{}, false, fmt.Errorf("pending deletion recovery requires a durable quarantine")
	}
	return rec, true, nil
}
