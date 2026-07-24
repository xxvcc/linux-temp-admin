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

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// Header is the first line of a v2 registry file; it also carries the schema
// version so a future format change is detectable.
const Header = "# linux-temp-admin registry v2"

// fieldCount is the minimum number of tab-separated fields a record line must
// have to be parsed. It stays at 9 deliberately: fields added since are appended
// and read only when present, so a registry written by an older build still
// parses here, and a registry written here still parses under an older build
// (which ignores the trailing extras). Never raise this — it would strand every
// deployed host's existing rows, leaving those accounts unrevocable.
const fieldCount = 9

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

// uidField and generationField are append-only compatibility columns.
const uidField = 9
const generationField = 10

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
		strconv.Itoa(r.UID), // appended; older builds ignore this trailing field
		sanitize(r.Generation),
	}, "\t")
}

// ParseLine parses one registry line into a Record. It returns ok=false only for
// the header and blank lines. Malformed non-empty rows are errors. Fields appended
// after the original nine are read only when present, so an older registry parses
// with them zero-valued.
func ParseLine(line string) (Record, bool, error) {
	if line == "" || strings.HasPrefix(line, "#") {
		return Record{}, false, nil
	}
	f := strings.Split(line, "\t")
	if len(f) < fieldCount {
		return Record{}, false, fmt.Errorf("record has %d fields, want at least %d", len(f), fieldCount)
	}
	if !validate.Username(f[0]) {
		return Record{}, false, fmt.Errorf("invalid username %q", f[0])
	}
	port, err := strconv.Atoi(f[5])
	if err != nil || !validate.Port(port) {
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
		if err != nil || rec.UID < 0 {
			return Record{}, false, fmt.Errorf("invalid uid %q", f[uidField])
		}
	}
	if len(f) > generationField {
		rec.Generation = f[generationField]
		if rec.Generation != "" && !validate.Generation(rec.Generation) {
			return Record{}, false, fmt.Errorf("invalid generation %q", rec.Generation)
		}
	}
	return rec, true, nil
}
