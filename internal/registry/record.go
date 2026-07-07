// Package registry stores the tool-managed temporary accounts. This file defines
// the v2 on-disk record format (a tab-separated line per account) and its
// parsing/formatting; the locked file store (flock, atomic rewrite, symlink
// guards) is added in a later phase.
//
// v2 is a clean break from v1: a schema header marks the format, and the field
// set drops v1's legacy "nopasswd" column.
package registry

import (
	"strconv"
	"strings"
)

// Header is the first line of a v2 registry file; it also carries the schema
// version so a future format change is detectable.
const Header = "# linux-temp-admin registry v2"

// fieldCount is the number of tab-separated fields per record line.
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
	}, "\t")
}

// ParseLine parses one registry line into a Record. It returns ok=false for the
// header, blank lines, and lines with too few fields (which are ignored rather
// than treated as corrupt records). Extra trailing fields are tolerated.
func ParseLine(line string) (Record, bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return Record{}, false
	}
	f := strings.Split(line, "\t")
	if len(f) < fieldCount {
		return Record{}, false
	}
	port, _ := strconv.Atoi(f[5])
	return Record{
		User:        f[0],
		Created:     f[1],
		Expires:     f[2],
		Sudo:        f[3] == "yes",
		Host:        f[4],
		Port:        port,
		Fingerprint: f[6],
		AutoRevoke:  f[7] == "yes",
		AutoUnit:    f[8],
	}, true
}
