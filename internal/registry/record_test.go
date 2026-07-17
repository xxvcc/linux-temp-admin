package registry

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Record{
		User:        "xxvcc-a1b2c3",
		Created:     "2026-07-07 12:00:00 UTC",
		Expires:     "2026-07-08 12:00:00 UTC",
		Sudo:        true,
		Host:        "server-1.example.com",
		Port:        22,
		Fingerprint: "SHA256:abcdef",
		AutoRevoke:  true,
		AutoUnit:    "linux-temp-admin-v2-revoke-xxvcc-a1b2c3",
	}
	line := in.TSV()
	if strings.Contains(line, "\n") {
		t.Fatalf("TSV must be a single line: %q", line)
	}
	got, ok := ParseLine(line)
	if !ok {
		t.Fatalf("ParseLine failed for %q", line)
	}
	if got != in {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

func TestSanitizeFlattensControlChars(t *testing.T) {
	in := Record{User: "u\tx", Host: "a\nb\rc", Port: 22}
	line := in.TSV()
	// A field value must never be able to add fields of its own. The count is
	// derived from what TSV writes today (fieldCount is only the parser's MINIMUM,
	// deliberately frozen at the original nine so older rows still parse), so this
	// keeps testing the injection property rather than the column count.
	if n := len(strings.Split(line, "\t")); n != len(strings.Split(Record{}.TSV(), "\t")) {
		t.Errorf("embedded control chars broke the layout: %d fields (%q)", n, line)
	}
	got, ok := ParseLine(line)
	if !ok {
		t.Fatal("ParseLine failed after sanitize")
	}
	if strings.ContainsAny(got.User+got.Host, "\t\r\n") {
		t.Errorf("sanitize left control chars: user=%q host=%q", got.User, got.Host)
	}
}

func TestParseLineRejectsNonRecords(t *testing.T) {
	for _, line := range []string{"", Header, "# comment", "too\tfew\tfields"} {
		if _, ok := ParseLine(line); ok {
			t.Errorf("ParseLine(%q) = ok, want rejected", line)
		}
	}
}

// TestParseLineAcceptsLegacyNineFieldRow pins the compatibility contract that
// makes appending the UID safe. A row written by a build from before the field
// existed MUST still parse — if it did not, every account already on a deployed
// host would become unparseable, and therefore unrevocable.
func TestParseLineAcceptsLegacyNineFieldRow(t *testing.T) {
	legacy := strings.Join([]string{
		"xxvcc-a1", "2026-07-07 12:00:00 UTC", "2026-07-08 12:00 CST",
		"yes", "203.0.113.5", "22", "SHA256:abc", "yes", "unit.timer",
	}, "\t")
	got, ok := ParseLine(legacy)
	if !ok {
		t.Fatal("a legacy 9-field row must still parse")
	}
	if got.User != "xxvcc-a1" || got.Port != 22 || !got.Sudo || got.AutoUnit != "unit.timer" {
		t.Errorf("legacy row parsed wrong: %+v", got)
	}
	if got.UID != 0 {
		t.Errorf("UID = %d, want 0 (the 'not recorded' marker) for a legacy row", got.UID)
	}
}

// TestTSVIsReadableByAnOlderParser pins the other direction: a row written now
// must still parse under a build that knows only the original nine fields, so a
// downgraded binary can still revoke what this one created.
func TestTSVIsReadableByAnOlderParser(t *testing.T) {
	line := Record{User: "xxvcc-a1", Port: 22, UID: 1001, AutoUnit: "u.timer"}.TSV()
	f := strings.Split(line, "\t")
	if len(f) < 9 {
		t.Fatalf("row has %d fields; an older parser requires at least 9", len(f))
	}
	// Simulate the old parser: it reads f[0..8] and ignores anything after.
	if f[0] != "xxvcc-a1" || f[5] != "22" || f[8] != "u.timer" {
		t.Errorf("the original nine columns moved: %q", f[:9])
	}
	// And the UID must be the appended one, not a repurposed old column.
	if f[9] != "1001" {
		t.Errorf("UID column = %q, want it appended last", f[9])
	}
}
