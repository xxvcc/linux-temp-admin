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
	// The record must still split into exactly the fixed field count.
	if n := len(strings.Split(line, "\t")); n != fieldCount {
		t.Errorf("embedded control chars broke the layout: %d fields, want %d (%q)", n, fieldCount, line)
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
