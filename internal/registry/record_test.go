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
		UID:         1001,
		Generation:  "0123456789abcdef0123456789abcdef",
	}
	line := in.TSV()
	if strings.Contains(line, "\n") {
		t.Fatalf("TSV must be a single line: %q", line)
	}
	got, ok, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("ParseLine failed for %q", line)
	}
	if got != in {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

func TestSanitizeFlattensControlChars(t *testing.T) {
	in := Record{User: "userx", Host: "a\nb\rc", Port: 22}
	line := in.TSV()
	// A field value must never be able to add fields of its own. The count is
	// derived from what TSV writes today (fieldCount is only the parser's MINIMUM,
	// deliberately frozen at the original nine so older rows still parse), so this
	// keeps testing the injection property rather than the column count.
	if n := len(strings.Split(line, "\t")); n != len(strings.Split(Record{}.TSV(), "\t")) {
		t.Errorf("embedded control chars broke the layout: %d fields (%q)", n, line)
	}
	got, ok, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("ParseLine failed after sanitize")
	}
	if strings.ContainsAny(got.User+got.Host, "\t\r\n") {
		t.Errorf("sanitize left control chars: user=%q host=%q", got.User, got.Host)
	}
}

func TestParseLineRejectsNonRecords(t *testing.T) {
	for _, line := range []string{"", Header, "# comment"} {
		if _, ok, err := ParseLine(line); ok || err != nil {
			t.Errorf("ParseLine(%q) = ok=%v err=%v, want ignored", line, ok, err)
		}
	}
	if _, _, err := ParseLine("too\tfew\tfields"); err == nil {
		t.Error("malformed record must return an error")
	}
}

func TestParseLineRejectsCorruptFields(t *testing.T) {
	valid := strings.Split(Record{User: "xxvcc-a1", Port: 22}.TSV(), "\t")
	tests := map[string][]string{}
	for name, mutate := range map[string]func([]string){
		"boolean":    func(f []string) { f[3] = "maybe" },
		"port":       func(f []string) { f[5] = "not-a-port" },
		"uid":        func(f []string) { f[9] = "broken" },
		"generation": func(f []string) { f[10] = "too-short" },
	} {
		fields := append([]string(nil), valid...)
		mutate(fields)
		tests[name] = fields
	}
	for name, fields := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseLine(strings.Join(fields, "\t")); err == nil {
				t.Fatal("corrupt record must return an error")
			}
		})
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
	got, ok, err := ParseLine(legacy)
	if err != nil {
		t.Fatal(err)
	}
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
