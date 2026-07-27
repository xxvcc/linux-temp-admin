package registry

import (
	"strconv"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Record{
		User:          "xxvcc-a1b2c3",
		Created:       "2026-07-07 12:00:00 UTC",
		Expires:       "2026-07-08 12:00:00 UTC",
		Sudo:          true,
		Host:          "server-1.example.com",
		Port:          22,
		Fingerprint:   "SHA256:abcdef",
		AutoRevoke:    true,
		AutoUnit:      "linux-temp-admin-v2-revoke-xxvcc-a1b2c3",
		UID:           1001,
		Generation:    "0123456789abcdef0123456789abcdef",
		IdentityBound: true,
		Pending:       true,
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
	// derived from what TSV writes today, so this
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
	for _, line := range []string{"", Header} {
		if _, ok, err := ParseLine(line); ok || err != nil {
			t.Errorf("ParseLine(%q) = ok=%v err=%v, want ignored", line, ok, err)
		}
	}
	for _, line := range []string{"too\tfew\tfields", "# comment", legacyHeaderV2} {
		if _, _, err := ParseLine(line); err == nil {
			t.Errorf("malformed/non-current line %q must return an error", line)
		}
	}
}

func TestParseLineRejectsCorruptFields(t *testing.T) {
	valid := strings.Split(Record{User: "xxvcc-a1", Port: 22}.TSV(), "\t")
	tests := map[string][]string{}
	for name, mutate := range map[string]func([]string){
		"boolean":        func(f []string) { f[3] = "maybe" },
		"port":           func(f []string) { f[5] = "not-a-port" },
		"uid":            func(f []string) { f[9] = "broken" },
		"generation":     func(f []string) { f[10] = "too-short" },
		"pending":        func(f []string) { f[11] = "maybe" },
		"identity bound": func(f []string) { f[12] = "maybe" },
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

func TestParseLineRequiresGenerationForBoundIdentity(t *testing.T) {
	line := Record{User: "xxvcc-a1", Port: 22, UID: 1001, IdentityBound: true}.TSV()
	if _, _, err := ParseLine(line); err == nil || !strings.Contains(err.Error(), "no valid generation") {
		t.Fatalf("ParseLine error = %v, want missing generation refusal", err)
	}
}

func TestParseLineRejectsReservedLinuxUID(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot represent the reserved uint32 uid sentinel")
	}
	fields := strings.Split(Record{User: "xxvcc-a1", Port: 22}.TSV(), "\t")
	fields[uidField] = strconv.FormatUint(uint64(^uint32(0)), 10)
	if _, _, err := ParseLine(strings.Join(fields, "\t")); err == nil || !strings.Contains(err.Error(), "invalid uid") {
		t.Fatalf("reserved uid error = %v, want refusal", err)
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
	got, ok, err := parseLegacyV2Line(legacy)
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
	if got.Pending {
		t.Error("a legacy row must not be interpreted as a pending creation intent")
	}
}

// TestV3SchemaStopsV2Writers pins the forward-compatibility boundary. v3 rows
// carry fields a v2 writer would discard, so the header and exact row width must
// make that writer fail closed instead of accepting and truncating them.
func TestV3SchemaStopsV2Writers(t *testing.T) {
	line := Record{User: "xxvcc-a1", Port: 22, UID: 1001, AutoUnit: "u.timer", Pending: true}.TSV()
	f := strings.Split(line, "\t")
	if Header == legacyHeaderV2 {
		t.Fatal("current and legacy registry headers must differ")
	}
	if len(f) != currentFieldCount {
		t.Fatalf("v3 row has %d fields, want %d", len(f), currentFieldCount)
	}
	if _, _, err := parseLegacyV2Line(line); err == nil {
		t.Fatal("v2 parser accepted a v3 row and could silently discard pending state")
	}
}
