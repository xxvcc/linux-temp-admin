package registry

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
)

func TestHeaderMatchesConfiguredSchema(t *testing.T) {
	want := "# linux-temp-admin registry v" + strconv.Itoa(config.RegistrySchema)
	if Header != want {
		t.Fatalf("registry header = %q, want %q", Header, want)
	}
}

func TestRoundTrip(t *testing.T) {
	in := Record{
		User:            "xxvcc-a1b2c3",
		Created:         "2026-07-07 12:00:00 UTC",
		Expires:         "2026-07-08 12:00:00 UTC",
		Sudo:            true,
		Host:            "server-1.example.com",
		Port:            22,
		Fingerprint:     "SHA256:abcdef",
		AutoRevoke:      true,
		AutoUnit:        "linux-temp-admin-v2-revoke-xxvcc-a1b2c3",
		UID:             1001,
		Generation:      "0123456789abcdef0123456789abcdef",
		IdentityBound:   true,
		Pending:         false,
		DeletionStarted: true,
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

func TestRecordLifecycleStates(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	deadline := time.Date(2026, 8, 19, 12, 2, 0, 0, time.UTC).Format(time.RFC3339)
	tests := []struct {
		name string
		rec  Record
		want recordLifecycleState
	}{
		{
			name: "legacy active",
			rec:  Record{User: "xxvcc-legacy", Port: 22},
			want: recordLegacyActive,
		},
		{
			name: "pending creation intent",
			rec: Record{User: "xxvcc-pending", Port: 22, Generation: generation,
				IdentityBound: true, Pending: true},
			want: recordPending,
		},
		{
			name: "active identity",
			rec: Record{User: "xxvcc-active", Port: 22, UID: 1001, Generation: generation,
				IdentityBound: true, SequentialID: true},
			want: recordActive,
		},
		{
			name: "sequential uid-only deletion recovery",
			rec: Record{User: "xxvcc-uid", UID: 1002, DeletionStarted: true,
				SequentialID: true},
			want: recordDeletingUIDOnly,
		},
		{
			name: "bound synchronous deletion",
			rec: Record{User: "xxvcc-delete", Port: 22, UID: 1003, Generation: generation,
				IdentityBound: true, DeletionStarted: true},
			want: recordDeletingBound,
		},
		{
			name: "bound quarantine",
			rec: Record{User: "xxvcc-quarantine", Port: 22, UID: 1004, Generation: generation,
				IdentityBound: true, DeletionStarted: true, QuarantineUntil: deadline,
				QuarantineUnit: config.QuarantineUnitPrefix + "xxvcc-quarantine"},
			want: recordQuarantined,
		},
		{
			name: "pending recovery quarantine",
			rec: Record{User: "xxvcc-pending-q", Port: 22, UID: 1005, Generation: generation,
				IdentityBound: true, Pending: true, DeletionStarted: true,
				QuarantineUntil: deadline,
				QuarantineUnit:  config.QuarantineUnitPrefix + "xxvcc-pending-q"},
			want: recordQuarantined,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, err := tc.rec.lifecycleState()
			if err != nil || state != tc.want {
				t.Fatalf("lifecycleState(%+v) = (%d, %v), want (%d, nil)", tc.rec, state, err, tc.want)
			}
			got, ok, err := ParseLine(tc.rec.TSV())
			if err != nil || !ok || got != tc.rec {
				t.Fatalf("state round trip = ok %v record %+v err %v", ok, got, err)
			}
		})
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
	for _, line := range []string{"too\tfew\tfields", "# comment", legacyHeaderV2, legacyHeaderV3} {
		if _, _, err := ParseLine(line); err == nil {
			t.Errorf("malformed/non-current line %q must return an error", line)
		}
	}
}

func TestParseLineRejectsCorruptFields(t *testing.T) {
	valid := strings.Split(Record{User: "xxvcc-a1", Port: 22}.TSV(), "\t")
	tests := map[string][]string{}
	for name, mutate := range map[string]func([]string){
		"boolean":          func(f []string) { f[3] = "maybe" },
		"port":             func(f []string) { f[5] = "not-a-port" },
		"uid":              func(f []string) { f[9] = "broken" },
		"generation":       func(f []string) { f[10] = "too-short" },
		"pending":          func(f []string) { f[11] = "maybe" },
		"identity bound":   func(f []string) { f[12] = "maybe" },
		"deletion started": func(f []string) { f[13] = "maybe" },
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

func TestRegistryParsersRejectInvalidUTF8(t *testing.T) {
	fields := strings.Split(Record{User: "xxvcc-a1", Port: 22}.TSV(), "\t")
	fields[4] += "\xff"
	tests := []struct {
		name   string
		width  int
		parser func(string) (Record, bool, error)
	}{
		{name: "current", width: currentFieldCount, parser: ParseLine},
		{name: "legacy v2", width: legacyFieldCount, parser: parseLegacyV2Line},
		{name: "legacy v3", width: legacyV3FieldCount, parser: parseLegacyV3Line},
		{name: "legacy v4", width: legacyV4FieldCount, parser: parseLegacyV4Line},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := strings.Join(fields[:tc.width], "\t")
			if _, ok, err := tc.parser(line); err == nil || ok || !strings.Contains(err.Error(), "valid UTF-8") {
				t.Fatalf("invalid UTF-8 parse = ok %v err %v, want explicit refusal", ok, err)
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

func TestParseLineRequiresUIDAndNonPendingStateForDeletionStarted(t *testing.T) {
	for _, rec := range []Record{
		{User: "xxvcc-a1", Port: 22, DeletionStarted: true},
		{User: "xxvcc-a1", Port: 22, UID: 1001, Pending: true, DeletionStarted: true},
		{User: "xxvcc-a1", Port: 22, UID: 1001, Generation: "0123456789abcdef0123456789abcdef", DeletionStarted: true},
	} {
		if _, _, err := ParseLine(rec.TSV()); err == nil {
			t.Fatalf("ParseLine(%+v) error = %v, want incomplete deletion witness refusal", rec, err)
		}
	}
	legacy := Record{User: "xxvcc-a1", Port: 22, UID: 1001, DeletionStarted: true}
	if got, ok, err := ParseLine(legacy.TSV()); err != nil || !ok || got != legacy {
		t.Fatalf("legacy deletion witness round trip = ok %v record %+v err %v", ok, got, err)
	}
	unregistered := Record{User: "xxvcc-a1", UID: 1001, DeletionStarted: true}
	if got, ok, err := ParseLine(unregistered.TSV()); err != nil || !ok || got != unregistered {
		t.Fatalf("unregistered deletion witness round trip = ok %v record %+v err %v", ok, got, err)
	}
	if _, _, err := ParseLine((Record{User: "xxvcc-a1", Port: 0}).TSV()); err == nil {
		t.Fatal("ordinary record accepted recovery-only port 0")
	}
	boundWithoutPort := Record{
		User: "xxvcc-a1", UID: 1001, Generation: "0123456789abcdef0123456789abcdef",
		IdentityBound: true, DeletionStarted: true,
	}
	if _, _, err := ParseLine(boundWithoutPort.TSV()); err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("generation-bound recovery with port 0 error = %v, want invalid port refusal", err)
	}
}

func TestParseLineAcceptsOnlyDurablePendingDeletionQuarantine(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	rec := Record{
		User: "xxvcc-pending", Port: 22, UID: 1001, Generation: generation,
		IdentityBound: true, Pending: true, DeletionStarted: true,
		QuarantineUntil: time.Date(2026, 8, 1, 12, 2, 0, 0, time.UTC).Format(time.RFC3339),
		QuarantineUnit:  config.QuarantineUnitPrefix + "xxvcc-pending",
	}
	got, ok, err := ParseLine(rec.TSV())
	if err != nil || !ok || got != rec {
		t.Fatalf("pending quarantine round trip = ok %v record %+v err %v", ok, got, err)
	}

	for _, mutate := range []func(*Record){
		func(r *Record) { r.QuarantineUntil = ""; r.QuarantineUnit = "" },
		func(r *Record) { r.IdentityBound = false; r.Generation = "" },
		func(r *Record) { r.QuarantineUnit = config.QuarantineUnitPrefix + "xxvcc-other" },
	} {
		bad := rec
		mutate(&bad)
		if _, _, err := ParseLine(bad.TSV()); err == nil {
			t.Fatalf("invalid pending quarantine was accepted: %+v", bad)
		}
	}
}

func TestParseLineRequiresSequentialIdentityProofState(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	for _, valid := range []Record{
		{
			User: "xxvcc-sequence", Port: 22, UID: 1001, Generation: generation,
			IdentityBound: true, SequentialID: true,
		},
		{
			User: "xxvcc-sequence", UID: 1001, DeletionStarted: true,
			SequentialID: true,
		},
	} {
		if _, ok, err := ParseLine(valid.TSV()); err != nil || !ok {
			t.Fatalf("valid sequential identity state rejected: rec=%+v ok=%v err=%v", valid, ok, err)
		}
	}
	for _, bad := range []Record{
		{User: "xxvcc-sequence", Port: 22, UID: 1001, SequentialID: true},
		{User: "xxvcc-sequence", Port: 22, Generation: generation, IdentityBound: true, SequentialID: true, Pending: true},
		{User: "xxvcc-sequence", DeletionStarted: true, SequentialID: true},
	} {
		if _, _, err := ParseLine(bad.TSV()); err == nil {
			t.Fatalf("unsafe sequential identity state accepted: %+v", bad)
		}
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

func TestParseLegacyV3RowDefaultsDeletionPhase(t *testing.T) {
	current := Record{
		User: "xxvcc-a1", Port: 22, UID: 1001,
		Generation: "0123456789abcdef0123456789abcdef", IdentityBound: true,
	}
	fields := strings.Split(current.TSV(), "\t")
	legacy := strings.Join(fields[:legacyV3FieldCount], "\t")
	got, ok, err := parseLegacyV3Line(legacy)
	if err != nil || !ok {
		t.Fatalf("parseLegacyV3Line ok=%v err=%v", ok, err)
	}
	if got.User != current.User || got.UID != current.UID || got.Generation != current.Generation ||
		!got.IdentityBound || got.Pending || got.DeletionStarted {
		t.Fatalf("legacy v3 row parsed incorrectly: %+v", got)
	}
	if _, _, err := ParseLine(legacy); err == nil {
		t.Fatal("v4 parser accepted a released 13-column v3 row without migration")
	}
}

// TestV4SchemaStopsOlderWriters pins the forward-compatibility boundary. v4
// rows carry a field older writers would discard, so the header and exact width
// make those writers fail closed instead of silently truncating recovery state.
func TestV4SchemaStopsOlderWriters(t *testing.T) {
	line := Record{User: "xxvcc-a1", Port: 22, UID: 1001, AutoUnit: "u.timer", Pending: true}.TSV()
	f := strings.Split(line, "\t")
	if Header == legacyHeaderV2 || Header == legacyHeaderV3 || Header == legacyHeaderV4 {
		t.Fatal("current and legacy registry headers must differ")
	}
	if len(f) != currentFieldCount {
		t.Fatalf("v4 row has %d fields, want %d", len(f), currentFieldCount)
	}
	if _, _, err := parseLegacyV2Line(line); err == nil {
		t.Fatal("v2 parser accepted a v4 row and could silently discard state")
	}
	if _, _, err := parseLegacyV3Line(line); err == nil {
		t.Fatal("v3 parser accepted a v4 row and could silently discard deletion state")
	}
	if _, _, err := parseLegacyV4Line(line); err == nil {
		t.Fatal("v4 parser accepted a v5 row and could silently discard identity quarantine state")
	}
}
