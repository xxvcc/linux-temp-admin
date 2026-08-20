package atqueue

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestValidJobID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{id: "1", want: true},
		{id: "18446744073709551615", want: true},
		{id: ""},
		{id: "0"},
		{id: "01"},
		{id: "+1"},
		{id: "1a"},
		{id: "184467440737095516150"},
	}
	for _, test := range tests {
		if got := ValidJobID(test.id); got != test.want {
			t.Errorf("ValidJobID(%q) = %t, want %t", test.id, got, test.want)
		}
	}
}

func TestParseInventory(t *testing.T) {
	got, err := ParseInventory([]byte("\n1 queued\n42 Fri Jul 24 00:00:00 2026 a root\n"), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1", "42"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseInventory() = %v, want %v", got, want)
	}
}

func TestParseInventoryFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		out  string
		want string
	}{
		{name: "malformed line", out: "warning: partial queue output\n42 queued\n", want: "parse atq line 1"},
		{name: "duplicate ID", out: "42 queued\n42 duplicate\n", want: "duplicate job id 42"},
		{name: "overlong line", out: "42 " + strings.Repeat("x", 2048), want: "parse atq:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseInventory([]byte(test.out), 1024); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseInventory() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseInventoryRejectsTooManyJobs(t *testing.T) {
	var out strings.Builder
	for id := 1; id <= MaxJobs+1; id++ {
		fmt.Fprintf(&out, "%d queued\n", id)
	}
	if _, err := ParseInventory([]byte(out.String()), 64<<10); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("more than %d inspectable jobs", MaxJobs)) {
		t.Fatalf("ParseInventory() error = %v, want queue-size refusal", err)
	}
}

func TestParseOwner(t *testing.T) {
	tests := []struct {
		name string
		body string
		want uint32
		err  string
	}{
		{name: "valid", body: "#!/bin/sh\n# atrun uid=1001 gid=2002\n/bin/true\n", want: 1001},
		{name: "valid high kernel IDs", body: "# atrun uid=4294967294 gid=4294967294\n", want: 4294967294},
		{name: "missing", body: "#!/bin/sh\n/bin/true\n", err: "no atrun owner header"},
		{name: "first header is authoritative", body: "# atrun uid=1001 gid=1001\n# atrun uid=2002 gid=2002\n", want: 1001},
		{name: "malformed first header", body: "# atrun owner is unknown\n# atrun uid=1001 gid=1001\n", err: "invalid atrun owner header"},
		{name: "negative UID", body: "# atrun uid=-1 gid=1001\n", err: "invalid atrun UID"},
		{name: "reserved UID", body: "# atrun uid=4294967295 gid=1001\n", err: "invalid atrun UID"},
		{name: "reserved GID", body: "# atrun uid=1001 gid=4294967295\n", err: "invalid atrun GID"},
		{name: "overlong line", body: strings.Repeat("x", 2048), err: "scan at job:"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseOwner([]byte(test.body), 1024)
			if test.err == "" {
				if err != nil || got != test.want {
					t.Fatalf("ParseOwner() = (%d, %v), want (%d, nil)", got, err, test.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.err) {
				t.Fatalf("ParseOwner() error = %v, want %q", err, test.err)
			}
		})
	}
}

func TestParseKernelID(t *testing.T) {
	for _, test := range []struct {
		value string
		want  uint32
		ok    bool
	}{
		{value: "0", ok: true},
		{value: "4294967294", want: 4294967294, ok: true},
		{value: "4294967295"},
		{value: "4294967296"},
		{value: "-1"},
		{value: ""},
	} {
		got, err := parseKernelID(test.value)
		if test.ok && (err != nil || got != test.want) {
			t.Errorf("parseKernelID(%q) = (%d, %v), want (%d, nil)", test.value, got, err, test.want)
		}
		if !test.ok && err == nil {
			t.Errorf("parseKernelID(%q) = (%d, nil), want error", test.value, got)
		}
	}
}
