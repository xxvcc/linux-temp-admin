package version

import "testing"

func TestGreater(t *testing.T) {
	cases := []struct {
		newer, older string
		want         bool
	}{
		{"1.2.0", "1.1.2", true},          // newer patch/minor
		{"2.0.0", "1.9.9", true},          // newer major
		{"1.2.0", "1.2.0-rc1", true},      // final > prerelease
		{"1.2.0", "1.2.0", false},         // equal is not greater
		{"1.1.9", "1.2.0", false},         // older is not greater
		{"1.2.0-rc1", "1.2.0", false},     // prerelease is not greater than final
		{"not-a-version", "1.2.0", false}, // unparseable => false
		{"1.2.0", "nope", false},          // unparseable older => false
		{"1.2.3-rc10", "1.2.3-rc9", true}, // numeric-aware suffix: rc10 > rc9
		{"1.2.3-rc9", "1.2.3-rc10", false},
		{"1.2.3-rc2", "1.2.3-rc2", false},   // identical prerelease is not greater
		{"1.2.10", "1.2.9", true},           // numeric core, not lexical
		{"1.0.0-beta", "1.0.0-alpha", true}, // non-numeric suffix still compares
	}
	for _, c := range cases {
		if got := Greater(c.newer, c.older); got != c.want {
			t.Errorf("Greater(%q, %q) = %v, want %v", c.newer, c.older, got, c.want)
		}
	}
}
