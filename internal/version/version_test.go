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
	}
	for _, c := range cases {
		if got := Greater(c.newer, c.older); got != c.want {
			t.Errorf("Greater(%q, %q) = %v, want %v", c.newer, c.older, got, c.want)
		}
	}
}
