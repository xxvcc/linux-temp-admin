package validate

import "testing"

func TestUsername(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"xxvcc-a1b2c3", true}, // prefix + random suffix
		{"_ops1", true},        // may start with underscore
		{"1ops", false},        // must not start with a digit
		{"ops.user", false},    // no dot
		{"ops-", false},        // must not end with a dash
		{"Ops", false},         // no uppercase
		{"a", false},           // too short (needs first+last)
		{"ab", true},           // minimum length
	}
	for _, c := range cases {
		if got := Username(c.in); got != c.want {
			t.Errorf("Username(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"ops-1", true},
		{"o", true},
		{"ops-", false}, // must not end with dash
		{"ops_", false}, // must not end with underscore
		{"Ops", false},  // no uppercase
	}
	for _, c := range cases {
		if got := Prefix(c.in); got != c.want {
			t.Errorf("Prefix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"server-1.example.com", true},
		{"203.0.113.10", true},
		{"2001:db8::1", true},
		{"::ffff:192.0.2.1", true},   // IPv4-mapped IPv6
		{"example.com:22", false},    // no embedded port
		{"bad host", false},          // no whitespace
		{"bad;touch", false},         // no shell metacharacters
		{"999.1.1.1", false},         // octet out of range
		{"010.0.0.1", false},         // no leading zeros
		{"2001:::1", false},          // triple colon
		{"1:2:3:4:5:6:7:8:9", false}, // too many groups
		{"-bad.example", false},      // label may not start with dash
		{"bad-.example", false},      // label may not end with dash
		{".example", false},          // may not start with dot
		{"example.", false},          // may not end with dot
	}
	for _, c := range cases {
		if got := Host(c.in); got != c.want {
			t.Errorf("Host(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPublicIPv4(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"8.8.8.8", true},
		{"10.0.0.1", false},      // private 10/8
		{"172.16.0.1", false},    // private 172.16/12
		{"192.168.1.1", false},   // private 192.168/16
		{"100.64.0.1", false},    // CGNAT
		{"169.254.1.1", false},   // link-local
		{"198.18.0.1", false},    // benchmark
		{"192.0.2.1", false},     // TEST-NET-1
		{"198.51.100.10", false}, // TEST-NET-2
		{"203.0.113.10", false},  // TEST-NET-3
		{"224.0.0.1", false},     // multicast
		{"010.0.0.1", false},     // invalid leading zero
	}
	for _, c := range cases {
		if got := PublicIPv4(c.in); got != c.want {
			t.Errorf("PublicIPv4(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestInstalledVersion(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.2.3", true},
		{"1.2.3-rc1", true},
		{"not-a-version", false},
		{"1.2", false},    // 2 components: version_gt cannot parse
		{"1.2.3.4", true}, // 3 components + ".4" suffix (comparator treats it the same)
	}
	for _, c := range cases {
		if got := InstalledVersion(c.in); got != c.want {
			t.Errorf("InstalledVersion(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUpgradeURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh", true},
		{"https://example.com/temp-admin.sh", true},
		{"http://example.com/temp-admin.sh", false}, // https only
		{"https://example.com/a b.sh", false},       // whitespace
		{"https://example.com/a|b.sh", false},       // shell metacharacter
		{"short", false},                            // below minimum length / not https
	}
	for _, c := range cases {
		if got := UpgradeURL(c.in); got != c.want {
			t.Errorf("UpgradeURL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPortAndHours(t *testing.T) {
	for _, p := range []int{1, 22, 65535} {
		if !Port(p) {
			t.Errorf("Port(%d) = false, want true", p)
		}
	}
	for _, p := range []int{0, -1, 65536} {
		if Port(p) {
			t.Errorf("Port(%d) = true, want false", p)
		}
	}
	for _, h := range []int{1, 24, 8760} {
		if !Hours(h) {
			t.Errorf("Hours(%d) = false, want true", h)
		}
	}
	for _, h := range []int{0, -1, 8761} {
		if Hours(h) {
			t.Errorf("Hours(%d) = true, want false", h)
		}
	}
}
