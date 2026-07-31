package validate

import (
	"strconv"
	"strings"
	"testing"
)

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

func TestKernelAndAccountID(t *testing.T) {
	for _, id := range []int{0, 1, 65534} {
		if !KernelID(id) {
			t.Errorf("KernelID(%d) = false, want true", id)
		}
	}
	if AccountID(0) || !AccountID(1) {
		t.Fatalf("AccountID root/non-root boundary is wrong")
	}
	for _, id := range []int{-1, -1000} {
		if KernelID(id) || AccountID(id) {
			t.Errorf("negative id %d was accepted", id)
		}
	}
	if strconv.IntSize >= 64 {
		reservedKernelID := uint64(^uint32(0))
		reserved := int(reservedKernelID)
		for _, id := range []int{reserved, reserved + 1} {
			if KernelID(id) || AccountID(id) {
				t.Errorf("out-of-range/reserved id %d was accepted", id)
			}
		}
		if !KernelID(reserved-1) || !AccountID(reserved-1) {
			t.Errorf("highest concrete Linux id %d was rejected", reserved-1)
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
		{"192.31.196.1", false},  // AS112-v4
		{"192.52.193.1", false},  // AMT
		{"192.88.99.1", false},   // deprecated 6to4 relay anycast
		{"192.175.48.1", false},  // AS112 direct delegation
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

func TestPublicIPv6(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"2400:cb00:2049:1::a29f:1804", true}, // routable global unicast
		{"2606:4700:4700::1111", true},        // Cloudflare resolver, global unicast
		{"2000::1", true},                     // lower 2000::/3 boundary
		{"3fef:ffff::1", true},                // representative high 2000::/3 address
		{"3ff0::1", true},                     // outside the narrower 3fff::/20 documentation prefix
		{"3fff:1000::1", true},                // immediately above 3fff::/20
		{"::1", false},                        // loopback
		{"::", false},                         // unspecified
		{"100:0:0:1::1", false},               // IANA Dummy IPv6 Prefix
		{"1fff:ffff::1", false},               // below current global-unicast allocation
		{"4000::1", false},                    // above current global-unicast allocation
		{"fe80::1", false},                    // link-local
		{"fec0::1", false},                    // deprecated site-local
		{"fc00::1", false},                    // unique-local fc00::/7
		{"fd12:3456::1", false},               // unique-local
		{"ff02::1", false},                    // multicast
		{"2001:db8::1", false},                // documentation 2001:db8::/32
		{"64:ff9b::8.8.8.8", false},           // NAT64 well-known prefix
		{"64:ff9b:1::1", false},               // NAT64 local-use prefix
		{"100::1", false},                     // discard-only prefix
		{"2002:808:808::1", false},            // deprecated 6to4
		{"3fff::1", false},                    // documentation prefix
		{"3fff:0fff::1", false},               // upper 3fff::/20 documentation boundary
		{"5f00::1", false},                    // IPv6 segment routing SIDs
		{"8.8.8.8", false},                    // an IPv4 is PublicIPv4's job, not this one
		{"::ffff:8.8.8.8", false},             // IPv4-mapped resolves to v4, rejected here
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := PublicIPv6(c.in); got != c.want {
			t.Errorf("PublicIPv6(%q) = %v, want %v", c.in, got, c.want)
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
		{"1.2.3-rc.1", true}, // dotted suffix after a real separator is fine
		{"1.2.3+build.5", true},
		{"1.2.3~pre", true},
		{"not-a-version", false},
		{"1.2", false}, // 2 components: version_gt cannot parse
		// EXACTLY three numeric components. A trailing ".4" is NOT a suffix — the
		// suffix must be led by one of - _ + ~, never '.', or version.Greater
		// mis-orders the 4-part string as a prerelease of the 3-part one and the
		// upgrade gate silently declines a genuinely newer release.
		{"1.2.3.4", false},
		{"10.20.30.40", false},
		{"2.6.0.1", false},
	}
	for _, c := range cases {
		if got := InstalledVersion(c.in); got != c.want {
			t.Errorf("InstalledVersion(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestReleaseVersion(t *testing.T) {
	for _, value := range []string{"0.0.0", "2.8.0", "12.34.56-rc.10"} {
		if !ReleaseVersion(value) {
			t.Errorf("ReleaseVersion(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "v2.8.0", "02.8.0", "2.08.0", "2.8", "2.8.0+build", "2.8.0-rc_1"} {
		if ReleaseVersion(value) {
			t.Errorf("ReleaseVersion(%q) = true, want false", value)
		}
	}
}

func TestUpgradeURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://github.com/xxvcc/linux-temp-admin/releases/latest/download/linux-temp-admin-linux-amd64", true},
		{"https://example.com/linux-temp-admin-linux-arm64", true},
		{"http://example.com/linux-temp-admin-linux-arm64", false}, // https only
		{"https://example.com/a b", false},                         // whitespace
		{"https://example.com/a|b", false},                         // shell metacharacter
		{"short", false},                                           // below minimum length / not https
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

func TestManagedHomeRequiresExactDedicatedPath(t *testing.T) {
	for _, home := range []string{"/home/xxvcc-u", "/home/_x"} {
		user := strings.TrimPrefix(home, "/home/")
		if !ManagedHome(user, home) {
			t.Errorf("ManagedHome(%q, %q) = false", user, home)
		}
	}
	for _, tc := range []struct{ user, home string }{
		{"xxvcc-u", "/srv/xxvcc-u"},
		{"xxvcc-u", "/home/xxvcc-u/"},
		{"xxvcc-u", "/home/../home/xxvcc-u"},
		{"bad:user", "/home/bad:user"},
	} {
		if ManagedHome(tc.user, tc.home) {
			t.Errorf("ManagedHome(%q, %q) accepted an unsafe path", tc.user, tc.home)
		}
	}
}
