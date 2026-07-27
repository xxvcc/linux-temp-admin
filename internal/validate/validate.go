// Package validate holds the input validators (usernames, prefixes, hosts,
// ports, hours, upgrade URLs, versions). Every value that later reaches a
// sudoers, systemd, at, or filesystem context is constrained here first, so an
// untrusted value can never take on meaning in the context it lands in.
package validate

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
)

var (
	// ^[a-z_][a-z0-9_-]{0,30}[a-z0-9]$  (min 2, max 32 chars)
	usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}[a-z0-9]$`)
	// ^[a-z_][a-z0-9_-]{0,19}$  (plus: must not end in '-' or '_')
	prefixRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,19}$`)
	// exactly four dotted decimal groups
	ipv4Re = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
	// DNS label: alnum at both edges, hyphen allowed inside
	dnsLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
	// exactly three numeric components + optional [._+~-]-led suffix
	installedVersionRe = regexp.MustCompile(`^[0-9]+([.][0-9]+){2}([-_+~][A-Za-z0-9._+~-]+)?$`)
	// Exact release version used by v-tags and the public mirror manifest.
	releaseVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)
	generationRe     = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

// Username reports whether s is a valid temporary username.
func Username(s string) bool { return usernameRe.MatchString(s) }

// Generation reports whether s is a 128-bit lowercase hex account-generation token.
func Generation(s string) bool { return generationRe.MatchString(s) }

// KernelID reports whether id can be represented as a concrete Linux uid_t or
// gid_t. The all-ones value is deliberately excluded: chown(2) reserves it as
// the "leave this owner unchanged" sentinel rather than an account identity.
func KernelID(id int) bool {
	return id >= 0 && uint64(id) < uint64(^uint32(0))
}

// AccountID is KernelID restricted to non-root identities. Temporary accounts
// and every unattended action tied to one require this stronger form.
func AccountID(id int) bool { return id > 0 && KernelID(id) }

// Prefix reports whether s is a valid username prefix.
func Prefix(s string) bool {
	return prefixRe.MatchString(s) && !strings.HasSuffix(s, "-") && !strings.HasSuffix(s, "_")
}

// Host reports whether s is a safe host: a DNS name, IPv4, or IPv6 literal with
// no ports, spaces, quotes, or shell metacharacters.
func Host(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	// Character allow-list also rejects whitespace and shell metacharacters.
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == ':':
		default:
			return false
		}
	}
	// IPv6 (optionally with an embedded IPv4 tail, e.g. ::ffff:192.0.2.1): any
	// string containing ':' must be a valid IP literal. A bare IPv4 never
	// contains ':', so ParseIP != nil here means a well-formed IPv6.
	if strings.Contains(s, ":") {
		return net.ParseIP(s) != nil
	}
	// IPv4: four octets 0..255, no leading zeros.
	if ipv4Re.MatchString(s) {
		for _, oct := range strings.Split(s, ".") {
			if !validOctet(oct) {
				return false
			}
		}
		return true
	}
	// DNS name: labels 1..63 chars, alnum edges, hyphen inside.
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || !dnsLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

func validOctet(oct string) bool {
	if len(oct) == 0 || len(oct) > 3 {
		return false
	}
	if len(oct) > 1 && oct[0] == '0' { // reject leading zeros (octal reinterpretation)
		return false
	}
	n, err := strconv.Atoi(oct)
	return err == nil && n >= 0 && n <= 255
}

// PublicIPv4 reports whether ip is a routable public IPv4 address (used only to
// filter auto-detection candidates). Mirrors is_public_ipv4.
func PublicIPv4(ip string) bool {
	if !ipv4Re.MatchString(ip) {
		return false
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if !validOctet(p) {
			return false
		}
	}
	return PublicIP(net.ParseIP(ip))
}

// PublicIPv6 reports whether ip is a routable global-unicast IPv6 address, using
// the same special-purpose exclusions as the redirect SSRF boundary. An IPv4 or
// IPv4-mapped address is rejected here; PublicIPv4 owns it.
func PublicIPv6(ip string) bool {
	if !strings.Contains(ip, ":") {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return false
	}
	return PublicIP(parsed)
}

// PublicIP reports whether ip is suitable for either an automatically advertised
// SSH endpoint or a redirect-time network destination. Keep this one classifier
// shared so public-IP detection cannot accept a special-use range that the
// upgrade SSRF boundary rejects (or vice versa).
func PublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	// netip's protocol-level IsGlobalUnicast also accepts deprecated site-local
	// space and address ranges that IANA has not allocated for global IPv6
	// unicast. Redirect targets must stay inside the current 2000::/3 allocation.
	if addr.Is6() && !ipv6GlobalUnicastPrefix.Contains(addr) {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var ipv6GlobalUnicastPrefix = netip.MustParsePrefix("2000::/3")

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

// Port reports whether p is a usable TCP port (1..65535).
func Port(p int) bool { return p >= 1 && p <= 65535 }

// Hours reports whether h is a valid account lifetime (1..MaxExpireHours).
func Hours(h int) bool { return h >= 1 && h <= config.MaxExpireHours }

// UpgradeURL reports whether u is an acceptable https upgrade URL: https-only,
// bounded length, and free of whitespace and shell metacharacters.
func UpgradeURL(u string) bool {
	if len(u) < 8 || len(u) > 2048 {
		return false
	}
	if !strings.HasPrefix(u, "https://") {
		return false
	}
	for _, r := range u { // reject all control characters (covers \t \r \n \v \f, NUL, DEL)
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return !strings.ContainsAny(u, " \"'`<>|")
}

// InstalledVersion reports whether v is a comparable version string: exactly
// three numeric components with an optional suffix, where the suffix must be led
// by one of - _ + ~ (never '.'). That leading-separator rule is load-bearing: if
// '.' could lead the suffix, "1.2.3.4" would match as "1.2.3" plus suffix ".4",
// and version.Greater would then rank that 4-part string BELOW the 3-part 1.2.3
// (a suffix reads as a prerelease), so the upgrade gate would silently decline a
// genuinely newer release. So a 2- or 4-part string cannot slip through.
func InstalledVersion(v string) bool { return installedVersionRe.MatchString(v) }

// ReleaseVersion reports whether v is the canonical version portion of a
// supported vX.Y.Z release tag.
func ReleaseVersion(v string) bool { return releaseVersionRe.MatchString(v) }
