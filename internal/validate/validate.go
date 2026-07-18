// Package validate holds the input validators (usernames, prefixes, hosts,
// ports, hours, upgrade URLs, versions). Every value that later reaches a
// sudoers, systemd, at, or filesystem context is constrained here first, so an
// untrusted value can never take on meaning in the context it lands in.
package validate

import (
	"net"
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
)

// Username reports whether s is a valid temporary username.
func Username(s string) bool { return usernameRe.MatchString(s) }

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
	o := make([]int, 4)
	for i, p := range parts {
		if !validOctet(p) {
			return false
		}
		o[i], _ = strconv.Atoi(p)
	}
	switch o[0] {
	case 0, 10, 127:
		return false
	}
	if o[0] >= 224 { // multicast + reserved (224.0.0.0/3)
		return false
	}
	switch {
	case o[0] == 100 && o[1] >= 64 && o[1] <= 127: // CGNAT 100.64/10
		return false
	case o[0] == 169 && o[1] == 254: // link-local
		return false
	case o[0] == 172 && o[1] >= 16 && o[1] <= 31: // 172.16/12
		return false
	case o[0] == 192 && o[1] == 0 && o[2] == 0: // 192.0.0.0/24
		return false
	case o[0] == 192 && o[1] == 0 && o[2] == 2: // TEST-NET-1
		return false
	case o[0] == 192 && o[1] == 88 && o[2] == 99: // 6to4 relay anycast
		return false
	case o[0] == 192 && o[1] == 168: // 192.168/16
		return false
	case o[0] == 198 && (o[1] == 18 || o[1] == 19): // benchmarking 198.18/15
		return false
	case o[0] == 198 && o[1] == 51 && o[2] == 100: // TEST-NET-2
		return false
	case o[0] == 203 && o[1] == 0 && o[2] == 113: // TEST-NET-3
		return false
	}
	return true
}

// PublicIPv6 reports whether ip is a routable global-unicast IPv6 address — the
// IPv6 counterpart of PublicIPv4, used only to filter auto-detection candidates.
// It leans on net's classifiers (which already exclude loopback ::1, the
// unspecified ::, link-local fe80::/10, and every multicast form) and adds the
// two they do not cover for our purpose: unique-local fc00::/7 (IsPrivate) and
// the documentation range 2001:db8::/32, which is global-unicast-shaped but not
// routable. An IPv4 or IPv4-mapped address is rejected here; PublicIPv4 owns it.
func PublicIPv6(ip string) bool {
	if !strings.Contains(ip, ":") {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return false
	}
	if !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
		return false
	}
	// 2001:db8::/32 — RFC 3849 documentation prefix.
	if parsed[0] == 0x20 && parsed[1] == 0x01 && parsed[2] == 0x0d && parsed[3] == 0xb8 {
		return false
	}
	return true
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
