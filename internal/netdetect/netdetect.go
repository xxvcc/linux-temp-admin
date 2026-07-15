// Package netdetect discovers the server's public IP for the invite, using
// net/http with per-request context timeouts (no curl/wget, so no busybox -T
// segfault or unbounded hang). It prefers cloud metadata and local interfaces,
// falling back to external echo services.
//
// Both address families are detected, IPv4 first (still the more universally
// reachable choice for whoever will SSH in) and IPv6 as the fallback that makes
// a v6-only host work without the operator having to type its address by hand.
package netdetect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// Detector performs public-IP detection. Fields are exported so tests can inject
// a test server and client.
//
// There is deliberately no IPv6 metadata list. Unlike a public IPv4 — which is
// frequently NAT'd and visible only through metadata — a host's global-unicast
// IPv6 is bound directly to an interface, so the interface scan already finds it.
// And the three clouds do not expose a v6 address at a fixed leaf: AWS and
// Alibaba put it under network/interfaces/macs/<mac>/ipv6s, Tencent under
// .../local-ipv6s, each reachable only after first listing the MACs. That
// per-provider two-hop dance buys nothing the interface scan does not already
// give us, so it is not attempted.
type Detector struct {
	Client           *http.Client
	MetadataServices []string // cloud metadata that returns an IPv4
	ExternalServices []string // echo services; the reply's family follows the connection
}

// New returns a Detector with the default services and a redirect-free client.
func New() *Detector {
	return &Detector{
		Client: &http.Client{
			// Never auto-follow redirects for a metadata/echo probe.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		MetadataServices: []string{
			"http://metadata.tencentyun.com/latest/meta-data/public-ipv4",
			"http://169.254.169.254/latest/meta-data/public-ipv4",
			"http://100.100.100.200/latest/meta-data/eipv4",
		},
		ExternalServices: []string{
			"https://api.ipify.org",
			"https://ifconfig.me/ip",
			"https://icanhazip.com",
		},
	}
}

// fetch GETs url and returns the trimmed body (CR/LF stripped), bounded by ctx.
func (d *Detector) fetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	s := strings.NewReplacer("\r", "", "\n", "").Replace(string(b))
	return strings.TrimSpace(s), nil
}

// LocalPublicIP tries the sources that never leave this host or its link — cloud
// metadata (IPv4 only; see the Detector doc) then local interface addresses — and
// returns the first routable public address found. perReq bounds each metadata
// request.
//
// IPv4 is preferred over IPv6: a dual-stack box hands out its v4 address (the
// more universally reachable one), and a v6-only box, whose interfaces carry no
// public v4, still gets its global v6 instead of falling through to a manual
// prompt.
func (d *Detector) LocalPublicIP(perReq time.Duration) (string, bool) {
	if ip, ok := d.metaIP(d.MetadataServices, perReq, validate.PublicIPv4); ok {
		return ip, true
	}
	if ip, ok := localInterfaceIP(validate.PublicIPv4); ok {
		return ip, true
	}
	if ip, ok := localInterfaceIP(validate.PublicIPv6); ok {
		return ip, true
	}
	return "", false
}

// PublicIP queries external echo services, returning the first routable public
// address they report. perReq bounds each request. It applies the same
// public-address filters as the metadata path — for either family — so a service
// that echoes a private/reserved/loopback address (or a bare hostname) is
// rejected rather than fed into the invite as a bogus "public IP".
func (d *Detector) PublicIP(perReq time.Duration) (string, bool) {
	for _, svc := range d.ExternalServices {
		ctx, cancel := context.WithTimeout(context.Background(), perReq)
		ip, err := d.fetch(ctx, svc)
		cancel()
		if err == nil && (validate.PublicIPv4(ip) || validate.PublicIPv6(ip)) {
			return ip, true
		}
	}
	return "", false
}

// metaIP tries each metadata URL, returning the first response that passes ok.
func (d *Detector) metaIP(urls []string, perReq time.Duration, ok func(string) bool) (string, bool) {
	for _, svc := range urls {
		ctx, cancel := context.WithTimeout(context.Background(), perReq)
		ip, err := d.fetch(ctx, svc)
		cancel()
		if err == nil && ok(ip) {
			return ip, true
		}
	}
	return "", false
}

// localInterfaceIP returns the first locally-bound address that passes ok. When
// ok is PublicIPv4 a v4 address is compared; for PublicIPv6 a v6 one — the
// wrong-family addresses simply fail the filter, so one loop serves both.
func localInterfaceIP(ok func(string) bool) (string, bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		// Compare in the address's own family: To4() gives dotted-quad for a v4
		// address (and nil for v6), so the string handed to ok matches what its
		// regex/parser expects.
		s := ip.String()
		if ip4 := ip.To4(); ip4 != nil {
			s = ip4.String()
		}
		if ok(s) {
			return s, true
		}
	}
	return "", false
}
