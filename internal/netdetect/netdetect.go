// Package netdetect discovers the server's public IP for the invite, using
// net/http with per-request context timeouts (no curl/wget, so no busybox -T
// segfault or unbounded hang). It prefers cloud metadata and local interfaces,
// falling back to external echo services.
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
type Detector struct {
	Client           *http.Client
	MetadataServices []string
	ExternalServices []string
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

// LocalPublicIP tries cloud metadata then local interface addresses, returning
// the first public IPv4 found. perReq bounds each metadata request.
func (d *Detector) LocalPublicIP(perReq time.Duration) (string, bool) {
	for _, svc := range d.MetadataServices {
		ctx, cancel := context.WithTimeout(context.Background(), perReq)
		ip, err := d.fetch(ctx, svc)
		cancel()
		if err == nil && validate.PublicIPv4(ip) {
			return ip, true
		}
	}
	if ip, ok := localInterfaceIP(); ok {
		return ip, true
	}
	return "", false
}

// PublicIP queries external echo services, returning the first valid host.
// perReq bounds each request.
func (d *Detector) PublicIP(perReq time.Duration) (string, bool) {
	for _, svc := range d.ExternalServices {
		ctx, cancel := context.WithTimeout(context.Background(), perReq)
		ip, err := d.fetch(ctx, svc)
		cancel()
		if err == nil && validate.Host(ip) {
			return ip, true
		}
	}
	return "", false
}

// localInterfaceIP returns the first public IPv4 bound to a local interface.
func localInterfaceIP() (string, bool) {
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
		if ip4 := ip.To4(); ip4 != nil && validate.PublicIPv4(ip4.String()) {
			return ip4.String(), true
		}
	}
	return "", false
}
