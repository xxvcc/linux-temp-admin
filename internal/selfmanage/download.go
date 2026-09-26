package selfmanage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

type transportFailure struct{ err error }

func (e *transportFailure) Error() string { return e.err.Error() }

func (e *transportFailure) Unwrap() error { return e.err }

// IsTransportFailure reports whether err occurred before a complete response
// was accepted. Only this class may move an official download to its fallback;
// signature, checksum, version, URL-policy, and redirect-policy failures do not.
func IsTransportFailure(err error) bool {
	var target *transportFailure
	return errors.As(err, &target)
}

func markTransportFailure(err error) error {
	if err == nil || IsTransportFailure(err) {
		return err
	}
	return &transportFailure{err: err}
}

type downloadPolicy struct {
	allowPrivateInitial bool
	allowRedirects      bool
}

type downloadPolicyContextKey struct{}

func (m *Manager) download(url string, max int64) ([]byte, error) {
	return m.downloadContextWithPolicy(context.Background(), url, max, maxDownloadAttempts, downloadPolicy{
		allowPrivateInitial: true,
		allowRedirects:      true,
	})
}

func (m *Manager) downloadContextWithPolicy(ctx context.Context, url string, max int64, attempts int, policy downloadPolicy) ([]byte, error) {
	m.downloadMu.Lock()
	defer m.downloadMu.Unlock()

	if attempts < 1 {
		return nil, fmt.Errorf("download attempts must be positive")
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, markTransportFailure(fmt.Errorf("download source deadline exceeded"))
		}
		attemptURL := url
		if attempt >= cacheBypassAttempt {
			var err error
			attemptURL, err = withDownloadCacheBypass(url)
			if err != nil {
				return nil, err
			}
		}
		body, retry, err := m.downloadOnce(ctx, attemptURL, max, policy)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry || attempt == attempts {
			break
		}
		if m.RetryDelay > 0 {
			timer := time.NewTimer(time.Duration(attempt) * m.RetryDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				// Since Go 1.23, receiving after Stop is guaranteed to block.
				// Do not use the pre-1.23 drain pattern when the deadline and
				// timer become ready together.
				timer.Stop()
				return nil, markTransportFailure(fmt.Errorf("download source deadline exceeded"))
			}
		}
	}
	return nil, lastErr
}

func withDownloadCacheBypass(rawURL string) (string, error) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("cannot prepare cache-bypass URL: %s", RedactedURL(rawURL))
	}
	// download=1 is an observed GitHub Releases edge-cache recovery. Applying it
	// to arbitrary mirrors can invalidate signed queries such as AWS SigV4, so
	// custom URLs are retried byte-for-byte unchanged.
	if u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(!strings.HasPrefix(u.Path, "/xxvcc/linux-temp-admin/releases/download/") &&
			!strings.HasPrefix(u.Path, "/xxvcc/linux-temp-admin/releases/latest/download/")) {
		return rawURL, nil
	}
	query := u.Query()
	query.Set("download", "1")
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (m *Manager) downloadOnce(ctx context.Context, url string, max int64, policy downloadPolicy) ([]byte, bool, error) {
	if !validate.UpgradeURL(url) {
		return nil, false, fmt.Errorf("unsafe or invalid URL: %s", RedactedURL(url))
	}
	ctx = context.WithValue(ctx, downloadPolicyContextKey{}, policy)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("cannot construct request for %s", RedactedURL(url))
	}
	// Only an explicit operator-selected URL may opt its initial address into the
	// private/reserved exception. Compiled-in mirror and GitHub requests do not;
	// every redirect clears the exception regardless of source.
	m.allowPrivateDial.Store(policy.allowPrivateInitial)
	resp, err := m.Client.Do(req)
	// Do has completed every dial (including redirects). Do not leave this
	// exception enabled while a response body is processed or between retries.
	m.allowPrivateDial.Store(false)
	if err != nil {
		safeErr := safeRequestError(url, err)
		var policy *safeDiagnosticError
		if errors.As(err, &policy) {
			return nil, false, safeErr
		}
		return nil, true, markTransportFailure(safeErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("request to %s returned status %d", redactedURLOrigin(url), resp.StatusCode)
		return nil, retryableHTTPStatus(resp.StatusCode), markTransportFailure(err)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, true, markTransportFailure(safeResponseReadError(url, err))
	}
	if int64(len(b)) > max {
		return nil, false, markTransportFailure(fmt.Errorf("response exceeds %d bytes", max))
	}
	if len(b) == 0 {
		return nil, true, markTransportFailure(fmt.Errorf("empty response"))
	}
	return b, false, nil
}

// RedactedURL renders enough of an upgrade URL to identify its endpoint while
// never disclosing HTTP userinfo or resource-specific path, query, or fragment
// data. It is also safe for malformed input: when no clean https origin can be
// recovered, no part of the supplied value is returned.
func RedactedURL(rawURL string) string {
	origin := redactedURLOrigin(rawURL)
	if origin == "[redacted URL]" {
		return origin
	}
	return origin + "/[details hidden]"
}

func redactedURLOrigin(rawURL string) string {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || !safeDiagnosticHost(u.Host) {
		return "[redacted URL]"
	}
	// u.Host deliberately excludes u.User. Constructing this string directly also
	// avoids URL.String, which would restore every sensitive URL component.
	return "https://" + u.Host
}

func safeDiagnosticHost(host string) bool {
	for _, r := range host {
		if r < 0x21 || r > 0x7e || strings.ContainsRune("/\\@?#<>'\"`|", r) {
			return false
		}
	}
	return true
}

// safeRequestError intentionally does not wrap or quote err. net/http's
// *url.Error and arbitrary RoundTrippers commonly embed the complete request
// URL in their text, including credentials and signed query parameters.
func safeRequestError(rawURL string, err error) error {
	endpoint := redactedURLOrigin(rawURL)
	var diagnostic *safeDiagnosticError
	var transportDiagnostic *safeTransportDiagnosticError
	switch {
	case errors.As(err, &diagnostic):
		return fmt.Errorf("request to %s failed: %s", endpoint, diagnostic.Error())
	case errors.As(err, &transportDiagnostic):
		return fmt.Errorf("request to %s failed: %s", endpoint, transportDiagnostic.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("request to %s timed out", endpoint)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("request to %s was cancelled", endpoint)
	default:
		return fmt.Errorf("request to %s failed", endpoint)
	}
}

func safeResponseReadError(rawURL string, err error) error {
	endpoint := redactedURLOrigin(rawURL)
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
		return fmt.Errorf("response from %s timed out", endpoint)
	}
	return fmt.Errorf("cannot read response from %s", endpoint)
}

type safeDiagnosticError struct{ message string }

func (e *safeDiagnosticError) Error() string { return e.message }

func safeDiagnostic(message string) error { return &safeDiagnosticError{message: message} }

// safeTransportDiagnosticError preserves a useful non-secret transport reason
// without putting it in the policy-error class that forbids source fallback.
type safeTransportDiagnosticError struct{ message string }

func (e *safeTransportDiagnosticError) Error() string { return e.message }

func safeTransportDiagnostic(message string) error {
	return &safeTransportDiagnosticError{message: message}
}

func retryableHTTPStatus(status int) bool {
	if status >= 500 && status <= 599 {
		return true
	}
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

// refusePrivateRedirect errors unless host resolves entirely to routable public
// addresses. A redirect that points at a private/reserved endpoint is rejected so
// a hostile release host cannot use the upgrade fetch as an SSRF pivot.
var (
	redirectLookupTimeout = 10 * time.Second
	lookupRedirectIPs     = net.DefaultResolver.LookupIP
)

func refusePrivateRedirect(parent context.Context, host string) error {
	ctx, cancel := context.WithTimeout(parent, redirectLookupTimeout)
	defer cancel()
	ips, err := lookupRedirectIPs(ctx, "ip", host)
	if err != nil {
		return safeTransportDiagnostic("cannot resolve redirect host")
	}
	if len(ips) == 0 {
		return safeTransportDiagnostic("redirect host resolved to no addresses")
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return safeDiagnostic("refusing redirect to a non-public address")
		}
	}
	return nil
}

// isPublicIP reports whether ip is a routable public address — not loopback,
// private (RFC1918/ULA), link-local, CGNAT (RFC6598), multicast, or unspecified.
// checkDialAddr is the dial-time policy the Control hook enforces on the address
// ACTUALLY being connected to (host:port, resolved). It is the rebinding-proof
// point: a name that passed a separate lookup but resolves to a private IP at
// connect time is refused here. A private address is allowed only while
// allowPrivate holds — true for the operator's initial URL (a deliberate internal
// mirror), cleared on the first redirect. It is a free function so the deny branch
// is directly testable, not reachable only through a live DNS-rebinding server.
func checkDialAddr(address string, allowPrivate bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ipHost := host
	if zone := strings.LastIndexByte(ipHost, '%'); zone > 0 && strings.Contains(ipHost[:zone], ":") {
		ipHost = ipHost[:zone]
	}
	ip := net.ParseIP(ipHost)
	if ip == nil {
		return safeDiagnostic("refusing to dial an unresolved address")
	}
	if isPublicIP(ip) || allowPrivate {
		return nil
	}
	return safeDiagnostic("refusing to dial a non-public address after redirect")
}

func isPublicIP(ip net.IP) bool {
	return validate.PublicIP(ip)
}
