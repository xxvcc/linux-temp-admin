// Package selfmanage installs, uninstalls, and upgrades the stable command. The
// upgrade path downloads the new binary over HTTPS and verifies a detached
// ed25519 signature against an embedded release public key before installing it
// — failing closed on any verification error.
package selfmanage

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"github.com/xxvcc/linux-temp-admin/internal/version"
)

// Manager performs install/uninstall/upgrade. Fields are injectable for tests.
type Manager struct {
	InstallPath string
	PublicKey   ed25519.PublicKey // release signing key; nil => signed upgrades disabled
	Client      *http.Client
	MaxBytes    int64

	// allowPrivateDial gates whether the dialer may connect to a private/reserved
	// IP. It is true only for the initial, operator-supplied URL of the current
	// download (a deliberate internal mirror is legitimate); the first redirect
	// clears it, so a redirect target is checked against the address ACTUALLY
	// dialed — closing the DNS-rebinding gap where the redirect's name passed a
	// separate lookup but resolved to a private IP at connect time. Set per
	// download; a Manager runs its fetches sequentially.
	allowPrivateDial bool
}

// New returns a Manager with the embedded release public key and an HTTPS client
// that refuses to follow a redirect to a non-https scheme.
func New(installPath string, maxBytes int64) *Manager {
	m := &Manager{
		InstallPath: installPath,
		PublicKey:   embeddedPublicKey(),
		MaxBytes:    maxBytes,
	}
	// The Control hook runs with the address ACTUALLY being dialed — the resolved
	// IP:port, after Go's own resolution — so it is the authoritative, rebinding-
	// proof enforcement point: a name that passed a separate lookup but resolves to
	// a private IP at connect time is still refused here. Private IPs are allowed
	// only while allowPrivateDial holds, i.e. for the operator's initial URL, so a
	// deliberate internal mirror still works; the first redirect clears it.
	dialer := &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || isPublicIP(ip) || m.allowPrivateDial {
				return nil
			}
			return fmt.Errorf("refusing to dial non-public address after redirect: %s", address)
		},
	}
	m.Client = &http.Client{
		Timeout:   60 * time.Second, // bound the whole fetch; a stalled server can't hang upgrade
		Transport: &http.Transport{DialContext: dialer.DialContext, ForceAttemptHTTP2: true},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			// A redirect target is chosen by the (possibly hostile) release server, so
			// it must stay https, and from here on a private address is refused: the
			// operator only vouched for the initial URL, not for wherever it bounces.
			m.allowPrivateDial = false
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-https: %s", req.URL)
			}
			// The name-based check stays as a friendly, early rejection; the Control
			// hook above is what actually holds under DNS rebinding.
			return refusePrivateRedirect(req.URL.Hostname())
		},
	}
	return m
}

// Install atomically writes srcBytes to InstallPath as a root-owned 0755 binary.
// It reports whether it actually wrote: a byte-identical target is left alone and
// returns (false, nil), mirroring Upgrade's ("", nil) for "nothing to do". If the
// target differs and force is false, it refuses.
func (m *Manager) Install(srcBytes []byte, force bool) (installed bool, err error) {
	if fi, err := os.Lstat(m.InstallPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%s is a symlink; refusing", m.InstallPath)
		}
		if fi.Mode().IsRegular() {
			cur, rerr := os.ReadFile(m.InstallPath)
			if rerr == nil && string(cur) == string(srcBytes) {
				return false, nil // already installed and byte-identical
			}
			if !force {
				// Fail closed: never replace an existing binary without --force, even
				// if it could not be read back for the identical-bytes comparison.
				if rerr != nil {
					return false, fmt.Errorf("%s exists but could not be read (%v); use --force to replace", m.InstallPath, rerr)
				}
				return false, fmt.Errorf("%s already exists and differs; use --force to replace", m.InstallPath)
			}
		}
	}
	if err := fsutil.WriteRootFile(m.InstallPath, srcBytes, 0o755); err != nil {
		return false, err
	}
	return true, nil
}

// Uninstall removes the stable command. Unless force is set, the target must be a
// safe root-owned regular file.
func (m *Manager) Uninstall(force bool) error {
	if _, err := os.Lstat(m.InstallPath); os.IsNotExist(err) {
		return nil
	}
	if !force {
		if err := fsutil.RootSafeFile(m.InstallPath); err != nil {
			return fmt.Errorf("refusing to remove an unsafe path: %w", err)
		}
	}
	return os.Remove(m.InstallPath)
}

// Upgrade downloads the binary and its detached signature, verifies the signature
// with the embedded public key, confirms the downloaded version is newer than
// currentVersion (unless force), and atomically installs it. It returns the new
// version, or ("", nil) if already up to date.
func (m *Manager) Upgrade(binaryURL, sigURL, currentVersion string, force bool) (string, error) {
	if len(m.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("no release signing key configured; signed upgrade is disabled")
	}
	bin, err := m.download(binaryURL, m.MaxBytes)
	if err != nil {
		return "", fmt.Errorf("download binary: %w", err)
	}
	sig, err := m.download(sigURL, ed25519.SignatureSize*4)
	if err != nil {
		return "", fmt.Errorf("download signature: %w", err)
	}
	sig = normalizeSig(sig)
	if !ed25519.Verify(m.PublicKey, bin, sig) {
		return "", fmt.Errorf("signature verification failed; refusing to install")
	}
	// The bytes are authenticated; safe to execute for its version.
	newVer, err := m.probeVersion(bin)
	if err != nil {
		return "", fmt.Errorf("read downloaded version: %w", err)
	}
	if !force && !version.Greater(newVer, currentVersion) {
		return "", nil // already up to date or newer
	}
	if _, err := m.Install(bin, true); err != nil {
		return "", err
	}
	return newVer, nil
}

func (m *Manager) download(url string, max int64) ([]byte, error) {
	if !validate.UpgradeURL(url) {
		return nil, fmt.Errorf("unsafe or invalid URL: %s", url)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// The operator vouched for this initial URL, so a private/reserved address is
	// allowed for it (a deliberate internal mirror); the first redirect clears this.
	m.allowPrivateDial = true
	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response exceeds %d bytes", max)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return b, nil
}

// probeVersion writes the (already verified) bytes to a temp file beside the
// install path, executes `<tmp> version`, and returns the validated version.
func (m *Manager) probeVersion(bin []byte) (string, error) {
	dir := filepath.Dir(m.InstallPath)
	// The install dir must be root-owned and not group/world-writable before we
	// write+exec a temp binary in it (a writable dir could let a local user swap
	// the temp between close and exec).
	if err := fsutil.RootSafeDir(dir); err != nil {
		return "", fmt.Errorf("install dir unsafe: %w", err)
	}
	f, err := os.CreateTemp(dir, ".lta-upgrade-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(bin); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Chmod(0o700); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	out, err := exec.Command(tmp, "version").Output()
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(out))
	if !validate.InstalledVersion(v) {
		return "", fmt.Errorf("downloaded binary reported an invalid version: %q", v)
	}
	return v, nil
}

// normalizeSig accepts a raw 64-byte signature or a hex-encoded one. It handles
// a lone trailing newline without TrimSpace (which could strip a whitespace-
// valued edge byte from a genuine raw signature).
func normalizeSig(b []byte) []byte {
	if len(b) == ed25519.SignatureSize {
		return b
	}
	if len(b) == ed25519.SignatureSize+1 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		return b[:ed25519.SignatureSize]
	}
	if s := strings.TrimSpace(string(b)); len(s) == ed25519.SignatureSize*2 {
		if raw, err := decodeHex(s); err == nil {
			return raw
		}
	}
	return b
}

// refusePrivateRedirect errors unless host resolves entirely to routable public
// addresses. A redirect that points at a private/reserved endpoint is rejected so
// a hostile release host cannot use the upgrade fetch as an SSRF pivot.
func refusePrivateRedirect(host string) error {
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve redirect host %q: %w", host, err)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("refusing redirect to non-public address (%s -> %s)", host, ip)
		}
	}
	return nil
}

// isPublicIP reports whether ip is a routable public address — not loopback,
// private (RFC1918/ULA), link-local, CGNAT (RFC6598), multicast, or unspecified.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// CGNAT 100.64.0.0/10 — where some cloud metadata services live.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64 {
		return false
	}
	return true
}
