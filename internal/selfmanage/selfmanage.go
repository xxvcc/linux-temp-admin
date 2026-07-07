// Package selfmanage installs, uninstalls, and upgrades the stable command. The
// upgrade path downloads the new binary over HTTPS and verifies a detached
// ed25519 signature against an embedded release public key before installing it
// — failing closed on any verification error. This is the authenticated
// self-upgrade the bash tool never had.
package selfmanage

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
}

// New returns a Manager with the embedded release public key and an HTTPS client
// that refuses to follow a redirect to a non-https scheme.
func New(installPath string, maxBytes int64) *Manager {
	return &Manager{
		InstallPath: installPath,
		PublicKey:   embeddedPublicKey(),
		MaxBytes:    maxBytes,
		Client: &http.Client{
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if req.URL.Scheme != "https" {
					return fmt.Errorf("refusing redirect to non-https: %s", req.URL)
				}
				return nil
			},
		},
	}
}

// Install atomically writes srcBytes to InstallPath as a root-owned 0755 binary.
// If the target exists, is byte-identical, install is a no-op; if it differs and
// force is false, it refuses.
func (m *Manager) Install(srcBytes []byte, force bool) error {
	if cur, err := os.ReadFile(m.InstallPath); err == nil {
		if string(cur) == string(srcBytes) {
			return nil
		}
		if !force {
			return fmt.Errorf("%s already exists and differs; use --force to replace", m.InstallPath)
		}
	}
	return fsutil.WriteRootFile(m.InstallPath, srcBytes, 0o755)
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
	if err := m.Install(bin, true); err != nil {
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

// normalizeSig accepts a raw 64-byte signature or a hex-encoded one.
func normalizeSig(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	if len(s) == ed25519.SignatureSize*2 {
		if raw, err := decodeHex(s); err == nil {
			return raw
		}
	}
	return b
}
