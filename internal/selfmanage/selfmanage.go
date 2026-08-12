// Package selfmanage installs, uninstalls, and upgrades the stable command. The
// upgrade path downloads the new binary over HTTPS and verifies a detached
// ed25519 signature against an embedded release public key before installing it
// — failing closed on any verification error.
package selfmanage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"github.com/xxvcc/linux-temp-admin/internal/version"
)

// Manager performs install/uninstall/upgrade. Fields are injectable for tests.
type Manager struct {
	InstallPath string
	// PublicKey is the legacy single-key injection point. PublicKeys is the
	// rotation-capable keyring; Upgrade accepts a signature made by either. New
	// populates both so existing callers that inspect PublicKey keep working.
	PublicKey      ed25519.PublicKey
	PublicKeys     []ed25519.PublicKey
	Client         *http.Client
	MaxBytes       int64
	RetryDelay     time.Duration
	ProbeTimeout   time.Duration
	ProbeMaxOutput int64
	// WriteRootFile is a filesystem fault-injection hook. Production leaves it nil
	// and uses fsutil.WriteRootFile.
	WriteRootFile func(string, []byte, os.FileMode) error
	// Lstat is a target-inspection fault-injection hook. Production uses os.Lstat.
	Lstat func(string) (os.FileInfo, error)

	// allowPrivateDial gates whether the dialer may connect to a private/reserved
	// IP. It is true only for the initial, operator-supplied URL of the current
	// download (a deliberate internal mirror is legitimate); the first redirect
	// clears it, so a redirect target is checked against the address ACTUALLY
	// dialed — closing the DNS-rebinding gap where the redirect's name passed a
	// separate lookup but resolved to a private IP at connect time. Set per
	// download; a Manager runs its fetches sequentially.
	allowPrivateDial atomic.Bool
	downloadMu       sync.Mutex
}

// ErrNotInstalled reports that InstallPath has no directory entry. Callers use
// it to distinguish a repairable missing command from an unsafe or unreadable
// installed command.
var ErrNotInstalled = errors.New("stable command is not installed")

const (
	defaultRetryDelay    = 500 * time.Millisecond
	maxDownloadAttempts  = 4
	defaultProbeTimeout  = 10 * time.Second
	defaultProbeMaxBytes = int64(256)
	cacheBypassAttempt   = 3
	maxReleaseMetadata   = int64(1 << 20)
	mirrorDownloadTries  = 2
	mirrorManifestBudget = 40 * time.Second
	mirrorReleaseBudget  = 90 * time.Second
	releaseSourceBudget  = 5 * time.Minute
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

// New returns a Manager with the embedded release public key and an HTTPS client
// that refuses to follow a redirect to a non-https scheme.
func New(installPath string, maxBytes int64) *Manager {
	keys := embeddedPublicKeys()
	m := &Manager{
		InstallPath:    installPath,
		PublicKeys:     keys,
		MaxBytes:       maxBytes,
		RetryDelay:     defaultRetryDelay,
		ProbeTimeout:   defaultProbeTimeout,
		ProbeMaxOutput: defaultProbeMaxBytes,
	}
	if len(keys) > 0 {
		m.PublicKey = keys[0]
	}
	// The Control hook runs with the address ACTUALLY being dialed — the resolved
	// IP:port, after Go's own resolution — so it is the authoritative, rebinding-
	// proof enforcement point: a name that passed a separate lookup but resolves to
	// a private IP at connect time is still refused here. Private IPs are allowed
	// only while allowPrivateDial holds, i.e. for the operator's initial URL, so a
	// deliberate internal mirror still works; the first redirect clears it.
	dialer := &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddr(address, m.allowPrivateDial.Load())
		},
	}
	m.Client = &http.Client{
		Timeout: 60 * time.Second, // bound the whole fetch; a stalled server can't hang upgrade
		// Disable reuse so every redirect target reaches the dial-time IP policy;
		// otherwise an already-idle private connection could bypass Control.
		Transport: &http.Transport{DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// net/http synthesizes Referer from the previous complete URL before it
			// calls CheckRedirect. Custom mirror URLs may carry signed query values or
			// fragments, so never forward that URL to a redirect-selected endpoint.
			req.Header.Del("Referer")
			// A redirect target is chosen by the (possibly hostile) release server, so
			// it must stay https, and from here on a private address is refused: the
			// operator only vouched for the initial URL, not for wherever it bounces.
			m.allowPrivateDial.Store(false)
			if policy, ok := req.Context().Value(downloadPolicyContextKey{}).(downloadPolicy); ok && !policy.allowRedirects {
				return safeDiagnostic("official mirror endpoints must not redirect")
			}
			if len(via) >= 10 {
				return safeDiagnostic("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return safeDiagnostic("refusing redirect to a non-https endpoint")
			}
			// The name-based check stays as a friendly, early rejection; the Control
			// hook above is what actually holds under DNS rebinding.
			return refusePrivateRedirect(req.Context(), req.URL.Hostname())
		},
	}
	return m
}

// Install atomically writes srcBytes to InstallPath as a root-owned 0755 binary.
// It reports whether it actually wrote: a byte-identical target is left alone and
// returns (false, nil), mirroring Upgrade's ("", nil) for "nothing to do". If the
// target differs and force is false, it refuses.
func (m *Manager) Install(srcBytes []byte, force bool) (installed bool, err error) {
	if err := ensureInstallDir(filepath.Dir(m.InstallPath)); err != nil {
		return false, err
	}
	fi, statErr := m.lstat(m.InstallPath)
	if statErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%s is a symlink; refusing", m.InstallPath)
		}
		if fi.Mode().IsRegular() {
			same, rerr := sameInstalledBytes(m.InstallPath, srcBytes)
			if rerr == nil && same {
				if installedFileMetadataSafe(fi) {
					return false, nil // byte-identical and already root:root 0755
				}
				// Identical bytes do not make an attacker-writable or set-id binary
				// safe. Rewrite atomically to normalize all metadata, even without
				// --force: no content replacement has been requested.
				if err := m.writeRootFile(srcBytes); err != nil {
					return mutationResult(err)
				}
				return true, nil
			}
			if !force {
				// Fail closed: never replace an existing binary without --force, even
				// if it could not be read back for the identical-bytes comparison.
				if rerr != nil {
					return false, fmt.Errorf("%s exists but could not be read (%v); use --force to replace", m.InstallPath, rerr)
				}
				return false, fmt.Errorf("%s already exists and differs; use --force to replace", m.InstallPath)
			}
		} else if !force {
			return false, fmt.Errorf("%s exists and is not a regular file; use --force to replace", m.InstallPath)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect existing install target: %w", statErr)
	}
	if err := m.writeRootFile(srcBytes); err != nil {
		return mutationResult(err)
	}
	return true, nil
}

func (m *Manager) lstat(path string) (os.FileInfo, error) {
	if m.Lstat != nil {
		return m.Lstat(path)
	}
	return os.Lstat(path)
}

func ensureInstallDir(dir string) error {
	if err := fsutil.RootSafeDir(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unsafe target directory: %w", err)
	}
	if err := fsutil.EnsureDir(dir, 0o755, 0, 0); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	if err := fsutil.RootSafeDir(dir); err != nil {
		return fmt.Errorf("unsafe target directory after creation: %w", err)
	}
	return nil
}

func sameInstalledBytes(path string, expected []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() != int64(len(expected)) {
		return false, nil
	}
	actual, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	if err != nil {
		return false, err
	}
	return bytes.Equal(actual, expected), nil
}

func (m *Manager) writeRootFile(content []byte) error {
	if m.WriteRootFile != nil {
		return m.WriteRootFile(m.InstallPath, content, 0o755)
	}
	return fsutil.WriteRootFile(m.InstallPath, content, 0o755)
}

// mutationResult preserves the crucial distinction exposed by DurabilityError:
// the new inode is already visible even though its parent-directory fsync failed.
func mutationResult(err error) (bool, error) {
	var durability *fsutil.DurabilityError
	return errors.As(err, &durability), err
}

func installedFileMetadataSafe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return false
	}
	special := os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return fi.Mode().IsRegular() && fi.Mode().Perm() == 0o755 && fi.Mode()&special == 0
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
	return fsutil.RemoveFile(m.InstallPath)
}

// UpgradeCandidate is an authenticated binary ready for a short locked commit.
// signedVersion comes from bytes covered by the detached signature and is read
// without executing the candidate. Its bytes are intentionally private so
// callers cannot alter the payload between verification and installation.
type UpgradeCandidate struct {
	bin           []byte
	signedVersion string
	expected      string
}

// ReleaseManifest is untrusted routing metadata from the official mirror. Its
// base URL is accepted only when it exactly matches the compiled-in mirror root
// plus Tag; release signatures remain the content trust root.
type ReleaseManifest struct {
	Version     string
	Tag         string
	BaseURL     string
	PublishedAt string
}

// Version reports the candidate's authenticated static release-version witness.
// Historical signed binaries without that witness report an empty version and
// require an explicit forced upgrade before they may be probed.
func (c *UpgradeCandidate) Version() string {
	if c == nil {
		return ""
	}
	return c.signedVersion
}

// FetchReleaseManifest downloads and strictly decodes one mirror manifest.
// Duplicate or unknown fields are rejected, as are noncanonical versions and a
// base URL that attempts to move downloads away from expectedRoot.
func (m *Manager) FetchReleaseManifest(manifestURL, expectedRoot string) (ReleaseManifest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mirrorManifestBudget)
	defer cancel()
	b, err := m.downloadContextWithPolicy(ctx, manifestURL, maxReleaseMetadata, mirrorDownloadTries, downloadPolicy{})
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("download release manifest: %w", err)
	}
	manifest, err := decodeReleaseManifest(b)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("invalid release manifest: %w", err)
	}
	root := strings.TrimSuffix(expectedRoot, "/")
	if !validate.UpgradeURL(root) {
		return ReleaseManifest{}, fmt.Errorf("invalid compiled-in mirror root")
	}
	if !validate.ReleaseVersion(manifest.Version) || manifest.Tag != "v"+manifest.Version {
		return ReleaseManifest{}, fmt.Errorf("version and tag are inconsistent")
	}
	if manifest.BaseURL != root+"/"+manifest.Tag {
		return ReleaseManifest{}, fmt.Errorf("base URL does not match the official mirror")
	}
	if !canonicalPublishedAt(manifest.PublishedAt) {
		return ReleaseManifest{}, fmt.Errorf("published_at is not canonical UTC RFC3339")
	}
	canonical, err := json.Marshal(struct {
		Version     string `json:"version"`
		Tag         string `json:"tag"`
		BaseURL     string `json:"base_url"`
		PublishedAt string `json:"published_at"`
	}{manifest.Version, manifest.Tag, manifest.BaseURL, manifest.PublishedAt})
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("encode canonical release manifest: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(b, canonical) {
		return ReleaseManifest{}, fmt.Errorf("release manifest is not canonical single-line JSON")
	}
	return manifest, nil
}

func canonicalPublishedAt(value string) bool {
	if len(value) < 20 || len(value) > 30 || value[4] != '-' || value[7] != '-' ||
		value[10] != 'T' || value[13] != ':' || value[16] != ':' || value[len(value)-1] != 'Z' {
		return false
	}
	for _, index := range []int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18} {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	if value[:4] == "0000" {
		return false
	}
	if len(value) == 20 {
		if value[19] != 'Z' {
			return false
		}
	} else {
		if value[19] != '.' || len(value) < 22 {
			return false
		}
		for i := 20; i < len(value)-1; i++ {
			if value[i] < '0' || value[i] > '9' {
				return false
			}
		}
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func decodeReleaseManifest(b []byte) (ReleaseManifest, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	open, err := dec.Token()
	if err != nil || open != json.Delim('{') {
		return ReleaseManifest{}, errors.New("expected one JSON object")
	}
	var manifest ReleaseManifest
	seen := make(map[string]bool, 4)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return ReleaseManifest{}, errors.New("invalid object key")
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return ReleaseManifest{}, errors.New("duplicate or invalid object key")
		}
		seen[key] = true
		var value string
		if err := dec.Decode(&value); err != nil {
			return ReleaseManifest{}, errors.New("manifest values must be strings")
		}
		switch key {
		case "version":
			manifest.Version = value
		case "tag":
			manifest.Tag = value
		case "base_url":
			manifest.BaseURL = value
		case "published_at":
			manifest.PublishedAt = value
		default:
			return ReleaseManifest{}, errors.New("unknown object key")
		}
	}
	closeToken, err := dec.Token()
	if err != nil || closeToken != json.Delim('}') {
		return ReleaseManifest{}, errors.New("unterminated JSON object")
	}
	if token, err := dec.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ReleaseManifest{}, errors.New("trailing JSON data")
	}
	if len(seen) != 4 || manifest.Version == "" || manifest.Tag == "" ||
		manifest.BaseURL == "" || manifest.PublishedAt == "" {
		return ReleaseManifest{}, errors.New("missing required field")
	}
	return manifest, nil
}

// PrepareUpgrade performs every slow, read-only upgrade step: download and
// detached signature verification. It does not execute the candidate. Callers
// can do this before taking their lifecycle mutation lock.
func (m *Manager) PrepareUpgrade(binaryURL, sigURL string) (*UpgradeCandidate, error) {
	keys := m.verificationKeys()
	if len(keys) == 0 {
		return nil, fmt.Errorf("no release signing key configured; signed upgrade is disabled")
	}
	bin, err := m.download(binaryURL, m.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("download binary: %w", err)
	}
	sig, err := m.download(sigURL, ed25519.SignatureSize*4)
	if err != nil {
		return nil, fmt.Errorf("download signature: %w", err)
	}
	return m.prepareVerifiedCandidate(bin, sig, "")
}

// PrepareReleaseUpgrade downloads the complete public set needed for one
// architecture from a single immutable base URL. Transport failures remain
// identifiable to the caller; once all bytes arrive, any checksum, signature,
// or version failure is fail-closed and must not select another source.
func (m *Manager) PrepareReleaseUpgrade(baseURL, asset, expectedVersion string) (*UpgradeCandidate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), releaseSourceBudget)
	defer cancel()
	return m.prepareReleaseUpgrade(ctx, baseURL, asset, expectedVersion, maxDownloadAttempts, downloadPolicy{allowRedirects: true})
}

// PrepareMirrorReleaseUpgrade gives the preferred mirror a short total budget
// before the caller selects GitHub. The budget spans all three files, so a black
// hole cannot consume one full retry window per asset.
func (m *Manager) PrepareMirrorReleaseUpgrade(baseURL, asset, expectedVersion string) (*UpgradeCandidate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mirrorReleaseBudget)
	defer cancel()
	return m.prepareReleaseUpgrade(ctx, baseURL, asset, expectedVersion, mirrorDownloadTries, downloadPolicy{})
}

func (m *Manager) prepareReleaseUpgrade(ctx context.Context, baseURL, asset, expectedVersion string, attempts int, policy downloadPolicy) (*UpgradeCandidate, error) {
	if asset != "linux-temp-admin-linux-amd64" && asset != "linux-temp-admin-linux-arm64" {
		return nil, fmt.Errorf("unsupported release asset")
	}
	if expectedVersion != "" && !validate.ReleaseVersion(expectedVersion) {
		return nil, fmt.Errorf("invalid expected release version")
	}
	sumsURL, err := releaseFileURL(baseURL, "SHA256SUMS")
	if err != nil {
		return nil, err
	}
	binaryURL, err := releaseFileURL(baseURL, asset)
	if err != nil {
		return nil, err
	}
	sigURL, err := releaseFileURL(baseURL, asset+".sig")
	if err != nil {
		return nil, err
	}
	sums, err := m.downloadContextWithPolicy(ctx, sumsURL, maxReleaseMetadata, attempts, policy)
	if err != nil {
		return nil, fmt.Errorf("download SHA256SUMS: %w", err)
	}
	bin, err := m.downloadContextWithPolicy(ctx, binaryURL, m.MaxBytes, attempts, policy)
	if err != nil {
		return nil, fmt.Errorf("download binary: %w", err)
	}
	sig, err := m.downloadContextWithPolicy(ctx, sigURL, ed25519.SignatureSize*4, attempts, policy)
	if err != nil {
		return nil, fmt.Errorf("download signature: %w", err)
	}
	if err := verifyReleaseChecksums(sums, map[string][]byte{asset: bin, asset + ".sig": sig}); err != nil {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("official release signature must be exactly %d raw bytes", ed25519.SignatureSize)
	}
	return m.prepareVerifiedCandidate(bin, sig, expectedVersion)
}

func releaseFileURL(baseURL, name string) (string, error) {
	u, err := neturl.Parse(baseURL)
	if err != nil || !validate.UpgradeURL(baseURL) || u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("invalid release base URL")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + name
	return u.String(), nil
}

func verifyReleaseChecksums(sums []byte, files map[string][]byte) error {
	if len(sums) == 0 || sums[len(sums)-1] != '\n' || bytes.IndexByte(sums, 0) >= 0 {
		return errors.New("SHA256SUMS is not a canonical newline-terminated manifest")
	}
	wanted := make(map[string]string, len(files))
	for _, line := range strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n") {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || len(parts[0]) != 64 || parts[1] == "" {
			return errors.New("SHA256SUMS contains an invalid record")
		}
		if parts[0] != strings.ToLower(parts[0]) {
			return errors.New("SHA256SUMS digest is not canonical lowercase hexadecimal")
		}
		if _, err := decodeHex(parts[0]); err != nil {
			return errors.New("SHA256SUMS contains an invalid digest")
		}
		if _, needed := files[parts[1]]; !needed {
			continue
		}
		if _, duplicate := wanted[parts[1]]; duplicate {
			return errors.New("SHA256SUMS contains a duplicate selected asset")
		}
		wanted[parts[1]] = parts[0]
	}
	for name, data := range files {
		want, ok := wanted[name]
		if !ok {
			return errors.New("SHA256SUMS is missing a selected asset")
		}
		got := fmt.Sprintf("%x", sha256.Sum256(data))
		if got != want {
			return errors.New("selected asset digest mismatch")
		}
	}
	return nil
}

func (m *Manager) prepareVerifiedCandidate(bin, sig []byte, expectedVersion string) (*UpgradeCandidate, error) {
	keys := m.verificationKeys()
	if len(keys) == 0 {
		return nil, fmt.Errorf("no release signing key configured; signed upgrade is disabled")
	}
	sig = normalizeSig(sig)
	verified := false
	for _, key := range keys {
		if ed25519.Verify(key, bin, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("signature verification failed; refusing to install")
	}
	signedVersion, err := releaseVersionWitness(bin)
	if err != nil {
		return nil, fmt.Errorf("read signed release version: %w", err)
	}
	if expectedVersion != "" && signedVersion != "" && signedVersion != expectedVersion {
		return nil, fmt.Errorf("signed candidate version %q does not match selected release %q", signedVersion, expectedVersion)
	}
	return &UpgradeCandidate{
		bin:           append([]byte(nil), bin...),
		signedVersion: signedVersion,
		expected:      expectedVersion,
	}, nil
}

// ApplyUpgrade re-reads the installed command at commit time, applies the
// downgrade policy to that current state, and atomically installs candidate.
// It returns ("", nil) if the installed command is already the same version or
// newer. If replacement is visible but not known durable, the version is returned
// alongside the durability error so the CLI can report the partial outcome.
func (m *Manager) ApplyUpgrade(candidate *UpgradeCandidate, force bool) (string, error) {
	if candidate == nil || len(candidate.bin) == 0 ||
		(candidate.signedVersion != "" && !validate.ReleaseVersion(candidate.signedVersion)) ||
		(candidate.expected != "" && !validate.ReleaseVersion(candidate.expected)) {
		return "", fmt.Errorf("invalid prepared upgrade candidate")
	}
	installedVersion := ""
	if current, err := m.InstalledVersion(); err == nil {
		installedVersion = current
	} else if !errors.Is(err, ErrNotInstalled) && !force {
		return "", fmt.Errorf("read installed version: %w", err)
	}
	if !force {
		if candidate.signedVersion == "" {
			return "", fmt.Errorf("signed candidate has no static release-version witness; use --force only after independently confirming the historical binary")
		}
		if installedVersion != "" && !version.Greater(candidate.signedVersion, installedVersion) {
			return "", nil // already up to date or newer; candidate was not executed
		}
	}
	probedVersion, err := m.probeVersion(candidate.bin)
	if err != nil {
		return "", fmt.Errorf("read downloaded version: %w", err)
	}
	if candidate.signedVersion != "" && probedVersion != candidate.signedVersion {
		return "", fmt.Errorf("candidate version %q does not match signed release-version witness %q", probedVersion, candidate.signedVersion)
	}
	if candidate.expected != "" && probedVersion != candidate.expected {
		return "", fmt.Errorf("signed candidate version %q does not match selected release %q", probedVersion, candidate.expected)
	}
	installed, err := m.Install(candidate.bin, true)
	if err != nil {
		if installed {
			return probedVersion, fmt.Errorf("installed command was replaced but durability is unknown: %w", err)
		}
		return "", err
	}
	if !installed {
		return "", nil
	}
	return probedVersion, nil
}

var releaseVersionWitnessPrefix = []byte{
	'L', 'T', 'A', '_', 'R', 'E', 'L', 'E', 'A', 'S', 'E', '_',
	'V', 'E', 'R', 'S', 'I', 'O', 'N', '_', 'V', '1', '{',
}

// releaseVersionWitness extracts one canonical framed version from signed
// candidate bytes. The byte-slice spelling avoids embedding a second complete
// marker in this binary merely as a parser constant.
func releaseVersionWitness(bin []byte) (string, error) {
	versionValue := ""
	search := bin
	for {
		index := bytes.Index(search, releaseVersionWitnessPrefix)
		if index < 0 {
			break
		}
		valueStart := index + len(releaseVersionWitnessPrefix)
		remaining := search[valueStart:]
		valueEnd := bytes.IndexByte(remaining, '}')
		if valueEnd >= 0 && valueEnd <= validate.MaxReleaseVersionBytes {
			candidate := string(remaining[:valueEnd])
			if validate.ReleaseVersion(candidate) {
				if versionValue != "" {
					return "", fmt.Errorf("candidate contains multiple release-version witnesses")
				}
				versionValue = candidate
			}
		}
		search = search[index+1:]
	}
	return versionValue, nil
}

// Upgrade is the one-shot API retained for callers that already provide their
// own serialization. CLI code uses PrepareUpgrade and ApplyUpgrade separately so
// network retries never hold the global lifecycle lock.
func (m *Manager) Upgrade(binaryURL, sigURL string, force bool) (string, error) {
	candidate, err := m.PrepareUpgrade(binaryURL, sigURL)
	if err != nil {
		return "", err
	}
	return m.ApplyUpgrade(candidate, force)
}

func (m *Manager) verificationKeys() []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(m.PublicKeys)+1)
	seen := make(map[string]struct{})
	add := func(key ed25519.PublicKey) {
		if len(key) != ed25519.PublicKeySize {
			return
		}
		id := string(key)
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		keys = append(keys, key)
	}
	for _, key := range m.PublicKeys {
		add(key)
	}
	add(m.PublicKey)
	return keys
}

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

// InstalledVersion safely executes `<InstallPath> version` under the same
// timeout, output cap, process-group cancellation, and WaitDelay used for a
// downloaded candidate.
func (m *Manager) InstalledVersion() (string, error) {
	if _, err := os.Lstat(m.InstallPath); err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotInstalled
		}
		return "", err
	}
	if err := fsutil.RootSafeFile(m.InstallPath); err != nil {
		return "", fmt.Errorf("installed command is unsafe: %w", err)
	}
	v, err := m.runVersionProbe(m.InstallPath)
	if err != nil {
		return "", fmt.Errorf("probe installed command: %w", err)
	}
	return v, nil
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
	if _, err := io.Copy(f, bytes.NewReader(bin)); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Chmod(0o700); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	v, err := m.runVersionProbe(tmp)
	if err != nil {
		return "", err
	}
	return v, nil
}

func (m *Manager) runVersionProbe(path string) (string, error) {
	timeout := m.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	maxOutput := m.ProbeMaxOutput
	if maxOutput <= 0 {
		maxOutput = defaultProbeMaxBytes
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	cmd.WaitDelay = time.Second
	out := &boundedBuffer{max: maxOutput}
	cmd.Stdout = out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("version probe timed out after %s", timeout)
	}
	if errors.Is(err, errProbeOutputLimit) || errors.Is(out.err, errProbeOutputLimit) {
		return "", fmt.Errorf("version probe output exceeds %d bytes", maxOutput)
	}
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(out.String())
	if !validate.InstalledVersion(v) {
		return "", fmt.Errorf("binary reported an invalid version: %q", v)
	}
	return v, nil
}

var errProbeOutputLimit = errors.New("version probe output limit exceeded")

type boundedBuffer struct {
	buf bytes.Buffer
	max int64
	err error
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.max - int64(b.buf.Len())
	if remaining <= 0 {
		b.err = errProbeOutputLimit
		return 0, b.err
	}
	if int64(len(p)) > remaining {
		n, _ := b.buf.Write(p[:remaining])
		b.err = errProbeOutputLimit
		return n, b.err
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string { return b.buf.String() }

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
