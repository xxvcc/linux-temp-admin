package selfmanage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"debug/elf"
	"fmt"
	"runtime"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// UpgradeCandidate is an authenticated binary ready for a short locked commit.
// signedVersion comes from bytes covered by the detached signature and is read
// without executing the candidate. Its bytes are intentionally private so
// callers cannot alter the payload between verification and installation.
type UpgradeCandidate struct {
	bin           []byte
	signedVersion string
	expected      string
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
	// The signature covers raw bytes only: it carries no asset name and no
	// architecture, and the release-version witness is byte-identical across the
	// amd64 and arm64 builds of the same release. SHA256SUMS, the only artifact
	// that binds a name to a digest, is unsigned. So a party controlling what the
	// mirror serves can hand this host the OTHER architecture's genuinely signed
	// binary under this architecture's asset name and every check above passes.
	// The bytes themselves still say which machine they are for; require that.
	if err := m.machineCheck()(bin); err != nil {
		return nil, err
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

func (m *Manager) verificationKeys() []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(m.PublicKeys))
	for _, key := range m.PublicKeys {
		if len(key) == ed25519.PublicKeySize {
			keys = append(keys, key)
		}
	}
	return keys
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

// machineCheck returns the architecture gate, defaulting to requireHostMachine.
// RequireHostMachine is a field so a test can present a non-ELF fixture; nothing
// in production sets it, and leaving it nil keeps the strict check.
func (m *Manager) machineCheck() func([]byte) error {
	if m != nil && m.RequireHostMachine != nil {
		return m.RequireHostMachine
	}
	return requireHostMachine
}

// hostELFMachine is the ELF machine this build must run on. An architecture that
// is not listed cannot be checked, and the official upgrade path already refuses
// to select an asset for one.
func hostELFMachine() (elf.Machine, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64, true
	case "arm64":
		return elf.EM_AARCH64, true
	}
	return 0, false
}

// requireHostMachine refuses a candidate that is not a 64-bit little-endian Linux
// ELF executable for this host's architecture. It is deliberately a check on the
// downloaded bytes rather than on the name they arrived under: the name is the
// part an attacker controls.
func requireHostMachine(bin []byte) error {
	want, known := hostELFMachine()
	if !known {
		return nil
	}
	f, err := elf.NewFile(bytes.NewReader(bin))
	if err != nil {
		return fmt.Errorf("candidate is not a readable ELF executable: %w", err)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("candidate ELF class/encoding %s/%s is not the 64-bit little-endian build this host runs", f.Class, f.Data)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("candidate ELF type %s is not an executable", f.Type)
	}
	if f.Machine != want {
		return fmt.Errorf("candidate is built for %s but this host runs %s (%s); refusing to install another architecture's release",
			f.Machine, want, runtime.GOARCH)
	}
	return nil
}
