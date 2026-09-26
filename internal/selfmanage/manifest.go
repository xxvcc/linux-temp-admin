package selfmanage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"strings"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// ReleaseManifest is untrusted routing metadata from the official mirror. Its
// base URL is accepted only when it exactly matches the compiled-in mirror root
// plus Tag; release signatures remain the content trust root.
type ReleaseManifest struct {
	Version     string
	Tag         string
	BaseURL     string
	PublishedAt string
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
	// published_at was validated for shape and then used only to rebuild the
	// canonical bytes, so it constrained nothing about WHICH release the mirror
	// names. A future timestamp is the one reading that is wrong on its face
	// rather than merely old: no release can be published after now, so it means a
	// skewed or fabricated index. Staleness itself stays a judgement this code
	// cannot make without a trusted clock reference; the version lower bound in
	// the caller is what covers a rolled-back index.
	if published, parseErr := time.Parse(time.RFC3339, manifest.PublishedAt); parseErr == nil {
		if published.After(time.Now().UTC().Add(publishedAtSkewAllowance)) {
			return ReleaseManifest{}, fmt.Errorf("published_at %s is in the future", manifest.PublishedAt)
		}
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

// publishedAtSkewAllowance tolerates ordinary clock disagreement between the
// mirror and this host without accepting a timestamp that is meaningfully ahead.
const publishedAtSkewAllowance = 24 * time.Hour

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
