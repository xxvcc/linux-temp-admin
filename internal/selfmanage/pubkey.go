package selfmanage

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed release_pubkey.hex
var releasePubkeyHex string

// embeddedPublicKey parses the embedded release signing key (hex; comment lines
// starting with '#' and whitespace ignored). Returns nil when unconfigured or
// malformed, which disables signed upgrades.
func embeddedPublicKey() ed25519.PublicKey {
	var b strings.Builder
	for _, line := range strings.Split(releasePubkeyHex, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b.WriteString(line)
	}
	raw, err := hex.DecodeString(b.String())
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
