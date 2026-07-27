package selfmanage

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed release_pubkey.hex
var releasePubkeyHex string

// embeddedPublicKeys parses the embedded release keyring. Each non-comment line
// is one complete hex-encoded ed25519 public key. Any malformed or duplicate key
// invalidates the whole keyring so a botched rotation fails closed.
func embeddedPublicKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	seen := make(map[string]struct{})
	for _, line := range strings.Split(releasePubkeyHex, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := hex.DecodeString(line)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil
		}
		id := string(raw)
		if _, ok := seen[id]; ok {
			return nil
		}
		seen[id] = struct{}{}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil
	}
	return keys
}

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
