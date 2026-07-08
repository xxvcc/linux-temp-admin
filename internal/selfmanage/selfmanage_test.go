package selfmanage

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEmbeddedPublicKeyConfigured(t *testing.T) {
	// A release signing key is embedded, so signed upgrades are enabled.
	if len(embeddedPublicKey()) != ed25519.PublicKeySize {
		t.Errorf("embedded release key must be a %d-byte ed25519 key, got %d", ed25519.PublicKeySize, len(embeddedPublicKey()))
	}
}

func TestUpgradeRefusedWithoutKey(t *testing.T) {
	m := &Manager{PublicKey: nil}
	if _, err := m.Upgrade("https://x/bin", "https://x/sig", "2.0.0", false); err == nil {
		t.Error("Upgrade must refuse when no signing key is configured")
	}
}

func TestNormalizeSig(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, []byte("hello"))
	// raw stays raw
	if got := normalizeSig(sig); string(got) != string(sig) {
		t.Error("raw signature should pass through")
	}
	// hex is decoded
	hexSig := []byte(toHex(sig) + "\n")
	if got := normalizeSig(hexSig); string(got) != string(sig) {
		t.Error("hex signature should decode to raw")
	}
	// raw + a single trailing newline is trimmed to exactly 64 bytes
	rawNL := append(append([]byte{}, sig...), '\n')
	if got := normalizeSig(rawNL); string(got) != string(sig) {
		t.Error("raw signature with a trailing newline should normalize to 64 bytes")
	}
}

func toHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}
