package selfmanage

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEmbeddedPublicKeyUnconfigured(t *testing.T) {
	// The shipped placeholder must parse as "no key" so upgrades fail closed.
	if embeddedPublicKey() != nil {
		t.Error("shipped release_pubkey.hex should be unconfigured (nil)")
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
