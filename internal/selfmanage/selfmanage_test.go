package selfmanage

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
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

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true}, // public IPv6
		{"169.254.169.254", false},     // link-local (cloud metadata)
		{"127.0.0.1", false},           // loopback
		{"10.0.0.1", false},            // RFC1918
		{"192.168.1.1", false},         // RFC1918
		{"172.16.0.1", false},          // RFC1918
		{"100.100.100.200", false},     // CGNAT (RFC6598)
		{"0.0.0.0", false},             // unspecified
		{"::1", false},                 // IPv6 loopback
		{"fd00::1", false},             // IPv6 ULA
		{"fe80::1", false},             // IPv6 link-local
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test ip %q", c.ip)
		}
		if got := isPublicIP(ip); got != c.public {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.public)
		}
	}
}

func TestRefusePrivateRedirect(t *testing.T) {
	// IP literals resolve without DNS, so this is hermetic.
	for _, bad := range []string{"127.0.0.1", "169.254.169.254", "10.1.2.3", "::1"} {
		if err := refusePrivateRedirect(bad); err == nil {
			t.Errorf("redirect to %s must be refused", bad)
		}
	}
	if err := refusePrivateRedirect("8.8.8.8"); err != nil {
		t.Errorf("redirect to public 8.8.8.8 must be allowed: %v", err)
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
