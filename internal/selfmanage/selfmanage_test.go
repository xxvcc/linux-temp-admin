package selfmanage

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
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
		{"0.1.2.3", false},             // "this network" (RFC1122)
		{"192.0.2.1", false},           // TEST-NET-1
		{"198.18.0.1", false},          // benchmarking (RFC2544)
		{"198.51.100.1", false},        // TEST-NET-2
		{"203.0.113.1", false},         // TEST-NET-3
		{"240.0.0.1", false},           // reserved for future use
		{"0.0.0.0", false},             // unspecified
		{"::1", false},                 // IPv6 loopback
		{"fd00::1", false},             // IPv6 ULA
		{"fe80::1", false},             // IPv6 link-local
		{"64:ff9b::a00:1", false},      // NAT64 well-known prefix
		{"100::1", false},              // discard-only prefix
		{"2001:db8::1", false},         // IPv6 documentation
		{"2002:a00:1::1", false},       // deprecated 6to4, embeds private IPv4
		{"3fff::1", false},             // IPv6 documentation
		{"::ffff:10.0.0.1", false},     // IPv4-mapped private address
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

// TestNewClientRedirectToPrivateIsRefused exercises the client New() actually
// builds (the other tests inject their own). Two properties: a deliberate
// internal mirror as the INITIAL url is reachable even on a loopback address,
// and a redirect to a private/loopback address is refused. The redirect leg is
// the DNS-rebinding hardening's job; here the target is loopback outright, which
// both the name check and the dial-time Control hook reject.
func TestNewClientRedirectToPrivateIsRefused(t *testing.T) {
	// A loopback TLS server standing in for an internal mirror.
	internal := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mirror-body"))
	}))
	defer internal.Close()

	m := New("/tmp/none", 1<<20)
	// New()'s Transport uses the default dialer; trust the test CA and let it reach
	// the loopback server, exactly as the operator's chosen mirror would be reached.
	m.Client.Transport.(*http.Transport).TLSClientConfig = internal.Client().Transport.(*http.Transport).TLSClientConfig

	// (a) initial URL on a loopback (private) address is allowed — internal mirror.
	if _, err := m.download(internal.URL+"/bin", 1<<20); err != nil {
		t.Errorf("initial internal-mirror URL should be reachable, got: %v", err)
	}

	// (b) a server that redirects to a private/loopback address: refused.
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/pivot", http.StatusFound)
	}))
	defer redirector.Close()
	m.Client.Transport.(*http.Transport).TLSClientConfig = redirector.Client().Transport.(*http.Transport).TLSClientConfig
	if _, err := m.download(redirector.URL+"/bin", 1<<20); err == nil {
		t.Error("a redirect to a private/loopback address must be refused")
	}
}

// TestCheckDialAddr exercises the dial-time policy the Control hook enforces —
// including the DENY branch, which the redirect integration test cannot reach
// (its loopback target is refused earlier by the name check). This is the
// rebinding-proof enforcement point, so its deny path must be pinned directly.
func TestCheckDialAddr(t *testing.T) {
	cases := []struct {
		addr         string
		allowPrivate bool
		wantErr      bool
	}{
		{"93.184.216.34:443", false, false}, // public, redirect phase -> allowed
		{"93.184.216.34:443", true, false},  // public, initial -> allowed
		{"127.0.0.1:443", true, false},      // private but initial mirror -> allowed
		{"127.0.0.1:443", false, true},      // private AFTER redirect -> DENIED (the fix)
		{"10.0.0.5:443", false, true},       // RFC1918 after redirect -> denied
		{"169.254.169.254:80", false, true}, // link-local metadata after redirect -> denied
		{"[::1]:443", false, true},          // ipv6 loopback after redirect -> denied
	}
	for _, c := range cases {
		err := checkDialAddr(c.addr, c.allowPrivate)
		if (err != nil) != c.wantErr {
			t.Errorf("checkDialAddr(%q, allowPrivate=%v) err=%v, wantErr=%v", c.addr, c.allowPrivate, err, c.wantErr)
		}
	}
}
