package selfmanage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type failingResponseBody struct{ err error }

func (b failingResponseBody) Read([]byte) (int, error) { return 0, b.err }
func (failingResponseBody) Close() error               { return nil }

func TestEmbeddedPublicKeyConfigured(t *testing.T) {
	keys := embeddedPublicKeys()
	if len(keys) == 0 {
		t.Fatal("at least one release signing key must be embedded")
	}
	for i, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			t.Errorf("embedded release key %d must be %d bytes, got %d", i, ed25519.PublicKeySize, len(key))
		}
	}
}

func TestSameInstalledBytesIsBoundedAndRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "command")
	if err := os.WriteFile(path, []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	if same, err := sameInstalledBytes(path, []byte("same")); err != nil || !same {
		t.Fatalf("equal comparison: same=%v err=%v", same, err)
	}
	// A sparse one-gigabyte target must be rejected by size without reading it into
	// the root process's heap.
	if err := os.Truncate(path, 1<<30); err != nil {
		t.Fatal(err)
	}
	if same, err := sameInstalledBytes(path, []byte("small")); err != nil || same {
		t.Fatalf("large comparison: same=%v err=%v", same, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := sameInstalledBytes(link, nil); err == nil {
		t.Fatal("sameInstalledBytes followed a symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := sameInstalledBytes(fifo, nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO comparison error = %v, want special-file refusal", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("FIFO comparison blocked for %s", elapsed)
	}
}

func TestInstallRejectsExistingUnsafeParent(t *testing.T) {
	t.Run("world writable", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "unsafe")
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "linux-temp-admin")
		if _, err := (&Manager{InstallPath: path}).Install([]byte("candidate"), false); err == nil {
			t.Fatal("Install accepted an existing world-writable parent")
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o777 {
			t.Fatalf("unsafe parent mode=%o, want unchanged 777", fi.Mode().Perm())
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("command was created in unsafe parent: %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		if err := os.Mkdir(realDir, 0o755); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(base, "sbin")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		if _, err := (&Manager{InstallPath: filepath.Join(linkDir, "linux-temp-admin")}).Install([]byte("candidate"), false); err == nil {
			t.Fatal("Install accepted a symlink parent")
		}
		if _, err := os.Lstat(filepath.Join(realDir, "linux-temp-admin")); !os.IsNotExist(err) {
			t.Fatalf("Install followed the parent symlink: %v", err)
		}
	})
}

func TestInstallerPublicKeysMatchEmbeddedKeyring(t *testing.T) {
	script, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	var installerKeys []ed25519.PublicKey
	rest := script
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "PUBLIC KEY" {
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse installer public key: %v", err)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("installer key is %T, want ed25519.PublicKey", parsed)
		}
		installerKeys = append(installerKeys, key)
	}
	embedded := embeddedPublicKeys()
	if len(installerKeys) != len(embedded) {
		t.Fatalf("installer has %d release keys; Go keyring has %d", len(installerKeys), len(embedded))
	}
	for i := range embedded {
		if !bytes.Equal(installerKeys[i], embedded[i]) {
			t.Errorf("installer release key %d differs from Go keyring", i)
		}
	}
}

func TestInstallerPinsAndValidatesTemporaryRoot(t *testing.T) {
	script, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	for _, required := range []string{
		"TMP_ROOT=/tmp",
		`[ ! -d "$TMP_ROOT" ] || [ -L "$TMP_ROOT" ]`,
		`if ! tmp_root_uid=$(stat -c %u -- "$TMP_ROOT"); then`,
		`'' | *[!0-9]*) fail "invalid temporary root owner: $TMP_ROOT"`,
		`if ! tmp_root_mode=$(stat -c %A -- "$TMP_ROOT"); then`,
		`d?????????)`,
		`?????????t|?????????T)`,
		`mktemp -d "$TMP_ROOT/linux-temp-admin.XXXXXXXXXX"`,
	} {
		if !strings.Contains(s, required) {
			t.Errorf("installer is missing temporary-root control %q", required)
		}
	}
	for _, forbidden := range []string{`tmp="$(mktemp -d)"`, "TMPDIR"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("installer must not use caller-controlled temporary placement: found %q", forbidden)
		}
	}
}

func TestInstallerDropsImportedShellFunctions(t *testing.T) {
	wantDiagnostic := "run this installer as root"
	if os.Geteuid() == 0 {
		wantDiagnostic = "DEST must be an absolute path"
	}
	for _, shell := range []struct {
		name string
		args []string
	}{
		{name: "bash"},
		{name: "bash-posix", args: []string{"--posix"}},
	} {
		t.Run(shell.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "imported-function-ran")
			env := append(os.Environ(),
				"DEST=relative",
				"TEST_IMPORTED_MARKER="+marker,
				`BASH_FUNC_id%%=() { printf imported > "$TEST_IMPORTED_MARKER"; /usr/bin/id "$@"; }`,
			)

			// Prove this exact Bash mode imports the fixture; otherwise the installer
			// assertion below could pass without exercising its startup hardening.
			probeArgs := append(append([]string(nil), shell.args...), "-c", `[ "$(type -t id)" = function ]`)
			probe := exec.Command("/bin/bash", probeArgs...)
			probe.Env = env
			if out, err := probe.CombinedOutput(); err != nil {
				t.Fatalf("Bash function-import fixture is inactive: %v\n%s", err, out)
			}

			args := append(append([]string(nil), shell.args...), "../../scripts/install.sh")
			cmd := exec.Command("/bin/bash", args...)
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), wantDiagnostic) {
				t.Fatalf("installer did not reach the expected validation boundary: err=%v\n%s", err, out)
			}
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Fatalf("installer executed an imported shell function: %v", err)
			}
		})
	}

	t.Run("bash-imported-special-builtins", func(t *testing.T) {
		dir := t.TempDir()
		unsetMarker := filepath.Join(dir, "imported-unset-ran")
		setMarker := filepath.Join(dir, "imported-set-ran")
		colonMarker := filepath.Join(dir, "imported-colon-ran")
		idMarker := filepath.Join(dir, "imported-id-ran")
		env := append(os.Environ(),
			"DEST=relative",
			"TEST_IMPORTED_UNSET_MARKER="+unsetMarker,
			"TEST_IMPORTED_SET_MARKER="+setMarker,
			"TEST_IMPORTED_COLON_MARKER="+colonMarker,
			"TEST_IMPORTED_ID_MARKER="+idMarker,
			`BASH_FUNC_unset%%=() { printf imported > "$TEST_IMPORTED_UNSET_MARKER"; return 0; }`,
			`BASH_FUNC_set%%=() { printf imported > "$TEST_IMPORTED_SET_MARKER"; return 0; }`,
			`BASH_FUNC_:%%=() { printf imported > "$TEST_IMPORTED_COLON_MARKER"; return 0; }`,
			`BASH_FUNC_id%%=() { printf imported > "$TEST_IMPORTED_ID_MARKER"; /usr/bin/id "$@"; }`,
		)

		probe := exec.Command("/bin/bash", "-c", `[ "$(type -t unset)" = function ] && [ "$(type -t set)" = function ] && [ "$(type -t ':')" = function ] && [ "$(type -t id)" = function ]`)
		probe.Env = env
		if out, err := probe.CombinedOutput(); err != nil {
			t.Fatalf("Bash special-builtin import fixture is inactive: %v\n%s", err, out)
		}

		cmd := exec.Command("/bin/bash", "../../scripts/install.sh")
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), wantDiagnostic) {
			t.Fatalf("installer did not reach the expected validation boundary with imported special builtins: err=%v\n%s", err, out)
		}
		for name, marker := range map[string]string{"unset": unsetMarker, "set": setMarker, ":": colonMarker, "id": idMarker} {
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Fatalf("installer executed imported %s function: %v", name, err)
			}
		}
	})
}

func TestUpgradeRefusedWithoutKey(t *testing.T) {
	m := &Manager{PublicKey: nil}
	if _, err := m.Upgrade("https://x/bin", "https://x/sig", false); err == nil {
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

func TestVerifyReleaseChecksumsRequiresCanonicalManifest(t *testing.T) {
	files := map[string][]byte{
		"linux-temp-admin-linux-amd64":     []byte("binary"),
		"linux-temp-admin-linux-amd64.sig": []byte("signature"),
	}
	canonical := fmt.Sprintf("%x  linux-temp-admin-linux-amd64\n%x  linux-temp-admin-linux-amd64.sig\n",
		sha256.Sum256(files["linux-temp-admin-linux-amd64"]),
		sha256.Sum256(files["linux-temp-admin-linux-amd64.sig"]))
	if err := verifyReleaseChecksums([]byte(canonical), files); err != nil {
		t.Fatalf("canonical checksum manifest failed: %v", err)
	}
	for name, manifest := range map[string][]byte{
		"missing newline":             []byte(strings.TrimSuffix(canonical, "\n")),
		"embedded NUL":                []byte(strings.Replace(canonical, "  linux", "\x00  linux", 1)),
		"uppercase digest":            []byte(strings.ToUpper(canonical[:64]) + canonical[64:]),
		"unselected uppercase digest": []byte(canonical + strings.Repeat("A", 64) + "  linux-temp-admin-linux-arm64\n"),
		"unselected non-hex digest":   []byte(canonical + strings.Repeat("g", 64) + "  linux-temp-admin-linux-arm64\n"),
		"extra separator":             []byte(canonical + strings.Repeat("0", 64) + "  ignored  name\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyReleaseChecksums(manifest, files); err == nil {
				t.Fatal("noncanonical checksum manifest was accepted")
			}
		})
	}
}

func TestDecodeReleaseManifestStrictly(t *testing.T) {
	valid := []byte(`{"version":"2.8.0","tag":"v2.8.0","base_url":"https://dl.ll.cd/linux-temp-admin/v2.8.0","published_at":"2026-07-27T05:00:00Z"}` + "\n")
	manifest, err := decodeReleaseManifest(valid)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "2.8.0" || manifest.Tag != "v2.8.0" {
		t.Fatalf("manifest=%+v", manifest)
	}
	for name, body := range map[string]string{
		"duplicate":  `{"version":"2.8.0","version":"2.8.1","tag":"v2.8.0","base_url":"https://dl.ll.cd/linux-temp-admin/v2.8.0","published_at":"2026-07-27T05:00:00Z"}`,
		"unknown":    `{"version":"2.8.0","tag":"v2.8.0","base_url":"https://dl.ll.cd/linux-temp-admin/v2.8.0","published_at":"2026-07-27T05:00:00Z","extra":"x"}`,
		"non-string": `{"version":280,"tag":"v2.8.0","base_url":"https://dl.ll.cd/linux-temp-admin/v2.8.0","published_at":"2026-07-27T05:00:00Z"}`,
		"trailing":   string(valid) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeReleaseManifest([]byte(body)); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestFetchReleaseManifestValidatesPinnedRouting(t *testing.T) {
	root := "https://dl.ll.cd/linux-temp-admin"
	valid := `{"version":"2.8.0","tag":"v2.8.0","base_url":"` + root + `/v2.8.0","published_at":"2026-07-27T05:00:00Z"}` + "\n"
	m := &Manager{Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(valid)), Request: req}, nil
	})}, RetryDelay: 0}
	manifest, err := m.FetchReleaseManifest(root+"/latest.json", root)
	if err != nil || manifest.BaseURL != root+"/v2.8.0" {
		t.Fatalf("FetchReleaseManifest: manifest=%+v err=%v", manifest, err)
	}

	for _, body := range []string{
		strings.Replace(valid, `"tag":"v2.8.0"`, `"tag":"v2.8.1"`, 1),
		strings.Replace(valid, root+`/v2.8.0`, `https://example.invalid/v2.8.0`, 1),
		strings.Replace(valid, `2026-07-27T05:00:00Z`, `not-a-time`, 1),
		strings.TrimSuffix(valid, "\n"),
		strings.Replace(valid, `{"version"`, `{ "version"`, 1),
		`{"tag":"v2.8.0","version":"2.8.0","base_url":"` + root + `/v2.8.0","published_at":"2026-07-27T05:00:00Z"}` + "\n",
	} {
		m.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		})
		if _, err := m.FetchReleaseManifest(root+"/latest.json", root); err == nil || IsTransportFailure(err) {
			t.Fatalf("semantic manifest failure err=%v, want non-transport failure", err)
		}
	}
}

func TestOfficialMirrorRedirectIsPolicyFailure(t *testing.T) {
	m := New("/tmp/none", 16)
	requests := 0
	m.RetryDelay = 0
	m.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		header := make(http.Header)
		header.Set("Location", "https://cdn.example.invalid/linux-temp-admin/latest.json")
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	})
	_, err := m.FetchReleaseManifest(
		"https://dl.ll.cd/linux-temp-admin/latest.json",
		"https://dl.ll.cd/linux-temp-admin",
	)
	if err == nil || IsTransportFailure(err) {
		t.Fatalf("official mirror redirect err=%v transport=%v, want policy failure", err, IsTransportFailure(err))
	}
	if requests != 1 {
		t.Fatalf("official mirror redirect made %d requests, want 1", requests)
	}
}

func TestOfficialSourceDoesNotAllowPrivateInitialAddress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"2.8.0"}`))
	}))
	defer srv.Close()

	m := New("/tmp/none", 16)
	m.RetryDelay = 0
	m.Client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	_, err := m.FetchReleaseManifest(srv.URL+"/latest.json", srv.URL)
	if err == nil || IsTransportFailure(err) {
		t.Fatalf("private official source err=%v transport=%v, want policy failure", err, IsTransportFailure(err))
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
		{"2000::1", true},              // lower 2000::/3 boundary
		{"3ff0::1", true},              // outside 3fff::/20 documentation space
		{"3fff:1000::1", true},         // immediately above 3fff::/20
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
		{"100:0:0:1::1", false},        // IANA Dummy IPv6 Prefix
		{"4000::1", false},             // outside current global-unicast allocation
		{"fec0::1", false},             // deprecated site-local
		{"fd00::1", false},             // IPv6 ULA
		{"fe80::1", false},             // IPv6 link-local
		{"64:ff9b::a00:1", false},      // NAT64 well-known prefix
		{"100::1", false},              // discard-only prefix
		{"2001:db8::1", false},         // IPv6 documentation
		{"2002:a00:1::1", false},       // deprecated 6to4, embeds private IPv4
		{"3fff::1", false},             // IPv6 documentation
		{"3fff:0fff::1", false},        // upper 3fff::/20 documentation boundary
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
		if err := refusePrivateRedirect(context.Background(), bad); err == nil {
			t.Errorf("redirect to %s must be refused", bad)
		}
	}
	if err := refusePrivateRedirect(context.Background(), "8.8.8.8"); err != nil {
		t.Errorf("redirect to public 8.8.8.8 must be allowed: %v", err)
	}
}

func TestRefusePrivateRedirectBoundsDNSLookup(t *testing.T) {
	oldLookup, oldTimeout := lookupRedirectIPs, redirectLookupTimeout
	redirectLookupTimeout = 25 * time.Millisecond
	lookupRedirectIPs = func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() {
		lookupRedirectIPs, redirectLookupTimeout = oldLookup, oldTimeout
	})

	start := time.Now()
	if err := refusePrivateRedirect(context.Background(), "lookup.invalid"); err == nil {
		t.Fatal("timed-out redirect lookup was accepted")
	} else {
		var transportDiagnostic *safeTransportDiagnosticError
		if !errors.As(err, &transportDiagnostic) {
			t.Fatalf("redirect DNS failure type = %T, want a transport diagnostic", err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("redirect lookup exceeded its bound: %s", elapsed)
	}
}

func TestRedirectDNSFailurePermitsSourceFallback(t *testing.T) {
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://redirect-lookup.invalid/asset", http.StatusFound)
	}))
	defer source.Close()

	oldLookup := lookupRedirectIPs
	lookupRedirectIPs = func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("synthetic DNS failure")
	}
	t.Cleanup(func() { lookupRedirectIPs = oldLookup })

	m := New("/tmp/none", 16)
	m.RetryDelay = 0
	m.Client.Transport.(*http.Transport).TLSClientConfig = source.Client().Transport.(*http.Transport).TLSClientConfig
	_, err := m.download(source.URL+"/asset", 16)
	if err == nil || !IsTransportFailure(err) {
		t.Fatalf("redirect DNS failure err=%v transport=%v, want transport failure", err, IsTransportFailure(err))
	}
	if !strings.Contains(err.Error(), "cannot resolve redirect host") {
		t.Fatalf("redirect DNS diagnostic lost its safe reason: %v", err)
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

func TestNewClientDoesNotForwardSensitiveRefererOnRedirect(t *testing.T) {
	referer := make(chan string, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		referer <- r.Referer()
		_, _ = w.Write([]byte("redirected body"))
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, targetPort, err := net.SplitHostPort(targetURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	targetURL.Host = net.JoinHostPort("redirect-target.example", targetPort)
	targetURL.Path = "/asset"

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL.String(), http.StatusFound)
	}))
	defer source.Close()

	oldLookup := lookupRedirectIPs
	lookupRedirectIPs = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	t.Cleanup(func() { lookupRedirectIPs = oldLookup })

	m := New("/tmp/none", 1<<20)
	m.RetryDelay = 0
	dialer := &net.Dialer{}
	transport := m.Client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		if host == "redirect-target.example" {
			address = target.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, address)
	}
	// Both endpoints are local test servers and the redirected hostname is
	// synthetic. Certificate verification is outside this header-focused test.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	const queryMarker = "query-secret-2c591f"
	const fragmentMarker = "fragment-secret-90ad47"
	if _, err := m.download(source.URL+"/private/path?token="+queryMarker+"#"+fragmentMarker, 1<<20); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-referer:
		if got != "" {
			t.Fatalf("redirect target received sensitive Referer %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("redirect target did not receive the request")
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
		{"93.184.216.34:443", false, false},   // public, redirect phase -> allowed
		{"93.184.216.34:443", true, false},    // public, initial -> allowed
		{"127.0.0.1:443", true, false},        // private but initial mirror -> allowed
		{"127.0.0.1:443", false, true},        // private AFTER redirect -> DENIED (the fix)
		{"10.0.0.5:443", false, true},         // RFC1918 after redirect -> denied
		{"169.254.169.254:80", false, true},   // link-local metadata after redirect -> denied
		{"[::1]:443", false, true},            // ipv6 loopback after redirect -> denied
		{"redirect.example:443", false, true}, // Control must receive an already-resolved IP
		{"[fe80::1%lo]:443", false, true},     // zone-qualified link-local redirect is still private
		{"[fe80::1%lo]:443", true, false},     // explicit internal mirror may need an interface zone
	}
	for _, c := range cases {
		err := checkDialAddr(c.addr, c.allowPrivate)
		if (err != nil) != c.wantErr {
			t.Errorf("checkDialAddr(%q, allowPrivate=%v) err=%v, wantErr=%v", c.addr, c.allowPrivate, err, c.wantErr)
		}
	}
}

func TestDownloadRetriesTransientStatus(t *testing.T) {
	requests := 0
	var queries []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		queries = append(queries, r.URL.RawQuery)
		if requests < 3 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	m := &Manager{Client: srv.Client(), RetryDelay: 0}
	got, err := m.download(srv.URL, 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" || requests != 3 {
		t.Fatalf("body=%q requests=%d, want ok and 3", got, requests)
	}
	if want := []string{"", "", ""}; !slices.Equal(queries, want) {
		t.Fatalf("queries=%q, want %q", queries, want)
	}
	if m.allowPrivateDial.Load() {
		t.Fatal("private-address dial exception remained enabled after download")
	}
}

func TestDownloadCacheBypassIsRestrictedToOfficialReleaseURLs(t *testing.T) {
	cases := map[string]string{
		"https://github.com/xxvcc/linux-temp-admin/releases/download/v2.8.0/linux-temp-admin-linux-amd64":     "https://github.com/xxvcc/linux-temp-admin/releases/download/v2.8.0/linux-temp-admin-linux-amd64?download=1",
		"https://github.com/xxvcc/linux-temp-admin/releases/latest/download/linux-temp-admin-linux-amd64.sig": "https://github.com/xxvcc/linux-temp-admin/releases/latest/download/linux-temp-admin-linux-amd64.sig?download=1",
		"https://example.com/bin?token=secret&download=old#fragment":                                          "https://example.com/bin?token=secret&download=old#fragment",
		"https://github.com/xxvcc/linux-temp-admin/releases/download/v2.8.0/bin?X-Amz-Signature=secret":       "https://github.com/xxvcc/linux-temp-admin/releases/download/v2.8.0/bin?X-Amz-Signature=secret",
		"https://github.com/another/repo/releases/download/v1.0.0/bin":                                        "https://github.com/another/repo/releases/download/v1.0.0/bin",
	}
	for input, want := range cases {
		got, err := withDownloadCacheBypass(input)
		if err != nil {
			t.Errorf("withDownloadCacheBypass(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("withDownloadCacheBypass(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestUpgradeURLDiagnosticsHideSensitiveComponents(t *testing.T) {
	const (
		userinfoMarker = "userinfo-marker-8d31"
		pathMarker     = "path-marker-4b72"
		queryMarker    = "query-marker-6c93"
		fragmentMarker = "fragment-marker-1a54"
	)
	rawURL := "https://" + userinfoMarker + ":password@example.invalid/releases/" + pathMarker +
		"?token=" + queryMarker + "#" + fragmentMarker
	markers := []string{userinfoMarker, pathMarker, queryMarker, fragmentMarker}

	if got, want := RedactedURL(rawURL), "https://example.invalid/[details hidden]"; got != want {
		t.Fatalf("RedactedURL() = %q, want %q", got, want)
	}

	tests := map[string]roundTripFunc{
		"transport error": func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("transport echoed complete URL %s", req.URL.String())
		},
		"response read error": func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       failingResponseBody{err: fmt.Errorf("body echoed complete URL %s", req.URL.String())},
				Request:    req,
			}, nil
		},
	}
	for name, transport := range tests {
		t.Run(name, func(t *testing.T) {
			m := &Manager{Client: &http.Client{Transport: transport}, RetryDelay: 0}
			_, err := m.download(rawURL, 16)
			if err == nil {
				t.Fatal("download unexpectedly succeeded")
			}
			diagnostic := err.Error()
			if !strings.Contains(diagnostic, "https://example.invalid") {
				t.Errorf("diagnostic lost the safe endpoint: %q", diagnostic)
			}
			for _, marker := range markers {
				if strings.Contains(diagnostic, marker) {
					t.Errorf("diagnostic leaked %q: %q", marker, diagnostic)
				}
			}
		})
	}

	malformed := "https://" + userinfoMarker + "@example.invalid/" + pathMarker +
		"/%zz?token=" + queryMarker + "#" + fragmentMarker
	if _, err := withDownloadCacheBypass(malformed); err == nil {
		t.Fatal("malformed cache-bypass URL unexpectedly succeeded")
	} else {
		for _, marker := range markers {
			if strings.Contains(err.Error(), marker) {
				t.Errorf("malformed-URL diagnostic leaked %q: %q", marker, err)
			}
		}
	}
}

func TestRedirectErrorDoesNotLeakTargetURLDetails(t *testing.T) {
	markers := []string{
		"redirect-userinfo-marker-2f85",
		"redirect-path-marker-7a46",
		"redirect-query-marker-9c17",
		"redirect-fragment-marker-3d68",
	}
	target := "http://" + markers[0] + ":password@example.invalid/" + markers[1] +
		"?token=" + markers[2] + "#" + markers[3]
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer srv.Close()

	m := New("/tmp/none", 16)
	m.RetryDelay = 0
	m.Client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	_, err := m.download(srv.URL+"/binary", 16)
	if err == nil {
		t.Fatal("non-https redirect unexpectedly succeeded")
	}
	if IsTransportFailure(err) {
		t.Fatalf("redirect-policy failure was classified as transport: %v", err)
	}
	if !strings.Contains(err.Error(), "non-https endpoint") {
		t.Fatalf("redirect diagnostic lost the useful refusal reason: %q", err)
	}
	for _, marker := range markers {
		if strings.Contains(err.Error(), marker) {
			t.Errorf("redirect diagnostic leaked %q: %q", marker, err)
		}
	}
}

func TestRetryableHTTPStatusIncludesEvery5xx(t *testing.T) {
	for status := 500; status <= 599; status++ {
		if !retryableHTTPStatus(status) {
			t.Fatalf("status %d should be retryable", status)
		}
	}
}

func TestDownloadDoesNotRetryPermanentStatus(t *testing.T) {
	requests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	m := &Manager{Client: srv.Client(), RetryDelay: 0}
	if _, err := m.download(srv.URL, 16); err == nil {
		t.Fatal("404 download should fail")
	} else if !IsTransportFailure(err) {
		t.Fatalf("404 should permit source fallback: %v", err)
	}
	if requests != 1 {
		t.Fatalf("404 made %d requests, want 1", requests)
	}
}
