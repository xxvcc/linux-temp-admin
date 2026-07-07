//go:build integration

package selfmanage

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func rootDir(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	d := t.TempDir()
	if err := os.Chown(d, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestInstallIdempotentAndForce(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin")}
	if err := m.Install([]byte("v1"), false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(m.InstallPath); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 755", fi.Mode().Perm())
	}
	if st := statT(t, m.InstallPath); st.Uid != 0 {
		t.Errorf("owner uid = %d, want 0", st.Uid)
	}
	// identical -> no-op
	if err := m.Install([]byte("v1"), false); err != nil {
		t.Fatalf("identical install should be a no-op: %v", err)
	}
	// differs, no force -> refuse
	if err := m.Install([]byte("v2"), false); err == nil {
		t.Fatal("differing install without force should refuse")
	}
	// differs, force -> replace
	if err := m.Install([]byte("v2"), true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(m.InstallPath); string(b) != "v2" {
		t.Errorf("content = %q, want v2", b)
	}
	// uninstall
	if err := m.Uninstall(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(m.InstallPath); !os.IsNotExist(err) {
		t.Error("binary should be gone after uninstall")
	}
}

func newBinary(version string) []byte {
	return []byte("#!/bin/sh\n[ \"$1\" = version ] && echo " + version + "\nexit 0\n")
}

func signedServer(t *testing.T, bin, sig []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			w.Write(bin)
		case "/sig":
			w.Write(sig)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUpgradeVerifiesSignatureAndInstalls(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := newBinary("2.0.1")
	sig := ed25519.Sign(priv, bin)
	srv := signedServer(t, bin, sig)

	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
	got, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", "2.0.0", false)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if got != "2.0.1" {
		t.Errorf("new version = %q, want 2.0.1", got)
	}
	if b, _ := os.ReadFile(m.InstallPath); string(b) != string(bin) {
		t.Error("installed binary does not match the downloaded one")
	}
}

func TestUpgradeRejectsBadSignature(t *testing.T) {
	dir := rootDir(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader) // signs with the WRONG key
	bin := newBinary("2.0.1")
	badSig := ed25519.Sign(wrongPriv, bin)
	srv := signedServer(t, bin, badSig)

	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
	if _, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", "2.0.0", false); err == nil {
		t.Fatal("Upgrade must reject a bad signature")
	}
	if _, err := os.Lstat(m.InstallPath); !os.IsNotExist(err) {
		t.Error("nothing should be installed when the signature is invalid")
	}
}

func TestUpgradeSkipsWhenNotNewer(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := newBinary("2.0.0")
	sig := ed25519.Sign(priv, bin)
	srv := signedServer(t, bin, sig)

	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
	got, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", "2.0.0", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("expected no upgrade (same version), got %q", got)
	}
	if _, err := os.Lstat(m.InstallPath); !os.IsNotExist(err) {
		t.Error("nothing should be installed when not newer")
	}
}

func statT(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}
