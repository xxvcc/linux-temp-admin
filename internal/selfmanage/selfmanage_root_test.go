//go:build integration

package selfmanage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
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
	installed, err := m.Install([]byte("v1"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Error("first install must report that it wrote")
	}
	if fi, _ := os.Lstat(m.InstallPath); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 755", fi.Mode().Perm())
	}
	if st := statT(t, m.InstallPath); st.Uid != 0 {
		t.Errorf("owner uid = %d, want 0", st.Uid)
	}
	// identical -> no-op, and it must say so rather than claim a write
	before := statT(t, m.InstallPath)
	installed, err = m.Install([]byte("v1"), false)
	if err != nil {
		t.Fatalf("identical install should be a no-op: %v", err)
	}
	if installed {
		t.Error("identical install must report that it wrote nothing")
	}
	if after := statT(t, m.InstallPath); after.Ino != before.Ino {
		t.Error("identical install replaced the file (inode changed)")
	}
	// identical + force -> still a no-op: the short-circuit precedes the force check
	if installed, err := m.Install([]byte("v1"), true); err != nil || installed {
		t.Errorf("identical install --force: installed=%v err=%v, want false,nil", installed, err)
	}
	// differs, no force -> refuse
	if _, err := m.Install([]byte("v2"), false); err == nil {
		t.Fatal("differing install without force should refuse")
	}
	// differs, force -> replace
	if installed, err := m.Install([]byte("v2"), true); err != nil || !installed {
		t.Fatalf("forced replace: installed=%v err=%v", installed, err)
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

func TestInstallFailsClosedOnTargetInspectionError(t *testing.T) {
	dir := rootDir(t)
	wrote := false
	m := &Manager{
		InstallPath: filepath.Join(dir, "linux-temp-admin"),
		Lstat:       func(string) (os.FileInfo, error) { return nil, fs.ErrPermission },
		WriteRootFile: func(string, []byte, os.FileMode) error {
			wrote = true
			return nil
		},
	}
	if _, err := m.Install([]byte("candidate"), true); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Install error = %v, want target inspection failure", err)
	}
	if wrote {
		t.Fatal("Install wrote after target inspection failed")
	}
}

func TestInstallRequiresForceForExistingSpecialFile(t *testing.T) {
	dir := rootDir(t)
	path := filepath.Join(dir, "linux-temp-admin")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{InstallPath: path}
	if _, err := m.Install([]byte("candidate"), false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Install error = %v, want special-file refusal", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Install removed existing FIFO without force: %v", err)
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("Install replaced existing FIFO without force: mode=%v", fi.Mode())
	}
}

func TestInstallCreatesMissingRootSafeParent(t *testing.T) {
	base := rootDir(t)
	localDir := filepath.Join(base, "usr", "local")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		t.Fatal(err)
	}
	installDir := filepath.Join(localDir, "sbin")
	m := &Manager{InstallPath: filepath.Join(installDir, "linux-temp-admin")}

	installed, err := m.Install([]byte("candidate"), false)
	if err != nil || !installed {
		t.Fatalf("Install with missing parent: installed=%v err=%v", installed, err)
	}
	if err := fsutil.RootSafeDir(installDir); err != nil {
		t.Fatalf("created install directory is not root-safe: %v", err)
	}
	fi, err := os.Lstat(installDir)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode().Perm() != 0o755 || st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("created install directory mode=%o owner=%d:%d, want 755 0:0", fi.Mode().Perm(), st.Uid, st.Gid)
	}
	if got, err := os.ReadFile(m.InstallPath); err != nil || string(got) != "candidate" {
		t.Fatalf("installed command content=%q err=%v", got, err)
	}
}

func TestInstallRepairsUnsafeMetadataOnIdenticalFile(t *testing.T) {
	dir := rootDir(t)
	path := filepath.Join(dir, "linux-temp-admin")
	m := &Manager{InstallPath: path}
	if _, err := m.Install([]byte("same"), false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o4777); err != nil {
		t.Fatal(err)
	}
	before := statT(t, path)
	installed, err := m.Install([]byte("same"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("unsafe identical target must be atomically repaired")
	}
	after := statT(t, path)
	if after.Uid != 0 || after.Gid != 0 {
		t.Fatalf("owner=%d:%d, want 0:0", after.Uid, after.Gid)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 || fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("mode=%v, want regular 0755 without special bits", fi.Mode())
	}
	if after.Ino == before.Ino {
		t.Fatal("metadata repair should use an atomic replacement")
	}
}

func TestInstallReportsVisibleReplacementOnDurabilityFailure(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin")}
	m.WriteRootFile = func(path string, content []byte, mode os.FileMode) error {
		if err := fsutil.WriteRootFile(path, content, mode); err != nil {
			return err
		}
		return &fsutil.DurabilityError{Operation: "rename", Err: syscall.EIO}
	}

	installed, err := m.Install([]byte("new command"), false)
	var durability *fsutil.DurabilityError
	if !installed || !errors.As(err, &durability) {
		t.Fatalf("Install = installed=%v err=%v, want visible replacement plus DurabilityError", installed, err)
	}
	if b, readErr := os.ReadFile(m.InstallPath); readErr != nil || string(b) != "new command" {
		t.Fatalf("visible replacement missing: content=%q err=%v", b, readErr)
	}
}

func newBinary(version string) []byte {
	return []byte("#!/bin/sh\n# LTA_RELEASE_VERSION_V1{" + version + "}\n[ \"$1\" = version ] && echo " + version + "\nexit 0\n")
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

func releaseSetServer(t *testing.T, asset string, bin, sig []byte, missing string) *httptest.Server {
	t.Helper()
	sums := fmt.Sprintf("%x  %s\n%x  %s.sig\n", sha256.Sum256(bin), asset, sha256.Sum256(sig), asset)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if name == missing {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch name {
		case "SHA256SUMS":
			_, _ = w.Write([]byte(sums))
		case asset:
			_, _ = w.Write(bin)
		case asset + ".sig":
			_, _ = w.Write(sig)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPrepareReleaseUpgradeVerifiesCompleteSet(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	asset := "linux-temp-admin-linux-amd64"
	bin := newBinary("2.8.0")
	sig := ed25519.Sign(priv, bin)
	srv := releaseSetServer(t, asset, bin, sig, "")
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
	candidate, err := m.PrepareReleaseUpgrade(srv.URL+"/v2.8.0", asset, "2.8.0")
	if err != nil || candidate.Version() != "2.8.0" {
		t.Fatalf("PrepareReleaseUpgrade: version=%q err=%v", candidate.Version(), err)
	}
}

func TestPrepareReleaseUpgradeClassifiesFallbackBoundary(t *testing.T) {
	asset := "linux-temp-admin-linux-amd64"
	for _, tc := range []struct {
		name          string
		candidate     string
		missing       string
		wrongSigner   bool
		signatureForm string
		wantTransport bool
	}{
		{name: "missing signature is transport", candidate: "2.8.0", missing: asset + ".sig", wantTransport: true},
		{name: "wrong signature is verification", candidate: "2.8.0", wrongSigner: true},
		{name: "signed version mismatch is verification", candidate: "2.8.1"},
		{name: "hex signature is not an official release signature", candidate: "2.8.0", signatureForm: "hex"},
		{name: "newline signature is not an official release signature", candidate: "2.8.0", signatureForm: "newline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := rootDir(t)
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			bin := newBinary(tc.candidate)
			if tc.wrongSigner {
				_, priv, _ = ed25519.GenerateKey(rand.Reader)
			}
			sig := ed25519.Sign(priv, bin)
			switch tc.signatureForm {
			case "hex":
				sig = []byte(fmt.Sprintf("%x", sig))
			case "newline":
				sig = append(sig, '\n')
			}
			srv := releaseSetServer(t, asset, bin, sig, tc.missing)
			m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20, RetryDelay: 0}
			_, err := m.PrepareReleaseUpgrade(srv.URL+"/v2.8.0", asset, "2.8.0")
			if err == nil || IsTransportFailure(err) != tc.wantTransport {
				t.Fatalf("err=%v transport=%v, want transport=%v", err, IsTransportFailure(err), tc.wantTransport)
			}
		})
	}
}

func TestUpgradeVerifiesSignatureAndInstalls(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := newBinary("2.0.1")
	sig := ed25519.Sign(priv, bin)
	srv := signedServer(t, bin, sig)

	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
	got, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", false)
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

func TestPreparedUpgradeRechecksInstalledVersionAtCommit(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	candidateBytes := newBinary("2.0.0")
	srv := signedServer(t, candidateBytes, ed25519.Sign(priv, candidateBytes))
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
	if wrote, err := m.Install(newBinary("1.0.0"), false); err != nil || !wrote {
		t.Fatalf("seed old install: wrote=%v err=%v", wrote, err)
	}

	candidate, err := m.PrepareUpgrade(srv.URL+"/bin", srv.URL+"/sig")
	if err != nil || candidate.Version() != "2.0.0" {
		t.Fatalf("PrepareUpgrade: version=%q err=%v", candidate.Version(), err)
	}
	if current, err := m.InstalledVersion(); err != nil || current != "1.0.0" {
		t.Fatalf("preparation mutated the install: version=%q err=%v", current, err)
	}
	if wrote, err := m.Install(newBinary("3.0.0"), true); err != nil || !wrote {
		t.Fatalf("concurrent newer install: wrote=%v err=%v", wrote, err)
	}
	if got, err := m.ApplyUpgrade(candidate, false); err != nil || got != "" {
		t.Fatalf("ApplyUpgrade over newer install: version=%q err=%v", got, err)
	}
	if current, err := m.InstalledVersion(); err != nil || current != "3.0.0" {
		t.Fatalf("prepared candidate downgraded newer install: version=%q err=%v", current, err)
	}
}

func TestPreparedUpgradeRejectsDowngradeBeforeExecutingCandidate(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	evidence := filepath.Join(dir, "candidate-executed")
	candidateBytes := []byte("#!/bin/sh\n# LTA_RELEASE_VERSION_V1{2.0.0}\nprintf executed > '" + evidence + "'\nprintf '2.0.0\\n'\n")
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, MaxBytes: 1 << 20}
	if wrote, err := m.Install(newBinary("3.0.0"), false); err != nil || !wrote {
		t.Fatalf("seed newer install: wrote=%v err=%v", wrote, err)
	}

	candidate, err := m.prepareVerifiedCandidate(candidateBytes, ed25519.Sign(priv, candidateBytes), "")
	if err != nil || candidate.Version() != "2.0.0" {
		t.Fatalf("PrepareUpgrade: version=%q err=%v", candidate.Version(), err)
	}
	if _, err := os.Lstat(evidence); !os.IsNotExist(err) {
		t.Fatalf("candidate executed during preparation: %v", err)
	}
	if got, err := m.ApplyUpgrade(candidate, false); err != nil || got != "" {
		t.Fatalf("ApplyUpgrade downgrade: version=%q err=%v", got, err)
	}
	if _, err := os.Lstat(evidence); !os.IsNotExist(err) {
		t.Fatalf("candidate executed before downgrade refusal: %v", err)
	}
}

func TestHistoricalSignedUpgradeRequiresForceBeforeProbe(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	evidence := filepath.Join(dir, "historical-candidate-executed")
	candidateBytes := []byte("#!/bin/sh\nprintf executed > '" + evidence + "'\nprintf '2.0.0\\n'\n")
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, MaxBytes: 1 << 20}

	candidate, err := m.prepareVerifiedCandidate(
		candidateBytes, ed25519.Sign(priv, candidateBytes), "2.0.0")
	if err != nil || candidate.Version() != "" {
		t.Fatalf("prepare historical candidate: version=%q err=%v", candidate.Version(), err)
	}
	if got, err := m.ApplyUpgrade(candidate, false); got != "" || err == nil ||
		!strings.Contains(err.Error(), "no static release-version witness") {
		t.Fatalf("non-forced historical candidate: version=%q err=%v", got, err)
	}
	if _, err := os.Lstat(evidence); !os.IsNotExist(err) {
		t.Fatalf("historical candidate executed without --force: %v", err)
	}
	if got, err := m.ApplyUpgrade(candidate, true); err != nil || got != "2.0.0" {
		t.Fatalf("forced historical candidate: version=%q err=%v", got, err)
	}
	if content, err := os.ReadFile(evidence); err != nil || string(content) != "executed" {
		t.Fatalf("forced candidate probe evidence: content=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(m.InstallPath); err != nil || !bytes.Equal(content, candidateBytes) {
		t.Fatalf("forced historical install: bytesMatch=%v err=%v", bytes.Equal(content, candidateBytes), err)
	}
}

func TestForcedHistoricalCandidateStillMustMatchSelectedRelease(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	evidence := filepath.Join(dir, "mismatched-candidate-executed")
	candidateBytes := []byte("#!/bin/sh\nprintf executed > '" + evidence + "'\nprintf '2.0.1\\n'\n")
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, MaxBytes: 1 << 20}
	candidate, err := m.prepareVerifiedCandidate(
		candidateBytes, ed25519.Sign(priv, candidateBytes), "2.0.0")
	if err != nil {
		t.Fatalf("prepare historical candidate: %v", err)
	}

	if got, err := m.ApplyUpgrade(candidate, true); got != "" || err == nil ||
		!strings.Contains(err.Error(), "does not match selected release") {
		t.Fatalf("forced mismatched historical candidate: version=%q err=%v", got, err)
	}
	if content, err := os.ReadFile(evidence); err != nil || string(content) != "executed" {
		t.Fatalf("bounded probe evidence: content=%q err=%v", content, err)
	}
	if _, err := os.Lstat(m.InstallPath); !os.IsNotExist(err) {
		t.Fatalf("mismatched historical candidate was installed: %v", err)
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
	if _, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", false); err == nil {
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
	if installed, err := m.Install(bin, false); err != nil || !installed {
		t.Fatalf("seed installed version: installed=%v err=%v", installed, err)
	}
	got, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("expected no upgrade (same version), got %q", got)
	}
	if b, err := os.ReadFile(m.InstallPath); err != nil || string(b) != string(bin) {
		t.Errorf("same installed version changed: content=%q err=%v", b, err)
	}
}

func TestUpgradeUsesInstalledCommandAsVersionBaseline(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed string
		candidate string
		want      string
	}{
		{name: "installed older", installed: "2.0.0", candidate: "2.0.1", want: "2.0.1"},
		{name: "installed newer", installed: "3.0.0", candidate: "2.0.1", want: "3.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := rootDir(t)
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			candidate := newBinary(tc.candidate)
			srv := signedServer(t, candidate, ed25519.Sign(priv, candidate))
			m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
			if wrote, err := m.Install(newBinary(tc.installed), false); err != nil || !wrote {
				t.Fatalf("seed installed command: wrote=%v err=%v", wrote, err)
			}

			got, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", false)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == tc.candidate && got != tc.candidate {
				t.Fatalf("Upgrade version=%q, want %q", got, tc.candidate)
			}
			if tc.want == tc.installed && got != "" {
				t.Fatalf("newer installed command was downgraded without --force: Upgrade=%q", got)
			}
			current, err := m.InstalledVersion()
			if err != nil || current != tc.want {
				t.Fatalf("installed version=%q err=%v, want %q", current, err, tc.want)
			}
		})
	}
}

func TestUpgradeReturnsCandidateWithDurabilityFailure(t *testing.T) {
	dir := rootDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := newBinary("2.0.1")
	srv := signedServer(t, bin, ed25519.Sign(priv, bin))
	m := &Manager{InstallPath: filepath.Join(dir, "linux-temp-admin"), PublicKey: pub, Client: srv.Client(), MaxBytes: 1 << 20}
	m.WriteRootFile = func(path string, content []byte, mode os.FileMode) error {
		if err := fsutil.WriteRootFile(path, content, mode); err != nil {
			return err
		}
		return &fsutil.DurabilityError{Operation: "rename", Err: syscall.EIO}
	}

	got, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", false)
	var durability *fsutil.DurabilityError
	if got != "2.0.1" || !errors.As(err, &durability) {
		t.Fatalf("Upgrade = version=%q err=%v, want candidate plus DurabilityError", got, err)
	}
}

func TestUpgradeAcceptsAnyKeyInKeyring(t *testing.T) {
	dir := rootDir(t)
	first, _, _ := ed25519.GenerateKey(rand.Reader)
	second, secondPriv, _ := ed25519.GenerateKey(rand.Reader)
	bin := newBinary("2.0.1")
	srv := signedServer(t, bin, ed25519.Sign(secondPriv, bin))
	m := &Manager{
		InstallPath: filepath.Join(dir, "linux-temp-admin"),
		PublicKeys:  []ed25519.PublicKey{first, second},
		Client:      srv.Client(),
		MaxBytes:    1 << 20,
	}
	if got, err := m.Upgrade(srv.URL+"/bin", srv.URL+"/sig", false); err != nil || got != "2.0.1" {
		t.Fatalf("Upgrade with secondary key: version=%q err=%v", got, err)
	}
}

func TestProbeVersionIsBounded(t *testing.T) {
	dir := rootDir(t)
	m := &Manager{
		InstallPath:    filepath.Join(dir, "linux-temp-admin"),
		ProbeTimeout:   100 * time.Millisecond,
		ProbeMaxOutput: 32,
	}
	if _, err := m.probeVersion([]byte("#!/bin/sh\nsleep 30\n")); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("hanging probe error=%v, want timeout", err)
	}
	noisy := []byte("#!/bin/sh\nwhile :; do printf '0123456789abcdef'; done\n")
	if _, err := m.probeVersion(noisy); err == nil || !strings.Contains(err.Error(), "output exceeds") {
		t.Fatalf("noisy probe error=%v, want output limit", err)
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
