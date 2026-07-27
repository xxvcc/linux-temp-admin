//go:build integration

package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/lifecycle"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
)

type cliRoundTripFunc func(*http.Request) (*http.Response, error)

func (f cliRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// rootOwnedDir returns a root-owned temp dir. Install writes through
// fsutil.WriteRootFile, which refuses a target directory that is not root-owned
// and then chowns the file to 0:0 -- so these tests cannot run unprivileged.
func rootOwnedDir(t *testing.T) string {
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

func TestInstallReactivatesExplicitlyAndRejectsUnsafeMarker(t *testing.T) {
	dir := rootOwnedDir(t)
	ip := filepath.Join(dir, "linux-temp-admin")
	lockPath := filepath.Join(dir, "lifecycle.lock")
	l := lifecycle.New(lockPath)
	a, _, errb := newTestApp(t, "")
	a.InstallPath = ip
	a.Selfmanage = selfmanage.New(ip, config.MaxUpgradeBytes)
	a.Lifecycle = l

	if rc := a.install(nil); rc != 0 {
		t.Fatalf("initial install rc=%d: %s", rc, errb.String())
	}
	if err := l.MarkUninstalled(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	a.Out = &out
	if rc := a.install(nil); rc != 0 {
		t.Fatalf("reactivation rc=%d: %s", rc, errb.String())
	}
	if !strings.Contains(out.String(), "reactivated the stable command") {
		t.Fatalf("reactivation was reported as a no-op: %q", out.String())
	}
	if stopped, err := l.IsUninstalled(); err != nil || stopped {
		t.Fatalf("uninstall marker remained after explicit reactivation: stopped=%v err=%v", stopped, err)
	}

	if err := os.Symlink("/dev/null", lockPath+".uninstalled"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ip)
	if err != nil {
		t.Fatal(err)
	}
	if rc := a.install([]string{"--force"}); rc != 1 {
		t.Fatalf("install rc=%d, want refusal for an unsafe uninstall marker", rc)
	}
	after, err := os.ReadFile(ip)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("binary changed before the unsafe uninstall marker was rejected")
	}
}

// TestInstallReportsNoOpWhenAlreadyStable: installing the binary that already sits
// at InstallPath writes nothing, so it must not claim it installed anything -- the
// message and the audit entry would both assert a privileged write that never
// happened.
func TestInstallReportsNoOpWhenAlreadyStable(t *testing.T) {
	dir := rootOwnedDir(t)
	ip := filepath.Join(dir, "linux-temp-admin")
	newApp := func() (*App, *bytes.Buffer) {
		a, out, _ := newTestApp(t, "")
		a.InstallPath = ip
		a.Selfmanage = selfmanage.New(ip, config.MaxUpgradeBytes)
		return a, out
	}

	a1, out1 := newApp()
	if rc := a1.install(nil); rc != 0 {
		t.Fatalf("first install rc=%d", rc)
	}
	if !strings.Contains(out1.String(), "installed the stable command") {
		t.Errorf("first install should report a write: %q", out1.String())
	}
	fi1, err := os.Stat(ip)
	if err != nil {
		t.Fatalf("nothing installed: %v", err)
	}

	// Same bytes at the target: no write, and no "installed" claim.
	a2, out2 := newApp()
	if rc := a2.install(nil); rc != 0 {
		t.Fatalf("second install rc=%d", rc)
	}
	if !strings.Contains(out2.String(), "nothing to install") {
		t.Errorf("second install should report a no-op: %q", out2.String())
	}
	if strings.Contains(out2.String(), "installed the stable command") {
		t.Errorf("second install claimed a write that never happened: %q", out2.String())
	}
	fi2, _ := os.Stat(ip)
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("second install rewrote the target")
	}

	// --force does not change that: the identical-bytes short-circuit precedes it.
	a3, out3 := newApp()
	if rc := a3.install([]string{"--force"}); rc != 0 {
		t.Fatalf("forced install rc=%d", rc)
	}
	if !strings.Contains(out3.String(), "nothing to install") {
		t.Errorf("forced identical install should still be a no-op: %q", out3.String())
	}
}

func TestInstallDurabilityFailureIsNonzeroAndAudited(t *testing.T) {
	dir := rootOwnedDir(t)
	installPath := filepath.Join(dir, "linux-temp-admin")
	auditDir := filepath.Join(dir, "audit")
	auditPath := filepath.Join(auditDir, "audit.log")
	a, _, errb := newTestApp(t, "")
	a.InstallPath = installPath
	a.Selfmanage = selfmanage.New(installPath, config.MaxUpgradeBytes)
	a.Selfmanage.WriteRootFile = func(path string, content []byte, mode os.FileMode) error {
		if err := fsutil.WriteRootFile(path, content, mode); err != nil {
			return err
		}
		return &fsutil.DurabilityError{Operation: "install test", Err: syscall.EIO}
	}
	a.Audit = &audit.Logger{
		Dir: auditDir, File: auditPath, Now: a.Now,
		Actor: func() (string, int) { return "test", 0 },
	}

	if rc := a.install(nil); rc != 1 {
		t.Fatalf("install rc=%d, want 1 for unknown replacement durability", rc)
	}
	if !strings.Contains(errb.String(), "replacement's durability is unknown") {
		t.Fatalf("install did not report the visible-but-uncertain replacement: %q", errb.String())
	}
	if _, err := os.Stat(installPath); err != nil {
		t.Fatalf("replacement was not visible: %v", err)
	}
	b, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"action":"install"`, `"result":"fail"`, "command replaced but durability unknown"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("audit log missing %q: %s", want, b)
		}
	}
}

func TestUpgradeDownloadDoesNotHoldLifecycleLock(t *testing.T) {
	dir := rootOwnedDir(t)
	installPath := filepath.Join(dir, "linux-temp-admin")
	lockPath := filepath.Join(dir, "lifecycle.lock")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bin := []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 9.9.9\n")
	sig := ed25519.Sign(priv, bin)
	started := make(chan struct{})
	unblock := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			select {
			case <-started:
			default:
				close(started)
			}
			<-unblock
			_, _ = w.Write(bin)
		case "/bin.sig":
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	var unblockOnce sync.Once
	releaseDownload := func() { unblockOnce.Do(func() { close(unblock) }) }
	t.Cleanup(releaseDownload)

	a, _, errb := newTestApp(t, "")
	a.InstallPath = installPath
	a.Lifecycle = lifecycle.New(lockPath)
	a.Selfmanage = &selfmanage.Manager{
		InstallPath: installPath,
		PublicKey:   pub,
		Client:      srv.Client(),
		MaxBytes:    config.MaxUpgradeBytes,
	}
	done := make(chan commandResult, 1)
	go func() { done <- a.upgradeResult([]string{"--url", srv.URL + "/bin", "--yes"}) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("upgrade download did not start: %q", errb.String())
	}

	acquired := make(chan func() error, 1)
	acquireErr := make(chan error, 1)
	go func() {
		release, err := lifecycle.New(lockPath).Acquire()
		if err != nil {
			acquireErr <- err
			return
		}
		acquired <- release
	}()
	select {
	case err := <-acquireErr:
		t.Fatal(err)
	case release := <-acquired:
		if err := release(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		releaseDownload()
		<-done
		t.Fatal("upgrade held the lifecycle lock during download")
	}
	releaseDownload()
	select {
	case result := <-done:
		if result.status != 0 || !result.applied {
			t.Fatalf("upgrade result=%+v, want a successful applied replacement: %s", result, errb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upgrade did not finish after download resumed")
	}

	// A second run authenticates the same candidate but does not replace anything.
	// It succeeds without becoming a terminal menu action.
	again := a.upgradeResult([]string{"--url", srv.URL + "/bin", "--yes"})
	if again.status != 0 || again.applied {
		t.Fatalf("already-current upgrade result=%+v, want successful but unapplied", again)
	}
}

func TestOfficialUpgradeMirrorFallbackBoundary(t *testing.T) {
	asset := config.BinaryAssetPrefix + "amd64"
	goodBin := []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 2.8.0\n")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	goodSig := ed25519.Sign(priv, goodBin)
	otherBin := []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 2.8.1\n")
	otherSig := ed25519.Sign(priv, otherBin)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongSig := ed25519.Sign(wrongPriv, goodBin)
	manifest := `{"version":"2.8.0","tag":"v2.8.0","base_url":"https://dl.ll.cd/linux-temp-admin/v2.8.0","published_at":"2026-07-27T05:00:00Z"}` + "\n"

	for _, tc := range []struct {
		name             string
		manifestStatus   int
		manifestBody     string
		mirrorSigStatus  int
		mirrorBin        []byte
		mirrorSig        []byte
		badChecksum      bool
		wantErr          bool
		wantGitHub       bool
		wantGitHubLatest bool
	}{
		{name: "mirror success", manifestStatus: http.StatusOK, manifestBody: manifest, mirrorSigStatus: http.StatusOK, mirrorSig: goodSig},
		{name: "mirror transport fallback", manifestStatus: http.StatusOK, manifestBody: manifest, mirrorSigStatus: http.StatusServiceUnavailable, mirrorSig: goodSig, wantGitHub: true},
		{name: "mirror checksum stops", manifestStatus: http.StatusOK, manifestBody: manifest, mirrorSigStatus: http.StatusOK, mirrorSig: goodSig, badChecksum: true, wantErr: true},
		{name: "mirror verification stops", manifestStatus: http.StatusOK, manifestBody: manifest, mirrorSigStatus: http.StatusOK, mirrorSig: wrongSig, wantErr: true},
		{name: "mirror version mismatch stops", manifestStatus: http.StatusOK, manifestBody: manifest, mirrorSigStatus: http.StatusOK, mirrorBin: otherBin, mirrorSig: otherSig, wantErr: true},
		{name: "manifest transport fallback", manifestStatus: http.StatusServiceUnavailable, manifestBody: manifest, mirrorSigStatus: http.StatusOK, mirrorSig: goodSig, wantGitHub: true, wantGitHubLatest: true},
		{name: "manifest semantics stop", manifestStatus: http.StatusOK, manifestBody: strings.Replace(manifest, `"tag":"v2.8.0"`, `"tag":"v2.8.1"`, 1), mirrorSigStatus: http.StatusOK, mirrorSig: goodSig, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := rootOwnedDir(t)
			requests := make(map[string]int)
			m := &selfmanage.Manager{
				InstallPath: filepath.Join(dir, "linux-temp-admin"),
				PublicKey:   pub,
				MaxBytes:    config.MaxUpgradeBytes,
				RetryDelay:  0,
			}
			m.Client = &http.Client{Transport: cliRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				mirrorBin := tc.mirrorBin
				if mirrorBin == nil {
					mirrorBin = goodBin
				}
				key := req.URL.Host + req.URL.Path
				requests[key]++
				status := http.StatusOK
				var body []byte
				switch {
				case req.URL.Host == "dl.ll.cd" && req.URL.Path == "/linux-temp-admin/latest.json":
					status, body = tc.manifestStatus, []byte(tc.manifestBody)
				case req.URL.Host == "dl.ll.cd" && strings.HasSuffix(req.URL.Path, "/SHA256SUMS"):
					if tc.badChecksum {
						body = releaseSetSums(asset, append(append([]byte(nil), mirrorBin...), 'x'), tc.mirrorSig)
					} else {
						body = releaseSetSums(asset, mirrorBin, tc.mirrorSig)
					}
				case req.URL.Host == "dl.ll.cd" && strings.HasSuffix(req.URL.Path, "/"+asset):
					body = mirrorBin
				case req.URL.Host == "dl.ll.cd" && strings.HasSuffix(req.URL.Path, "/"+asset+".sig"):
					status, body = tc.mirrorSigStatus, tc.mirrorSig
				case req.URL.Host == "github.com" && strings.HasSuffix(req.URL.Path, "/SHA256SUMS"):
					body = releaseSetSums(asset, goodBin, goodSig)
				case req.URL.Host == "github.com" && strings.HasSuffix(req.URL.Path, "/"+asset):
					body = goodBin
				case req.URL.Host == "github.com" && strings.HasSuffix(req.URL.Path, "/"+asset+".sig"):
					body = goodSig
				default:
					status = http.StatusNotFound
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
			})}
			a, _, _ := newTestApp(t, "")
			a.Selfmanage = m
			candidate, gotErr := a.prepareOfficialUpgrade()
			if (gotErr != nil) != tc.wantErr {
				t.Fatalf("candidate=%v err=%v, wantErr=%v", candidate, gotErr, tc.wantErr)
			}
			githubRequests := 0
			latestRequests := 0
			for key, count := range requests {
				if strings.HasPrefix(key, "github.com") {
					githubRequests += count
					if strings.Contains(key, "/releases/latest/download/") {
						latestRequests += count
					}
				}
			}
			if (githubRequests > 0) != tc.wantGitHub {
				t.Fatalf("GitHub requests=%d, wantGitHub=%v; all=%v", githubRequests, tc.wantGitHub, requests)
			}
			if tc.wantGitHub && githubRequests != 3 {
				t.Fatalf("fallback downloaded %d GitHub requests, want one complete three-file set; all=%v", githubRequests, requests)
			}
			if (latestRequests > 0) != tc.wantGitHubLatest {
				t.Fatalf("GitHub Latest requests=%d, wantLatest=%v; all=%v", latestRequests, tc.wantGitHubLatest, requests)
			}
		})
	}
}

func releaseSetSums(asset string, bin, sig []byte) []byte {
	return []byte(fmt.Sprintf("%x  %s\n%x  %s.sig\n", sha256.Sum256(bin), asset, sha256.Sum256(sig), asset))
}

func TestUpgradeURLSecretsNeverReachTerminalOrAudit(t *testing.T) {
	dir := rootOwnedDir(t)
	auditDir := filepath.Join(dir, "audit")
	auditPath := filepath.Join(auditDir, "audit.log")
	markers := []string{
		"userinfo-marker-8d31",
		"path-marker-4b72",
		"query-marker-6c93",
		"fragment-marker-1a54",
	}
	rawURL := "https://" + markers[0] + ":password@example.invalid/releases/" + markers[1] +
		"?token=" + markers[2] + "#" + markers[3]
	urlFile := filepath.Join(dir, "upgrade-url")
	if err := os.WriteFile(urlFile, []byte(rawURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, out, errb := newTestApp(t, "")
	a.Selfmanage = selfmanage.New(filepath.Join(dir, "linux-temp-admin"), config.MaxUpgradeBytes)
	a.Selfmanage.RetryDelay = 0
	a.Selfmanage.Client = &http.Client{Transport: cliRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("transport echoed complete URL %s", req.URL.String())
	})}
	a.Audit = &audit.Logger{
		Dir: auditDir, File: auditPath, Now: a.Now,
		Actor: func() (string, int) { return "test", 0 },
	}

	if rc := a.upgrade([]string{"--url-file", urlFile, "--yes"}); rc != 1 {
		t.Fatalf("failed upgrade rc=%d, want 1", rc)
	}
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic := out.String() + errb.String() + string(auditBytes)
	if !strings.Contains(diagnostic, "https://example.invalid") {
		t.Errorf("terminal and audit diagnostics lost the safe endpoint: %q", diagnostic)
	}
	for _, marker := range markers {
		if strings.Contains(diagnostic, marker) {
			t.Errorf("terminal or audit diagnostics leaked %q: %q", marker, diagnostic)
		}
	}
}

func TestLanguagePreferencesCannotRecreateStateAfterUninstall(t *testing.T) {
	dir := rootOwnedDir(t)
	stateDir := filepath.Join(dir, "state")
	oldPrefs := prefs.File
	prefs.File = filepath.Join(stateDir, "prefs")
	t.Cleanup(func() { prefs.File = oldPrefs })
	l := lifecycle.New(filepath.Join(dir, "lifecycle.lock"))
	release, err := l.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.MarkUninstalled(); err != nil {
		_ = release()
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}

	a, _, _ := newTestApp(t, "2\n")
	a.Lifecycle = l
	a.rememberLangChoice(i18n.EN)
	if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("initial language choice recreated uninstalled state: %v", err)
	}
	if rc := a.switchLang(); rc != 1 {
		t.Fatalf("switchLang rc=%d, want uninstall-marker refusal", rc)
	}
	if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("menu language switch recreated uninstalled state: %v", err)
	}
}
