// Package selfmanage installs, uninstalls, and upgrades the stable command. The
// upgrade path downloads the new binary over HTTPS and verifies a detached
// ed25519 signature against the embedded release keyring before installing it
// — failing closed on any verification error.
package selfmanage

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Manager performs install/uninstall/upgrade. Fields are injectable for tests.
type Manager struct {
	InstallPath string
	// PublicKeys is the rotation-capable release-signing keyring.
	PublicKeys     []ed25519.PublicKey
	Client         *http.Client
	MaxBytes       int64
	RetryDelay     time.Duration
	ProbeTimeout   time.Duration
	ProbeMaxOutput int64
	// WriteRootFile is a filesystem fault-injection hook. Production leaves it nil
	// and uses fsutil.WriteRootFile.
	WriteRootFile func(string, []byte, os.FileMode) error
	// RemoveFile is a filesystem fault-injection hook. Production uses fsutil.RemoveFile.
	RemoveFile func(string) error
	// Lstat is a target-inspection fault-injection hook. Production uses os.Lstat.
	Lstat func(string) (os.FileInfo, error)
	// RequireHostMachine gates a candidate on being an ELF built for this host's
	// architecture. Production leaves it nil and uses requireHostMachine; it is a
	// field only so tests can present non-ELF fixture bytes.
	RequireHostMachine func([]byte) error

	// allowPrivateDial gates whether the dialer may connect to a private/reserved
	// IP. It is true only for the initial, operator-supplied URL of the current
	// download (a deliberate internal mirror is legitimate); the first redirect
	// clears it, so a redirect target is checked against the address ACTUALLY
	// dialed — closing the DNS-rebinding gap where the redirect's name passed a
	// separate lookup but resolved to a private IP at connect time. Set per
	// download; a Manager runs its fetches sequentially.
	allowPrivateDial atomic.Bool
	downloadMu       sync.Mutex
}

const (
	defaultRetryDelay    = 500 * time.Millisecond
	maxDownloadAttempts  = 4
	defaultProbeTimeout  = 10 * time.Second
	defaultProbeMaxBytes = int64(256)
	cacheBypassAttempt   = 3
	maxReleaseMetadata   = int64(1 << 20)
	mirrorDownloadTries  = 2
	mirrorManifestBudget = 40 * time.Second
	mirrorReleaseBudget  = 90 * time.Second
	releaseSourceBudget  = 5 * time.Minute
)

// New returns a Manager with the embedded release keyring and an HTTPS client
// that refuses to follow a redirect to a non-https scheme.
func New(installPath string, maxBytes int64) *Manager {
	keys := embeddedPublicKeys()
	m := &Manager{
		InstallPath:    installPath,
		PublicKeys:     keys,
		MaxBytes:       maxBytes,
		RetryDelay:     defaultRetryDelay,
		ProbeTimeout:   defaultProbeTimeout,
		ProbeMaxOutput: defaultProbeMaxBytes,
	}
	// The Control hook runs with the address ACTUALLY being dialed — the resolved
	// IP:port, after Go's own resolution — so it is the authoritative, rebinding-
	// proof enforcement point: a name that passed a separate lookup but resolves to
	// a private IP at connect time is still refused here. Private IPs are allowed
	// only while allowPrivateDial holds, i.e. for the operator's initial URL, so a
	// deliberate internal mirror still works; the first redirect clears it.
	dialer := &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddr(address, m.allowPrivateDial.Load())
		},
	}
	m.Client = &http.Client{
		Timeout: 60 * time.Second, // bound the whole fetch; a stalled server can't hang upgrade
		// Disable reuse so every redirect target reaches the dial-time IP policy;
		// otherwise an already-idle private connection could bypass Control.
		Transport: &http.Transport{DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// net/http synthesizes Referer from the previous complete URL before it
			// calls CheckRedirect. Custom mirror URLs may carry signed query values or
			// fragments, so never forward that URL to a redirect-selected endpoint.
			req.Header.Del("Referer")
			// A redirect target is chosen by the (possibly hostile) release server, so
			// it must stay https, and from here on a private address is refused: the
			// operator only vouched for the initial URL, not for wherever it bounces.
			m.allowPrivateDial.Store(false)
			if policy, ok := req.Context().Value(downloadPolicyContextKey{}).(downloadPolicy); ok && !policy.allowRedirects {
				return safeDiagnostic("official mirror endpoints must not redirect")
			}
			if len(via) >= 10 {
				return safeDiagnostic("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return safeDiagnostic("refusing redirect to a non-https endpoint")
			}
			// The name-based check stays as a friendly, early rejection; the Control
			// hook above is what actually holds under DNS rebinding.
			return refusePrivateRedirect(req.Context(), req.URL.Hostname())
		},
	}
	return m
}
