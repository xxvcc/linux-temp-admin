package cli

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/lifecycle"
	"github.com/xxvcc/linux-temp-admin/internal/netdetect"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"golang.org/x/sys/unix"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type failingScheduleSystem struct{}

func (failingScheduleSystem) HasSystemctl() bool                           { return false }
func (failingScheduleSystem) Systemctl(...string) error                    { return nil }
func (failingScheduleSystem) HasAt() bool                                  { return true }
func (failingScheduleSystem) ScheduleAt(string, time.Time) (string, error) { return "", nil }
func (failingScheduleSystem) RemoveAtJobsFor(string) error                 { return nil }
func (failingScheduleSystem) AtrmJob(string) error                         { return nil }
func (failingScheduleSystem) AtJobs() ([]schedule.AtJob, error) {
	return nil, errors.New("at queue unreadable")
}

type revokeRunner struct {
	calls  []string
	failOn string
}

func (r *revokeRunner) Run(name string, _ ...string) error {
	r.calls = append(r.calls, name)
	if name == r.failOn {
		return fmt.Errorf("%s failed", name)
	}
	return nil
}

func (r *revokeRunner) RunInput(_ string, name string, args ...string) error {
	return r.Run(name, args...)
}

func (*revokeRunner) Look(name string) bool { return name == "userdel" }

var (
	testClearScheduledJobs = func(string, int) error { return nil }
	testDrainScheduledJobs = func() error { return nil }
)

// newTestApp builds a minimal, root-free App: Geteuid is faked to 0 and the
// registry points at a temp dir. Collaborators that only the mutating paths need
// (Users/Sudoers/Scheduler/Selfmanage) are left nil; the tests here exercise
// dispatch, prompts, and guard paths that return before any mutation.
func newTestApp(t *testing.T, in string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	var out, errb bytes.Buffer
	a := &App{
		Out: &out, Err: &errb, In: strings.NewReader(in),
		P:                        i18n.Printer{Lang: i18n.EN},
		Registry:                 &registry.Store{Dir: dir, File: filepath.Join(dir, "r.tsv"), Lock: filepath.Join(dir, "r.lock")},
		InstallPath:              filepath.Join(dir, "lta"),
		Now:                      func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) },
		RandHex:                  func(int) (string, error) { return "abcdef0123", nil },
		StdoutIsTTY:              func() bool { return true },
		StdinIsTTY:               func() bool { return false },
		Geteuid:                  func() int { return 0 },
		SSHDHasUnverifiableMatch: func(bool) bool { return false },
		ClearScheduledJobs:       testClearScheduledJobs,
		DrainScheduledJobs:       testDrainScheduledJobs,
		ListMarkerAccounts:       func() ([]string, error) { return nil, nil },
		RunningLegacyRevoke:      func(string, string) (bool, error) { return false, nil },
	}
	return a, &out, &errb
}

func setTestRegistryRecord(t *testing.T, a *App, rec registry.Record) {
	t.Helper()
	dir := t.TempDir()
	a.Registry = &registry.Store{
		Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock"),
	}
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	if rec.Port == 0 {
		rec.Port = 22
	}
	deletionStarted := rec.DeletionStarted
	rec.DeletionStarted = false
	if err := a.Registry.Record(rec); err != nil {
		t.Fatal(err)
	}
	if deletionStarted {
		generation := rec.Generation
		if rec.Pending || !rec.IdentityBound {
			generation = ""
		}
		if err := a.Registry.BeginDeletion(rec.User, rec.UID, generation); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrintInviteClearsPrivateKeySource(t *testing.T) {
	a, out, _ := newTestApp(t, "")
	privatePEM := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n")
	err := a.printInvite(inviteBundle{
		user: "xxvcc-a1", host: "203.0.113.10", port: 22, expires: "soon",
		kp: &sshkey.KeyPair{PrivatePEM: privatePEM}, verified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatal("invite did not write the one-time private key")
	}
	for i, b := range privatePEM {
		if b != 0 {
			t.Fatalf("private key source byte %d was not cleared", i)
		}
	}
}

func TestExtractLang(t *testing.T) {
	cases := []struct {
		args     []string
		wantLang string
		wantRest []string
		wantErr  bool
	}{
		{[]string{"invite", "--host", "x"}, "", []string{"invite", "--host", "x"}, false},
		{[]string{"--lang", "zh", "status"}, "zh", []string{"status"}, false},
		{[]string{"status", "--lang=en"}, "en", []string{"status"}, false},
		{[]string{"--lang="}, "", nil, true},           // empty value must error
		{[]string{"--lang", "fr", "x"}, "", nil, true}, // invalid value
		{[]string{"--lang"}, "", nil, true},            // missing value
		{[]string{"--lang", "--yes"}, "", nil, true},   // value looks like a flag
	}
	for _, c := range cases {
		lang, rest, err := extractLang(c.args)
		if (err != nil) != c.wantErr {
			t.Errorf("extractLang(%v) err=%v wantErr=%v", c.args, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if lang != c.wantLang || strings.Join(rest, ",") != strings.Join(c.wantRest, ",") {
			t.Errorf("extractLang(%v) = (%q,%v), want (%q,%v)", c.args, lang, rest, c.wantLang, c.wantRest)
		}
	}
}

func TestSetTrustedRootPath(t *testing.T) {
	var key, value string
	if err := setTrustedRootPath(func() int { return 0 }, func(k, v string) error {
		key, value = k, v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if key != "PATH" || value != trustedRootPath {
		t.Fatalf("root environment set (%q, %q), want PATH=%q", key, value, trustedRootPath)
	}

	called := false
	if err := setTrustedRootPath(func() int { return 1000 }, func(string, string) error {
		called = true
		return nil
	}); err != nil || called {
		t.Fatalf("non-root path changed: called=%v err=%v", called, err)
	}

	wantErr := errors.New("setenv failed")
	if err := setTrustedRootPath(func() int { return 0 }, func(string, string) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("setenv error = %v, want %v", err, wantErr)
	}
}

func TestReadLineEOFvsBlank(t *testing.T) {
	a := &App{In: strings.NewReader("hello\n\nx")}
	for _, want := range []struct {
		s  string
		ok bool
	}{
		{"hello", true}, // first line
		{"", true},      // a blank line (not EOF)
		{"x", true},     // final content with no trailing newline
		{"", false},     // EOF, no data
	} {
		s, ok := a.readLine()
		if s != want.s || ok != want.ok {
			t.Errorf("readLine = (%q,%v), want (%q,%v)", s, ok, want.s, want.ok)
		}
	}
}

func TestReadLineRejectsAndDrainsOversizedInput(t *testing.T) {
	var errb bytes.Buffer
	a := &App{
		In:  strings.NewReader(strings.Repeat("x", maxInteractiveLineBytes+1) + "\nYES\n"),
		Err: &errb,
	}
	if got, ok := a.readLine(); got != rejectedInteractiveLine || !ok {
		t.Fatalf("oversized readLine = (%q, %v), want rejected input", got, ok)
	}
	if got, ok := a.readLine(); got != "YES" || !ok {
		t.Fatalf("line after oversized input = (%q, %v), want YES", got, ok)
	}
	if !strings.Contains(errb.String(), "input line is too long") {
		t.Fatalf("oversized input warning missing: %q", errb.String())
	}
}

type notifyingBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	needle string
	once   sync.Once
	seen   chan struct{}
}

func newNotifyingBuffer(needle string) *notifyingBuffer {
	return &notifyingBuffer{needle: needle, seen: make(chan struct{})}
}

func (b *notifyingBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(p)
	matched := strings.Contains(b.buf.String(), b.needle)
	b.mu.Unlock()
	if matched {
		b.once.Do(func() { close(b.seen) })
	}
	return n, err
}

func (b *notifyingBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRevokeConfirmationDoesNotHoldLifecycleLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	a, _, _ := newTestApp(t, "")
	a.Lifecycle = lifecycle.New(path)
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	a.In = reader
	a.inReader = nil
	errOut := newNotifyingBuffer("type the full username root to confirm deletion")
	a.Err = errOut
	done := make(chan int, 1)
	go func() { done <- a.revoke([]string{"--user", "root", "--force"}) }()
	select {
	case <-errOut.seen:
	case <-time.After(2 * time.Second):
		t.Fatalf("revoke did not reach its confirmation prompt: %q", errOut.String())
	}

	acquired := make(chan func() error, 1)
	acquireErr := make(chan error, 1)
	go func() {
		release, err := lifecycle.New(path).Acquire()
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
		_, _ = io.WriteString(writer, "root\n")
		<-done
		t.Fatal("revoke held the lifecycle lock while waiting for confirmation")
	}
	if _, err := io.WriteString(writer, "root\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 1 {
			t.Fatalf("revoke rc=%d, want protected-root refusal", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoke did not finish after confirmation")
	}
}

func TestUninstallConfirmationDoesNotHoldLifecycleLock(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "lifecycle.lock")
	a, _, _ := newTestApp(t, "")
	a.Lifecycle = lifecycle.New(path)
	a.StateDir = filepath.Join(base, "missing-state")
	a.AuditLogDir = filepath.Join(base, "audit")
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	a.In = reader
	a.inReader = nil
	errOut := newNotifyingBuffer("type YES to uninstall")
	a.Err = errOut
	done := make(chan int, 1)
	go func() { done <- a.uninstall(nil) }()
	select {
	case <-errOut.seen:
	case <-time.After(2 * time.Second):
		t.Fatalf("uninstall did not reach its confirmation prompt: %q", errOut.String())
	}

	acquired := make(chan func() error, 1)
	acquireErr := make(chan error, 1)
	go func() {
		release, err := lifecycle.New(path).Acquire()
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
		_, _ = io.WriteString(writer, "NO\n")
		<-done
		t.Fatal("uninstall held the lifecycle lock while waiting for confirmation")
	}
	if _, err := io.WriteString(writer, "NO\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("cancelled uninstall rc=%d, want 0", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("uninstall did not finish after cancellation")
	}
}

func TestQueuedLifecycleMutationStopsAfterUninstallMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	l := lifecycle.New(path)
	release, err := l.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := newTestApp(t, "")
	a.Lifecycle = lifecycle.New(path)
	runs := make(chan struct{}, 1)
	done := make(chan int, 1)
	go func() {
		done <- a.withLifecycleLock(func() int {
			runs <- struct{}{}
			return 0
		})
	}()
	select {
	case <-runs:
		t.Fatal("queued mutation ran while the lifecycle lock was held")
	case <-time.After(50 * time.Millisecond):
	}
	if err := l.MarkUninstalled(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 1 {
			t.Fatalf("queued mutation rc=%d, want refusal", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued mutation did not finish after uninstall")
	}
	select {
	case <-runs:
		t.Fatal("queued mutation ran after uninstall marker was written")
	default:
	}
}

func TestLegacyUnboundRevokeSkipsSameNameInviteBarrier(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.Lifecycle = lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	release, err := a.accountLifecycleLock("xxvcc-a1").Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	}()

	started := time.Now()
	rc := a.revoke([]string{"--user", "xxvcc-a1", "--yes"})
	if rc != 0 {
		t.Fatalf("contending legacy revoke rc = %d, want successful stale-job skip", rc)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("legacy revoke queued behind the lifecycle lock for %s", elapsed)
	}
	if got := errb.String(); !strings.Contains(got, "no account was revoked") ||
		!strings.Contains(got, "invoke revoke again") {
		t.Fatalf("legacy revoke did not explain the non-destructive retry requirement: %q", got)
	}
}

func TestGenerationBoundRevokeWaitsForSameNameInviteBarrier(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	a.Lifecycle = lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	release, err := a.accountLifecycleLock("xxvcc-a1").Acquire()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		done <- a.revoke([]string{
			"--user", "xxvcc-a1", "--yes", "--force", "--confirm-force", "xxvcc-a1",
			"--expected-uid", "1001", "--generation", "0123456789abcdef0123456789abcdef",
		})
	}()
	select {
	case rc := <-done:
		_ = release()
		t.Fatalf("generation-bound revoke bypassed serialization with rc=%d", rc)
	case <-time.After(50 * time.Millisecond):
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("stale generation-bound revoke rc = %d, want safe skip", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("generation-bound revoke did not resume after account-barrier release")
	}
}

func TestLegacyUnboundRevokeStillQueuesBehindUnrelatedGlobalMutation(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.Lifecycle = lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	release, err := a.Lifecycle.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		done <- a.revoke([]string{"--user", "xxvcc-a1", "--yes"})
	}()
	select {
	case rc := <-done:
		_ = release()
		t.Fatalf("legacy revoke treated unrelated global contention as stale with rc=%d", rc)
	case <-time.After(50 * time.Millisecond):
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 1 {
			t.Fatalf("legacy revoke after global release rc=%d, want normal unregistered-user refusal", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legacy revoke did not resume after global lifecycle release")
	}
	if strings.Contains(errb.String(), "no account was revoked") {
		t.Fatalf("unrelated global contention was reported as a stale same-name collision: %q", errb.String())
	}
}

func TestLegacyUnboundRevokesShareSameNameBarrier(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lifecycle.lock")
	globalRelease, err := lifecycle.New(path).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	a1, _, err1 := newTestApp(t, "")
	a2, _, err2 := newTestApp(t, "")
	a1.Lifecycle = lifecycle.New(path)
	a2.Lifecycle = lifecycle.New(path)

	done1 := make(chan int, 1)
	done2 := make(chan int, 1)
	go func() { done1 <- a1.revoke([]string{"--user", "xxvcc-a1", "--yes"}) }()
	go func() { done2 <- a2.revoke([]string{"--user", "xxvcc-a1", "--yes"}) }()
	for i, done := range []<-chan int{done1, done2} {
		select {
		case rc := <-done:
			_ = globalRelease()
			t.Fatalf("legacy revoke %d was swallowed while another reader held the same-name barrier: rc=%d", i+1, rc)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := globalRelease(); err != nil {
		t.Fatal(err)
	}
	for i, done := range []<-chan int{done1, done2} {
		select {
		case rc := <-done:
			if rc != 1 {
				t.Fatalf("legacy revoke %d rc=%d, want normal unregistered-user refusal", i+1, rc)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("legacy revoke %d did not resume after global lifecycle release", i+1)
		}
	}
	if strings.Contains(err1.String(), "no account was revoked") || strings.Contains(err2.String(), "no account was revoked") {
		t.Fatalf("shared same-name revokes were treated as writer contention: first=%q second=%q", err1.String(), err2.String())
	}
}

func TestReadRunningBinaryUsesProcSelfExe(t *testing.T) {
	got, err := (&App{}).readRunningBinary()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(procSelfExe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("production running-binary reader did not read /proc/self/exe")
	}
}

func TestReadRunningBinaryRejectsOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-binary")
	if err := os.WriteFile(path, []byte("12345"), 0o700); err != nil {
		t.Fatal(err)
	}
	a := &App{
		Executable: func() (string, error) { return path, nil },
		Selfmanage: &selfmanage.Manager{MaxBytes: 4},
	}
	if _, err := a.readRunningBinary(); err == nil || !strings.Contains(err.Error(), "exceeds 4-byte") {
		t.Fatalf("oversized running binary error = %v, want bounded-read refusal", err)
	}
}

func TestDispatchRouting(t *testing.T) {
	a, out, _ := newTestApp(t, "")
	if rc := a.Dispatch([]string{"version"}); rc != 0 || !strings.Contains(out.String(), buildinfo.Version) {
		t.Errorf("version: rc=%d out=%q", rc, out.String())
	}
	a2, out2, _ := newTestApp(t, "")
	if rc := a2.Dispatch([]string{"help"}); rc != 0 || !strings.Contains(out2.String(), "Usage") {
		t.Errorf("help: rc=%d", rc)
	}
	a3, _, _ := newTestApp(t, "")
	if rc := a3.Dispatch([]string{"bogus"}); rc != 1 {
		t.Errorf("unknown command: rc=%d, want 1", rc)
	}
}

func TestOrphanScanErrorsAreNotHealthy(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: "/usr/local/sbin/linux-temp-admin",
		UnitPrefix: "linux-temp-admin-test-", Sys: failingScheduleSystem{},
	}
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}

	if _, err := a.orphanArtifacts(nil); err == nil || !strings.Contains(err.Error(), "at queue unreadable") {
		t.Fatalf("orphanArtifacts error = %v, want scheduler scan failure", err)
	}
	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc=%d, want 1 when scheduler inventory cannot be read", rc)
	}
	if !strings.Contains(errb.String(), "at queue unreadable") {
		t.Errorf("doctor hid the scheduler error: %q", errb.String())
	}
}

func TestDoctorFailsWhenSSHDLoginCannotBeConfirmed(t *testing.T) {
	t.Run("future account phase", func(t *testing.T) {
		a, _, errb := newTestApp(t, "")
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
		}
		var phases []bool
		a.SSHDHasUnverifiableMatch = func(accountExists bool) bool {
			phases = append(phases, accountExists)
			return !accountExists
		}
		if rc := a.doctor(nil); rc != 1 {
			t.Fatalf("doctor rc=%d, want 1 for a pre-account Match uncertainty", rc)
		}
		if len(phases) != 2 || !phases[0] || phases[1] {
			t.Fatalf("doctor Match account phases = %v, want [true false]", phases)
		}
		if !strings.Contains(errb.String(), "before creation") {
			t.Fatalf("doctor did not report the pre-account uncertainty: %q", errb.String())
		}
	})

	t.Run("connection-dependent rule", func(t *testing.T) {
		a, _, errb := newTestApp(t, "")
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nallowusers xxvcc-doctor@203.0.113.0/24\n"), nil
		}

		rep := a.checkKeyLogin(mustSSHDConfig(t, a, "xxvcc-doctor"), "xxvcc-doctor", []string{"xxvcc-doctor"}, false)
		if !rep.OK() || rep.Certain() {
			t.Fatalf("fixture report: OK=%v Certain=%v blockers=%v unverifiable=%v", rep.OK(), rep.Certain(), rep.Blockers, rep.Unverifiable)
		}
		if rc := a.doctor(nil); rc != 1 {
			t.Fatalf("doctor rc=%d, want 1 for an unverifiable key-login policy", rc)
		}
		if got := strings.Count(errb.String(), "xxvcc-doctor@"); got != 1 {
			t.Fatalf("connection-dependent rule reported %d times, want once:\n%s", got, errb.String())
		}
	})

	t.Run("effective config probe failure", func(t *testing.T) {
		a, _, errb := newTestApp(t, "")
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return nil, errors.New("injected sshd probe failure")
		}
		if rc := a.doctor(nil); rc != 1 {
			t.Fatalf("doctor rc=%d, want 1 when sshd cannot be inspected", rc)
		}
		if !strings.Contains(errb.String(), "injected sshd probe failure") {
			t.Fatalf("doctor hid the sshd probe failure: %q", errb.String())
		}
	})
}

func TestDoctorDependencyPolicyTreatsConditionalHelpersAsOptionalFeatures(t *testing.T) {
	for _, label := range []string{"sudo", "visudo", "chpasswd"} {
		if doctorDependencyIsFatal(label) {
			t.Errorf("missing %s should disable only its invite feature, not fail the base doctor report", label)
		}
	}
	for _, label := range []string{"id", "useradd", "usermod", "chage", "userdel"} {
		if !doctorDependencyIsFatal(label) {
			t.Errorf("missing core dependency %s should fail the doctor report", label)
		}
	}
}

func TestDoctorDescribesOnlyEffectiveConfigCredentialVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lang      i18n.Lang
		config    string
		wantOut   string
		wantErr   string
		forbidden string
	}{
		{
			name:      "English success",
			lang:      i18n.EN,
			config:    "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n",
			wantOut:   "effective sshd config check found no blocker for a new account's key credential",
			forbidden: "sshd accepts public-key logins",
		},
		{
			name:      "English blocker",
			lang:      i18n.EN,
			config:    "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n",
			wantErr:   "effective sshd config check found a blocker for a freshly created temporary account's key credential",
			forbidden: "sshd would not accept a public-key login",
		},
		{
			name:      "Chinese success",
			lang:      i18n.ZH,
			config:    "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n",
			wantOut:   "sshd 有效配置检查未发现新账号公钥凭据的阻碍",
			forbidden: "sshd 接受公钥登录",
		},
		{
			name:      "Chinese blocker",
			lang:      i18n.ZH,
			config:    "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n",
			wantErr:   "sshd 有效配置检查发现新建临时账号公钥凭据的阻碍",
			forbidden: "sshd 不会接受",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, out, errb := newTestApp(t, "")
			a.P = i18n.Printer{Lang: tc.lang}
			a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
				return sysinfo.ParseSSHD(tc.config), nil
			}
			_ = a.doctor(nil)
			combined := out.String() + errb.String()
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Fatalf("doctor stdout missing %q: %q", tc.wantOut, out.String())
			}
			if tc.wantErr != "" && !strings.Contains(errb.String(), tc.wantErr) {
				t.Fatalf("doctor stderr missing %q: %q", tc.wantErr, errb.String())
			}
			if strings.Contains(combined, tc.forbidden) {
				t.Fatalf("doctor retained end-to-end claim %q: %q", tc.forbidden, combined)
			}
		})
	}
}

func mustSSHDConfig(t *testing.T, a *App, user string) *sysinfo.SSHDConfig {
	t.Helper()
	cfg, err := a.sshdConfig(user)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEnsureStableInstalledRejectsUnsafeExistingCommand(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("#!/bin/sh\necho 0.0.0-dev\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "linux-temp-admin")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		a := &App{InstallPath: link, Selfmanage: &selfmanage.Manager{InstallPath: link}}
		if err := a.ensureStableInstalled(); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("ensureStableInstalled error = %v, want symlink refusal", err)
		}
	})

	t.Run("non-root owner", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires root to create a non-root-owned command")
		}
		path := filepath.Join(t.TempDir(), "linux-temp-admin")
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho 0.0.0-dev\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 1, 1); err != nil {
			t.Fatal(err)
		}
		a := &App{InstallPath: path, Selfmanage: &selfmanage.Manager{InstallPath: path}}
		if err := a.ensureStableInstalled(); err == nil || !strings.Contains(err.Error(), "not owned by root") {
			t.Fatalf("ensureStableInstalled error = %v, want owner refusal", err)
		}
	})
}

const menuTitleEN = "Linux Temporary Admin Manager"

func TestMenuBlankRedrawsAndEOFExits(t *testing.T) {
	// A blank line asks for the menu back rather than being an error.
	a, out, errb := newTestApp(t, "\n")
	if rc := a.menu(); rc != 0 { // blank, then EOF
		t.Fatalf("menu rc=%d", rc)
	}
	if n := strings.Count(out.String(), menuTitleEN); n != 2 {
		t.Errorf("blank line should redraw the menu: title drawn %d times, want 2", n)
	}
	if strings.Contains(errb.String(), "invalid choice") {
		t.Errorf("blank line must not be an error: %q", errb.String())
	}
	// EOF with no input -> clean exit, no infinite loop.
	a2, _, _ := newTestApp(t, "")
	if rc := a2.menu(); rc != 0 {
		t.Errorf("EOF menu rc=%d, want 0", rc)
	}
}

// TestMenuDoesNotRedrawAfterAction pins the fix for results scrolling out of
// view: after an action the menu must not reappear on its own, so the result is
// the last thing on screen above the prompt.
func TestMenuDoesNotRedrawAfterAction(t *testing.T) {
	exit := strconv.Itoa(len(menuItems))
	// "2" manages the temporary users: with an empty registry it prints the list,
	// prints nothing that looks like the menu, and returns without prompting.
	a, out, _ := newTestApp(t, "2\n"+exit+"\n")
	if rc := a.menu(); rc != 0 {
		t.Fatalf("menu rc=%d", rc)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "Registered temporary users") {
		t.Fatalf("choice 2 did not list the users: %q", rendered)
	}
	if n := strings.Count(rendered, menuTitleEN); n != 1 {
		t.Errorf("menu redrawn after an action: title drawn %d times, want 1:\n%s", n, rendered)
	}
	// The result must come after the menu, with nothing of the menu after it.
	if strings.Index(rendered, "Registered temporary users") < strings.Index(rendered, menuTitleEN) {
		t.Error("the action's output should follow the menu, not precede it")
	}

	// An explicit blank line still brings the menu back.
	a2, out2, _ := newTestApp(t, "2\n\n"+exit+"\n")
	if rc := a2.menu(); rc != 0 {
		t.Fatalf("menu rc=%d", rc)
	}
	if n := strings.Count(out2.String(), menuTitleEN); n != 2 {
		t.Errorf("blank line after an action should redraw: title drawn %d times, want 2", n)
	}
}

func TestMenuPreservesActionFailure(t *testing.T) {
	original := menuItems
	defer func() { menuItems = original }()
	menuItems = []menuItem{
		{zh: "失败动作", en: "Failing action", run: func(*App) commandResult { return statusResult(7) }},
		{zh: "退出", en: "Exit"},
	}
	a, _, _ := newTestApp(t, "1\n2\n")
	if rc := a.menu(); rc != 7 {
		t.Fatalf("menu rc=%d, want the action failure 7", rc)
	}
}

func TestMenuExitsAfterAppliedTerminalAction(t *testing.T) {
	original := menuItems
	defer func() { menuItems = original }()
	calls := 0
	menuItems = []menuItem{
		{zh: "升级", en: "Upgrade", run: func(*App) commandResult {
			calls++
			return commandResult{applied: true}
		}, exitOnApply: true},
		{zh: "不应执行", en: "Must not run", run: func(*App) commandResult {
			calls++
			return commandResult{}
		}},
		{zh: "退出", en: "Exit"},
	}
	a, _, _ := newTestApp(t, "1\n2\n")
	if rc := a.menu(); rc != 0 {
		t.Fatalf("menu rc=%d, want 0", rc)
	}
	if calls != 1 {
		t.Fatalf("terminal action did not exit the menu: calls=%d, want 1", calls)
	}
}

func TestMenuContinuesAfterUnappliedTerminalAction(t *testing.T) {
	original := menuItems
	defer func() { menuItems = original }()
	calls := 0
	menuItems = []menuItem{
		{zh: "取消的升级", en: "Cancelled upgrade", run: func(*App) commandResult {
			calls++
			return commandResult{}
		}, exitOnApply: true},
		{zh: "后续动作", en: "Following action", run: func(*App) commandResult {
			calls++
			return commandResult{}
		}},
		{zh: "退出", en: "Exit"},
	}
	a, _, _ := newTestApp(t, "1\n2\n3\n")
	if rc := a.menu(); rc != 0 {
		t.Fatalf("menu rc=%d, want 0", rc)
	}
	if calls != 2 {
		t.Fatalf("menu stopped after an unapplied terminal action: calls=%d, want 2", calls)
	}
}

func TestMenuCancelledUpgradeAndUninstallStayInMenu(t *testing.T) {
	mainPrompt := fmt.Sprintf("select [1-%d] (Enter shows the menu): ", len(menuItems))
	for _, tc := range []struct {
		name   string
		choice int
	}{
		{name: "upgrade", choice: 4},
		{name: "uninstall", choice: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := newTestApp(t, fmt.Sprintf("%d\nNO\n%d\n", tc.choice, len(menuItems)))
			a.StateDir = filepath.Join(t.TempDir(), "state")
			a.AuditLogDir = filepath.Join(t.TempDir(), "audit")
			if rc := a.menu(); rc != 0 {
				t.Fatalf("menu rc=%d, want 0", rc)
			}
			if got := strings.Count(errb.String(), mainPrompt); got != 2 {
				t.Fatalf("cancelled %s did not return to the menu prompt: got %d prompts\nstderr:\n%s", tc.name, got, errb.String())
			}
		})
	}
}

func TestMenuPromptChangesLanguageImmediately(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("language preference persistence requires root-owned fixtures")
	}
	oldPrefs := prefs.File
	prefs.File = filepath.Join(t.TempDir(), "prefs")
	defer func() { prefs.File = oldPrefs }()

	for _, tc := range []struct {
		name      string
		initial   i18n.Lang
		selection string
		target    i18n.Lang
	}{
		{name: "English to Chinese", initial: i18n.EN, selection: "1", target: i18n.ZH},
		{name: "Chinese to English", initial: i18n.ZH, selection: "2", target: i18n.EN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			switchChoice := len(menuItems) - 1
			a, _, errb := newTestApp(t, fmt.Sprintf("%d\n%s\n%d\n", switchChoice, tc.selection, len(menuItems)))
			a.P = i18n.Printer{Lang: tc.initial}
			if rc := a.menu(); rc != 0 {
				t.Fatalf("menu rc=%d, want 0", rc)
			}
			if a.P.Lang != tc.target {
				t.Fatalf("language=%q, want %q", a.P.Lang, tc.target)
			}
			wantPrompt := fmt.Sprintf(map[i18n.Lang]string{
				i18n.ZH: "请选择 [1-%d]（回车显示菜单）: ",
				i18n.EN: "select [1-%d] (Enter shows the menu): ",
			}[tc.target], len(menuItems))
			if !strings.Contains(errb.String(), wantPrompt) {
				t.Fatalf("menu did not use the switched language immediately; want %q in %q", wantPrompt, errb.String())
			}
		})
	}
}

// TestMenuItemsAreTranslated guards the regression this table was built to fix:
// entries once carried the bare English subcommand name in both languages, so a
// zh run printed an English menu body. Asserting zh != en catches that directly,
// without depending on any particular wording.
func TestMenuItemsAreTranslated(t *testing.T) {
	for i, it := range menuItems {
		if it.zh == "" || it.en == "" {
			t.Errorf("menuItems[%d]: empty label (zh=%q en=%q)", i, it.zh, it.en)
		}
		if it.zh == it.en {
			t.Errorf("menuItems[%d]: zh is untranslated (both %q)", i, it.zh)
		}
	}
	// Only the last entry leaves the menu; every other one must dispatch.
	for i, it := range menuItems[:len(menuItems)-1] {
		if it.run == nil {
			t.Errorf("menuItems[%d] (%q) has no action", i, it.en)
		}
	}
	if last := menuItems[len(menuItems)-1]; last.run != nil {
		t.Errorf("last entry %q should exit, not dispatch", last.en)
	}
}

// TestMenuRendersEveryEntryInBothLanguages renders the menu in each language and
// checks that every entry of the table appears, so a new entry cannot be added
// without being localized.
func TestMenuRendersEveryEntryInBothLanguages(t *testing.T) {
	exit := strconv.Itoa(len(menuItems)) + "\n"
	for _, tc := range []struct {
		lang  i18n.Lang
		label func(i int) string
	}{
		{i18n.ZH, func(i int) string { return menuItems[i].zh }},
		{i18n.EN, func(i int) string { return menuItems[i].en }},
	} {
		a, out, _ := newTestApp(t, exit)
		a.P = i18n.Printer{Lang: tc.lang}
		if rc := a.menu(); rc != 0 {
			t.Fatalf("%s menu rc=%d, want 0", tc.lang, rc)
		}
		rendered := out.String()
		for i := range menuItems {
			if want := tc.label(i); !strings.Contains(rendered, want) {
				t.Errorf("%s menu missing entry %d (%q):\n%s", tc.lang, i+1, want, rendered)
			}
		}
	}
}

// TestMenuOmitsInstall pins the reason install is not a menu entry: from the menu
// the running binary is already root, so install is either a no-op or a one-time
// bootstrap done from the shell. upgrade must be the menu's only update path.
func TestMenuOmitsInstall(t *testing.T) {
	for i, it := range menuItems {
		if strings.Contains(strings.ToLower(it.en), "install") && !strings.Contains(strings.ToLower(it.en), "uninstall") {
			t.Errorf("menuItems[%d] reintroduces install: %q", i, it.en)
		}
	}
}

// TestMenuChoiceOutOfRange covers the digits either side of the table. It runs
// as a TTY because re-prompting after an invalid choice is deliberately
// terminal-only: a non-TTY run exits instead, so an unbounded stream of garbage
// cannot spin the loop (see TestMenuDoesNotSpinOnNonTTYInvalidInput).
func TestMenuChoiceOutOfRange(t *testing.T) {
	last := len(menuItems)
	a, _, errb := newTestApp(t, fmt.Sprintf("0\n%d\n%d\n", last+1, last))
	a.StdinIsTTY = func() bool { return true }
	if rc := a.menu(); rc != 0 {
		t.Fatalf("menu rc=%d", rc)
	}
	if n := strings.Count(errb.String(), "invalid choice"); n != 2 {
		t.Errorf("want 2 invalid-choice warnings for 0 and %d, got %d: %q", last+1, n, errb.String())
	}
}

func TestInviteGuardsReject(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bad hours", []string{"--user", "xxvcc-a1", "--host", "1.2.3.4", "--hours", "0", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"bad prefix", []string{"--prefix", "BAD", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"yes needs host", []string{"--user", "xxvcc-a1", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"bad host", []string{"--user", "xxvcc-a1", "--host", "bad host", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"port zero", []string{"--user", "xxvcc-a1", "--host", "1.2.3.4", "--port", "0", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"sudo yes needs confirm", []string{"--user", "xxvcc-a1", "--host", "1.2.3.4", "--sudo", "--yes"}},
		{"conflicting sudo", []string{"--sudo", "--no-sudo"}},
		{"conflicting sudo alias", []string{"--nopasswd-sudo", "--no-sudo"}},
		{"conflicting auto revoke", []string{"--auto-revoke", "--no-auto-revoke"}},
		{"conflicting dependency install", []string{"--install-deps", "--no-install-deps"}},
		{"trailing arg", []string{"--user", "xxvcc-a1", "--host", "1.2.3.4", "--yes", "junk"}},
		{"reserved user root", []string{"--user", "root", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"reserved user systemd-", []string{"--user", "systemd-abc", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"reserved prefix systemd", []string{"--prefix", "systemd", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
	}
	for _, c := range cases {
		a, _, errb := newTestApp(t, "")
		if rc := a.invite(c.args); rc != 1 {
			t.Errorf("%s: rc=%d, want 1 (stderr: %s)", c.name, rc, errb.String())
		}
	}
}

// TestInviteRejectsReservedNames pins the fix for the create/revoke asymmetry: a
// reserved name (explicit --user or generated from a reserved --prefix) must be
// refused at creation with the reserved-namespace reason, before any mutation —
// otherwise the tool could mint an account its own revoke path would never delete.
// newTestApp leaves Users nil, so reaching creation would panic instead of pass.
func TestInviteRejectsReservedNames(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"explicit root", []string{"--user", "root", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"explicit systemd-", []string{"--user", "systemd-resolve", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"generated from systemd prefix", []string{"--prefix", "systemd", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
		{"generated from systemd- subprefix", []string{"--prefix", "systemd-x", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"}},
	}
	for _, c := range cases {
		a, _, errb := newTestApp(t, "")
		if rc := a.invite(c.args); rc != 1 {
			t.Errorf("%s: rc=%d, want 1", c.name, rc)
		}
		if !strings.Contains(errb.String(), "reserved") {
			t.Errorf("%s: want a reserved-namespace refusal, got: %q", c.name, errb.String())
		}
	}
}

// TestInvitePrefixGuardSkippedWithExplicitUser pins the fix for a regression the
// reserved-name guard introduced: the prefix guard must NOT fire when --user is
// given, because the prefix is then unused for name generation. A legitimate
// explicit username must clear both name guards and be rejected only by a later
// guard (here an invalid host) — never by the reserved-namespace message.
func TestInvitePrefixGuardSkippedWithExplicitUser(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	rc := a.invite([]string{"--user", "alice", "--prefix", "systemd", "--host", "bad host", "--no-sudo", "--no-auto-revoke", "--yes"})
	if rc != 1 {
		t.Fatalf("rc=%d, want 1 (reject on the invalid host, not create)", rc)
	}
	got := errb.String()
	if strings.Contains(got, "reserved") {
		t.Errorf("prefix guard wrongly rejected an explicit --user invite: %q", got)
	}
	if !strings.Contains(got, "invalid host") {
		t.Errorf("want rejection at the host guard, got: %q", got)
	}
}

func TestRevokeGuardsReject(t *testing.T) {
	// invalid username
	a, _, _ := newTestApp(t, "")
	if rc := a.revoke([]string{"--user", "BAD!"}); rc != 1 {
		t.Errorf("invalid username: rc=%d, want 1", rc)
	}
	// unregistered without --force (registry is empty)
	a2, _, _ := newTestApp(t, "")
	if rc := a2.revoke([]string{"--user", "xxvcc-nope"}); rc != 1 {
		t.Errorf("unregistered without --force: rc=%d, want 1", rc)
	}
}

func TestForceWarningDoesNotClaimManagedIdentityChecksAreBypassed(t *testing.T) {
	a, _, errb := newTestApp(t, "not-alice\n")
	a.LookupUser = func(string) (user.Passwd, bool, error) {
		return user.Passwd{Name: "alice", UID: 1001, GID: 1001, Home: "/home/alice", Shell: "/bin/sh"}, true, nil
	}
	if rc := a.revoke([]string{"--user", "alice", "--force"}); rc != 0 {
		t.Fatalf("cancelled revoke rc = %d, want 0", rc)
	}
	got := errb.String()
	if !strings.Contains(got, "only if the remaining managed-identity checks also pass") {
		t.Fatalf("force warning omits the protection boundary: %q", got)
	}
	if strings.Contains(got, "delete a real system user") {
		t.Fatalf("force warning contradicts the real-account protection gate: %q", got)
	}
}

func TestTeardownLocalAccountStopsWhenDisableLoginIsIncomplete(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{Name: "xxvcc-a1", UID: 1001, GID: 1001, Home: "/home/xxvcc-a1", Shell: "/bin/sh", GECOS: config.ManagedGenerationGECOSPrefix + generation}
	for _, failedCommand := range []string{"chage", "usermod"} {
		t.Run(failedCommand, func(t *testing.T) {
			runner := &revokeRunner{failOn: failedCommand}
			terminateCalls := 0
			a := &App{
				Users: &user.Manager{Runner: runner},
				LookupUser: func(string) (user.Passwd, bool, error) {
					return pw, true, nil
				},
				TerminateProcesses: func(int) error {
					terminateCalls++
					return nil
				},
			}

			stage, err := a.teardownLocalAccount("xxvcc-a1", pw, func() error { return nil })
			if err == nil || stage != revokeDisableLogin {
				t.Fatalf("teardownLocalAccount = stage %v, err %v; want disable failure", stage, err)
			}
			if terminateCalls != 0 {
				t.Fatalf("TerminateProcesses called %d time(s) after incomplete login disable", terminateCalls)
			}
			if got, want := strings.Join(runner.calls, ","), "chage,usermod"; got != want {
				t.Fatalf("account commands = %q, want %q and no userdel", got, want)
			}
		})
	}
}

func TestTeardownLocalAccountReachesDeleteOnlyAfterDisableSucceeds(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{Name: "xxvcc-a1", UID: 1001, GID: 1001, Home: "/home/xxvcc-a1", Shell: "/bin/sh", GECOS: config.ManagedGenerationGECOSPrefix + generation}
	runner := &revokeRunner{failOn: "userdel"}
	terminateCalls := 0
	lookup := func(string) (user.Passwd, bool, error) { return pw, true, nil }
	a := &App{
		Users: &user.Manager{
			Runner: runner, LookupUser: lookup,
			RemoveManagedMail: func(user.Passwd) error { return nil },
			RemoveManagedHome: func(user.Passwd) error { return nil },
		},
		TerminateProcesses: func(uid int) error {
			terminateCalls++
			if uid != 1001 {
				t.Fatalf("TerminateProcesses uid = %d, want 1001", uid)
			}
			return nil
		},
		LookupUser:         lookup,
		ClearScheduledJobs: testClearScheduledJobs,
		DrainScheduledJobs: testDrainScheduledJobs,
	}

	stage, err := a.teardownLocalAccount("xxvcc-a1", pw, func() error { return nil })
	if err == nil || stage != revokeDeleteAccount {
		t.Fatalf("teardownLocalAccount = stage %v, err %v; want delete failure", stage, err)
	}
	if terminateCalls != 3 {
		t.Fatalf("TerminateProcesses calls = %d, want initial two-pass drain plus final pre-userdel pass", terminateCalls)
	}
	if got, want := strings.Join(runner.calls, ","), "chage,usermod,userdel"; got != want {
		t.Fatalf("account commands = %q, want %q", got, want)
	}
}

func TestRollbackInviteAccountRequiresCompleteCapturedIdentity(t *testing.T) {
	runner := &revokeRunner{}
	terminateCalls := 0
	a := &App{
		Users: &user.Manager{Runner: runner},
		TerminateProcesses: func(int) error {
			terminateCalls++
			return nil
		},
	}

	for _, tc := range []struct {
		rec      registry.Record
		expected user.Passwd
	}{
		{rec: registry.Record{User: "xxvcc-a1", Pending: true}},
		{rec: registry.Record{User: "xxvcc-a1", UID: 1001, Generation: "0123456789abcdef0123456789abcdef", IdentityBound: true}},
	} {
		if err := a.rollbackInviteAccount("xxvcc-a1", tc.rec, tc.expected, true); err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("rollbackInviteAccount(%+v) error = %v, want incomplete-identity refusal", tc.rec, err)
		}
	}
	if len(runner.calls) != 0 || terminateCalls != 0 {
		t.Fatalf("pending identity reached destructive teardown: commands=%v terminateCalls=%d", runner.calls, terminateCalls)
	}
}

func TestRollbackInviteAccountUsesFailClosedTeardown(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{Name: "xxvcc-a1", UID: 1001, GID: 1001, Home: "/home/xxvcc-a1", Shell: "/bin/sh", GECOS: config.ManagedGenerationGECOSPrefix + generation}
	rec := registry.Record{User: "xxvcc-a1", UID: 1001, Generation: generation, IdentityBound: true}
	t.Run("success", func(t *testing.T) {
		runner := &revokeRunner{}
		terminateCalls := 0
		lookup := func(string) (user.Passwd, bool, error) {
			if len(runner.calls) > 0 && runner.calls[len(runner.calls)-1] == "userdel" {
				return user.Passwd{}, false, nil
			}
			return pw, true, nil
		}
		a := &App{
			Users: &user.Manager{
				Runner: runner, LookupUser: lookup,
				RemoveManagedMail: func(user.Passwd) error { return nil },
				RemoveManagedHome: func(user.Passwd) error { return nil },
			},
			TerminateProcesses: func(uid int) error {
				terminateCalls++
				if uid != 1001 {
					t.Fatalf("TerminateProcesses uid = %d, want 1001", uid)
				}
				return nil
			},
			LookupUser:         lookup,
			ClearScheduledJobs: testClearScheduledJobs,
			DrainScheduledJobs: testDrainScheduledJobs,
		}
		setTestRegistryRecord(t, a, rec)
		if err := a.rollbackInviteAccount("xxvcc-a1", rec, pw, true); err != nil {
			t.Fatal(err)
		}
		if terminateCalls != 3 || strings.Join(runner.calls, ",") != "chage,usermod,userdel" {
			t.Fatalf("rollback order wrong: commands=%v terminateCalls=%d", runner.calls, terminateCalls)
		}
	})

	t.Run("process uncertainty retains account", func(t *testing.T) {
		runner := &revokeRunner{}
		wantErr := errors.New("process scan incomplete")
		a := &App{
			Users:              &user.Manager{Runner: runner},
			TerminateProcesses: func(int) error { return wantErr },
			LookupUser:         func(string) (user.Passwd, bool, error) { return pw, true, nil },
			ClearScheduledJobs: testClearScheduledJobs,
			DrainScheduledJobs: testDrainScheduledJobs,
		}
		err := a.rollbackInviteAccount("xxvcc-a1", rec, pw, true)
		if !errors.Is(err, wantErr) {
			t.Fatalf("rollback error = %v, want %v", err, wantErr)
		}
		if got := strings.Join(runner.calls, ","); got != "chage,usermod" {
			t.Fatalf("process uncertainty reached userdel: commands=%q", got)
		}
	})

	t.Run("captured pending identity can be rolled back", func(t *testing.T) {
		pending := pw
		pending.GECOS = config.PendingGenerationGECOSPrefix + generation
		pendingRec := rec
		pendingRec.UID = 0
		pendingRec.Pending = true
		runner := &revokeRunner{}
		lookup := func(string) (user.Passwd, bool, error) {
			if len(runner.calls) > 0 && runner.calls[len(runner.calls)-1] == "userdel" {
				return user.Passwd{}, false, nil
			}
			return pending, true, nil
		}
		a := &App{
			Users: &user.Manager{
				Runner: runner, LookupUser: lookup,
				RemoveManagedMail: func(user.Passwd) error { return nil },
				RemoveManagedHome: func(user.Passwd) error { return nil },
			},
			TerminateProcesses: func(int) error { return nil },
			LookupUser:         lookup,
			ClearScheduledJobs: testClearScheduledJobs,
			DrainScheduledJobs: testDrainScheduledJobs,
		}
		setTestRegistryRecord(t, a, pendingRec)
		if err := a.rollbackInviteAccount("xxvcc-a1", pendingRec, pending, true); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(runner.calls, ","); got != "chage,usermod,userdel" {
			t.Fatalf("pending rollback order = %q", got)
		}
	})

	t.Run("retained pending identity uses captured UID", func(t *testing.T) {
		pending := pw
		pending.GECOS = config.PendingGenerationGECOSPrefix + generation
		pendingRec := rec
		pendingRec.UID = 0
		pendingRec.Pending = true
		runner := &revokeRunner{}
		terminatedUID := 0
		a := &App{
			Users:              &user.Manager{Runner: runner},
			TerminateProcesses: func(uid int) error { terminatedUID = uid; return nil },
			LookupUser:         func(string) (user.Passwd, bool, error) { return pending, true, nil },
			ClearScheduledJobs: testClearScheduledJobs,
			DrainScheduledJobs: testDrainScheduledJobs,
		}
		if err := a.rollbackInviteAccount("xxvcc-a1", pendingRec, pending, false); err != nil {
			t.Fatal(err)
		}
		if terminatedUID != pending.UID {
			t.Fatalf("rollback terminated UID %d, want captured UID %d", terminatedUID, pending.UID)
		}
		if got := strings.Join(runner.calls, ","); got != "chage,usermod" {
			t.Fatalf("retained pending rollback commands = %q", got)
		}
	})

	t.Run("already absent account never reaches home cleanup", func(t *testing.T) {
		runner := &revokeRunner{}
		lookup := func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
		homeTouched := false
		mailCalls := 0
		a := &App{
			Users: &user.Manager{
				Runner: runner, LookupUser: lookup,
				RemoveManagedMail: func(user.Passwd) error { mailCalls++; return nil },
				RemoveManagedHome: func(got user.Passwd) error {
					homeTouched = true
					if got != pw {
						t.Fatalf("cleanup identity = %+v, want %+v", got, pw)
					}
					return nil
				},
			},
			LookupUser: lookup,
		}
		if err := a.rollbackInviteAccount("xxvcc-a1", rec, pw, true); err != nil {
			t.Fatal(err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("absent account reached a name-scoped helper: %v", runner.calls)
		}
		if homeTouched || mailCalls != 2 {
			t.Fatalf("absent cleanup touched Home=%v or mail calls=%d, want Home=false mail=2", homeTouched, mailCalls)
		}
	})

	t.Run("same UID replacement is retained", func(t *testing.T) {
		runner := &revokeRunner{}
		lookups := 0
		replacement := pw
		replacement.GECOS = config.ManagedGenerationGECOSPrefix + "fedcba9876543210fedcba9876543210"
		a := &App{
			Users: &user.Manager{Runner: runner},
			LookupUser: func(string) (user.Passwd, bool, error) {
				lookups++
				if lookups == 1 {
					return pw, true, nil
				}
				return replacement, true, nil
			},
			TerminateProcesses: func(int) error {
				t.Fatal("replacement reached process termination")
				return nil
			},
		}
		err := a.rollbackInviteAccount("xxvcc-a1", rec, pw, true)
		if err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("rollback error = %v, want replacement refusal", err)
		}
		if got := strings.Join(runner.calls, ","); got != "" {
			t.Fatalf("replacement reached account helper: commands=%q", got)
		}
	})
}

func TestUninstallRefusesOnRegistryReadError(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	// Make the registry file a symlink so List() errors.
	if err := os.Symlink("/nonexistent", a.Registry.File); err != nil {
		t.Fatal(err)
	}
	if rc := a.uninstall([]string{}); rc != 1 {
		t.Errorf("uninstall with unreadable registry: rc=%d, want 1 (stderr: %s)", rc, errb.String())
	}
}

func TestRecursiveRemovalNeverAcceptsBroadNonCanonicalOrRelativePaths(t *testing.T) {
	for _, path := range []string{"", ".", "relative/state", "/", "/etc", "/tmp", "/var", "/var/lib", "/var/log", "/usr/local", "/var/lib/../etc"} {
		if err := safeRecursiveRemovalPath(path); err == nil {
			t.Errorf("safeRecursiveRemovalPath(%q) unexpectedly allowed recursive removal", path)
		}
	}
	if err := safeRecursiveRemovalPath("/var/lib/linux-temp-admin"); err != nil {
		t.Fatalf("safe managed path rejected: %v", err)
	}
}

func TestRecursiveRemovalRefusesSymlinkedParentEvenWithForce(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	realState := filepath.Join(realParent, "state")
	if err := os.Mkdir(realState, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(realState, "must-survive")
	if err := os.WriteFile(sentinel, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(base, "linked-parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}

	removeCalled := false
	a := &App{
		StateDir: filepath.Join(linkParent, "state"),
		RemoveAll: func(path string) error {
			removeCalled = true
			return os.RemoveAll(path)
		},
	}
	err := a.removeStateDir(true)
	if err == nil || !strings.Contains(err.Error(), "symlinked parent") {
		t.Fatalf("symlinked-parent removal error = %v, want refusal", err)
	}
	if removeCalled {
		t.Fatal("symlinked parent reached recursive removal")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "unrelated" {
		t.Fatalf("redirected tree changed: content=%q err=%v", got, err)
	}
}

func TestRecursiveRemovalRetrySyncsParentAfterVisibleDeletion(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "managed")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}

	realSync := syncRecursiveRemovalParent
	t.Cleanup(func() { syncRecursiveRemovalParent = realSync })
	wantErr := errors.New("forced recursive-removal parent sync failure")
	syncs := 0
	syncRecursiveRemovalParent = func(*os.File) error {
		syncs++
		if syncs == 1 {
			return wantErr
		}
		return nil
	}

	a := &App{StateDir: state}
	err := a.removeStateDir(true)
	var durability *fsutil.DurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, wantErr) || durability.Operation != "recursive removal" {
		t.Fatalf("first removal error = %v, want recursive-removal DurabilityError", err)
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatalf("first removal was not visible: %v", err)
	}
	if err := a.removeStateDir(true); err != nil {
		t.Fatalf("retry after visible removal: %v", err)
	}
	if syncs != 2 {
		t.Fatalf("recursive-removal parent sync calls = %d, want failed sync plus absent-root retry", syncs)
	}
}

func TestRecursiveRemovalRejectsRootAndNestedMounts(t *testing.T) {
	base := "28 1 254:4 / / rw,relatime - ext4 /dev/root rw\n"
	for _, line := range []string{
		"40 28 0:40 / /var/lib/linux-temp-admin rw - tmpfs tmpfs rw\n",
		"41 28 0:41 / /var/lib/linux-temp-admin/cache rw - tmpfs tmpfs rw\n",
		"42 28 0:42 / /var/lib/linux-temp-admin/with\\040space rw - tmpfs tmpfs rw\n",
	} {
		if err := rejectMountsUnder(strings.NewReader(base+line), "/var/lib/linux-temp-admin"); err == nil {
			t.Fatalf("mountinfo entry was accepted: %q", line)
		}
	}
	outside := base + "43 28 0:43 / /var/lib/linux-temp-admin-old rw - tmpfs tmpfs rw\n"
	if err := rejectMountsUnder(strings.NewReader(outside), "/var/lib/linux-temp-admin"); err != nil {
		t.Fatalf("sibling mountpoint was mistaken for a child: %v", err)
	}
}

func TestMountInfoParserFailsClosed(t *testing.T) {
	for _, input := range []string{"too short\n", "40 28 0:40 / /bad\\0 rw - x x rw\n"} {
		if err := rejectMountsUnder(strings.NewReader(input), "/state"); err == nil {
			t.Fatalf("malformed mountinfo was accepted: %q", input)
		}
	}
}

// TestInviteNonTTYRefusesBeforeAnyPrompt pins the ordering: a piped run must be
// rejected before invite asks anything or probes the network for a host, so an
// operator never answers prompts only to be refused at the end.
func TestInviteNonTTYRefusesBeforeAnyPrompt(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.StdoutIsTTY = func() bool { return false }
	// No Detector and no stdin: if invite reaches host resolution it nil-derefs
	// or blocks, which is exactly the regression this test catches.
	if rc := a.invite(nil); rc != 1 {
		t.Fatalf("invite on non-TTY stdout: rc=%d, want 1", rc)
	}
	if !strings.Contains(errb.String(), "not a TTY") {
		t.Errorf("want the non-TTY refusal, got: %q", errb.String())
	}
	if strings.Contains(errb.String(), "public IP") || strings.Contains(errb.String(), "IP/domain") {
		t.Errorf("invite prompted for a host before refusing: %q", errb.String())
	}
}

// TestInviteRefusesBeforeAskingAnything pins the ordering that makes a refusal
// cheap and quiet. On a host whose sshd explicitly denies the account (a rule the
// tool will never bypass), the invite is doomed no matter what the operator
// answers — so it must be refused before a single question is asked and before
// the Host is resolved, which can mean asking an external echo service for this
// server's public IP. Phoning home for an invite that is about to be refused is
// exactly the disclosure this tool promises not to make.
//
// The nil Detector is the tripwire: reaching Host resolution would dereference it.
func TestInviteRefusesBeforeAskingAnything(t *testing.T) {
	a, _, errb := newTestApp(t, "y\nYES\n") // answers that must never be consumed
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		// An explicit deny: unfixable by design, so nothing the operator says matters.
		return sysinfo.ParseSSHD("pubkeyauthentication yes\ndenyusers xxvcc-a1\n"), nil
	}

	// No --host, so reaching Host resolution would prompt and probe (and panic on
	// the nil Detector).
	rc := a.invite([]string{"--user", "xxvcc-a1", "--no-sudo", "--no-auto-revoke"})

	if rc != 1 {
		t.Fatalf("rc=%d, want 1 (an explicit sshd deny must refuse)", rc)
	}
	if !strings.Contains(errb.String(), "explicit sshd deny rule") {
		t.Errorf("refusal did not name the reason:\n%s", errb.String())
	}
	// Not one question may have been put to the operator.
	for _, q := range []string{"Grant sudo", "Auto-delete", "Type YES",
		"public-key login for this account only", "public IP"} {
		if strings.Contains(errb.String(), q) {
			t.Errorf("operator was asked %q before the invite was refused:\n%s", q, errb.String())
		}
	}
}

func TestDetectedLocalHostRequiresOperatorConfirmation(t *testing.T) {
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("8.8.4.4"))
	}))
	t.Cleanup(metadata.Close)

	a, _, errb := newTestApp(t, "admin.example.com\n")
	a.Detector = netdetect.New()
	a.Detector.MetadataServices = []string{metadata.URL}
	if got := a.detectOrPromptHost(); got != "admin.example.com" {
		t.Fatalf("detected Host = %q, want the operator's confirmed override", got)
	}
	if !strings.Contains(errb.String(), "[8.8.4.4]") {
		t.Fatalf("metadata Host was not presented as a confirmable default: %q", errb.String())
	}
}

// TestInviteSurvivesAnUnwiredSSHDProbe pins that a root-run tool has no path that
// panics: an unset probe is reported, not dereferenced.
func TestInviteSurvivesAnUnwiredSSHDProbe(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.SSHDConfig = nil // never happens via NewApp; must still not crash
	// Users is nil in the fixture, so creation would panic -- the point is only that
	// the probe itself does not.
	defer func() {
		if r := recover(); r != nil && !strings.Contains(errb.String(), "unverified") {
			t.Fatalf("an unwired probe panicked before it could be reported: %v", r)
		}
	}()
	_ = a.invite([]string{"--user", "xxvcc-a1", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke", "--yes"})
	if !strings.Contains(errb.String(), "unverified") {
		t.Errorf("an unwired probe should be reported as unverified:\n%s", errb.String())
	}
}

func TestSSHDConfigRejectsNilResult(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return nil, nil }

	cfg, err := a.sshdConfig("xxvcc-a1")
	if err == nil || cfg != nil || !strings.Contains(err.Error(), "returned no configuration") {
		t.Fatalf("sshdConfig nil result = %#v, %v; want nil, descriptive error", cfg, err)
	}
}

func TestPasswordLoginFailsClosedWhenSSHDProbeFails(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return nil, errors.New("probe unavailable")
	}
	if plan, ok := a.planLogin("xxvcc-a1", true, "no", true); ok {
		t.Fatalf("password plan unexpectedly accepted after probe failure: %+v", plan)
	}
	if !strings.Contains(errb.String(), "refusing a password login") {
		t.Fatalf("password refusal did not name the fail-closed reason: %q", errb.String())
	}
}

func TestPasswordLoginFailsClosedWhenConfirmationProbeFails(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return nil, errors.New("second probe unavailable")
	}
	plan := loginPlan{password: true, verified: true}
	if a.confirmLogin("xxvcc-a1", []string{"xxvcc-a1"}, &plan) {
		t.Fatal("password login remained accepted after its confirmation probe failed")
	}
}

func TestPasswordLoginFailsClosedWhenSSHDPolicyIsUnverifiable(t *testing.T) {
	const conf = "passwordauthentication yes\nallowusers xxvcc-a1@203.0.113.5\n"
	a, _, errb := newTestApp(t, "")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD(conf), nil
	}
	if plan, ok := a.planLogin("xxvcc-a1", true, "no", true); ok {
		t.Fatalf("password plan unexpectedly accepted an address-dependent policy: %+v", plan)
	}
	if !strings.Contains(errb.String(), "effective sshd config check cannot confirm") {
		t.Fatalf("password refusal did not name the unverifiable policy: %q", errb.String())
	}
}

func TestPasswordConfirmationFailsClosedWhenSSHDPolicyBecomesUnverifiable(t *testing.T) {
	const conf = "passwordauthentication yes\nallowusers xxvcc-a1@203.0.113.5\n"
	a, _, _ := newTestApp(t, "")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD(conf), nil
	}
	plan := loginPlan{password: true, verified: true}
	if a.confirmLogin("xxvcc-a1", []string{"xxvcc-a1"}, &plan) {
		t.Fatal("password login remained accepted after its policy became address-dependent")
	}
}

func TestPasswordFallbackIsNotOfferedForUnverifiablePolicy(t *testing.T) {
	const conf = "passwordauthentication yes\nallowusers xxvcc-a1@203.0.113.5\n"
	a, errb := interactiveApp(t, "y\n", conf)
	if plan, ok := a.offerPasswordFallback(sysinfo.ParseSSHD(conf), "xxvcc-a1", true); ok {
		t.Fatalf("password fallback unexpectedly accepted an address-dependent policy: %+v", plan)
	}
	if !strings.Contains(errb.String(), "no password fallback") {
		t.Fatalf("password fallback refusal did not explain the unverifiable policy: %q", errb.String())
	}
}

func TestDeferredPasswordFallbackRequiresExplicitConsentAndPostAccountCheck(t *testing.T) {
	const conf = "pubkeyauthentication no\npasswordauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"

	t.Run("default no declines", func(t *testing.T) {
		a, errb := interactiveApp(t, "\n", conf)
		a.SSHDHasUnverifiableMatch = func(accountExists bool) bool { return !accountExists }
		if plan, ok := a.offerPasswordFallback(sysinfo.ParseSSHD(conf), "xxvcc-a1", true); ok {
			t.Fatalf("default-No consent unexpectedly produced a password plan: %+v", plan)
		}
		diagnostic := errb.String()
		if !strings.Contains(diagnostic, "brute-forceable") || !strings.Contains(diagnostic, "[y/N]") {
			t.Fatalf("deferred fallback omitted its risk warning or default-No prompt: %q", diagnostic)
		}
	})

	t.Run("yes still fails closed after creation", func(t *testing.T) {
		a, errb := interactiveApp(t, "y\n", conf)
		var phases []bool
		a.SSHDHasUnverifiableMatch = func(accountExists bool) bool {
			phases = append(phases, accountExists)
			return !accountExists
		}
		plan, ok := a.offerPasswordFallback(sysinfo.ParseSSHD(conf), "xxvcc-a1", true)
		if !ok || !plan.password || plan.verified || plan.unverified == "" {
			t.Fatalf("consented deferred fallback = (%+v, %v), want an unverified password plan", plan, ok)
		}
		if !strings.Contains(errb.String(), "brute-forceable") || !strings.Contains(errb.String(), "[y/N]") {
			t.Fatalf("consented deferred fallback omitted its risk warning or prompt: %q", errb.String())
		}

		// Account creation resolves Match Group, but consent must not authorize a
		// password by itself. The mandatory post-account check sees the real policy
		// and refuses before runInvite reaches SetPassword.
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD("passwordauthentication no\n"), nil
		}
		if a.confirmLogin("xxvcc-a1", []string{"xxvcc-a1"}, &plan) {
			t.Fatal("password fallback consent bypassed the post-account policy check")
		}
		if len(phases) != 3 || !phases[0] || phases[1] || !phases[2] {
			t.Fatalf("deferred fallback Match phases = %v, want [true false true]", phases)
		}
	})
}

func TestDeferredPasswordFallbackDoesNotHideKnownBlocker(t *testing.T) {
	const conf = "pubkeyauthentication no\npasswordauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n"
	a, errb := interactiveApp(t, "y\n", conf)
	a.SSHDHasUnverifiableMatch = func(accountExists bool) bool { return !accountExists }
	if plan, ok := a.offerPasswordFallback(sysinfo.ParseSSHD(conf), "xxvcc-a1", true); ok {
		t.Fatalf("known password blocker was hidden by Match Group deferral: %+v", plan)
	}
	if strings.Contains(errb.String(), "Issue a password login instead?") {
		t.Fatalf("known password blocker still reached the fallback consent prompt: %q", errb.String())
	}
}

func TestLoginChecksPassAccountPhaseToInjectedUnverifiableMatchProbe(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	var phases []bool
	a.SSHDHasUnverifiableMatch = func(accountExists bool) bool {
		phases = append(phases, accountExists)
		return !accountExists
	}
	cfg := sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n")
	rep := a.checkKeyLogin(cfg, "xxvcc-a1", []string{"xxvcc-a1"}, false)
	if rep.Certain() || len(rep.Unverifiable) != 1 {
		t.Fatalf("unverifiable Match probe did not downgrade the report: %+v", rep)
	}
	post := a.checkKeyLogin(cfg, "xxvcc-a1", []string{"xxvcc-a1"}, true)
	if !post.Certain() {
		t.Fatalf("post-account Group-only Match remained unverifiable: %+v", post)
	}
	if len(phases) != 3 || !phases[0] || phases[1] || !phases[2] {
		t.Fatalf("unverifiable Match account phases = %v, want [true false true]", phases)
	}
}

func TestLoginPlanningAndConfirmationUseTheirActualAccountPhase(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	var phases []bool
	a.SSHDHasUnverifiableMatch = func(accountExists bool) bool {
		phases = append(phases, accountExists)
		return false
	}
	plan, ok := a.planLogin("xxvcc-a1", false, "no", true)
	if !ok {
		t.Fatal("key login planning unexpectedly failed")
	}
	if len(phases) != 2 || !phases[0] || phases[1] {
		t.Fatalf("planning Match account phases = %v, want [true false]", phases)
	}
	phases = nil
	if !a.confirmLogin("xxvcc-a1", []string{"xxvcc-a1"}, &plan) {
		t.Fatal("key login confirmation unexpectedly failed")
	}
	if len(phases) != 1 || !phases[0] {
		t.Fatalf("confirmation Match account phases = %v, want [true]", phases)
	}
}

func TestExplicitSSHDRepairPermissionSurvivesPreAccountMatchGroup(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	a.SSHD = &sshdconf.Manager{}
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	a.SSHDHasUnverifiableMatch = func(accountExists bool) bool { return !accountExists }
	plan, ok := a.planLogin("xxvcc-a1", false, "yes", true)
	if !ok || !plan.fixSSHD {
		t.Fatalf("pre-account Match Group discarded explicit repair permission: ok=%v plan=%+v", ok, plan)
	}
	if !a.confirmLogin("xxvcc-a1", []string{"xxvcc-a1"}, &plan) {
		t.Fatal("post-account fixable blocker was refused despite explicit repair permission")
	}
	if !plan.fixSSHD || !plan.report.Has(sysinfo.BlockPubkeyDisabled) {
		t.Fatalf("confirmed repair plan = %+v, want retained fix with real blocker", plan)
	}
}

func TestPreAccountMatchGroupDoesNotBypassKeyRepairChoice(t *testing.T) {
	const conf = "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n"

	t.Run("explicit refusal remains refusal", func(t *testing.T) {
		a, _, _ := newTestApp(t, "")
		a.SSHD = &sshdconf.Manager{}
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD(conf), nil
		}
		a.SSHDHasUnverifiableMatch = func(accountExists bool) bool { return !accountExists }
		if plan, ok := a.planLogin("xxvcc-a1", false, "no", true); ok {
			t.Fatalf("known key blocker bypassed --no-fix-sshd through Match Group deferral: %+v", plan)
		}
	})

	t.Run("interactive consent is still required", func(t *testing.T) {
		a, _ := interactiveApp(t, "y\n", conf)
		a.SSHD = &sshdconf.Manager{}
		a.SSHDHasUnverifiableMatch = func(accountExists bool) bool { return !accountExists }
		plan, ok := a.planLogin("xxvcc-a1", false, "ask", false)
		if !ok || !plan.fixSSHD {
			t.Fatalf("known key blocker bypassed the normal repair choice: ok=%v plan=%+v", ok, plan)
		}
	})
}

func TestPasswordDefersOnlyPreAccountMatchGroup(t *testing.T) {
	t.Run("group is resolved before password", func(t *testing.T) {
		a, _, _ := newTestApp(t, "")
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD("passwordauthentication yes\n"), nil
		}
		a.SSHDHasUnverifiableMatch = func(accountExists bool) bool { return !accountExists }
		plan, ok := a.planLogin("xxvcc-a1", true, "no", true)
		if !ok || !plan.password {
			t.Fatalf("Group-only pre-account uncertainty was not deferred: ok=%v plan=%+v", ok, plan)
		}
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD("passwordauthentication yes\n"), nil
		}
		if !a.confirmLogin("xxvcc-a1", []string{"xxvcc-a1"}, &plan) {
			t.Fatal("password was not accepted after the post-account config became conclusive")
		}
	})

	t.Run("known blocker is rejected before account creation", func(t *testing.T) {
		a, _, _ := newTestApp(t, "")
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD("passwordauthentication no\n"), nil
		}
		a.SSHDHasUnverifiableMatch = func(accountExists bool) bool { return !accountExists }
		if plan, ok := a.planLogin("xxvcc-a1", true, "no", true); ok {
			t.Fatalf("known password blocker was deferred until after account creation: %+v", plan)
		}
	})

	t.Run("connection uncertainty still fails closed", func(t *testing.T) {
		a, _, _ := newTestApp(t, "")
		a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
			return sysinfo.ParseSSHD("passwordauthentication yes\n"), nil
		}
		a.SSHDHasUnverifiableMatch = func(bool) bool { return true }
		if plan, ok := a.planLogin("xxvcc-a1", true, "no", true); ok {
			t.Fatalf("password plan accepted persistent Match uncertainty: %+v", plan)
		}
	})
}

func TestDetachedSignatureURLPreservesQueryAndFragment(t *testing.T) {
	cases := map[string]string{
		"https://example.com/releases/lta":                         "https://example.com/releases/lta.sig",
		"https://example.com/releases/lta?token=abc#download":      "https://example.com/releases/lta.sig?token=abc#download",
		"https://example.com/releases/a%2Fb?token=abc%2Fdef#asset": "https://example.com/releases/a%2Fb.sig?token=abc%2Fdef#asset",
	}
	for raw, want := range cases {
		got, err := detachedSignatureURL(raw)
		if err != nil {
			t.Errorf("detachedSignatureURL(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("detachedSignatureURL(%q) = %q, want %q", raw, got, want)
		}
	}
	if _, err := detachedSignatureURL("https://example.com/%zz"); err == nil {
		t.Fatal("malformed escaped URL was accepted")
	}
}

func TestUpgradePromptRedactsCustomURLDetails(t *testing.T) {
	const (
		userinfoMarker = "userinfo-marker-8d31"
		pathMarker     = "path-marker-4b72"
		queryMarker    = "query-marker-6c93"
		fragmentMarker = "fragment-marker-1a54"
	)
	rawURL := "https://" + userinfoMarker + ":password@example.invalid/releases/" + pathMarker +
		"?token=" + queryMarker + "#" + fragmentMarker
	urlFile := filepath.Join(t.TempDir(), "upgrade-url")
	if err := os.WriteFile(urlFile, []byte(rawURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, out, errb := newTestApp(t, "NO\n")
	if rc := a.upgrade([]string{"--url-file", urlFile}); rc != 0 {
		t.Fatalf("cancelled upgrade rc=%d, want 0", rc)
	}
	display := out.String() + errb.String()
	if !strings.Contains(display, "https://example.invalid/[details hidden]") {
		t.Fatalf("custom upgrade prompt lost the safe endpoint: %q", display)
	}
	for _, marker := range []string{userinfoMarker, pathMarker, queryMarker, fragmentMarker} {
		if strings.Contains(display, marker) {
			t.Errorf("custom upgrade prompt leaked %q: %q", marker, display)
		}
	}
}

func TestUpgradeMalformedURLDiagnosticDoesNotEchoInput(t *testing.T) {
	markers := []string{
		"userinfo-marker-8d31",
		"path-marker-4b72",
		"query-marker-6c93",
		"fragment-marker-1a54",
	}
	rawURL := "https://" + markers[0] + "@example.invalid/releases/" + markers[1] +
		"/%zz?token=" + markers[2] + "#" + markers[3]
	urlFile := filepath.Join(t.TempDir(), "upgrade-url")
	if err := os.WriteFile(urlFile, []byte(rawURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, out, errb := newTestApp(t, "")
	if rc := a.upgrade([]string{"--url-file", urlFile}); rc != 1 {
		t.Fatalf("malformed upgrade URL rc=%d, want 1", rc)
	}
	diagnostic := out.String() + errb.String()
	if !strings.Contains(diagnostic, "malformed URL syntax") {
		t.Fatalf("malformed URL diagnostic is not useful: %q", diagnostic)
	}
	for _, marker := range markers {
		if strings.Contains(diagnostic, marker) {
			t.Errorf("malformed URL diagnostic leaked %q: %q", marker, diagnostic)
		}
	}
}

func TestUpgradeRejectsSensitiveCommandLineURL(t *testing.T) {
	markers := []string{"user-marker-18d2", "query-marker-8be1", "fragment-marker-c7f4"}
	cases := []string{
		"https://" + markers[0] + ":password@example.invalid/releases/bin",
		"https://example.invalid/releases/bin?token=" + markers[1],
		"https://example.invalid/releases/bin#" + markers[2],
	}
	for _, rawURL := range cases {
		a, out, errb := newTestApp(t, "")
		if rc := a.upgrade([]string{"--url", rawURL, "--yes"}); rc != 1 {
			t.Errorf("sensitive --url %q rc=%d, want 1", rawURL, rc)
		}
		diagnostic := out.String() + errb.String()
		if !strings.Contains(diagnostic, "--url-file") {
			t.Errorf("sensitive --url refusal lacks safe alternative: %q", diagnostic)
		}
		for _, marker := range markers {
			if strings.Contains(diagnostic, marker) {
				t.Errorf("sensitive --url refusal echoed %q: %q", marker, diagnostic)
			}
		}
	}
}

func TestUpgradeURLFileInputGuards(t *testing.T) {
	write := func(t *testing.T, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "upgrade-url")
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}

	valid := write(t, "https://example.invalid/releases/bin?token=secret#fragment\n", 0o600)
	if got, err := readUpgradeURLFile(valid); err != nil || got.binary != "https://example.invalid/releases/bin?token=secret#fragment" || got.signature != "" {
		t.Fatalf("valid URL file: got=%+v err=%v", got, err)
	}
	twoURLs := write(t, "https://example.invalid/bin?binary-token=one\nhttps://signatures.invalid/bin.sig?signature-token=two\n", 0o600)
	if got, err := readUpgradeURLFile(twoURLs); err != nil ||
		got.binary != "https://example.invalid/bin?binary-token=one" ||
		got.signature != "https://signatures.invalid/bin.sig?signature-token=two" {
		t.Fatalf("two-URL file: got=%+v err=%v", got, err)
	}
	t.Run("two maximum length URLs", func(t *testing.T) {
		prefix := "https://example.invalid/"
		maxURL := prefix + strings.Repeat("a", 2048-len(prefix))
		path := write(t, maxURL+"\n"+maxURL+"\n", 0o600)
		got, err := readUpgradeURLFile(path)
		if err != nil || got.binary != maxURL || got.signature != maxURL {
			t.Fatalf("maximum URL file: got lengths=(%d,%d) err=%v",
				len(got.binary), len(got.signature), err)
		}
	})
	for name, path := range map[string]string{
		"relative path":  "relative-upgrade-url",
		"three lines":    write(t, "https://example.invalid/bin\nhttps://example.invalid/bin.sig\nhttps://example.invalid/extra\n", 0o600),
		"group readable": write(t, "https://example.invalid/bin\n", 0o640),
		"oversized":      write(t, strings.Repeat("x", int(maxUpgradeURLFileBytes)+1), 0o600),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readUpgradeURLFile(path); err == nil {
				t.Fatal("unsafe URL file unexpectedly accepted")
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("https://example.invalid/bin\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "upgrade-url")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readUpgradeURLFile(link); err == nil {
			t.Fatal("symlink URL file unexpectedly accepted")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upgrade-url")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readUpgradeURLFile(path); err == nil {
			t.Fatal("FIFO URL file unexpectedly accepted")
		}
	})
}

func TestUpgradeRejectsUnsafeURLBeforePromptOrDownload(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "http binary", content: "http://example.invalid/bin\n"},
		{name: "missing host", content: "https:///bin\n"},
		{name: "oversized binary", content: "https://example.invalid/" + strings.Repeat("a", 2048) + "\n"},
		{name: "http signature", content: "https://example.invalid/bin\nhttp://example.invalid/bin.sig\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "upgrade-url")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			a, out, errb := newTestApp(t, "YES\n")
			if rc := a.upgrade([]string{"--url-file", path}); rc != 1 {
				t.Fatalf("unsafe URL rc=%d, want 1", rc)
			}
			diagnostic := out.String() + errb.String()
			if strings.Contains(diagnostic, "type YES") || strings.Contains(diagnostic, "确认请输入 YES") {
				t.Fatalf("unsafe URL reached confirmation prompt: %q", diagnostic)
			}
		})
	}
}

func TestUpgradeURLFileUsesIndependentSignedURLs(t *testing.T) {
	const (
		binaryURL    = "https://binary.example.invalid/release?binary-token=one"
		signatureURL = "https://signature.example.invalid/release.sig?signature-token=two"
	)
	urlFile := filepath.Join(t.TempDir(), "upgrade-url")
	if err := os.WriteFile(urlFile, []byte(binaryURL+"\n"+signatureURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var requested []string
	m := &selfmanage.Manager{
		InstallPath: filepath.Join(t.TempDir(), "linux-temp-admin"),
		PublicKey:   make(ed25519.PublicKey, ed25519.PublicKeySize),
		MaxBytes:    1 << 20,
		RetryDelay:  time.Nanosecond,
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requested = append(requested, req.URL.String())
			if req.URL.String() == binaryURL {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("candidate")),
					Request:    req,
				}, nil
			}
			return nil, errors.New("injected signature fetch stop")
		})},
	}
	a, _, _ := newTestApp(t, "")
	a.Selfmanage = m
	if rc := a.upgrade([]string{"--url-file", urlFile, "--yes"}); rc != 1 {
		t.Fatalf("injected failed upgrade rc=%d, want 1", rc)
	}
	if len(requested) < 2 || requested[0] != binaryURL {
		t.Fatalf("binary request sequence = %q", requested)
	}
	for _, got := range requested[1:] {
		if got != signatureURL {
			t.Fatalf("derived or wrong signature URL requested: got %q want %q; all=%q", got, signatureURL, requested)
		}
	}
}

func TestUpgradePositionalArgumentDiagnosticDoesNotEchoSecret(t *testing.T) {
	const marker = "positional-query-secret-7d21"
	a, out, errb := newTestApp(t, "")
	if rc := a.upgrade([]string{"https://example.invalid/bin?token=" + marker}); rc != 1 {
		t.Fatalf("positional upgrade URL rc=%d, want 1", rc)
	}
	diagnostic := out.String() + errb.String()
	if !strings.Contains(diagnostic, "does not accept positional arguments") {
		t.Fatalf("generic positional diagnostic missing: %q", diagnostic)
	}
	if strings.Contains(diagnostic, marker) {
		t.Fatalf("positional diagnostic leaked secret: %q", diagnostic)
	}
}

func TestUpgradeURLSelectorsAreMutuallyExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade-url")
	if err := os.WriteFile(path, []byte("https://example.invalid/bin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, errb := newTestApp(t, "")
	if rc := a.upgrade([]string{"--url", "https://example.invalid/bin", "--url-file", path, "--yes"}); rc != 1 {
		t.Fatalf("mutually exclusive URL selectors rc=%d, want 1", rc)
	}
	if !strings.Contains(errb.String(), "mutually exclusive") {
		t.Fatalf("mutual-exclusion diagnostic missing: %q", errb.String())
	}
}

func TestUpgradePromptNamesOfficialMirrorAndTransportFallback(t *testing.T) {
	a, out, _ := newTestApp(t, "NO\n")
	if rc := a.upgrade(nil); rc != 0 {
		t.Fatalf("cancelled default upgrade rc=%d, want 0", rc)
	}
	if display := out.String(); !strings.Contains(display, config.ReleaseMirrorBaseURL) ||
		!strings.Contains(display, config.GitHubReleaseRoot) {
		t.Fatalf("default source and fallback were not shown: %q", display)
	}
}

// interactiveApp is a root App wired for the interactive planLogin branches: a
// TTY stdin fed from `in`, and an sshd effective config parsed from `sshdConf`.
func interactiveApp(t *testing.T, in, sshdConf string) (*App, *bytes.Buffer) {
	t.Helper()
	a, _, errb := newTestApp(t, in)
	a.StdinIsTTY = func() bool { return true }
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return sysinfo.ParseSSHD(sshdConf), nil }
	return a, errb
}

// TestPlanLoginOffersPasswordFallback covers the dead-end fix: a host that refuses
// keys but accepts passwords must, interactively, offer a password rather than
// leaving a menu-driven operator stranded.
func TestPlanLoginOffersPasswordFallback(t *testing.T) {
	// pubkey auth off (fixable), but the operator declines the sshd exception ("n"),
	// then accepts the password fallback ("y"). Passwords are on.
	const conf = "pubkeyauthentication no\npasswordauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
	a, _ := interactiveApp(t, "n\ny\n", conf)
	a.SSHD = &sshdconf.Manager{} // non-nil, so the exception path is offered first

	plan, ok := a.planLogin("xxvcc-a1", false, "ask", false)
	if !ok {
		t.Fatal("planLogin refused although a password fallback was available and accepted")
	}
	if !plan.password {
		t.Fatalf("expected a password plan, got %+v", plan)
	}
	if plan.fixSSHD {
		t.Error("declined exception must not still be planned")
	}
}

func TestPlanLoginRejectsTyposAtLoginChoicePrompts(t *testing.T) {
	const conf = "pubkeyauthentication no\npasswordauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
	a, errb := interactiveApp(t, "maybe\nn\nperhaps\ny\n", conf)
	a.SSHD = &sshdconf.Manager{}

	plan, ok := a.planLogin("xxvcc-a1", false, "ask", false)
	if !ok || !plan.password {
		t.Fatalf("planLogin after corrected answers = (%+v, %v), want password fallback", plan, ok)
	}
	if got := strings.Count(errb.String(), "enter y or n"); got != 2 {
		t.Fatalf("invalid login-choice answers produced %d validation messages, want 2: %q", got, errb.String())
	}
}

// TestPlanLoginPasswordFallbackDefaultsNo: the offer defaults to No, so a blank
// answer leaves the operator refused rather than silently issuing a password.
func TestPlanLoginPasswordFallbackDefaultsNo(t *testing.T) {
	const conf = "pubkeyauthentication no\npasswordauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
	a, _ := interactiveApp(t, "n\n\n", conf) // decline exception, then blank at the password offer
	a.SSHD = &sshdconf.Manager{}
	if _, ok := a.planLogin("xxvcc-a1", false, "ask", false); ok {
		t.Error("a blank answer must not opt into a password login")
	}
}

// TestPlanLoginNoPasswordFallbackWhenPasswordsOff: an explicit deny blocks
// passwords too, so no fallback is offered — the invite is simply refused.
func TestPlanLoginNoPasswordFallbackWhenPasswordsOff(t *testing.T) {
	const conf = "pubkeyauthentication yes\npasswordauthentication no\ndenyusers xxvcc-a1\n"
	a, errb := interactiveApp(t, "y\n", conf) // a "y" that must never be consumed
	if _, ok := a.planLogin("xxvcc-a1", false, "ask", false); ok {
		t.Error("must refuse: neither a key nor a password can work here")
	}
	if strings.Contains(errb.String(), "password login instead") {
		t.Error("must not offer a password when sshd would refuse one too")
	}
}

// TestPromptHours covers the new interactive lifetime prompt: a value is taken,
// a blank keeps the default, and an out-of-range entry is re-asked.
func TestPromptHours(t *testing.T) {
	if got := mustHours(t, "48\n", 24); got != 48 {
		t.Errorf("hours = %d, want 48", got)
	}
	if got := mustHours(t, "\n", 24); got != 24 {
		t.Errorf("blank hours = %d, want the default 24", got)
	}
	if got := mustHours(t, "0\n99999999\n72\n", 24); got != 72 {
		t.Errorf("hours after invalid entries = %d, want 72", got)
	}
	if got := mustHours(t, "", 24); got != 24 { // EOF settles on the default, never loops
		t.Errorf("EOF hours = %d, want 24", got)
	}
}

func TestPromptYesNoRejectsTypos(t *testing.T) {
	a, _, errb := newTestApp(t, "never\nmaybe\nn\n")
	a.StdinIsTTY = func() bool { return true }
	if answer, ok := a.promptYesNo("Auto-delete? [Y/n]: ", true); !ok || answer {
		t.Fatal("an eventual explicit no was not accepted")
	}
	if got := strings.Count(errb.String(), "enter y or n"); got != 2 {
		t.Fatalf("invalid answers produced %d validation messages, want 2: %q", got, errb.String())
	}
	a, _, _ = newTestApp(t, "\n")
	if answer, ok := a.promptYesNo("Auto-delete? [Y/n]: ", true); !ok || !answer {
		t.Fatal("blank answer did not accept the documented yes default")
	}
}

func TestPromptYesNoStopsAfterInvalidNonTTYInputAndEOF(t *testing.T) {
	a, _, errb := newTestApp(t, "maybe\nmaybe\n")
	if answer, ok := a.promptYesNo("Auto-delete? [Y/n]: ", true); ok || answer {
		t.Fatal("invalid non-TTY input must abort instead of selecting a default")
	}
	if got := strings.Count(errb.String(), "enter y or n"); got != 1 {
		t.Fatalf("invalid non-TTY input produced %d validation messages, want 1: %q", got, errb.String())
	}

	a, _, errb = newTestApp(t, "")
	if answer, ok := a.promptYesNo("Auto-delete? [Y/n]: ", true); ok || answer {
		t.Fatal("EOF must abort instead of selecting the yes default")
	}
	if !strings.Contains(errb.String(), "input ended; cancelled") {
		t.Fatalf("EOF cancellation was not reported: %q", errb.String())
	}
}

func TestClassifyRegisteredAccountIdentityStates(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	managed := user.Passwd{Name: "xxvcc-a1", UID: 1001, GID: 1001, GECOS: config.ManagedGenerationGECOSPrefix + generation, Home: "/home/xxvcc-a1", Shell: "/bin/sh"}
	legacy := user.Passwd{Name: "xxvcc-a1", UID: 1001, GID: 1001, GECOS: config.ManagedGECOS, Home: "/home/xxvcc-a1", Shell: "/bin/sh"}
	rootUID := managed
	rootUID.UID = 0
	rootGID := managed
	rootGID.GID = 0
	invalidGID := managed
	reservedKernelID := uint64(^uint32(0))
	invalidGID.GID = int(reservedKernelID)
	homeMismatch := managed
	homeMismatch.Home = "/srv/xxvcc-a1"
	tests := []struct {
		name   string
		rec    registry.Record
		pw     user.Passwd
		exists bool
		err    error
		want   registeredAccountState
	}{
		{name: "missing", want: registeredMissing},
		{name: "lookup error", err: errors.New("passwd unreadable"), want: registeredUnknown},
		{name: "pending", rec: registry.Record{UID: 1001, Generation: generation, IdentityBound: true, Pending: true}, pw: managed, exists: true, want: registeredPending},
		{name: "pending with root primary GID", rec: registry.Record{Generation: generation, IdentityBound: true, Pending: true}, pw: rootGID, exists: true, want: registeredIdentityUnverified},
		{name: "no trusted UID", rec: registry.Record{}, pw: managed, exists: true, want: registeredIdentityUnverified},
		{name: "root account UID", rec: registry.Record{UID: 1001}, pw: rootUID, exists: true, want: registeredIdentityUnverified},
		{name: "root primary GID", rec: registry.Record{UID: 1001}, pw: rootGID, exists: true, want: registeredIdentityUnverified},
		{name: "reserved kernel GID", rec: registry.Record{UID: 1001}, pw: invalidGID, exists: true, want: registeredIdentityUnverified},
		{name: "reserved recorded UID", rec: registry.Record{UID: int(reservedKernelID)}, pw: managed, exists: true, want: registeredIdentityUnverified},
		{name: "UID mismatch", rec: registry.Record{UID: 1002, Generation: generation, IdentityBound: true}, pw: managed, exists: true, want: registeredUIDMismatch},
		{name: "legacy", rec: registry.Record{UID: 1001}, pw: legacy, exists: true, want: registeredLegacyIdentity},
		{name: "marker mismatch", rec: registry.Record{UID: 1001, Generation: generation, IdentityBound: true}, pw: user.Passwd{UID: 1001, GID: 1001}, exists: true, want: registeredMarkerMismatch},
		{name: "generation mismatch", rec: registry.Record{UID: 1001, Generation: "fedcba9876543210fedcba9876543210", IdentityBound: true}, pw: managed, exists: true, want: registeredMarkerMismatch},
		{name: "home mismatch", rec: registry.Record{User: "xxvcc-a1", UID: 1001, Generation: generation, IdentityBound: true}, pw: homeMismatch, exists: true, want: registeredHomeMismatch},
		{name: "active", rec: registry.Record{User: "xxvcc-a1", UID: 1001, Generation: generation, IdentityBound: true}, pw: managed, exists: true, want: registeredActive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRegisteredAccount(tc.rec, tc.pw, tc.exists, tc.err); got != tc.want {
				t.Fatalf("state=%v, want %v", got, tc.want)
			}
		})
	}
}

func mustHours(t *testing.T, in string, def int) int {
	t.Helper()
	a, _, _ := newTestApp(t, in)
	return a.promptHours(def)
}

// TestPlanDepsRefusesBeforeSummaryAndInstallsAfter is a lightweight check that the
// dependency split reports missing deps read-only. With no package manager the
// plan must refuse (returns false), never claiming an install it cannot do.
func TestPlanDepsAllPresent(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	binDir := t.TempDir()
	for _, name := range []string{"id", "useradd", "usermod", "chage", "userdel"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)

	pkgs, ok := a.planDeps(false, false, false, false, true)
	if !ok || len(pkgs) != 0 {
		t.Errorf("planDeps = %v, %v; want nil,true when nothing is missing", pkgs, ok)
	}
}

func TestPlanDepsRefusesAutomaticPacmanPartialUpgrade(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pacman"), []byte("#!/bin/sh\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	pkgs, ok := a.planDeps(false, false, true, false, true)
	if ok || len(pkgs) != 0 {
		t.Fatalf("planDeps = %v, %v; want refusal on pacman", pkgs, ok)
	}
	got := errb.String()
	if !strings.Contains(got, "Arch does not support partial upgrades") ||
		!strings.Contains(got, "pacman -Syu --needed coreutils shadow") {
		t.Fatalf("pacman refusal did not explain the safe manual path: %q", got)
	}
}

func TestPlanDepsRequiresChpasswdOnlyForPasswordLogin(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	binDir := t.TempDir()
	for _, name := range []string{"id", "useradd", "usermod", "chage", "userdel"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)

	if pkgs, ok := a.planDeps(false, false, false, false, true); !ok || len(pkgs) != 0 {
		t.Fatalf("key-only planDeps = %v, %v; want nil,true", pkgs, ok)
	}
	if pkgs, ok := a.planDeps(false, true, false, false, true); ok || len(pkgs) != 0 {
		t.Fatalf("password planDeps = %v, %v; want pre-transaction refusal", pkgs, ok)
	}
	if got := errb.String(); !strings.Contains(got, "missing dependencies") || !strings.Contains(got, "chpasswd") {
		t.Fatalf("password dependency refusal did not name chpasswd: %q", got)
	}
}

// A generated username is chosen before dependency planning. If `id` itself is
// missing, that early step must still reach the dependency gate so --install-deps
// can repair the host; the authoritative NSS collision check runs later, after
// dependencies are installed and while the lifecycle lock is held.
func TestGeneratedInviteReachesDependencyGateWithoutID(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	t.Setenv("PATH", t.TempDir())

	rc := a.invite([]string{"--host", "192.0.2.1", "--no-sudo", "--no-auto-revoke", "--yes"})
	if rc != 1 {
		t.Fatalf("invite rc=%d, want the missing-dependency refusal", rc)
	}
	got := errb.String()
	if !strings.Contains(got, "missing dependencies") || !strings.Contains(got, "id") {
		t.Fatalf("invite did not reach the dependency gate without id: %q", got)
	}
	if strings.Contains(got, "NSS") {
		t.Fatalf("username selection tried NSS before id could be installed: %q", got)
	}
}

// TestInviteSkipsHoursPromptOnNonTTYStdin is the regression guard for the
// promptHours infinite-loop. promptHours re-asks on invalid input, so on a
// non-TTY stdin feeding non-numeric lines (the `yes n | lta invite` idiom, whose
// stream never blanks) it would spin forever. The hours prompt is therefore gated
// on StdinIsTTY. This asserts the gate directly — the lifetime question must never
// appear when stdin is not a terminal — which is deterministic, unlike trying to
// reproduce the spin with a necessarily-finite input.
func TestInviteSkipsHoursPromptOnNonTTYStdin(t *testing.T) {
	a, _, errb := newTestApp(t, "n\nn\nn\n")
	a.StdinIsTTY = func() bool { return false } // non-TTY stdin, TTY stdout (the default)
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	// --no-sudo/--no-auto-revoke suppress those prompts; the key verifies so
	// planLogin is silent; the confirmation reads "n" (not YES) and cancels before
	// any account is created. What matters is only that the hours prompt never ran.
	a.invite([]string{"--user", "xxvcc-a1", "--host", "1.2.3.4", "--no-sudo", "--no-auto-revoke"})
	for _, s := range []string{"有效期", "Lifetime in hours"} {
		if strings.Contains(errb.String(), s) {
			t.Errorf("hours prompt appeared on a non-TTY stdin (would spin on an unbounded stream):\n%s", errb.String())
		}
	}
}

// TestMenuDoesNotSpinOnNonTTYInvalidInput pins the L5 fix: menu() re-prompts on
// an invalid choice, and readLine only reports EOF, so an unbounded non-TTY
// stream of invalid lines used to pin a root process at 100% CPU. A
// non-interactive run must get one complaint and exit.
func TestMenuDoesNotSpinOnNonTTYInvalidInput(t *testing.T) {
	a, _, errb := newTestApp(t, "x\nx\nx\nx\n")
	a.StdinIsTTY = func() bool { return false }
	done := make(chan int, 1)
	go func() { done <- a.menu() }()
	select {
	case <-done:
		// exited — good
	case <-time.After(5 * time.Second):
		t.Fatal("menu() spun on a non-TTY stream of invalid input")
	}
	if strings.Count(errb.String(), "invalid choice") > 1 {
		t.Errorf("a non-interactive run should complain once, not loop:\n%s", errb.String())
	}
}

// TestResolveLangPrecedence pins the language rules: --lang beats the env
// override, which beats the remembered preference, and the host's locale is not
// consulted at all — a server with LANG=en_US must not override the tool's own
// default, which is what used to force operators to discover --lang.
func TestResolveLangPrecedence(t *testing.T) {
	// Point the prefs file at a temp path so the test cannot read or write the
	// real one.
	dir := t.TempDir()
	old := prefs.File
	prefs.File = filepath.Join(dir, "prefs")
	t.Cleanup(func() { prefs.File = old })

	// An English locale must be ignored entirely.
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("LC_ALL", "en_US.UTF-8")

	// Nothing set anywhere, nothing remembered, and no TTY to ask at -> Chinese.
	if got := resolveLang("", "", nil); got != i18n.ZH {
		t.Errorf("no flag/env/pref on an en_US host = %q, want zh (locale must not win)", got)
	}
	// The remembered preference is used when there is no flag or env.
	if err := prefs.SetLang("en"); err != nil {
		t.Skipf("cannot write prefs here: %v", err)
	}
	if got := resolveLang("", "", nil); got != i18n.EN {
		t.Errorf("remembered preference = %q, want en", got)
	}
	// The env override beats the remembered preference...
	if got := resolveLang("", "zh", nil); got != i18n.ZH {
		t.Errorf("env over pref = %q, want zh", got)
	}
	// ...and an explicit flag beats everything.
	if got := resolveLang("zh", "en", nil); got != i18n.ZH {
		t.Errorf("flag over env = %q, want zh", got)
	}
}

// TestAskLangSkipsUnattendedRuns: a --yes run said "do not ask me anything", and
// a non-TTY run has nobody to ask. Neither may be stopped by the question.
func TestAskLangSkipsUnattendedRuns(t *testing.T) {
	// stdin here is not a terminal, which alone is enough to skip.
	if _, ok, prompted := askLang(nil); ok || prompted {
		t.Error("askLang must not prompt without a terminal")
	}
	if _, ok, prompted := askLang([]string{"invite", "--yes"}); ok || prompted {
		t.Error("askLang must not prompt during a --yes run")
	}
}

func TestResolveLangPromptEOFAbortsInteractiveRun(t *testing.T) {
	dir := t.TempDir()
	old := prefs.File
	prefs.File = filepath.Join(dir, "prefs")
	t.Cleanup(func() { prefs.File = old })

	lang, remember, proceed := resolveLangChoiceWith("", "", nil,
		func([]string) (i18n.Lang, bool, bool) { return "", false, true })
	if lang != i18n.ZH || remember || proceed {
		t.Fatalf("language prompt EOF = (%q, remember=%v, proceed=%v), want (zh, false, false)", lang, remember, proceed)
	}
}

func TestShouldAskLangSkipsInviteThatCannotSafelyPrintCredential(t *testing.T) {
	if shouldAskLang([]string{"invite"}, true, true, false) {
		t.Fatal("invite with redirected stdout must reach its refusal without a language prompt")
	}
	if !shouldAskLang([]string{"invite", "--allow-non-tty-private-key-output"}, true, true, false) {
		t.Fatal("the explicit non-TTY credential-output override should permit the language prompt")
	}
	if !shouldAskLang(nil, true, true, false) {
		t.Fatal("a redirected menu is not a credential-output refusal and may still ask")
	}
	if shouldAskLang([]string{"invite"}, false, true, true) {
		t.Fatal("non-TTY stdin must never be prompted")
	}
}

func TestAskLangInputValidatesAndPreservesBufferedAnswers(t *testing.T) {
	var out bytes.Buffer
	lang, ok := askLangInput(strings.NewReader("9\nwrong\n2\n"), &out)
	if !ok || lang != i18n.EN {
		t.Fatalf("askLangInput = (%q, %v), want (en, true)", lang, ok)
	}
	if got := strings.Count(out.String(), "选择 / select [1-2]"); got != 3 {
		t.Errorf("prompt count = %d, want 3:\n%s", got, out.String())
	}
	if got := strings.Count(out.String(), "invalid choice"); got != 2 {
		t.Errorf("invalid warning count = %d, want 2:\n%s", got, out.String())
	}
}

func TestAskLangInputRejectsOversizedLineAndKeepsNextAnswer(t *testing.T) {
	var out bytes.Buffer
	input := strings.Repeat("9", maxInteractiveLineBytes+1) + "\n2\n"
	lang, ok := askLangInput(strings.NewReader(input), &out)
	if !ok || lang != i18n.EN {
		t.Fatalf("askLangInput after oversized line = (%q, %v), want (en, true)", lang, ok)
	}
	if !strings.Contains(out.String(), "input is too long") {
		t.Fatalf("oversized language input warning missing: %q", out.String())
	}
}

func TestAskLangInputDefaultsAndEOF(t *testing.T) {
	tests := []struct {
		name string
		in   string
		lang i18n.Lang
		ok   bool
	}{
		{name: "blank default", in: "\n", lang: i18n.ZH, ok: true},
		{name: "explicit Chinese", in: "1\n", lang: i18n.ZH, ok: true},
		{name: "English at EOF", in: "2", lang: i18n.EN, ok: true},
		{name: "empty EOF", in: "", ok: false},
		{name: "invalid EOF", in: "wrong", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			lang, ok := askLangInput(strings.NewReader(tc.in), &out)
			if lang != tc.lang || ok != tc.ok {
				t.Errorf("askLangInput(%q) = (%q, %v), want (%q, %v)", tc.in, lang, ok, tc.lang, tc.ok)
			}
		})
	}
}
