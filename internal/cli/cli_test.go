package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/prefs"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
)

type failingScheduleSystem struct{}

func (failingScheduleSystem) HasSystemctl() bool                     { return false }
func (failingScheduleSystem) Systemctl(...string) error              { return nil }
func (failingScheduleSystem) HasAt() bool                            { return true }
func (failingScheduleSystem) ScheduleAt(string, int) (string, error) { return "", nil }
func (failingScheduleSystem) RemoveAtJobsFor(string) error           { return nil }
func (failingScheduleSystem) AtrmJob(string) error                   { return nil }
func (failingScheduleSystem) AtJobs() ([]schedule.AtJob, error) {
	return nil, errors.New("at queue unreadable")
}

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
		P:           i18n.Printer{Lang: i18n.EN},
		Registry:    &registry.Store{Dir: dir, File: filepath.Join(dir, "r.tsv"), Lock: filepath.Join(dir, "r.lock")},
		InstallPath: filepath.Join(dir, "lta"),
		Now:         func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) },
		RandHex:     func(int) (string, error) { return "abcdef0123", nil },
		StdoutIsTTY: func() bool { return true },
		StdinIsTTY:  func() bool { return false },
		Geteuid:     func() int { return 0 },
	}
	return a, &out, &errb
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
	// The account tools exist on this test host, so nothing is missing and no
	// package list is produced.
	pkgs, ok := a.planDeps(false, false, false, true)
	if !ok || len(pkgs) != 0 {
		t.Errorf("planDeps = %v, %v; want nil,true when nothing is missing", pkgs, ok)
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
	if _, ok := askLang(nil); ok {
		t.Error("askLang must not prompt without a terminal")
	}
	if _, ok := askLang([]string{"invite", "--yes"}); ok {
		t.Error("askLang must not prompt during a --yes run")
	}
}
