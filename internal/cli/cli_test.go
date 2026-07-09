package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
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
	if rc := a.Dispatch([]string{"version"}); rc != 0 || !strings.Contains(out.String(), "2.0.0") {
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
	// "3" is status: it prints, and prints nothing that looks like the menu.
	a, out, _ := newTestApp(t, "3\n"+exit+"\n")
	if rc := a.menu(); rc != 0 {
		t.Fatalf("menu rc=%d", rc)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "Registered temporary users") {
		t.Fatalf("choice 3 did not run status: %q", rendered)
	}
	if n := strings.Count(rendered, menuTitleEN); n != 1 {
		t.Errorf("menu redrawn after an action: title drawn %d times, want 1:\n%s", n, rendered)
	}
	// The result must come after the menu, with nothing of the menu after it.
	if strings.Index(rendered, "Registered temporary users") < strings.Index(rendered, menuTitleEN) {
		t.Error("status output should follow the menu, not precede it")
	}

	// An explicit blank line still brings the menu back.
	a2, out2, _ := newTestApp(t, "3\n\n"+exit+"\n")
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

// TestMenuChoiceOutOfRange covers the digits either side of the table.
func TestMenuChoiceOutOfRange(t *testing.T) {
	last := len(menuItems)
	a, _, errb := newTestApp(t, fmt.Sprintf("0\n%d\n%d\n", last+1, last))
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
	}
	for _, c := range cases {
		a, _, errb := newTestApp(t, "")
		if rc := a.invite(c.args); rc != 1 {
			t.Errorf("%s: rc=%d, want 1 (stderr: %s)", c.name, rc, errb.String())
		}
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
