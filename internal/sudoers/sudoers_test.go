package sudoers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
)

func writeSudoersCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestAllPropagatesDirectoryReadFailure(t *testing.T) {
	old := readManagedDir
	readManagedDir = func(string) ([]os.DirEntry, error) {
		return nil, errors.New("injected directory I/O failure")
	}
	t.Cleanup(func() { readManagedDir = old })

	if _, err := (&Manager{Dir: t.TempDir()}).All(); err == nil || !strings.Contains(err.Error(), "injected directory I/O failure") {
		t.Fatalf("All error = %v, want directory failure", err)
	}
}

func TestAllRejectsSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Manager{Dir: link}).All(); err == nil {
		t.Fatal("All followed a symlinked sudoers directory")
	}
}

func TestAllAllowsAbsentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	users, err := (&Manager{Dir: dir}).All()
	if err != nil || len(users) != 0 {
		t.Fatalf("All on absent directory = %v, %v; want empty success", users, err)
	}
}

func TestAllRejectsMalformedManagedArtifact(t *testing.T) {
	dir := t.TempDir()
	name := filePrefix + "not.valid"
	if err := os.WriteFile(filepath.Join(dir, name), nil, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Manager{Dir: dir}).All(); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("All error = %v, want malformed managed artifact", err)
	}
}

func TestSudoersProbesAreBoundedAndUseCLocale(t *testing.T) {
	old := sudoProbeOptions
	oldNSSwitchPath := nsswitchConfigPath
	nsswitchConfigPath = filepath.Join(t.TempDir(), "absent-nsswitch.conf")
	t.Cleanup(func() {
		sudoProbeOptions = old
		nsswitchConfigPath = oldNSSwitchPath
	})

	t.Run("visudo locale", func(t *testing.T) {
		sudoProbeOptions = old
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "visudo", `[ "$LC_ALL:$LANG:$1:$2" = "C:C:-cf:-" ]`)
		t.Setenv("PATH", dir)
		if err := visudoValidate([]byte("alice ALL=(ALL) NOPASSWD:ALL\n")); err != nil {
			t.Fatalf("visudoValidate did not force the C locale: %v", err)
		}
	})

	t.Run("missing visudo fails closed", func(t *testing.T) {
		sudoProbeOptions = old
		t.Setenv("PATH", t.TempDir())
		if err := visudoValidate([]byte("alice ALL=(ALL) NOPASSWD:ALL\n")); err == nil || !strings.Contains(err.Error(), "visudo is required") {
			t.Fatalf("visudoValidate with no visudo = %v, want fail-closed error", err)
		}
	})

	t.Run("sudo locale and argv", func(t *testing.T) {
		sudoProbeOptions = old
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "sudo", `[ "$LC_ALL:$LANG:$1:$2:$3:$4" = "C:C:-n:-l:-U:alice" ] || exit 9
printf '    (root) NOPASSWD: ALL\n'`)
		t.Setenv("PATH", dir)
		if err := verifyNopasswd("alice"); err != nil {
			t.Fatalf("verifyNopasswd did not force the C locale/expected argv: %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "sudo", `/bin/sleep 30 & wait`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = 50 * time.Millisecond
		sudoProbeOptions = opts
		if err := verifyNopasswd("alice"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("verifyNopasswd error = %v, want timeout", err)
		}
	})

	t.Run("output limit", func(t *testing.T) {
		dir := t.TempDir()
		writeSudoersCommand(t, dir, "visudo", `while :; do printf 0123456789abcdef; done`)
		t.Setenv("PATH", dir)
		opts := old
		opts.Timeout = time.Second
		opts.MaxOutput = 64
		sudoProbeOptions = opts
		if err := visudoValidate([]byte("alice ALL=(ALL) NOPASSWD:ALL\n")); !errors.Is(err, executil.ErrOutputLimit) {
			t.Fatalf("visudoValidate error = %v, want output limit", err)
		}
	})
}

func TestRequireReachableFilesSource(t *testing.T) {
	tests := []struct {
		name string
		spec string
		ok   bool
	}{
		{name: "files only", spec: "files", ok: true},
		{name: "files first", spec: "files sss [SUCCESS=return]", ok: true},
		{name: "case insensitive sources", spec: "SSS FILES", ok: true},
		{name: "sources continue by default", spec: "sss ldap files", ok: true},
		{name: "generic continue token is ignored", spec: "sss [SUCCESS=continue] files", ok: true},
		{name: "unknown token detaches control", spec: "sss unknown [SUCCESS=return] files", ok: true},
		{name: "duplicate source detaches control", spec: "sss sss [SUCCESS=return] files", ok: true},
		{name: "only immediate first control applies", spec: "sss [SUCCESS=continue] [SUCCESS=return] files", ok: true},
		{name: "no recognized source defaults to files", spec: "compat nis", ok: true},
		{name: "empty defaults to files", spec: "", ok: true},
		{name: "carriage return is not token whitespace", spec: "files\r sss [SUCCESS=return]", ok: false},
		{name: "unicode space is not token whitespace", spec: "files\u00a0x sss [SUCCESS=return]", ok: false},
		{name: "unicode case fold is not C locale case fold", spec: "f\u0130les sss [SUCCESS=return]", ok: false},
		{name: "explicit success return", spec: "sss [SUCCESS=return] files", ok: false},
		{name: "case insensitive success return", spec: "SSS [success=return] files", ok: false},
		{name: "explicit notfound return", spec: "ldap [NOTFOUND=return] files", ok: false},
		{name: "recognized source without files", spec: "sss", ok: false},
		{name: "stopping second source", spec: "sss ldap [SUCCESS=return] files", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireReachableFilesSource(tt.spec)
			if tt.ok && err != nil {
				t.Fatalf("requireReachableFilesSource(%q) = %v, want success", tt.spec, err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("requireReachableFilesSource(%q) succeeded, want fail-closed error", tt.spec)
			}
		})
	}
}

func TestSudoersSourceSpecUsesFirstDatabaseLine(t *testing.T) {
	tests := []struct {
		name    string
		content string
		ok      bool
	}{
		{name: "database absent defaults to files", content: "passwd: files\ngroup: files\n", ok: true},
		{name: "files source", content: "sudoers: files\n", ok: true},
		{name: "CRLF files source", content: "sudoers: files\r\n", ok: true},
		{name: "CRLF non-files source", content: "sudoers: sss\r\n", ok: false},
		{name: "case insensitive database and comment", content: "SuDoErS: sss files # local fallback\n", ok: true},
		{name: "dangerous success return", content: "sudoers: sss [SUCCESS=return] files\n", ok: false},
		{name: "dangerous notfound return", content: "sudoers: sss [NOTFOUND=return] files\n", ok: false},
		{name: "sources continue by default", content: "sudoers: sss files\n", ok: true},
		{name: "files missing", content: "sudoers: sss\n", ok: false},
		{name: "first sudoers line wins", content: "sudoers: sss [SUCCESS=return] files\nsudoers: files\n", ok: false},
		{name: "safe first sudoers line wins", content: "sudoers: files\nsudoers: sss [SUCCESS=return] files\n", ok: true},
		{name: "unicode leading space does not expose database name", content: "\u00a0sudoers: files\nsudoers: sss [SUCCESS=return] files\n", ok: false},
		{name: "colon must be attached", content: "sudoers : sss [SUCCESS=return] files\n", ok: true},
		{name: "malformed database line defaults to files", content: "sudoers files\n", ok: true},
		{name: "continuation is rejected", content: "sudoers: unknown \\\nsss [SUCCESS=return] files\n", ok: false},
		{name: "continued database name is rejected", content: "sudoers\\\n: sss [SUCCESS=return] files\n", ok: false},
		{name: "NUL is rejected", content: "sudoers: sss\x00 ignored [SUCCESS=return] files\n", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, found, err := sudoersSourceSpec([]byte(tt.content))
			if err == nil && found {
				err = requireReachableFilesSource(spec)
			}
			if tt.ok && err != nil {
				t.Fatalf("sudoers source proof = %v, want success", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("sudoers source proof succeeded, want fail-closed error")
			}
		})
	}

	t.Run("secure root-owned config is read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nsswitch.conf")
		if err := os.WriteFile(path, []byte("sudoers: files\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := verifyFilesSudoersSource(path)
		if os.Geteuid() == 0 && err != nil {
			t.Fatalf("root-owned nsswitch.conf = %v, want success", err)
		}
		if os.Geteuid() != 0 && (err == nil || !strings.Contains(err.Error(), "root-owned")) {
			t.Fatalf("non-root-owned nsswitch.conf error = %v, want ownership refusal", err)
		}
	})

	t.Run("missing config defaults to files", func(t *testing.T) {
		if err := verifyFilesSudoersSource(filepath.Join(t.TempDir(), "absent")); err != nil {
			t.Fatalf("missing nsswitch.conf = %v, want local-files default", err)
		}
	})

	t.Run("symlink is rejected", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("sudoers: files\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "nsswitch.conf")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := verifyFilesSudoersSource(link); err == nil {
			t.Fatal("verifyFilesSudoersSource followed a symlink")
		}
	})

	t.Run("oversized config is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nsswitch.conf")
		content := strings.Repeat("#", int(maxNSSwitchConfigBytes)+1)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyFilesSudoersSource(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("oversized nsswitch.conf error = %v, want bounded-read refusal", err)
		}
	})

	t.Run("writable config is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nsswitch.conf")
		if err := os.WriteFile(path, []byte("sudoers: files\n"), 0o622); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o622); err != nil {
			t.Fatal(err)
		}
		if err := verifyFilesSudoersSource(path); err == nil || !strings.Contains(err.Error(), "group/other-writable") {
			t.Fatalf("writable nsswitch.conf error = %v, want mode refusal", err)
		}
	})

	t.Run("non-root owner is rejected", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires root to assign a non-root owner")
		}
		path := filepath.Join(t.TempDir(), "nsswitch.conf")
		if err := os.WriteFile(path, []byte("sudoers: files\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 1, -1); err != nil {
			t.Fatal(err)
		}
		if err := verifyFilesSudoersSource(path); err == nil || !strings.Contains(err.Error(), "root-owned") {
			t.Fatalf("non-root-owned nsswitch.conf error = %v, want ownership refusal", err)
		}
	})
}

func TestVerifyNopasswdRejectsNSSListingFalsePositiveBeforeCallingSudo(t *testing.T) {
	oldReader := readSudoersNSSConfig
	readSudoersNSSConfig = func(string) (string, bool, error) {
		return "sss [SUCCESS=return] files", true, nil
	}
	t.Cleanup(func() { readSudoersNSSConfig = oldReader })

	dir := t.TempDir()
	called := filepath.Join(dir, "sudo-called")
	writeSudoersCommand(t, dir, "sudo", "/usr/bin/touch '"+called+"'\nprintf '    (root) PASSWD: ALL\\n    (root) NOPASSWD: ALL\\n'")
	t.Setenv("PATH", dir)

	err := verifyNopasswd("alice")
	if err == nil || !strings.Contains(err.Error(), "source \"sss\" before files can stop") {
		t.Fatalf("verifyNopasswd error = %v, want unsafe NSS source refusal", err)
	}
	if _, statErr := os.Stat(called); !os.IsNotExist(statErr) {
		t.Fatalf("sudo was called despite unsafe NSS order: %v", statErr)
	}
}

func TestGrantFailsClosedWithoutValidationOrPolicyVerification(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *Manager
		want string
	}{
		{name: "validator", m: &Manager{Dir: t.TempDir()}, want: "validator is not configured"},
		{name: "verifier", m: &Manager{Dir: t.TempDir(), Validate: func([]byte) error { return nil }}, want: "verifier is not configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.m.Grant("xxvcc-a1"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Grant without %s = %v, want fail-closed error", tc.name, err)
			}
			if _, err := os.Lstat(tc.m.FilePath("xxvcc-a1")); !os.IsNotExist(err) {
				t.Fatalf("Grant without %s wrote a live policy: %v", tc.name, err)
			}
		})
	}
}

func TestRemoveUsesInjectedRemoveFile(t *testing.T) {
	wantErr := errors.New("injected remove failure")
	var removed string
	m := &Manager{
		Dir: t.TempDir(),
		RemoveFile: func(path string) error {
			removed = path
			return wantErr
		},
	}

	err := m.Remove("xxvcc-a1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Remove error = %v, want injected failure", err)
	}
	if removed != m.FilePath("xxvcc-a1") {
		t.Fatalf("removed path = %q, want %q", removed, m.FilePath("xxvcc-a1"))
	}
}

func TestRemoveRejectsInvalidUsernameBeforePathResolution(t *testing.T) {
	const malicious = "x/../../linux-temp-admin-target"

	t.Run("injected remover is not called", func(t *testing.T) {
		called := false
		m := &Manager{
			Dir: t.TempDir(),
			RemoveFile: func(string) error {
				called = true
				return nil
			},
		}
		if err := m.Remove(malicious); err == nil || !strings.Contains(err.Error(), "invalid username") {
			t.Fatalf("Remove error = %v, want invalid username refusal", err)
		}
		if called {
			t.Fatal("RemoveFile was called for an invalid username")
		}
	})

	t.Run("file outside sudoers directory survives", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "sudoers")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(root, "linux-temp-admin-target")
		if err := os.WriteFile(sentinel, []byte("keep\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := (&Manager{Dir: dir}).Remove(malicious); err == nil {
			t.Fatal("Remove accepted a path-traversal username")
		}
		if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep\n" {
			t.Fatalf("outside sentinel changed: content=%q err=%v", got, err)
		}
	})
}

func TestVerifyNopasswdOutputRequiresRootNopasswdAll(t *testing.T) {
	tests := []struct {
		name string
		out  string
		ok   bool
	}{
		{"root", "User alice may run the following commands:\n    (root) NOPASSWD: ALL\n", true},
		{"numeric root", "    (#0) NOPASSWD: ALL\n", true},
		{"all runas", "    (ALL : ALL) NOPASSWD: ALL\n", true},
		{"all except root", "    (ALL, !root) NOPASSWD: ALL\n", false},
		{"root exclusion before all", "    (!root, ALL) NOPASSWD: ALL\n", false},
		{"negated all", "    (root, !ALL) NOPASSWD: ALL\n", false},
		{"non-root runas", "    (daemon) NOPASSWD: ALL\n", false},
		{"restricted command", "    (root) NOPASSWD: /usr/bin/id\n", false},
		{"password required", "    (root) PASSWD: ALL\n", false},
		{"unrelated nopasswd", "    (daemon) NOPASSWD: /bin/true\n    (root) PASSWD: ALL\n", false},
		{"tag changes before all", "    (root) NOPASSWD: /bin/true, PASSWD: ALL\n", false},
		{"later passwd all overrides", "    (root) NOPASSWD: ALL\n    (root) PASSWD: ALL\n", false},
		{"later all-runas passwd all overrides", "    (root) NOPASSWD: ALL\n    (ALL) PASSWD: ALL\n", false},
		{"later root-applicable exclusion is globally ambiguous", "    (root) NOPASSWD: ALL\n    (ALL, !daemon) PASSWD: ALL\n", false},
		{"restricted root-applicable exclusion is globally ambiguous", "    (root) NOPASSWD: ALL\n    (ALL, !daemon) PASSWD: /bin/true\n    (root) NOPASSWD: ALL\n", false},
		{"later restricted passwd invalidates full grant", "    (root) NOPASSWD: ALL\n    (root) PASSWD: /bin/true\n", false},
		{"numeric root restricted passwd invalidates full grant", "    (root) NOPASSWD: ALL\n    (#0) PASSWD: /bin/true\n", false},
		{"later command-list passwd all invalidates full grant", "    (root) NOPASSWD: ALL\n    (root) NOPASSWD: /bin/false, PASSWD: ALL\n", false},
		{"exact later grant restores after command list", "    (root) NOPASSWD: ALL\n    (root) PASSWD: /bin/true\n    (root) NOPASSWD: ALL\n", true},
		{"later nopasswd all restores", "    (root) PASSWD: ALL\n    (root) NOPASSWD: ALL\n", true},
		{"later non-root rule does not override", "    (root) NOPASSWD: ALL\n    (daemon) PASSWD: ALL\n", true},
		{"later non-root uid rule does not override", "    (root) NOPASSWD: ALL\n    (#1) PASSWD: ALL\n", true},
		{"dynamic group is ambiguous", "    (root) NOPASSWD: ALL\n    (%wheel) PASSWD: /bin/true\n", false},
		{"netgroup is ambiguous", "    (root) NOPASSWD: ALL\n    (+operators) PASSWD: /bin/true\n", false},
		{"user alias is ambiguous", "    (root) NOPASSWD: ALL\n    (OPERATORS) PASSWD: /bin/true\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyNopasswdOutput([]byte(tt.out))
			if tt.ok && err != nil {
				t.Fatalf("verifyNopasswdOutput rejected full grant: %v", err)
			}
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "root NOPASSWD: ALL")) {
				t.Fatalf("verifyNopasswdOutput error = %v, want precise refusal", err)
			}
		})
	}
}

func TestRunasRootScopeFailsClosedOnDynamicOrNegatedEntries(t *testing.T) {
	tests := []struct {
		name  string
		runas string
		want  rootRunasScope
	}{
		{name: "root", runas: "root", want: runasRootIncluded},
		{name: "numeric root", runas: "#0", want: runasRootIncluded},
		{name: "numeric root with leading zeroes", runas: "#000", want: runasRootIncluded},
		{name: "all users", runas: "ALL : ALL", want: runasRootIncluded},
		{name: "mixed literal users", runas: "daemon, root", want: runasRootIncluded},
		{name: "non-root user", runas: "daemon", want: runasRootExcluded},
		{name: "non-root uid", runas: "#1", want: runasRootExcluded},
		{name: "root exclusion", runas: "ALL, !root", want: runasRootAmbiguous},
		{name: "leading exclusion", runas: "!root, ALL", want: runasRootAmbiguous},
		{name: "all exclusion", runas: "root, !ALL", want: runasRootAmbiguous},
		{name: "other exclusion", runas: "ALL, !daemon", want: runasRootAmbiguous},
		{name: "unix group", runas: "%wheel", want: runasRootAmbiguous},
		{name: "netgroup", runas: "+operators", want: runasRootAmbiguous},
		{name: "user alias", runas: "OPERATORS", want: runasRootAmbiguous},
		{name: "malformed uid", runas: "#root", want: runasRootAmbiguous},
		{name: "empty user list", runas: ": wheel", want: runasRootAmbiguous},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runasRootScope(tt.runas); got != tt.want {
				t.Fatalf("runasRootScope(%q) = %d, want %d", tt.runas, got, tt.want)
			}
		})
	}
}

// TestOrphansFindsGrantsWhoseAccountIsGone pins the M1 fix. An orphaned
// NOPASSWD:ALL drop-in is the most dangerous leftover this tool can produce — it
// re-arms full root the instant its username is reused — so it must be findable.
func TestOrphansFindsGrantsWhoseAccountIsGone(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		filePrefix + "xxvcc-gone",  // ours, account deleted -> orphan
		filePrefix + "xxvcc-alive", // ours, account exists -> not an orphan
		"90-someone-elses-file",    // not ours: never report or remove it
		"foreign-valid-user",       // valid username, but still not our namespace
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x ALL=(ALL) NOPASSWD:ALL\n"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{Dir: dir}
	orphans, err := m.Orphans(func(u string) (bool, error) { return u == "xxvcc-alive", nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 1 || orphans[0] != "xxvcc-gone" {
		t.Fatalf("orphans = %v, want exactly [xxvcc-gone]", orphans)
	}
}

// TestRemoveOnlyTouchesItsOwnFile: the sweep removes by username, so it must
// never reach a file this tool did not write.
func TestRemoveOnlyTouchesItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "90-someone-elses-file")
	if err := os.WriteFile(foreign, []byte("x\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	ours := filepath.Join(dir, filePrefix+"xxvcc-a1")
	if err := os.WriteFile(ours, []byte("x\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: dir}
	m.Remove("xxvcc-a1")
	if _, err := os.Lstat(ours); !os.IsNotExist(err) {
		t.Error("our own drop-in should be gone")
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Error("a file this tool does not own must survive")
	}
}
