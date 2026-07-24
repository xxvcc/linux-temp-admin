package sshdconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
)

const acct = "xxvcc-a1b2c3"

// report builds a LoginReport carrying exactly the given blockers, the way
// CheckKeyLogin would.
func report(config string) sysinfo.LoginReport {
	return sysinfo.CheckKeyLogin(sysinfo.ParseSSHD(config), acct, []string{acct})
}

func TestDropInIsScopedToTheAccount(t *testing.T) {
	body, err := dropIn(acct, []string{acct}, report("pubkeyauthentication no\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "Match User "+acct+"\n") {
		t.Errorf("no Match block for the account:\n%s", got)
	}
	// Every directive must sit inside the Match block. A single line above it
	// would silently become global policy for every account on the host -- the one
	// outcome this whole design exists to prevent.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	seenMatch := false
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "#"):
		case strings.HasPrefix(ln, "Match "):
			seenMatch = true
		case strings.TrimSpace(ln) == "":
		default:
			if !seenMatch {
				t.Errorf("directive outside the Match block (it would be global): %q", ln)
			}
			if !strings.HasPrefix(ln, "    ") {
				t.Errorf("directive is not indented into the Match block: %q", ln)
			}
		}
	}
}

func TestDropInLiftsOnlyWhatBlocks(t *testing.T) {
	tests := []struct {
		name   string
		config string
		groups []string
		want   []string
		absent []string
	}{
		{
			name:   "only the pubkey switch",
			config: "pubkeyauthentication no\n",
			want:   []string{"PubkeyAuthentication yes"},
			// Nothing was wrong with the key file's location, so the drop-in must not
			// pin it: an operator reading this file should see only what it had to fix.
			absent: []string{"AuthorizedKeysFile", "AuthenticationMethods", "AllowUsers", "AllowGroups"},
		},
		{
			name:   "a redirected authorized_keys",
			config: "pubkeyauthentication yes\nauthorizedkeysfile /etc/ssh/keys/%u\n",
			want:   []string{"AuthorizedKeysFile .ssh/authorized_keys"},
			absent: []string{"PubkeyAuthentication"},
		},
		{
			name:   "a second factor the locked account can never supply",
			config: "pubkeyauthentication yes\nauthenticationmethods publickey,password\n",
			want:   []string{"AuthenticationMethods publickey"},
		},
		{
			// NEVER `+ssh-ed25519`: OpenSSH's leading `+` appends to its COMPILED-IN
			// default set, not to the operator's list, and a Match block does not
			// inherit the global value. On the only hosts where this fires -- the ones
			// that deliberately narrowed the algorithm set -- `+` would hand the account
			// sshd's whole default set. Re-state the effective list and append ed25519.
			name:   "a crypto policy without ed25519",
			config: "pubkeyauthentication yes\npubkeyacceptedalgorithms rsa-sha2-512\n",
			want:   []string{"PubkeyAcceptedAlgorithms rsa-sha2-512,ssh-ed25519"},
			absent: []string{"+ssh-ed25519"},
		},
		{
			// sshd renamed the directive in 8.5; the 8.5 spelling is a fatal
			// "Bad configuration option" on the 8.2/8.4 releases that still support
			// Include. Write back the name this host's own sshd used.
			name:   "a pre-8.5 sshd's spelling of the same directive",
			config: "pubkeyauthentication yes\npubkeyacceptedkeytypes rsa-sha2-512\n",
			want:   []string{"PubkeyAcceptedKeyTypes rsa-sha2-512,ssh-ed25519"},
			absent: []string{"PubkeyAcceptedAlgorithms"},
		},
		{
			name:   "a user whitelist",
			config: "pubkeyauthentication yes\nallowusers alice\n",
			want:   []string{"AllowUsers " + acct},
		},
		{
			// The whitelist is satisfied by naming the account's own primary group,
			// never by adding it to one of the admin's existing groups -- that would
			// hand it whatever else that group carries.
			name:   "a group whitelist",
			config: "pubkeyauthentication yes\nallowgroups wheel\n",
			groups: []string{acct, "extra"},
			want:   []string{"AllowGroups " + acct},
			absent: []string{"wheel"},
		},
		{
			name:   "everything at once",
			config: "pubkeyauthentication no\nauthorizedkeysfile none\nauthenticationmethods publickey,password\nallowusers alice\n",
			want: []string{"PubkeyAuthentication yes", "AuthorizedKeysFile .ssh/authorized_keys",
				"AuthenticationMethods publickey", "AllowUsers " + acct},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			groups := tc.groups
			if groups == nil {
				groups = []string{acct}
			}
			body, err := dropIn(acct, groups, report(tc.config))
			if err != nil {
				t.Fatal(err)
			}
			got := string(body)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("drop-in missing %q:\n%s", w, got)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(got, a) {
					t.Errorf("drop-in carries %q, which nothing was blocking on:\n%s", a, got)
				}
			}
		})
	}
}

func TestGrantRefusesWhatItCannotFix(t *testing.T) {
	m := &Manager{Dir: t.TempDir()}
	// An explicit deny is a decision, not an omission. Writing a Match block would
	// not lift it anyway, so the grant must refuse rather than leave a useless
	// file behind and print an invite that cannot be used.
	rep := report("pubkeyauthentication yes\ndenyusers " + acct + "\n")
	if _, err := m.Grant(acct, []string{acct}, rep); err == nil {
		t.Fatal("Grant must refuse a policy it cannot lift for one account")
	}
	if _, err := m.Grant(acct, []string{acct}, report("pubkeyauthentication yes\n")); err == nil {
		t.Error("Grant must refuse when nothing is blocking: it would write a pointless file")
	}
}

func TestGrantAndRemoveRefuseInvalidNames(t *testing.T) {
	m := &Manager{Dir: t.TempDir()}
	// Defense in depth: a name that escaped validation must never reach a
	// `Match User` line or a file path.
	for _, bad := range []string{"root; rm -rf /", "../../etc/passwd", "a b", ""} {
		if _, err := m.Grant(bad, nil, report("pubkeyauthentication no\n")); err == nil {
			t.Errorf("Grant accepted an invalid username %q", bad)
		}
		if err := m.Remove(bad); err == nil {
			t.Errorf("Remove accepted an invalid username %q", bad)
		}
	}
}

func TestRemoveWithNoDropIn(t *testing.T) {
	// revoke calls this for every account, including the ones that never needed an
	// sshd exception. It must be a silent no-op -- and must not reload sshd.
	reloads := 0
	m := &Manager{Dir: t.TempDir(), Reload: func() error { reloads++; return nil }}
	if err := m.Remove(acct); err != nil {
		t.Fatalf("Remove on an account with no drop-in: %v", err)
	}
	if reloads != 0 {
		t.Error("Remove reloaded sshd although it had nothing to remove")
	}
}

func TestOrphansFindsExceptionsWhoseAccountIsGone(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		filePrefix + "xxvcc-gone.conf",  // ours, account deleted -> orphan
		filePrefix + "xxvcc-alive.conf", // ours, account exists -> not an orphan
		"99-somebody-else.conf",         // not ours: never touch it
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("# x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{Dir: dir}
	orphans, err := m.Orphans(func(u string) (bool, error) { return u == "xxvcc-alive", nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 1 || orphans[0] != "xxvcc-gone" {
		t.Fatalf("orphans = %v, want [xxvcc-gone]", orphans)
	}
}
