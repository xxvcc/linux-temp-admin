package sysinfo

import (
	"os"
	"testing"
)

// The account an invite creates: a fresh name, in no group but its own.
const acct = "xxvcc-a1b2c3"

var acctGroups = []string{acct}

func TestParseSSHDAccumulatesRepeatedDirectives(t *testing.T) {
	c := ParseSSHD("port 22\nallowusers alice\nallowusers bob\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n")
	if got := c.First("port"); got != "22" {
		t.Errorf("port = %q, want 22", got)
	}
	// sshd prints AllowUsers once per entry; a parser that kept only the first
	// would think a whitelist admitted everyone it happened to list second.
	if got := c.Values("allowusers"); len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Errorf("allowusers = %v, want [alice bob]", got)
	}
	if got := c.Values("authorizedkeysfile"); len(got) != 2 {
		t.Errorf("authorizedkeysfile = %v, want both entries", got)
	}
	if c.Has("pubkeyauthentication") {
		t.Error("Has must not invent a directive sshd never printed")
	}
}

func TestCheckKeyLogin(t *testing.T) {
	const okConfig = "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
	tests := []struct {
		name    string
		config  string
		want    []Blocker
		fixable bool
	}{
		{
			name:   "a stock server accepts the key",
			config: okConfig,
		},
		{
			// The failure the operator actually hit: the invite used to be printed
			// anyway, claiming "Login: SSH key only".
			name:    "public-key auth disabled",
			config:  "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n",
			want:    []Blocker{BlockPubkeyDisabled},
			fixable: true,
		},
		{
			name:    "authorized_keys redirected to a central path sshd alone can read",
			config:  "pubkeyauthentication yes\nauthorizedkeysfile /etc/ssh/keys/%u\n",
			want:    []Blocker{BlockAuthorizedKeysFile},
			fixable: true,
		},
		{
			name:    "authorized_keys turned off entirely",
			config:  "pubkeyauthentication yes\nauthorizedkeysfile none\n",
			want:    []Blocker{BlockAuthorizedKeysFile},
			fixable: true,
		},
		{
			// The tool locks the password, so a second factor can never be offered:
			// this account could never complete the login, not even with a good key.
			name:    "a second factor is required",
			config:  okConfig + "authenticationmethods publickey,password\n",
			want:    []Blocker{BlockAuthMethods},
			fixable: true,
		},
		{
			name:   "publickey is one of several accepted alternatives",
			config: okConfig + "authenticationmethods publickey password\n",
		},
		{
			name:   "authenticationmethods any",
			config: okConfig + "authenticationmethods any\n",
		},
		{
			name:    "a crypto policy that excludes ed25519, the only type we issue",
			config:  okConfig + "pubkeyacceptedalgorithms rsa-sha2-512,ecdsa-sha2-nistp384\n",
			want:    []Blocker{BlockKeyAlgorithm},
			fixable: true,
		},
		{
			name:   "ed25519 among the accepted algorithms",
			config: okConfig + "pubkeyacceptedalgorithms rsa-sha2-512,ssh-ed25519\n",
		},
		{
			name:   "the pre-8.5 spelling of the same directive",
			config: okConfig + "pubkeyacceptedkeytypes ssh-ed25519\n",
		},
		{
			// A brand-new random account is on nobody's whitelist, by construction.
			name:    "an AllowUsers whitelist that cannot contain a fresh account",
			config:  okConfig + "allowusers alice\nallowusers bob\n",
			want:    []Blocker{BlockAllowUsers},
			fixable: true,
		},
		{
			name:   "an AllowUsers wildcard that does admit it",
			config: okConfig + "allowusers xxvcc-*\n",
		},
		{
			// NOT a pass. The address half decides this rule and we cannot know which
			// IP the invitee connects from, so there is no verdict -- see
			// TestAddressQualifiedAllowUsersIsNoVerdict. It must not become a blocker
			// either: the automatic fix would then write `AllowUsers <account>` and
			// quietly cancel the operator's network restriction for this account.
			name:   "AllowUsers with a user@host suffix yields no verdict, not a pass",
			config: okConfig + "allowusers " + acct + "@203.0.113.5\n",
		},
		{
			name:    "an AllowGroups whitelist",
			config:  okConfig + "allowgroups wheel\n",
			want:    []Blocker{BlockAllowGroups},
			fixable: true,
		},
		{
			// An explicit deny is the operator saying "never this account". The tool
			// refuses to bypass it, so it must not be reported as fixable.
			name:    "an explicit DenyUsers rule",
			config:  okConfig + "denyusers " + acct + "\n",
			want:    []Blocker{BlockDenyUsers},
			fixable: false,
		},
		{
			name:    "an explicit DenyGroups rule",
			config:  okConfig + "denygroups " + acct + "\n",
			want:    []Blocker{BlockDenyGroups},
			fixable: false,
		},
		{
			name:   "a deny list that does not name this account",
			config: okConfig + "denyusers mallory\n",
		},
		{
			name:   "no authorizedkeysfile line at all falls back to sshd's default",
			config: "pubkeyauthentication yes\n",
		},
		{
			// A fixable blocker beside an unfixable one must not read as fixable: the
			// drop-in would be written and the login would still be refused.
			name:    "an explicit deny alongside a fixable blocker",
			config:  "pubkeyauthentication no\ndenyusers " + acct + "\n",
			want:    []Blocker{BlockPubkeyDisabled, BlockDenyUsers},
			fixable: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := CheckKeyLogin(ParseSSHD(tc.config), acct, acctGroups)
			if len(rep.Blockers) != len(tc.want) {
				t.Fatalf("blockers = %v, want %v", rep.Blockers, tc.want)
			}
			for _, w := range tc.want {
				if !rep.Has(w) {
					t.Errorf("blockers = %v, missing %v", rep.Blockers, w)
				}
			}
			if rep.OK() != (len(tc.want) == 0) {
				t.Errorf("OK() = %v with blockers %v", rep.OK(), rep.Blockers)
			}
			if rep.Fixable() != tc.fixable {
				t.Errorf("Fixable() = %v, want %v", rep.Fixable(), tc.fixable)
			}
		})
	}
}

func TestCheckKeyLoginWarnsOnAuthorizedKeysCommand(t *testing.T) {
	// Not a blocker: the command is an *additional* source of keys, so the file we
	// wrote is still read. The operator should still hear about it.
	rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand /usr/bin/ldap-keys\n"), acct, acctGroups)
	if !rep.OK() {
		t.Errorf("an AuthorizedKeysCommand must not block a login: %v", rep.Blockers)
	}
	if len(rep.Warnings) != 1 {
		t.Errorf("warnings = %v, want one", rep.Warnings)
	}
	if rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\nauthorizedkeyscommand none\n"), acct, acctGroups); len(rep.Warnings) != 0 {
		t.Errorf("`none` is sshd's way of saying there is no command: %v", rep.Warnings)
	}
}

func TestCheckPasswordLogin(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   []Blocker
	}{
		{
			name:   "passwords accepted",
			config: "passwordauthentication yes\n",
		},
		{
			// The common shape of a host that has pubkey auth off: it is not that
			// keys were disabled in favour of passwords, it is that both are.
			name:   "passwords disabled too",
			config: "passwordauthentication no\n",
			want:   []Blocker{BlockPasswordDisabled},
		},
		{
			name:   "a second factor is required",
			config: "passwordauthentication yes\nauthenticationmethods password,publickey\n",
			want:   []Blocker{BlockAuthMethods},
		},
		{
			name:   "host-level access control blocks passwords just as it blocks keys",
			config: "passwordauthentication yes\nallowusers alice\n",
			want:   []Blocker{BlockAllowUsers},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := CheckPasswordLogin(ParseSSHD(tc.config), acct, acctGroups)
			if len(rep.Blockers) != len(tc.want) {
				t.Fatalf("blockers = %v, want %v", rep.Blockers, tc.want)
			}
			for _, w := range tc.want {
				if !rep.Has(w) {
					t.Errorf("blockers = %v, missing %v", rep.Blockers, w)
				}
			}
		})
	}
}

func TestAddressQualifiedAllowUsersIsNoVerdict(t *testing.T) {
	// `AllowUsers *@10.0.0.0/8` admits the account only from one network. sshd
	// evaluates the user half and the address half separately, and the address half
	// is not something this tool can evaluate: it has no idea where the invitee
	// will connect from. Reading the user half alone and calling it a pass is how a
	// tool prints "verified" on a key that sshd then refuses.
	for _, pattern := range []string{"*@10.0.0.0/8", acct + "@203.0.113.5"} {
		rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\nallowusers "+pattern+"\n"), acct, acctGroups)
		if !rep.OK() {
			t.Errorf("%s: must not be a blocker (a fix would cancel the operator's address restriction): %v", pattern, rep.Blockers)
		}
		if rep.Certain() {
			t.Errorf("%s: must not count as proof that the login works", pattern)
		}
		if len(rep.Unverifiable) != 1 {
			t.Errorf("%s: expected the rule to be named as unverifiable, got %v", pattern, rep.Unverifiable)
		}
	}
	// An unconditional entry alongside it IS a proof: the account is admitted from
	// anywhere by that one.
	rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\nallowusers other@10.0.0.0/8\nallowusers "+acct+"\n"), acct, acctGroups)
	if !rep.Certain() {
		t.Errorf("an unconditional AllowUsers entry admits the account: %v %v", rep.Blockers, rep.Unverifiable)
	}
}

func TestDenyRulesFailClosed(t *testing.T) {
	// The two directions fail in opposite ways, so they must be evaluated in
	// opposite ways. An un-evaluatable DENY that could name this account has to
	// count as a denial: erring toward "allowed" prints an invite sshd refuses,
	// while erring toward "denied" costs only a needless refusal.
	rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\ndenyusers "+acct+"@10.0.0.0/8\n"), acct, acctGroups)
	if !rep.Has(BlockDenyUsers) {
		t.Errorf("an address-qualified DenyUsers naming this account must fail closed: %v", rep.Blockers)
	}
	// ...but a deny that names somebody else never applies, address or not.
	rep = CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\ndenyusers mallory@10.0.0.0/8\n"), acct, acctGroups)
	if !rep.Certain() {
		t.Errorf("a deny rule for another account must not touch this one: %v", rep.Blockers)
	}
}

func TestAlgoDirectiveIsReportedForWriteBack(t *testing.T) {
	// sshd renamed this directive in 8.5. A fix has to write back the spelling the
	// host's own sshd understands, or sshd refuses to start on the file we wrote --
	// so the checker must carry the name it actually saw.
	for _, tc := range []struct{ line, want string }{
		{"pubkeyacceptedalgorithms rsa-sha2-512", "PubkeyAcceptedAlgorithms"},
		{"pubkeyacceptedkeytypes rsa-sha2-512", "PubkeyAcceptedKeyTypes"},
	} {
		rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\n"+tc.line+"\n"), acct, acctGroups)
		if rep.AlgoDirective != tc.want {
			t.Errorf("%q: AlgoDirective = %q, want %q", tc.line, rep.AlgoDirective, tc.want)
		}
		// Detail must be the operator's effective list verbatim: the fix re-states it.
		if rep.Detail[BlockKeyAlgorithm] != "rsa-sha2-512" {
			t.Errorf("%q: Detail = %q, want the effective list verbatim", tc.line, rep.Detail[BlockKeyAlgorithm])
		}
	}
}

func TestBareAllowUsersSuppressesTheUnverifiableSibling(t *testing.T) {
	// A bare `AllowUsers acct` admits the account from anywhere. A redundant
	// address-qualified sibling must NOT then drag the verdict down to unverifiable:
	// the login is provably allowed by the bare entry (sshd ORs the entries).
	rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\nallowusers "+acct+"\nallowusers "+acct+"@10.0.0.0/8\n"), acct, acctGroups)
	if !rep.Certain() {
		t.Errorf("a bare AllowUsers entry admits the account; the login is certain: blockers=%v unverifiable=%v", rep.Blockers, rep.Unverifiable)
	}
}

func TestHasAddressScopedMatch(t *testing.T) {
	dir := t.TempDir()
	main := dir + "/sshd_config"
	dropins := dir + "/sshd_config.d"
	if err := os.MkdirAll(dropins, 0o755); err != nil {
		t.Fatal(err)
	}
	oldC, oldD := sshdConfigPath, sshdConfigDropInDir
	sshdConfigPath, sshdConfigDropInDir = main, dropins
	t.Cleanup(func() { sshdConfigPath, sshdConfigDropInDir = oldC, oldD })

	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The exact shape the probe cannot otherwise see: pubkey on globally, denied
	// from a specific network -- `sshd -T -C user=X` with no address reads it as OK.
	write(main, "PubkeyAuthentication yes\nMatch Address 203.0.113.0/24\n    DenyUsers "+acct+"\n")
	if !HasAddressScopedMatch() {
		t.Error("a `Match Address` block in the main config must be detected")
	}

	// In a drop-in, on the Host criterion, and as a later criterion after User.
	write(main, "PubkeyAuthentication yes\n")
	write(dropins+"/10-x.conf", "Match User bob Host bastion.example\n    X11Forwarding no\n")
	if !HasAddressScopedMatch() {
		t.Error("a `Match ... Host` criterion in a drop-in must be detected")
	}

	// No address/host-scoped Match at all -> not flagged. A `Match User` alone is
	// fully evaluable via `sshd -T -C user=`, so it is not address-scoped.
	write(dropins+"/10-x.conf", "Match User bob\n    PermitTTY no\n")
	if HasAddressScopedMatch() {
		t.Error("a plain `Match User` block is not address-scoped and must not be flagged")
	}

	// Includes are relative to the main ssh configuration directory even when an
	// included file contains another Include. The address-scoped Match must not be
	// hidden two levels away from the main file.
	nested := dir + "/nested"
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	write(main, "Include first.conf\n")
	write(dir+"/first.conf", "Include nested/second.conf\n")
	write(nested+"/second.conf", "Match User bob Address 198.51.100.0/24\n    PermitTTY no\n")
	if !HasAddressScopedMatch() {
		t.Error("a nested Include containing `Match Address` must be detected")
	}

	// An explicit Include that cannot be read makes the scan incomplete. The
	// caller must downgrade to unverifiable instead of claiming key login works.
	write(main, "Include missing.conf\n")
	if !HasAddressScopedMatch() {
		t.Error("an unreadable explicit Include must make the result unverifiable")
	}
}

// TestMatchSSHDPattern pins the matcher against OpenSSH's match.c semantics:
// only '*' and '?' are special, everything else is literal.
func TestMatchSSHDPattern(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"xxvcc-a1", "xxvcc-a1", true},
		{"xxvcc-a1", "xxvcc-a2", false},
		{"*", "anything", true},
		{"*", "", true},
		{"xxvcc-*", "xxvcc-a1b2c3", true},
		{"xxvcc-*", "other-a1", false},
		{"*-admin", "temp-admin", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},
		{"*a*b*", "xxayybzz", true},
		{"*a*b*", "xxbyyazz", false},
		// THE regression: sshd treats brackets literally; path.Match would expand
		// them into a character class and call this a match, which is how the tool
		// printed "verified" for a login sshd refuses.
		{"admin-[0-9]", "admin-5", false},
		{"admin-[0-9]", "admin-[0-9]", true},
		// Other path.Match metacharacters that sshd does not honour, either.
		{`a\*b`, `a\*b`, true},
		{`a\*b`, "aXb", false},
		{"a[bc]d", "abd", false},
		{"a[bc]d", "a[bc]d", true},
		// Trailing stars collapse; a pattern of only stars matches everything.
		{"**", "abc", true},
		{"abc*", "abc", true},
	}
	for _, c := range cases {
		if got := matchSSHDPattern(c.pattern, c.s); got != c.want {
			t.Errorf("matchSSHDPattern(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// TestBracketAllowUsersIsNotAFalseVerify is the end-to-end shape of the same bug:
// an AllowUsers whose brackets sshd reads literally must NOT admit the account.
func TestBracketAllowUsersIsNotAFalseVerify(t *testing.T) {
	rep := CheckKeyLogin(ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nallowusers xxvcc-[0-9]*\n"),
		"xxvcc-a1b2c3", []string{"xxvcc-a1b2c3"})
	if rep.OK() {
		t.Error("a literal-bracket AllowUsers must not read as admitting this account")
	}
	if !rep.Has(BlockAllowUsers) {
		t.Errorf("expected the whitelist to block; blockers=%v", rep.Blockers)
	}
}
