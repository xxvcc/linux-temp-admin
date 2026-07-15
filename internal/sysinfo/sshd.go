// This file reads sshd's *effective* configuration and answers the one question
// the tool used to assume: will this server actually let the account we are about
// to create log in with the key we are about to write?
//
// The answer comes from `sshd -T`, never from parsing /etc/ssh/sshd_config by
// hand: -T resolves Include directives, Match blocks, compiled-in defaults, and
// distro crypto policy, and it is the same evaluation the running sshd performs.
// Guessing at the file's text would be worse than not looking at all, because a
// wrong guess turns into a confidently false invite.
package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// sshdCommand is the sshd binary; overridable in tests.
var sshdCommand = "sshd"

// SSHDConfig is sshd's effective configuration, as reported by `sshd -T`. Keys
// are the lowercase directive names sshd prints; a directive that sshd repeats
// across lines (AllowUsers, AllowGroups, ...) accumulates all of its values.
type SSHDConfig struct {
	vals map[string][]string
}

// Values returns every value recorded for key (nil if absent).
func (c *SSHDConfig) Values(key string) []string { return c.vals[key] }

// First returns the first value for key, or "" if absent.
func (c *SSHDConfig) First(key string) string {
	if v := c.vals[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Has reports whether sshd printed key at all.
func (c *SSHDConfig) Has(key string) bool { return len(c.vals[key]) > 0 }

// SSHDEffective returns sshd's effective configuration for a connection from
// user. Passing a user is what makes `Match User` blocks visible, and sshd
// evaluates it happily for an account that does not exist yet — which is what
// lets invite check a username *before* creating it.
//
// No address is supplied, because the tool cannot know which IP the invitee will
// connect from. That makes `Match Address` blocks evaluate as non-matching, so a
// server that enables pubkey auth only for one network reads here as "disabled".
// That bias is deliberate: it can produce a needless warning, never a false
// promise that a key login will work.
//
// A blank user asks for the plain global view (`sshd -T`).
func SSHDEffective(user string) (*SSHDConfig, error) {
	if !has(sshdCommand) {
		return nil, fmt.Errorf("sshd not found in PATH")
	}
	args := []string{"-T"}
	if user != "" {
		args = append(args, "-C", "user="+user)
	}
	out, err := exec.Command(sshdCommand, args...).Output()
	if err != nil {
		// A failed per-user probe must NOT fall back to the global view. The global
		// view cannot see `Match User` blocks, so a host whose Match block blocks
		// precisely this account would read as "keys accepted" — the tool would then
		// stamp the invite "verified" and hand out a key that cannot log in, which is
		// the exact failure this check exists to end. Report the failure instead and
		// let the caller say plainly that nothing was verified.
		return nil, fmt.Errorf("sshd -T failed: %w", err)
	}
	return ParseSSHD(string(out)), nil
}

// ParseSSHD parses `sshd -T` output. It is exported so a test can build an
// effective config from a fixture instead of whatever sshd the test host happens
// to be running — a check about sshd policy must not have its verdict decided by
// the machine running the tests.
func ParseSSHD(out string) *SSHDConfig {
	c := &SSHDConfig{vals: map[string][]string{}}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		c.vals[key] = append(c.vals[key], fields[1:]...)
	}
	return c
}

// sshdConfigDropInDir is the standard drop-in directory; overridable in tests.
var sshdConfigDropInDir = "/etc/ssh/sshd_config.d"

// HasAddressScopedMatch reports whether sshd's configuration contains a `Match`
// stanza keyed on the client's Address or Host.
//
// This is the one thing `sshd -T -C user=X` cannot answer: it evaluates Match
// blocks for the connection spec it is given, and the tool cannot supply the
// invitee's source address because it does not know it. So a host that enables
// pubkey auth globally but denies it from the internet (`Match Address`), or
// that requires a second factor except on the LAN, would read as "key login
// works" from a no-address probe and print a verified invite that then fails.
//
// Detection, not interpretation: it scans the main config and the drop-in
// directory for a `Match` line naming Address/Host as a criterion and reports
// only that one exists. A caller treats that as "cannot verify" and downgrades
// the invite to UNVERIFIED — it never turns into a blocker or a refusal, so a
// false positive costs only a needless caveat. A Match hidden in a nested
// Include this scan does not reach falls back to the prior behaviour (the login
// is judged from the no-address view); it is never made worse.
func HasAddressScopedMatch() bool {
	files := []string{sshdConfigPath}
	if entries, err := filepath.Glob(filepath.Join(sshdConfigDropInDir, "*.conf")); err == nil {
		files = append(files, entries...)
	}
	for _, f := range files {
		if fileHasAddressScopedMatch(f) {
			return true
		}
	}
	return false
}

func fileHasAddressScopedMatch(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Match") {
			continue
		}
		// A Match line is keyword/value pairs: `Match User bob Address 10.0.0.0/8`.
		// Any Address/Host criterion makes the outcome depend on where the client
		// connects from, which is unknowable here.
		for _, tok := range fields[1:] {
			if strings.EqualFold(tok, "address") || strings.EqualFold(tok, "host") {
				return true
			}
		}
	}
	return false
}

// Blocker is one reason a login would fail. The values are stable identifiers,
// not messages: sysinfo stays free of i18n, and the cli layer renders them.
type Blocker int

const (
	// BlockPubkeyDisabled is `PubkeyAuthentication no`.
	BlockPubkeyDisabled Blocker = iota
	// BlockAuthorizedKeysFile means sshd does not read ~/.ssh/authorized_keys,
	// which is the only place this tool writes the key.
	BlockAuthorizedKeysFile
	// BlockAuthMethods means AuthenticationMethods cannot be satisfied by a public
	// key alone — and the tool locks the password, so no second factor can ever be
	// offered.
	BlockAuthMethods
	// BlockKeyAlgorithm means the server refuses ssh-ed25519, the only key type
	// this tool issues (FIPS/crypto-policy hosts).
	BlockKeyAlgorithm
	// BlockAllowUsers means an AllowUsers whitelist excludes the account.
	BlockAllowUsers
	// BlockAllowGroups means an AllowGroups whitelist excludes the account.
	BlockAllowGroups
	// BlockDenyUsers means a DenyUsers rule names the account.
	BlockDenyUsers
	// BlockDenyGroups means a DenyGroups rule names one of the account's groups.
	BlockDenyGroups
	// BlockPasswordDisabled is `PasswordAuthentication no` (password login only).
	BlockPasswordDisabled
)

// String names the offending directive. It is a stable identifier for logs and
// errors, not a user-facing message — the cli renders those bilingually.
func (b Blocker) String() string {
	switch b {
	case BlockPubkeyDisabled:
		return "PubkeyAuthentication no"
	case BlockAuthorizedKeysFile:
		return "AuthorizedKeysFile"
	case BlockAuthMethods:
		return "AuthenticationMethods"
	case BlockKeyAlgorithm:
		return "PubkeyAcceptedAlgorithms"
	case BlockAllowUsers:
		return "AllowUsers"
	case BlockAllowGroups:
		return "AllowGroups"
	case BlockDenyUsers:
		return "DenyUsers"
	case BlockDenyGroups:
		return "DenyGroups"
	case BlockPasswordDisabled:
		return "PasswordAuthentication no"
	}
	return "unknown"
}

// Fixable reports whether a per-user `Match User` drop-in can lift this blocker.
//
// The Deny* blockers are deliberately NOT fixable. "Not on the allow list" is a
// default the operator never spoke about, and an invite may lift it for one
// throwaway account. An explicit DenyUsers/DenyGroups rule is the operator
// saying "never this account" — a tool that quietly overrode that would be
// defeating the very policy it was pointed at.
func (b Blocker) Fixable() bool {
	switch b {
	case BlockPubkeyDisabled, BlockAuthorizedKeysFile, BlockAuthMethods,
		BlockKeyAlgorithm, BlockAllowUsers, BlockAllowGroups:
		return true
	}
	return false
}

// LoginReport is what sshd's effective config says about one account's ability
// to log in. Detail carries the offending effective value, so a message can
// quote what it actually found rather than a generic complaint.
type LoginReport struct {
	Blockers []Blocker
	Warnings []string // human-facing English notes; the cli renders them verbatim
	Detail   map[Blocker]string

	// Unverifiable holds the rules that could match this account but whose verdict
	// depends on something the tool cannot know — today, only the address half of
	// an `AllowUsers user@host` pattern, because nobody can say which IP the
	// invitee will connect from. Such a rule is neither a pass nor a blocker: it
	// means "no verdict". An invite must not be stamped verified while one stands,
	// and a grant must not claim to have proved anything.
	Unverifiable []string

	// AlgoDirective is the directive name sshd itself used for the accepted
	// public-key algorithms — PubkeyAcceptedAlgorithms, or PubkeyAcceptedKeyTypes
	// on sshd older than 8.5. A fix must write back the spelling the host's own
	// sshd understands, or sshd will refuse to start on the file we just wrote.
	AlgoDirective string
}

// OK reports whether nothing blocks the login.
func (r LoginReport) OK() bool { return len(r.Blockers) == 0 }

// Certain reports whether the login provably works: nothing blocks it AND every
// rule that bears on it could actually be evaluated. Only a Certain report may
// be printed as "verified" — OK() alone would let an unevaluated rule pass for a
// proof, which is the class of false promise this whole check exists to end.
func (r LoginReport) Certain() bool { return r.OK() && len(r.Unverifiable) == 0 }

// Fixable reports whether every blocker can be lifted by a per-user drop-in.
func (r LoginReport) Fixable() bool {
	if r.OK() {
		return false
	}
	for _, b := range r.Blockers {
		if !b.Fixable() {
			return false
		}
	}
	return true
}

// Has reports whether b is among the blockers.
func (r LoginReport) Has(b Blocker) bool {
	for _, x := range r.Blockers {
		if x == b {
			return true
		}
	}
	return false
}

func (r *LoginReport) block(b Blocker, detail string) {
	r.Blockers = append(r.Blockers, b)
	if r.Detail == nil {
		r.Detail = map[Blocker]string{}
	}
	r.Detail[b] = detail
}

// CheckKeyLogin reports whether c would let user log in with an ed25519 key
// written to ~/.ssh/authorized_keys. groups are the account's group names (its
// primary group is enough for a freshly created account); pass the predicted
// group before the account exists.
//
// It is used twice: once before anything is created (to refuse or to offer a
// fix), and once after a drop-in is written (to prove the fix actually took
// effect). Reusing one function for both is the point — the invite can only
// claim "SSH key only" because this exact check passed against the live config.
func CheckKeyLogin(c *SSHDConfig, user string, groups []string) LoginReport {
	var r LoginReport
	if !yes(c.First("pubkeyauthentication")) {
		r.block(BlockPubkeyDisabled, c.First("pubkeyauthentication"))
	}
	if akf := c.Values("authorizedkeysfile"); len(akf) > 0 && !readsDefaultAuthorizedKeys(akf) {
		r.block(BlockAuthorizedKeysFile, strings.Join(akf, " "))
	}
	if m := c.Values("authenticationmethods"); !methodsSatisfiedBy(m, "publickey") {
		r.block(BlockAuthMethods, strings.Join(m, " "))
	}
	algs, directive := pubkeyAlgorithms(c)
	r.AlgoDirective = directive
	if len(algs) > 0 && !contains(algs, "ssh-ed25519") {
		// Detail is the effective list verbatim: a fix must re-state it and append
		// ed25519, never widen it back to sshd's compiled-in default.
		r.block(BlockKeyAlgorithm, strings.Join(algs, ","))
	}
	checkAccess(c, user, groups, &r)
	if cmd := c.First("authorizedkeyscommand"); cmd != "" && cmd != "none" {
		r.Warnings = append(r.Warnings,
			"sshd has an AuthorizedKeysCommand ("+cmd+"); keys may also come from an external source")
	}
	return r
}

// CheckPasswordLogin reports whether c would let user log in with a password.
// It exists so --password-login can never print a password for an account that
// the server would refuse anyway.
func CheckPasswordLogin(c *SSHDConfig, user string, groups []string) LoginReport {
	var r LoginReport
	if !yes(c.First("passwordauthentication")) {
		r.block(BlockPasswordDisabled, c.First("passwordauthentication"))
	}
	if m := c.Values("authenticationmethods"); !methodsSatisfiedBy(m, "password") {
		r.block(BlockAuthMethods, strings.Join(m, " "))
	}
	checkAccess(c, user, groups, &r)
	return r
}

// checkAccess applies sshd's host-level access control (Allow*/Deny*), which is
// evaluated before any authentication method runs, so it blocks key and password
// logins alike.
//
// The two directions fail in opposite ways, so they are evaluated in opposite
// ways. A rule the tool cannot fully evaluate — `AllowUsers user@host`, whose
// address half depends on where the invitee connects from — must never count as
// permission granted, and a deny rule the tool cannot fully evaluate must always
// count as denial. Erring toward "allowed" would print an invite that sshd
// refuses; erring toward "denied" only ever costs a needless warning.
func checkAccess(c *SSHDConfig, user string, groups []string, r *LoginReport) {
	// Deny: fail closed. An entry whose user half matches counts as a denial even
	// if an address half would have narrowed it, because we cannot prove it would not.
	if deny := c.Values("denyusers"); len(deny) > 0 && matchesUser(deny, []string{user}) {
		r.block(BlockDenyUsers, strings.Join(deny, " "))
	}
	if deny := c.Values("denygroups"); len(deny) > 0 && matchesUser(deny, groups) {
		r.block(BlockDenyGroups, strings.Join(deny, " "))
	}
	// Allow: fail open only on proof. An address-qualified entry yields no verdict
	// rather than a pass. It must NOT become a blocker either: the automatic fix
	// would then write `AllowUsers <account>`, quietly cancelling the operator's
	// network restriction for this account — repairing the report by weakening the
	// host.
	if allow := c.Values("allowusers"); len(allow) > 0 {
		allowed, unsure := matchesAllow(allow, []string{user})
		switch {
		case allowed:
			// A bare entry admits the account from anywhere; the address-qualified ones
			// are then redundant, so the login is provably allowed and there is nothing
			// unverifiable to carry.
		case len(unsure) > 0:
			r.Unverifiable = append(r.Unverifiable, unsure...)
		default:
			r.block(BlockAllowUsers, strings.Join(allow, " "))
		}
	}
	if allow := c.Values("allowgroups"); len(allow) > 0 {
		// AllowGroups takes bare group names; sshd gives it no user@host form, so it
		// is always decidable.
		if !matchesUser(allow, groups) {
			r.block(BlockAllowGroups, strings.Join(allow, " "))
		}
	}
}

// pubkeyAlgorithms returns the accepted public-key algorithms and the directive
// name sshd used for them (sshd renamed it in 8.5). The name is carried out so a
// fix writes back the spelling this host's sshd actually understands.
func pubkeyAlgorithms(c *SSHDConfig) (algs []string, directive string) {
	for _, k := range []struct{ key, name string }{
		{"pubkeyacceptedalgorithms", "PubkeyAcceptedAlgorithms"},
		{"pubkeyacceptedkeytypes", "PubkeyAcceptedKeyTypes"}, // pre-8.5
	} {
		if v := c.Values(k.key); len(v) > 0 {
			return splitCommas(v), k.name
		}
	}
	return nil, ""
}

// readsDefaultAuthorizedKeys reports whether any AuthorizedKeysFile entry names
// the per-user file this tool writes. "none" and central paths like
// /etc/ssh/authorized_keys/%u do not.
func readsDefaultAuthorizedKeys(entries []string) bool {
	for _, e := range entries {
		if e == ".ssh/authorized_keys" || e == "%h/.ssh/authorized_keys" {
			return true
		}
	}
	return false
}

// methodsSatisfiedBy reports whether an AuthenticationMethods setting can be
// satisfied by `method` on its own. The setting is a space-separated list of
// alternatives, each a comma-separated chain that must be completed in full; a
// login succeeds if any one alternative is completed. "any" (or unset) means
// sshd's normal single-method behaviour.
func methodsSatisfiedBy(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, alt := range methods {
		if alt == "any" || alt == method {
			return true
		}
	}
	return false
}

// matchesUser reports whether any name matches the user half of any pattern. It
// is the fail-closed evaluation: an address-qualified pattern counts as a match
// on its user half alone, so a deny rule that *might* apply is treated as one
// that does.
func matchesUser(patterns, names []string) bool {
	for _, p := range patterns {
		if userHalf(p, names) {
			return true
		}
	}
	return false
}

// matchesAllow evaluates an allow-list. allowed is true only when a pattern
// matches unconditionally; a pattern that matches the user but also constrains
// the source address is returned in unsure, because the invitee's address is not
// something this tool can know.
func matchesAllow(patterns, names []string) (allowed bool, unsure []string) {
	for _, p := range patterns {
		if !userHalf(p, names) {
			continue
		}
		if strings.Contains(p, "@") {
			unsure = append(unsure,
				"sshd's AllowUsers entry "+p+" also restricts the source address, which this tool cannot evaluate")
			continue
		}
		allowed = true
	}
	return allowed, unsure
}

// userHalf reports whether any name matches the user half of an sshd pattern
// (sshd patterns allow * and ?; an entry may carry a user@host suffix).
func userHalf(pattern string, names []string) bool {
	if i := strings.Index(pattern, "@"); i >= 0 {
		pattern = pattern[:i]
	}
	for _, n := range names {
		if n == "" {
			continue
		}
		if ok, err := path.Match(pattern, n); err == nil && ok {
			return true
		}
	}
	return false
}

func splitCommas(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func yes(v string) bool { return strings.EqualFold(v, "yes") }
