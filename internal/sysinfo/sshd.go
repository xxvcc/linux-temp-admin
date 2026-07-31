package sysinfo

// This file reads sshd's *effective* configuration and checks whether it admits
// the account and credential the tool plans to create.
//
// The credential verdict comes from `sshd -T`: it resolves Include directives,
// Match blocks, compiled-in defaults, and distro crypto policy with sshd's own
// evaluator. A separate bounded scan of the source configuration only discovers
// Match conditions that a user-only `-T -C` probe cannot evaluate; it never
// derives the authentication verdict itself. This is not an end-to-end connection
// test: network policy, PAM, SELinux, and the complete state of a running daemon
// remain outside this check.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"golang.org/x/sys/unix"
)

// sshdCommand is the sshd binary; overridable in tests.
var sshdCommand = "sshd"

var sshdProbeOptions = executil.Options{
	Timeout:   10 * time.Second,
	MaxOutput: 1 << 20,
	ExtraEnv:  []string{"LC_ALL=C", "LANG=C"},
}

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
// Only the user is supplied because the tool cannot know the future connection's
// source/server address, local port, or routing attributes. sshd may therefore
// leave connection-scoped Match blocks unevaluated; the caller separately scans
// the configuration and downgrades such a result to UNVERIFIED.
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
	out, err := executil.Output(sshdCommand, args, sshdProbeOptions)
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
	// SSHDEffective already captured the complete output in memory. Splitting that
	// string avoids bufio.Scanner's 64 KiB token limit: a very long directive must
	// not silently hide a later DenyUsers/DenyGroups rule and turn an incomplete
	// parse into a false "login accepted" verdict.
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
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

const (
	maxSSHDIncludeDepth = 64
	maxSSHDIncludeFiles = 256
	maxSSHDIncludeGlobs = 1024
	maxSSHDIncludeBytes = int64(64 << 20)
)

type sshdConfigIdentity struct {
	dev uint64
	ino uint64
}

type sshdIncludeScan struct {
	paths      map[string]bool
	identities map[sshdConfigIdentity]bool
	// accountExists controls whether Match Group is evaluable by `sshd -T -C
	// user=...`. OpenSSH cannot resolve group membership for a not-yet-created
	// account, but it can after creation.
	accountExists bool
	files         int
	globs         int
	bytes         int64
}

// HasConnectionScopedMatch reports whether sshd's configuration contains a
// `Match` criterion that `sshd -T -C user=X` cannot evaluate without more
// connection attributes.
//
// This is the one thing `sshd -T -C user=X` cannot answer: it evaluates Match
// blocks for the connection spec it is given, and the tool cannot supply the
// invitee's source/server address, port, or routing domain because it does not
// know them. So a host that enables
// pubkey auth globally but denies it from the internet (`Match Address`), or
// that requires a second factor except on the LAN, would read as "key login
// works" from a no-address probe and print a verified invite that then fails.
//
// Detection, not interpretation: it scans the main config and recursively follows
// Include directives and parses Match criterion/value pairs. A
// caller treats that as "cannot verify" and downgrades the invite to UNVERIFIED.
// An include that cannot be read is also unverifiable, so an incomplete scan can
// never produce a false verified claim.
func HasConnectionScopedMatch() bool {
	return HasUnverifiableMatch(true)
}

// HasUnverifiableMatch reports whether sshd has a Match rule that a user-only
// effective-config probe cannot evaluate in the caller's account phase.
// Connection attributes (address, host, port, routing domain) are always
// unavailable. Group is unavailable only before the account exists: OpenSSH
// resolves actual NSS group membership when evaluating an existing user, but a
// future account receives only the global result from `sshd -T -C user=name`.
func HasUnverifiableMatch(accountExists bool) bool {
	files := []string{sshdConfigPath}
	if entries, err := strictGlob(filepath.Join(sshdConfigDropInDir, "*.conf")); err == nil {
		files = append(files, entries...)
	} else {
		return true
	}
	scan := &sshdIncludeScan{
		paths:         map[string]bool{},
		identities:    map[sshdConfigIdentity]bool{},
		accountExists: accountExists,
	}
	baseDir := filepath.Dir(sshdConfigPath)
	for _, f := range files {
		found, complete := fileHasConnectionScopedMatch(f, baseDir, scan, 0)
		if found || !complete {
			return true
		}
	}
	return false
}

func fileHasConnectionScopedMatch(path, baseDir string, scan *sshdIncludeScan, depth int) (found, complete bool) {
	if depth >= maxSSHDIncludeDepth {
		return false, false
	}
	path = filepath.Clean(path)
	if scan.paths[path] {
		return false, true
	}
	scan.paths[path] = true
	// sshd follows symlinked configuration files, so this scanner does too. Open
	// nonblocking, then require the resolved descriptor to be regular and bounded:
	// a damaged Include that names a FIFO or device must downgrade the verdict
	// instead of hanging or streaming forever.
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return false, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxSSHDConfigBytes {
		return false, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false
	}
	identity := sshdConfigIdentity{dev: uint64(st.Dev), ino: st.Ino}
	if scan.identities[identity] {
		return false, true
	}
	if scan.files >= maxSSHDIncludeFiles || fi.Size() > maxSSHDIncludeBytes-scan.bytes {
		return false, false
	}
	scan.identities[identity] = true
	scan.files++
	scan.bytes += fi.Size()
	limited := &io.LimitedReader{R: f, N: maxSSHDConfigBytes + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 64<<10), maxSSHDConfigLine)
	for sc.Scan() {
		keyword, fields, parsed := parseSSHDDirective(sc.Text())
		if !parsed {
			return false, false
		}
		if keyword == "" || len(fields) == 0 {
			continue
		}
		if strings.EqualFold(keyword, "Include") {
			for _, pattern := range fields {
				if scan.globs >= maxSSHDIncludeGlobs {
					return false, false
				}
				scan.globs++
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(baseDir, pattern)
				}
				matches, err := strictGlob(pattern)
				if err != nil {
					return false, false
				}
				if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
					return false, false
				}
				for _, include := range matches {
					found, complete := fileHasConnectionScopedMatch(include, baseDir, scan, depth+1)
					if found || !complete {
						return found, complete
					}
				}
			}
			continue
		}
		if !strings.EqualFold(keyword, "Match") {
			continue
		}
		// Match is a sequence of criterion/value pairs, except the standalone All.
		// Parse criterion positions rather than searching every token: `Match User
		// host` has a value named "host", not a Host criterion.
		for i := 0; i < len(fields); {
			criterion, _, embeddedValue := strings.Cut(fields[i], "=")
			criterion = strings.ToLower(criterion)
			switch criterion {
			case "all":
				i++
			case "user":
				if !embeddedValue && i+1 >= len(fields) {
					return false, false
				}
				if embeddedValue {
					i++
				} else {
					i += 2
				}
			case "group":
				if !embeddedValue && i+1 >= len(fields) {
					return false, false
				}
				if !scan.accountExists {
					return true, true
				}
				if embeddedValue {
					i++
				} else {
					i += 2
				}
			case "address", "host", "localaddress", "localport", "rdomain", "localnetwork", "tagged":
				return true, true
			default:
				// A newer criterion we do not understand is not evidence that the
				// user-only probe covered it. Downgrade instead of guessing.
				return true, true
			}
		}
	}
	return false, sc.Err() == nil && limited.N > 0
}

// parseSSHDDirective accepts both forms supported by OpenSSH's configuration
// parser: "Keyword value" and "Keyword=value". It intentionally handles only
// simple quoted tokens. A more complicated quoted line is reported as incomplete
// so the caller downgrades the login verdict instead of silently skipping policy.
func parseSSHDDirective(line string) (keyword string, args []string, complete bool) {
	var ok bool
	line, ok = stripSSHDComment(line)
	if !ok {
		return "", nil, false
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil, true
	}
	separator := strings.IndexAny(line, " \t=")
	if separator < 0 {
		keyword, ok := unquoteSimpleSSHDToken(line)
		return keyword, nil, ok
	}
	keyword, ok = unquoteSimpleSSHDToken(line[:separator])
	if !ok {
		return "", nil, false
	}
	rest := strings.TrimLeft(line[separator:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	for _, field := range strings.Fields(rest) {
		value, ok := unquoteSimpleSSHDToken(field)
		if !ok {
			return "", nil, false
		}
		args = append(args, value)
	}
	return keyword, args, true
}

// stripSSHDComment mirrors OpenSSH's token boundary for comments: '#' starts a
// comment only at the beginning of a token after whitespace. A hash embedded in
// an unquoted or quoted argument is literal (for example Include conf#backup).
// Backslash escapes are deliberately left unsupported; treating a complex line
// as incomplete makes the caller downgrade the verdict instead of guessing.
func stripSSHDComment(line string) (string, bool) {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			return "", false
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i], true
			}
		}
	}
	return line, !inQuote
}

func unquoteSimpleSSHDToken(token string) (string, bool) {
	if !strings.ContainsRune(token, '"') {
		return token, true
	}
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' || strings.Count(token, "\"") != 2 {
		return "", false
	}
	return token[1 : len(token)-1], true
}

var errSSHDGlobLimit = errors.New("sshd Include directory exceeds traversal limit")

var strictGlobReadDir = readSSHDGlobDir

func readSSHDGlobDir(path string) ([]os.DirEntry, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maxSSHDIncludeFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxSSHDIncludeFiles {
		return nil, errSSHDGlobLimit
	}
	return entries, nil
}

// strictGlob is filepath.Glob with one security-relevant difference: directory
// I/O errors are returned instead of silently treated as no matches. An
// incomplete sshd Include scan must downgrade the login verdict, not hide a
// connection-scoped Match rule.
func strictGlob(pattern string) ([]string, error) {
	if _, err := matchSSHDIncludeGlob(pattern, ""); err != nil {
		return nil, err
	}
	return strictGlobDepth(pattern, 0)
}

func strictGlobDepth(pattern string, depth int) ([]string, error) {
	const maxDepth = 256
	if depth == maxDepth {
		return nil, filepath.ErrBadPattern
	}
	if !globHasMeta(pattern) {
		if _, err := os.Lstat(pattern); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		return []string{pattern}, nil
	}

	dir, file := filepath.Split(pattern)
	switch dir {
	case "":
		dir = "."
	case string(filepath.Separator):
	default:
		dir = dir[:len(dir)-1]
	}
	if !globHasMeta(dir) {
		return strictGlobDir(dir, file, nil)
	}
	if dir == pattern {
		return nil, filepath.ErrBadPattern
	}
	dirs, err := strictGlobDepth(dir, depth+1)
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, matchedDir := range dirs {
		matches, err = strictGlobDir(matchedDir, file, matches)
		if err != nil {
			return nil, err
		}
	}
	return matches, nil
}

func strictGlobDir(dir, pattern string, matches []string) ([]string, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return matches, nil
		}
		return nil, err
	}
	if !fi.IsDir() {
		return matches, nil
	}
	entries, err := strictGlobReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		matched, err := matchSSHDIncludeGlob(pattern, entry.Name())
		if err != nil {
			return nil, err
		}
		if matched {
			if len(matches) >= maxSSHDIncludeFiles {
				return nil, errSSHDGlobLimit
			}
			matches = append(matches, filepath.Join(dir, entry.Name()))
		}
	}
	return matches, nil
}

// OpenSSH expands Include with POSIX glob(3), where [!x] negates a bracket
// expression. Go's filepath.Match uses [^x] for the same operation. Translate
// only an unescaped '!' immediately after '['; the rest of the pattern retains
// filepath.Match's pathname and escaping rules.
func matchSSHDIncludeGlob(pattern, name string) (bool, error) {
	// POSIX glob also supports named character classes, collating symbols, and
	// equivalence classes. filepath.Match does not. Refuse those constructs so an
	// Include cannot silently disappear from this safety scan.
	if hasUnsupportedPOSIXBracketConstruct(pattern) {
		return false, filepath.ErrBadPattern
	}
	var normalized strings.Builder
	normalized.Grow(len(pattern))
	escaped := false
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if !escaped && ch == '[' && i+1 < len(pattern) && pattern[i+1] == '!' {
			normalized.WriteString("[^")
			i++
			escaped = false
			continue
		}
		normalized.WriteByte(ch)
		if ch == '\\' && !escaped {
			escaped = true
		} else {
			escaped = false
		}
	}
	return filepath.Match(normalized.String(), name)
}

func hasUnsupportedPOSIXBracketConstruct(pattern string) bool {
	inBracket := false
	escaped := false
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if !inBracket {
			if ch == '[' {
				inBracket = true
			}
			continue
		}
		if ch == '[' && i+1 < len(pattern) && strings.ContainsRune(":.=", rune(pattern[i+1])) {
			return true
		}
		if ch == ']' {
			inBracket = false
		}
	}
	return false
}

func globHasMeta(path string) bool { return strings.ContainsAny(path, `*?[\`) }

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

// LoginReport describes whether sshd's effective config contains a known blocker
// or an unevaluated rule for one account. Detail carries the offending effective
// value, so a message can quote what it found rather than a generic complaint.
type LoginReport struct {
	Blockers []Blocker
	Warnings []string // human-facing English notes; the cli renders them verbatim
	Detail   map[Blocker]string

	// Unverifiable holds the rules that could match this account but whose verdict
	// depends on something the tool cannot know — today, only the address half of
	// an `AllowUsers user@host` pattern, because nobody can say which IP the
	// invitee will connect from. Such a rule is neither a pass nor a blocker: it
	// means "no verdict". An invite must not be stamped verified while one stands,
	// and a grant must not claim a conclusive configuration result.
	Unverifiable []string

	// AlgoDirective is the directive name sshd itself used for the accepted
	// public-key algorithms — PubkeyAcceptedAlgorithms, or PubkeyAcceptedKeyTypes
	// on sshd older than 8.5. A fix must write back the spelling the host's own
	// sshd understands, or sshd will refuse to start on the file we just wrote.
	AlgoDirective string
}

// OK reports whether the effective-config check produced no blocker.
func (r LoginReport) OK() bool { return len(r.Blockers) == 0 }

// Certain reports whether the effective-config check produced no blocker and could
// evaluate every relevant rule. Only a Certain report may be printed as "verified
// against the effective sshd config"; it does not prove an end-to-end login.
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

// CheckKeyLogin evaluates c for an ed25519 key planned for
// ~/.ssh/authorized_keys. groups are the account's group names (its primary group
// is enough for a freshly created account); pass the predicted group before the
// account exists.
//
// It is used twice: once before anything is created (to refuse or to offer a
// fix), and once after a drop-in is written (to confirm the effective config
// contains the intended change). Reusing one function for both keeps the invite's
// configuration verdict tied to the same check.
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

// CheckPasswordLogin evaluates c for the planned password credential. It exists
// so --password-login is refused when the check reports a blocker or cannot fully
// evaluate that authentication method.
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
	// Allow: require a conclusive match. An address-qualified entry yields no verdict
	// rather than a pass. It must NOT become a blocker either: the automatic fix
	// would then write `AllowUsers <account>`, quietly cancelling the operator's
	// network restriction for this account — repairing the report by weakening the
	// host.
	if allow := c.Values("allowusers"); len(allow) > 0 {
		allowed, unsure := matchesAllow(allow, []string{user})
		switch {
		case allowed:
			// A bare entry admits the account from anywhere; the address-qualified ones
			// are then redundant, so the config conclusively admits the account and
			// there is nothing unverifiable to carry.
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
// (an entry may carry a user@host suffix, whose host half is not ours to judge).
func userHalf(pattern string, names []string) bool {
	if i := strings.Index(pattern, "@"); i >= 0 {
		pattern = pattern[:i]
	}
	for _, n := range names {
		if n == "" {
			continue
		}
		if matchSSHDPattern(pattern, n) {
			return true
		}
	}
	return false
}

// matchSSHDPattern reports whether s matches an OpenSSH pattern, per sshd's own
// match.c: only '*' (any run, including empty) and '?' (exactly one character)
// are special — every other byte, notably '[' and ']', is literal.
//
// This deliberately does NOT use path.Match, whose bracket character classes
// sshd does not implement. The divergence is not cosmetic: for a config carrying
// AllowUsers admin-[0-9], path.Match says the account admin-5 is admitted while
// sshd would compare against the literal name "admin-[0-9]" and refuse it — the
// tool would print a verified invite for a login that cannot work.
func matchSSHDPattern(pattern, s string) bool {
	// Iterative backtracking: linear in the common case, and immune to the
	// exponential blowup a naive recursion hits on patterns full of '*'.
	var star, mark int = -1, 0
	i, j := 0, 0
	for i < len(s) {
		switch {
		case j < len(pattern) && (pattern[j] == '?' || pattern[j] == s[i]):
			i++
			j++
		case j < len(pattern) && pattern[j] == '*':
			star, mark = j, i // remember the '*' and where it started consuming
			j++
		case star >= 0:
			j = star + 1 // backtrack: let the last '*' swallow one more byte
			mark++
			i = mark
		default:
			return false
		}
	}
	for j < len(pattern) && pattern[j] == '*' {
		j++
	}
	return j == len(pattern)
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
