package cli

import (
	"bytes"
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
)

// ynStr renders a bool as "yes"/"no" for audit fields.
func ynStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// inviteBundle is everything the printed invite needs. It is a struct because
// the invite's honesty now depends on several facts at once (which secret was
// issued, whether sshd was asked, whether the claim was verified), and a
// positional argument list that long is one transposition away from printing a
// lie.
type inviteBundle struct {
	user, host string
	port       int
	sudo, auto bool
	permanent  bool
	expires    string
	// expiresServerLocal is the same instant in the server's zone, shown only
	// when the server is not already on UTC.
	expiresServerLocal string
	autoUnit           string
	kp                 *sshkey.KeyPair // nil for a password invite
	password           []byte          // nil for a key invite
	sshdDropIn         string          // empty when sshd was not touched
	verified           bool            // the effective-config check completed without a blocker or unknown
	unverified         string          // why it could not be confirmed; set exactly when verified is false
}

func loginKind(p loginPlan) string {
	if p.password {
		return "password"
	}
	return "key"
}

// byPassword reports whether this invite's credential is a password. Exactly one
// secret is ever issued, so a non-empty password is what distinguishes the two
// kinds of invite.
func (b inviteBundle) byPassword() bool { return len(b.password) != 0 }

// loginLine renders the invite's Login: field. It is a computed value, never a
// literal: the old invite asserted "SSH key only" on every host, including the
// ones where sshd would refuse the key.
func (b inviteBundle) loginLine() string {
	login := "SSH key only"
	if b.byPassword() {
		login = "password"
	}
	if b.verified {
		return login + " (verified against the effective sshd config)"
	}
	reason := b.unverified
	if reason == "" {
		reason = "the effective sshd config could not be read"
	}
	return login + " (UNVERIFIED: " + reason + ")"
}

// inviteRenderReserve is the capacity printInvite reserves before it writes
// anything. It is far above any real invite (the largest part, an ed25519
// OpenSSH PEM, is well under a kilobyte) so the render never outgrows its first
// allocation. See printInvite for why that matters.
const inviteRenderReserve = 16 << 10

func (a *App) printInvite(b inviteBundle) error {
	var out bytes.Buffer
	// Reserve the whole render up front. clear() below can only zero the buffer's
	// CURRENT backing array, and every write past capacity makes bytes.Buffer
	// allocate a new array, copy into it, and orphan the old one. Writes continue
	// after the private-key heredoc — the security note always, the sshd and
	// permanent-account notes sometimes — so without this the orphaned array still
	// holds the complete one-time PEM, unreachable and unclearable, for the rest of
	// the process's life. In menu mode that is until the operator quits, across
	// later privileged actions and into any swap or hibernation image. Reserving
	// once keeps the key in a single array the deferred clear actually reaches.
	out.Grow(inviteRenderReserve)
	defer func() { clear(out.Bytes()) }()
	if b.kp != nil {
		defer clear(b.kp.PrivatePEM)
	}
	// The password gets the same treatment the key already had. It is the only
	// other credential this function renders, and it is equally unrecoverable once
	// the invite is printed.
	if len(b.password) != 0 {
		defer clear(b.password)
	}
	yesno := func(v bool) string {
		if v {
			return "yes"
		}
		return "no"
	}
	passwordLine := "disabled"
	if b.byPassword() {
		passwordLine = "enabled (this invite's only credential)"
	}
	fmt.Fprintf(&out, `
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: %s
Port: %d
User: %s
Expires: %s%s
Sudo: %s
Login: %s
Password login: %s
Auto revoke: %s
Auto revoke unit: %s
Sshd exception: %s
`,
		b.host, b.port, b.user, b.expires, b.serverLocalSuffix(), yesno(b.sudo),
		b.loginLine(), passwordLine, yesno(b.auto), orNone(b.autoUnit), orNone(b.sshdDropIn))

	// The credential only. The SSH login command that used to sit here was dropped:
	// the header carries the Host, Port, and User to build it from, and the noise
	// was not worth it for a recipient who runs ssh.
	if b.byPassword() {
		fmt.Fprintf(&out, "\n%s\n%s\n",
			a.P.M("登录密码（只显示这一次）:", "Login password (shown only once):"), b.password)
	} else {
		fmt.Fprintf(&out, `
%s
(
umask 077
set -C
[ ! -e './%s.key' ] && [ ! -L './%s.key' ] || exit 1
cat > './%s.key' <<'EOF_KEY'
%sEOF_KEY
)
`,
			a.P.M("保存私钥命令:", "Save private key command:"), b.user, b.user, b.user, b.kp.PrivatePEM)
	}

	if b.sshdDropIn != "" {
		fmt.Fprint(&out, "\n"+a.P.M(
			"Sshd 提示: 已为该账号单独写入一个 sshd 例外（仅 Match User 块，全局策略未改动）；撤销时会删除该文件并 reload sshd。",
			"Sshd note: a per-account sshd exception was written (a Match User block only; the global policy is untouched). Revoking deletes that file and reloads sshd.")+"\n")
	}
	if b.byPassword() {
		fmt.Fprint(&out, "\n"+a.P.M(
			"密码提示: 密码登录可被全网爆破，且必须以明文交付；这是本工具最弱的一种授权方式，用完请立即撤销。",
			"Password note: a password login is brute-forceable from anywhere and must be delivered in the clear. This is the weakest grant this tool issues; revoke as soon as you are done.")+"\n")
	}
	if b.permanent {
		fmt.Fprint(&out, "\n"+a.P.M(
			"永久账号提示: 未选择自动删除，此账号不会过期、不会被自动删除；用完请手动撤销（revoke）。",
			"Permanent-account note: auto-delete was not chosen, so this account does not expire and is not auto-deleted. Revoke it by hand when done.")+"\n")
	}
	secret := a.P.M("私钥", "private key")
	if b.byPassword() {
		secret = a.P.M("密码", "password")
	}
	fmt.Fprint(&out, "\n"+a.P.M(
		"安全提醒: "+secret+"只显示这一次、服务器不保存；仅通过可信私聊发送；用完立即撤销。",
		"Security notes: the "+secret+" is shown only once and not stored on the server; send only via trusted private chat; revoke immediately after use.")+
		"\n\n----- END LINUX TEMP ADMIN INVITE -----\n")
	_, err := a.Out.Write(out.Bytes())
	return err
}

// --- helpers ---

// serverLocalSuffix appends the server's own rendering of the deadline after the
// authoritative UTC one. The recipient acts on Expires, so the UTC instant leads;
// the operator reading the same bundle still gets the local time, with a numeric
// offset rather than a zone abbreviation two regions can both claim.
func (b inviteBundle) serverLocalSuffix() string {
	if b.permanent || b.expiresServerLocal == "" {
		return ""
	}
	return " (server local " + b.expiresServerLocal + ")"
}
