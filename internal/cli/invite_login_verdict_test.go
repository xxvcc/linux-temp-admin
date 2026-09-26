package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/expiry"
	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
)

// The Login: field is the only thing telling the operator whether this key will
// actually be accepted, and it is the basis for shipping the bundle to a
// collaborator. Nothing exercised the UNVERIFIED branch: a change that made every
// invite claim "verified" passed the entire suite.
func TestInviteRendersTheLoginVerdictItWasGiven(t *testing.T) {
	render := func(t *testing.T, b inviteBundle) string {
		t.Helper()
		a, out, _ := newTestApp(t, "")
		b.user, b.host, b.port = "xxvcc-a1", "203.0.113.5", 22
		b.expires = "2026-07-08 04:00:00 UTC"
		if b.kp == nil && !b.byPassword() {
			b.kp = &sshkey.KeyPair{PrivatePEM: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")}
		}
		if err := a.printInvite(b); err != nil {
			t.Fatalf("printInvite: %v", err)
		}
		return out.String()
	}

	const verifiedText = "verified against the effective sshd config"

	t.Run("an unverified key invite says so, and does not claim verification", func(t *testing.T) {
		got := render(t, inviteBundle{verified: false, unverified: "sshd has a Match Address block"})
		if !strings.Contains(got, "Login: SSH key only (UNVERIFIED: sshd has a Match Address block)") {
			t.Fatalf("invite = %q, want the UNVERIFIED verdict and its reason", got)
		}
		if strings.Contains(got, "Login: SSH key only ("+verifiedText) {
			t.Fatalf("invite = %q, want no verified claim on an unverified invite", got)
		}
	})

	t.Run("an unverified invite with no reason still says UNVERIFIED", func(t *testing.T) {
		got := render(t, inviteBundle{verified: false})
		if !strings.Contains(got, "UNVERIFIED: the effective sshd config could not be read") {
			t.Fatalf("invite = %q, want the fallback reason", got)
		}
	})

	t.Run("a verified key invite says verified", func(t *testing.T) {
		got := render(t, inviteBundle{verified: true})
		if !strings.Contains(got, "Login: SSH key only ("+verifiedText+")") {
			t.Fatalf("invite = %q, want the verified verdict", got)
		}
		if strings.Contains(got, "UNVERIFIED") {
			t.Fatalf("invite = %q, want no UNVERIFIED text", got)
		}
	})

	t.Run("a password invite carries the same verdict distinction", func(t *testing.T) {
		unverified := render(t, inviteBundle{password: []byte("correct horse"), unverified: "sshd has a Match Group"})
		if !strings.Contains(unverified, "Login: password (UNVERIFIED: sshd has a Match Group)") {
			t.Fatalf("password invite = %q, want the UNVERIFIED verdict", unverified)
		}
		verified := render(t, inviteBundle{password: []byte("correct horse"), verified: true})
		if !strings.Contains(verified, "Login: password ("+verifiedText+")") {
			t.Fatalf("password invite = %q, want the verified verdict", verified)
		}
	})
}

// loginSummary is the same verdict shown before the operator types YES. It has
// to agree with the bundle: approving a "verified" invite that prints
// UNVERIFIED, or the reverse, is the failure this pins.
func TestLoginSummaryStatesTheSameVerdictAsTheBundle(t *testing.T) {
	a, _, _ := newTestApp(t, "")

	if got := a.loginSummary(loginPlan{verified: true}, "xxvcc-a1"); !strings.Contains(got, "verified against the effective sshd config") {
		t.Fatalf("verified summary = %q", got)
	}
	got := a.loginSummary(loginPlan{unverified: "sshd has a Match Address block"}, "xxvcc-a1")
	if !strings.Contains(got, "UNVERIFIED: sshd has a Match Address block") {
		t.Fatalf("unverified summary = %q, want the reason the operator must weigh", got)
	}
	if strings.Contains(got, "(verified") {
		t.Fatalf("unverified summary = %q, want no verified claim", got)
	}
	if pw := a.loginSummary(loginPlan{password: true}, "xxvcc-a1"); !strings.Contains(pw, "weakest grant") {
		t.Fatalf("password summary = %q", pw)
	}
}

// The Expires line is what the recipient acts on. It used to carry an ambiguous
// zone abbreviation ("CST"), which a reader in another region resolves to a
// different instant — in the unsafe direction. The bundle now leads with the UTC
// instant the scheduler actually fires on, and adds the server's own reading with
// a numeric offset.
func TestInviteBundleExpiresIsUnambiguous(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	deadline := time.Date(2026, 7, 8, 12, 0, 0, 0, shanghai)

	render := func(t *testing.T, b inviteBundle) string {
		t.Helper()
		a, out, _ := newTestApp(t, "")
		b.user, b.host, b.port = "xxvcc-a1", "203.0.113.5", 22
		b.kp = &sshkey.KeyPair{PrivatePEM: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")}
		if err := a.printInvite(b); err != nil {
			t.Fatalf("printInvite: %v", err)
		}
		return out.String()
	}

	got := render(t, inviteBundle{
		verified:           true,
		expires:            expiry.Display(deadline),
		expiresServerLocal: expiry.DisplayServerLocal(deadline),
	})
	if !strings.Contains(got, "Expires: 2026-07-08 04:00:00 UTC") {
		t.Fatalf("invite = %q, want the UTC instant the timer fires on", got)
	}
	if !strings.Contains(got, "(server local 2026-07-08 12:00:00 +0800)") {
		t.Fatalf("invite = %q, want the server-local reading with a numeric offset", got)
	}
	for _, ambiguous := range []string{" CST", " MST", " EST", " IST"} {
		if strings.Contains(got, ambiguous) {
			t.Fatalf("invite = %q, want no zone abbreviation anywhere", got)
		}
	}

	// A UTC server must not print the same instant twice.
	utc := render(t, inviteBundle{
		verified:           true,
		expires:            expiry.Display(deadline.UTC()),
		expiresServerLocal: expiry.DisplayServerLocal(deadline.UTC()),
	})
	if strings.Contains(utc, "server local") {
		t.Fatalf("invite on a UTC server = %q, want no redundant server-local suffix", utc)
	}

	// A permanent invite has no deadline to qualify.
	perm := render(t, inviteBundle{verified: true, permanent: true, expires: "never (does not expire or auto-delete)"})
	if strings.Contains(perm, "server local") {
		t.Fatalf("permanent invite = %q, want no server-local suffix", perm)
	}
}
