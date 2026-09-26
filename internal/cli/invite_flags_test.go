package cli

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
)

// `--sudo --yes` without `--user` used to fail with a message naming the
// throwaway username this run had just generated. The next run generated a
// different one, so an operator automating "create a sudo temp admin" looped
// forever on an instruction that could never be satisfied.
func TestSudoYesWithoutAnExplicitUserNamesTheRealRequirement(t *testing.T) {
	a, _, errb := newTestApp(t, "")

	rc := a.invite([]string{"--host", "203.0.113.5", "--hours", "24", "--sudo", "--yes",
		"--allow-non-tty-private-key-output"})
	if rc == 0 {
		t.Fatal("invite --sudo --yes without --user succeeded; it cannot confirm a generated name")
	}
	got := errb.String()
	if !strings.Contains(got, "requires an explicit --user") {
		t.Fatalf("stderr = %q, want the message to name --user as the requirement", got)
	}
	if strings.Contains(got, "xxvcc-") {
		t.Fatalf("stderr = %q, want no generated username the operator can never reuse", got)
	}
}

// A rolled-back invite must not leave the credentials it generated live in the
// process. The interactive menu keeps one root process for the whole session, so
// anything left here survives into every later action, and into swap or a core
// dump.
func TestFailedInviteZeroesTheCredentialsItGenerated(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	tx := newInviteTransaction(a, invitePlan{username: "xxvcc-a1", host: "203.0.113.5", port: 22, hours: 24, wantSudo: false, wantAuto: false, login: loginPlan{verified: true}, generatedUsername: false})

	key := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n")
	tx.kp = &sshkey.KeyPair{PrivatePEM: key}
	password := []byte("correct horse battery staple")
	tx.password = password

	tx.clearSecrets()

	for _, b := range key {
		if b != 0 {
			t.Fatalf("private key still in memory after clearSecrets: %q", key)
		}
	}
	for _, b := range password {
		if b != 0 {
			t.Fatalf("password still in memory after clearSecrets: %q", password)
		}
	}

	// Idempotent: printInvite clears the same arrays on the success path.
	tx.clearSecrets()
}

// Go's flag package accepts several spellings of the same boolean. Any of them
// means "unattended", so none of them may reach the first-run language prompt —
// a prompt nobody is there to answer aborts the run.
func TestEveryYesSpellingSuppressesTheFirstRunLanguagePrompt(t *testing.T) {
	for _, arg := range []string{
		"--yes", "-yes", "--y", "-y",
		"--yes=true", "-yes=true", "--y=1", "-y=1", "--yes=false", "-y=0",
	} {
		t.Run(arg, func(t *testing.T) {
			if shouldAskLang([]string{"revoke", "--user", "xxvcc-a1", arg}, true, true, true) {
				t.Fatalf("shouldAskLang with %q = true, want an unattended run left alone", arg)
			}
		})
	}

	// Only the boolean itself: a value that happens to look like one must not
	// silently suppress the prompt for an interactive operator.
	for _, arg := range []string{"yes", "--yesterday", "--user", "-yy", "--dry-yes"} {
		t.Run("not a yes flag: "+arg, func(t *testing.T) {
			if !shouldAskLang([]string{"revoke", arg}, true, true, true) {
				t.Fatalf("shouldAskLang with %q = false, want the prompt still offered", arg)
			}
		})
	}
}

// The fix for the credential-leak finding is one line — `defer tx.clearSecrets()`
// in runInvite. A test that calls clearSecrets directly guards
// the helper, not the wiring: move, reorder or drop the defer and the leak comes
// back with the suite green. This drives a real failing invite and inspects the
// bytes the generator handed out.
func TestRolledBackInviteLeavesNoCredentialBytesInMemory(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Registry.Init writes root-owned state and requires root")
	}
	a, _, _ := newTestApp(t, "")

	issued := []byte("correct horse battery staple")
	a.RandPassword = func(int) ([]byte, error) { return issued, nil }
	// Fail immediately after the credential exists, so the run aborts on a path
	// that reaches the deferred clear and nothing else.
	a.RandHex = func(n int) (string, error) {
		if n == 16 {
			return "", errors.New("injected generation failure")
		}
		return "abcdef0123", nil
	}

	rc := a.runInvite(invitePlan{username: "xxvcc-a1", host: "203.0.113.5", port: 22, hours: 24, wantSudo: false, wantAuto: false, login: loginPlan{password: true, verified: true}, generatedUsername: false})
	if rc == 0 {
		t.Fatal("the invite was expected to fail at generation")
	}

	for i, b := range issued {
		if b != 0 {
			t.Fatalf("the issued password is still in memory after a failed invite (byte %d = %q): %q", i, b, issued)
		}
	}
}
