package sshkey

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateEd25519(t *testing.T) {
	kp, err := GenerateEd25519("xxvcc-a1-linux-temp-admin")
	if err != nil {
		t.Fatal(err)
	}

	// Private key parses and is ed25519.
	signer, err := ssh.ParsePrivateKey(kp.PrivatePEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if got := signer.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %q, want %q", got, ssh.KeyAlgoED25519)
	}

	// Authorized key parses, carries the comment, and matches the private key.
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(kp.AuthorizedKey)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if comment != "xxvcc-a1-linux-temp-admin" {
		t.Errorf("comment = %q", comment)
	}
	if string(pub.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Error("authorized key does not match the private key")
	}

	// Fingerprint matches the public key and is SHA256.
	if want := ssh.FingerprintSHA256(pub); kp.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", kp.Fingerprint, want)
	}
	if !strings.HasPrefix(kp.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint %q is not SHA256", kp.Fingerprint)
	}

	// Distinct keys each call.
	kp2, _ := GenerateEd25519("x")
	if kp2.Fingerprint == kp.Fingerprint {
		t.Error("two generated keys share a fingerprint")
	}
}
