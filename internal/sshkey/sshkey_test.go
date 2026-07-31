package sshkey

import (
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
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

func TestWriteAuthorizedKeysRejectsIDsOutsideKernelRange(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot represent a uid above uint32")
	}
	reservedKernelID := uint64(^uint32(0))
	reserved := int(reservedKernelID)
	tooLarge := reserved + 1
	for _, ids := range [][2]int{{reserved, 1}, {1, reserved}, {tooLarge, 1}, {1, tooLarge}} {
		if err := WriteAuthorizedKeys("/unused", ids[0], ids[1], nil); err == nil || !strings.Contains(err.Error(), "refusing non-user uid/gid") {
			t.Fatalf("WriteAuthorizedKeys(%d, %d) error=%v, want range refusal", ids[0], ids[1], err)
		}
	}
}

func TestSafeInitialSSHDirectoryDistinguishesNewFromExisting(t *testing.T) {
	const uid = 12345
	tests := []struct {
		name    string
		created bool
		stat    unix.Stat_t
		want    bool
	}{
		{"new root-owned", true, unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: 0}, true},
		{"new swapped to user directory", true, unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: uid}, false},
		{"existing account-owned", false, unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: uid}, true},
		{"existing foreign-owned", false, unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: 0}, false},
		{"not a directory", false, unix.Stat_t{Mode: unix.S_IFREG | 0o600, Uid: uid}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeInitialSSHDirectory(tt.stat, tt.created, uid); got != tt.want {
				t.Fatalf("safeInitialSSHDirectory() = %v, want %v", got, tt.want)
			}
		})
	}
}
