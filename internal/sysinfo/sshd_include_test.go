package sysinfo

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
	"golang.org/x/crypto/ssh"
)

const addressRestrictedSSHDPolicy = "Match Address 203.0.113.0/24\n    PubkeyAuthentication no\n    PasswordAuthentication no\nMatch all\n"

// Keep these paths textual: filepath.Join would remove the very component
// whose kernel resolution these regression tests exercise.
var symlinkParentIncludes = []struct{ name, path string }{
	{"literal", "link/../policy.conf"},
	{"file_glob", "link/../policy*.conf"},
	{"directory_glob", "li*/../policy.conf"},
	{"directory_and_file_glob", "li*/../policy*.conf"},
	{"dot_after_glob", "li*/./../policy.conf"},
}

func writeSSHDIncludeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newSSHDIncludeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, child := range []string{"real/leaf", "dropins"} {
		if err := os.MkdirAll(dir+"/"+child, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("real/leaf", dir+"/link"); err != nil {
		t.Fatal(err)
	}
	oldConfig, oldDropins := sshdConfigPath, sshdConfigDropInDir
	sshdConfigPath, sshdConfigDropInDir = dir+"/sshd_config", dir+"/dropins"
	t.Cleanup(func() { sshdConfigPath, sshdConfigDropInDir = oldConfig, oldDropins })
	return dir
}

func TestSSHDIncludePreservesSymlinkParentResolution(t *testing.T) {
	dir := newSSHDIncludeFixture(t)
	for _, base := range []struct{ name, path string }{{"relative", ""}, {"absolute", dir + "/"}} {
		for _, include := range symlinkParentIncludes {
			pattern := base.path + include.path
			t.Run(base.name+"/"+include.name, func(t *testing.T) {
				writeSSHDIncludeFixture(t, sshdConfigPath, "Include "+pattern+"\n")
				for _, restricted := range []bool{true, false} {
					actual, decoy := "# unrestricted\n", addressRestrictedSSHDPolicy
					if restricted {
						actual, decoy = decoy, actual
					}
					writeSSHDIncludeFixture(t, dir+"/real/policy.conf", actual)
					writeSSHDIncludeFixture(t, dir+"/policy.conf", decoy)
					if got := HasUnverifiableMatch(true); got != restricted {
						t.Fatalf("Include %q: unverifiable=%v, want %v from the kernel-resolved file", pattern, got, restricted)
					}
				}
			})
		}
	}

	// A previously scanned lexical spelling must not hide a different inode.
	writeSSHDIncludeFixture(t, dir+"/policy.conf", "# harmless decoy\n")
	writeSSHDIncludeFixture(t, dir+"/real/policy.conf", addressRestrictedSSHDPolicy)
	writeSSHDIncludeFixture(t, sshdConfigPath, "Include policy.conf link/../policy.conf\n")
	if !HasUnverifiableMatch(true) {
		t.Fatal("an earlier lexical path hid the distinct symlink/.. target")
	}
}

func TestSSHDIncludeDistinguishesCompletedInodesFromCycles(t *testing.T) {
	dir := newSSHDIncludeFixture(t)
	writeSSHDIncludeFixture(t, dir+"/policy.conf", "Match User alice\n    PubkeyAuthentication yes\nMatch all\n")
	if err := os.Symlink("policy.conf", dir+"/alias.conf"); err != nil {
		t.Fatal(err)
	}
	writeSSHDIncludeFixture(t, sshdConfigPath, "Include policy.conf alias.conf\n")
	if HasUnverifiableMatch(true) {
		t.Fatal("repeating a completely scanned inode must not make the policy unverifiable")
	}
	writeSSHDIncludeFixture(t, dir+"/policy.conf", "Include alias.conf\n")
	if !HasUnverifiableMatch(true) {
		t.Fatal("a recursive Include was mistaken for a complete scan")
	}
}

func TestSSHDIncludeSymlinkParentAgreesWithOpenSSH(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd is unavailable")
	}
	dir := newSSHDIncludeFixture(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.MarshalPrivateKey(private, "sshd Include test")
	if err != nil {
		t.Fatal(err)
	}
	writeSSHDIncludeFixture(t, dir+"/host_key", string(pem.EncodeToMemory(key)))
	writeSSHDIncludeFixture(t, dir+"/policy.conf", "# harmless lexical path\n")
	writeSSHDIncludeFixture(t, dir+"/real/policy.conf", addressRestrictedSSHDPolicy)

	// OpenSSH resolves relative Include paths against its compiled /etc/ssh,
	// even with -f. Point back to our temp fixture without writing to /etc/ssh.
	relativeDir, err := filepath.Rel("/etc/ssh", dir)
	if err != nil {
		t.Fatal(err)
	}
	probe := func(t *testing.T, connection string) *SSHDConfig {
		t.Helper()
		out, err := executil.CombinedOutput(sshd, []string{"-T", "-f", sshdConfigPath, "-C", connection}, sshdProbeOptions)
		if err != nil {
			if strings.Contains(string(out), "Missing privilege separation directory") {
				t.Skip("sshd's required privilege-separation directory is absent; tests do not create system paths")
			}
			t.Fatalf("sshd -T: %v: %s", err, out)
		}
		return ParseSSHD(string(out))
	}
	for _, base := range []struct{ name, path string }{{"absolute", dir}, {"relative", relativeDir}} {
		for _, include := range symlinkParentIncludes {
			pattern := base.path + "/" + include.path
			t.Run(base.name+"/"+include.name, func(t *testing.T) {
				writeSSHDIncludeFixture(t, sshdConfigPath, "HostKey "+dir+"/host_key\nUsePAM no\nPubkeyAuthentication yes\nPasswordAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys\nInclude "+pattern+"\n")
				withoutAddress := probe(t, "user="+acct)
				withAddress := probe(t, "user="+acct+",addr=203.0.113.25,host=client.example")
				for _, directive := range []string{"pubkeyauthentication", "passwordauthentication"} {
					if withoutAddress.First(directive) != "yes" || withAddress.First(directive) != "no" {
						t.Fatalf("sshd fixture did not expose the address-dependent %s policy: without=%q with=%q", directive, withoutAddress.First(directive), withAddress.First(directive))
					}
				}
				scan := &sshdIncludeScan{identities: map[sshdConfigIdentity]bool{}, accountExists: true}
				found, complete := fileHasConnectionScopedMatch(sshdConfigPath, "/etc/ssh", scan, 0)
				if !found || !complete {
					t.Fatalf("scanner missed the Match rule sshd used: found=%v complete=%v", found, complete)
				}
			})
		}
	}
}
