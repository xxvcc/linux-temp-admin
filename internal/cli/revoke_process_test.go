package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEffectiveUIDAcceptsFullLinuxUIDRange(t *testing.T) {
	got, err := effectiveUID([]byte("Name:\ttest\nUid:\t4294967295\t4294967295\t4294967295\t4294967295\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != ^uint32(0) {
		t.Fatalf("effective UID = %d, want %d", got, ^uint32(0))
	}
}

const testInstallPath = "/usr/local/sbin/linux-temp-admin"

func writeProcProcess(t *testing.T, root, pid string, uid int, argv ...string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var cmdline []byte
	for _, arg := range argv {
		cmdline = append(cmdline, []byte(arg)...)
		cmdline = append(cmdline, 0)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), cmdline, 0o600); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\ttest\nUid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunningLegacyRevokeProcessRecognizesKnownRootCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{name: "five argument release", argv: []string{testInstallPath, "revoke", "--user", "xxvcc-a1", "--yes"}},
		{name: "eight argument release", argv: []string{testInstallPath, "revoke", "--user", "xxvcc-a1", "--yes", "--force", "--confirm-force", "xxvcc-a1"}},
		{name: "at shell", argv: []string{"/bin/sh", "-c", testInstallPath + " revoke --user xxvcc-a1 --yes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeProcProcess(t, root, "123", 0, tc.argv...)
			found, err := runningLegacyRevokeProcess(root, testInstallPath, "xxvcc-a1")
			if err != nil || !found {
				t.Fatalf("runningLegacyRevokeProcess = (%v, %v), want (true, nil)", found, err)
			}
		})
	}
}

func TestRunningLegacyRevokeProcessRejectsLookalikesAndBoundCommands(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "101", 1001, testInstallPath, "revoke", "--user", "xxvcc-a1", "--yes")
	writeProcProcess(t, root, "102", 0, testInstallPath+"-helper", "revoke", "--user", "xxvcc-a1", "--yes")
	writeProcProcess(t, root, "103", 0, testInstallPath, "revoke", "--user", "someone-else", "--yes")
	writeProcProcess(t, root, "104", 0, testInstallPath, "revoke", "--user", "xxvcc-a1", "--yes", "--force", "--confirm-force", "xxvcc-a1", "--expected-uid", "1001", "--generation", "0123456789abcdef0123456789abcdef")

	found, err := runningLegacyRevokeProcess(root, testInstallPath, "xxvcc-a1")
	if err != nil || found {
		t.Fatalf("runningLegacyRevokeProcess = (%v, %v), want (false, nil)", found, err)
	}
}

func TestRunningLegacyRevokeProcessFailsClosedOnMatchingMalformedIdentity(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "123")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmdline := testInstallPath + "\x00revoke\x00--user\x00xxvcc-a1\x00--yes\x00"
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\ttest\nUid:\tbroken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runningLegacyRevokeProcess(root, testInstallPath, "xxvcc-a1"); err == nil {
		t.Fatal("matching process with malformed credentials was ignored")
	}
}

func TestRunningLegacyRevokeProcessIgnoresOversizedUnrelatedCmdline(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "123", 1001, "/usr/bin/unrelated", strings.Repeat("x", int(procCmdlineMaxBytes)))

	found, err := runningLegacyRevokeProcess(root, testInstallPath, "xxvcc-a1")
	if err != nil || found {
		t.Fatalf("runningLegacyRevokeProcess = (%v, %v), want (false, nil)", found, err)
	}
}

func TestRunningLegacyRevokeProcessRecognizesOversizedMatchingShellPrefix(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "123", 0,
		"/bin/sh", "-c", testInstallPath+" revoke --user xxvcc-a1 --yes",
		strings.Repeat("x", int(procCmdlineMaxBytes)))

	found, err := runningLegacyRevokeProcess(root, testInstallPath, "xxvcc-a1")
	if err != nil || !found {
		t.Fatalf("runningLegacyRevokeProcess = (%v, %v), want (true, nil)", found, err)
	}
}
