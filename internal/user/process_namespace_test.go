package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type namespaceFixture struct {
	owner     uint32
	parent    string
	ownerErr  error
	parentErr error
}

// Model kernel namespace handles with ordinary temporary files. These tests do
// not create user namespaces, run account helpers, or signal real processes.
func syntheticUserNamespaces(t *testing.T, nodes map[string]namespaceFixture) func(string, string) {
	t.Helper()
	dir := t.TempDir()
	byInode := map[uint64]namespaceFixture{}
	for name, node := range nodes {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Fatal(err)
		}
		byInode[st.Ino] = node
	}
	lookup := func(fd int) namespaceFixture {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		node, ok := byInode[st.Ino]
		if !ok {
			t.Fatalf("unexpected namespace handle %d", fd)
		}
		return node
	}
	oldOwner, oldParent := userNamespaceOwner, userNamespaceParent
	t.Cleanup(func() { userNamespaceOwner, userNamespaceParent = oldOwner, oldParent })
	userNamespaceOwner = func(fd int) (uint32, error) {
		node := lookup(fd)
		return node.owner, node.ownerErr
	}
	userNamespaceParent = func(fd int) (int, error) {
		node := lookup(fd)
		if node.parentErr != nil {
			return -1, node.parentErr
		}
		return unix.Open(filepath.Join(dir, node.parent), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	link := func(path, name string) {
		t.Helper()
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, name), path); err != nil {
			t.Fatal(err)
		}
	}
	link(filepath.Join(procRoot, "self", "ns", "user"), "root")
	return link
}

func TestProcessSnapshotAttributesUserNamespaceAncestry(t *testing.T) {
	const uid = 2345
	for _, tc := range []struct {
		name      string
		namespace string
		wantMatch bool
		wantError string
	}{
		{name: "caller namespace", namespace: "root"},
		{name: "legacy subordinate identity", namespace: "owned", wantMatch: true},
		{name: "nested subordinate owner", namespace: "nested", wantMatch: true},
		{name: "unrelated namespace", namespace: "unrelated"},
		{name: "owner unreadable", namespace: "unreadable", wantError: "read user namespace owner"},
		{name: "parent outside scope", namespace: "outside", wantError: "read parent user namespace"},
		{name: "owner match outside scope", namespace: "outside-owned", wantError: "read parent user namespace"},
		{name: "bounded ancestry", namespace: "cycle", wantError: "nesting limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setProcRoot(t, map[int]string{77: "State:\tS (sleeping)\nUid:\t100001\t100001\t100001\t100001\n"})
			link := syntheticUserNamespaces(t, map[string]namespaceFixture{
				// Traversing the caller's parent would fail. It must be recognized
				// by namespace identity before issuing either ioctl.
				"root":          {ownerErr: unix.EPERM, parentErr: unix.EPERM},
				"owned":         {owner: uid, parent: "root"},
				"nested":        {owner: 100001, parent: "owned"},
				"unrelated":     {owner: 3456, parent: "root"},
				"unreadable":    {ownerErr: unix.ENOTTY},
				"outside":       {owner: 3456, parentErr: unix.EPERM},
				"outside-owned": {owner: uid, parentErr: unix.EPERM},
				"cycle":         {owner: 3456, parent: "cycle"},
			})
			link(filepath.Join(procRoot, "77", "task", "77", "ns", "user"), tc.namespace)
			pids, stable, err := processSnapshotForUID(uid)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || stable {
					t.Fatalf("snapshot = %v, %v, %v; want refusal %q", pids, stable, err, tc.wantError)
				}
				return
			}
			if err != nil || !stable || (len(pids) == 1) != tc.wantMatch {
				t.Fatalf("snapshot = %v, %v, %v; want match=%v", pids, stable, err, tc.wantMatch)
			}
		})
	}
}

func TestNamespaceDisappearanceCannotProveUIDAbsent(t *testing.T) {
	setProcRoot(t, map[int]string{77: "State:\tS (sleeping)\nUid:\t100001\t100001\t100001\t100001\n"})
	if err := os.Remove(filepath.Join(procRoot, "77", "task", "77", "ns", "user")); err != nil {
		t.Fatal(err)
	}
	pids, stable, err := processSnapshotForUID(2345)
	if err != nil || stable || len(pids) != 0 {
		t.Fatalf("vanished namespace snapshot = %v, %v, %v", pids, stable, err)
	}
	if _, err := processesForUID(2345); err == nil || !strings.Contains(err.Error(), "no consecutive stable empty") {
		t.Fatalf("missing namespace error = %v, want unstable scan refusal", err)
	}
}

func TestTerminateProcessesIncludesNamespaceOwnedWorker(t *testing.T) {
	setProcRoot(t, map[int]string{77: "State:\tZ (zombie)\nUid:\t100001\t100001\t100001\t100001\n"})
	writeProcTask(t, 77, 78, "State:\tS (sleeping)\nUid:\t100001\t100001\t100001\t100001\n")
	link := syntheticUserNamespaces(t, map[string]namespaceFixture{
		"root":  {},
		"owned": {owner: 2345, parent: "root"},
	})
	link(filepath.Join(procRoot, "77", "task", "78", "ns", "user"), "owned")
	var signals []unix.Signal
	withFakePidfds(t, func(fd int, sig unix.Signal, _ *unix.Siginfo, _ int) error {
		if fd != 10077 {
			t.Fatalf("unexpected pidfd %d", fd)
		}
		signals = append(signals, sig)
		if sig == unix.SIGKILL {
			return os.RemoveAll(filepath.Join(procRoot, "77"))
		}
		return nil
	})
	if err := TerminateProcesses(2345); err != nil {
		t.Fatal(err)
	}
	if want := []unix.Signal{unix.SIGTERM, unix.SIGKILL}; !reflect.DeepEqual(signals, want) {
		t.Fatalf("signals = %v, want %v", signals, want)
	}
}

func TestNamespaceOwnershipRecheckedAfterPidfdOpen(t *testing.T) {
	setProcRoot(t, map[int]string{77: "State:\tS (sleeping)\nUid:\t100001\t100001\t100001\t100001\n"})
	link := syntheticUserNamespaces(t, map[string]namespaceFixture{
		"root":  {},
		"owned": {owner: 2345, parent: "root"},
	})
	namespacePath := filepath.Join(procRoot, "77", "task", "77", "ns", "user")
	link(namespacePath, "owned")
	withFakePidfds(t, func(int, unix.Signal, *unix.Siginfo, int) error {
		t.Fatal("signalled process after namespace ownership changed")
		return nil
	})
	pidfdOpen = func(int, int) (int, error) {
		link(namespacePath, "root")
		return 10077, nil
	}
	if pids, err := signalUID(unix.SIGKILL, 2345); err != nil || len(pids) != 0 {
		t.Fatalf("signalUID = %v, %v", pids, err)
	}
}

func TestTaskUserNamespaceBoundaryUsesRealKernelNamespace(t *testing.T) {
	// This is a harmless read of the calling test process, without unshare or
	// privileged setup. A caller namespace must not require an owner/parent ioctl.
	old := procRoot
	procRoot = "/proc"
	t.Cleanup(func() { procRoot = old })
	owned, err := taskUserNamespaceOwnedBy(os.Getpid(), os.Getpid(), 2345)
	if err != nil || owned {
		t.Fatalf("self namespace = %v, %v", owned, err)
	}
	// Verify the kernel's owner ioctl is accepted by this runtime, independently
	// of the synthetic ancestry tests. Its value is in the caller's user namespace.
	ns, err := os.Open("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if _, err := unix.IoctlGetUint32(int(ns.Fd()), unix.NS_GET_OWNER_UID); err != nil && !errors.Is(err, syscall.EINVAL) {
		t.Fatal(fmt.Errorf("read kernel namespace owner: %w", err))
	}
}
