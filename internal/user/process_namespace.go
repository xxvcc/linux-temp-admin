package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

var (
	userNamespaceOwner = func(fd int) (uint32, error) {
		return unix.IoctlGetUint32(fd, unix.NS_GET_OWNER_UID)
	}
	userNamespaceParent = func(fd int) (int, error) {
		return unix.IoctlRetInt(fd, unix.NS_GET_PARENT)
	}
)

// Linux allows at most 32 nested user namespaces. Include the caller's namespace
// as the final boundary, without asking for its inaccessible parent.
const maxUserNamespaceDepth = 32

// taskUserNamespaceOwnedBy recognizes processes whose primary UID has been
// replaced by a subordinate UID in a user namespace. The kernel retains the
// creator's effective UID as the immutable namespace owner, and
// NS_GET_OWNER_UID translates it into the caller's user namespace. Walking the
// ancestors also recognizes nested namespaces owned by a subordinate UID.
//
// This deliberately does not kill every UID currently listed in /etc/subuid:
// allocations can overlap or change, and are not proof of process ownership.
func taskUserNamespaceOwnedBy(tgid, tid, uid int) (owned bool, err error) {
	boundary, err := os.Stat(filepath.Join(procRoot, "self", "ns", "user"))
	if err != nil {
		return false, fmt.Errorf("identify caller user namespace: %w", err)
	}
	ns, err := os.Open(filepath.Join(procRoot, strconv.Itoa(tgid), "task", strconv.Itoa(tid), "ns", "user"))
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, ns.Close()) }()
	return userNamespaceOwnedBy(ns, boundary, uid, 0)
}

func userNamespaceOwnedBy(ns *os.File, boundary os.FileInfo, uid, depth int) (owned bool, err error) {
	identity, err := ns.Stat()
	if err != nil {
		return false, fmt.Errorf("identify task user namespace: %w", err)
	}
	if os.SameFile(identity, boundary) {
		return false, nil
	}
	if depth >= maxUserNamespaceDepth {
		return false, fmt.Errorf("user namespace ancestry exceeds Linux nesting limit")
	}
	owner, err := userNamespaceOwner(int(ns.Fd()))
	if err != nil {
		return false, fmt.Errorf("read user namespace owner: %w", err)
	}
	// NS_GET_PARENT permits traversal while the parent is within the caller's
	// namespace scope; it does not require CAP_SYS_ADMIN. EPERM here is therefore
	// ambiguous, not an empty result. Ordinary unrelated namespaces reach the
	// boundary above and are excluded without querying that boundary's parent.
	parentFD, err := userNamespaceParent(int(ns.Fd()))
	if err != nil {
		return false, fmt.Errorf("read parent user namespace: %w", err)
	}
	parent := os.NewFile(uintptr(parentFD), "parent-user-namespace")
	defer func() { err = errors.Join(err, parent.Close()) }()
	ancestorOwned, err := userNamespaceOwnedBy(parent, boundary, uid, depth+1)
	if err != nil {
		return false, err
	}
	// Establish that the whole ancestry reaches our namespace before accepting
	// an owner match: an owner outside this scope can be reported as overflowuid.
	return uint64(owner) == uint64(uid) || ancestorOwned, nil
}
