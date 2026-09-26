package mountinfo

import (
	"strings"
	"testing"
)

func TestRejectUnder(t *testing.T) {
	base := "28 1 254:4 / / rw,relatime - ext4 /dev/root rw\n"
	for _, line := range []string{
		"40 28 0:40 / /home/xxvcc-u rw - tmpfs tmpfs rw\n",
		"41 28 0:41 / /home/xxvcc-u/nested rw - tmpfs tmpfs rw\n",
		"42 28 0:42 / /home/xxvcc-u/with\\040space rw - tmpfs tmpfs rw\n",
	} {
		if err := RejectUnder(strings.NewReader(base+line), "/home/xxvcc-u"); err == nil {
			t.Fatalf("mountinfo entry was accepted: %q", line)
		}
	}
	outside := base + "43 28 0:43 / /home/xxvcc-u-old rw - tmpfs tmpfs rw\n"
	if err := RejectUnder(strings.NewReader(outside), "/home/xxvcc-u"); err != nil {
		t.Fatalf("outside mount rejected: %v", err)
	}
}

func TestRejectUnderFailsClosedOnMalformedInput(t *testing.T) {
	for _, input := range []string{
		"",
		"short\n",
		"1 2 3 4 /bad\\zzzz rest\n",
		"1 2 0:1 / /home/xxvcc-u rw ext4 /dev/root rw extra\n",
		"1 2 0:1 / relative rw - ext4 /dev/root rw\n",
		"1 2 0:1 / /home/../home/xxvcc-u rw - ext4 /dev/root rw\n",
		"1 2 0:1 / /home/xxvcc-u\\057escape rw - ext4 /dev/root rw\n",
	} {
		if err := RejectUnder(strings.NewReader(input), "/home/xxvcc-u"); err == nil {
			t.Fatalf("malformed mountinfo was accepted: %q", input)
		}
	}
	validNSFS := "1 2 0:4 net:[4026532381] /run/netns/test rw - nsfs nsfs rw\n"
	if err := RejectUnder(strings.NewReader(validNSFS), "/home/xxvcc-u"); err != nil {
		t.Fatalf("valid non-path mount root rejected: %v", err)
	}
	if err := RejectUnder(nil, "/home/xxvcc-u"); err == nil {
		t.Fatal("nil mountinfo reader was accepted")
	}
}

func TestRejectUnderRejectsUnsafeRoot(t *testing.T) {
	valid := "1 2 0:1 / / rw - ext4 /dev/root rw\n"
	for _, root := range []string{"", "relative", "/", "/home/../home/xxvcc-u", "/home/xxvcc-u/"} {
		if err := RejectUnder(strings.NewReader(valid), root); err == nil {
			t.Fatalf("unsafe root %q was accepted", root)
		}
	}
}

// TestRejectUnderSplitsOnlyOnTheKernelSeparator pins the parser to mountinfo's
// actual format. The kernel escapes exactly space, tab, newline and backslash
// inside path fields, so a vertical tab reaches this parser literally.
//
// The payload matters: strings.Fields turns "/home/u/x\v/etc" into two fields,
// so the positional mountpoint read at index 4 becomes "/etc" — a perfectly
// valid absolute path that is not under the removal root. The check then passes
// the line as an unrelated mount and reports no mount under the root, while the
// real mountpoint in field 5 is /home/u/hidden. A payload whose split halves are
// not valid paths would merely trip the mountpoint validation and pass this test
// against either implementation.
func TestRejectUnderSplitsOnlyOnTheKernelSeparator(t *testing.T) {
	shifted := "50 25 0:44 /home/u/x\v/etc /home/u/hidden rw,relatime - ext4 /dev/sda1 rw\n"
	if err := RejectUnder(strings.NewReader(shifted), "/home/u"); err == nil {
		t.Fatal("RejectUnder reported no mount under the root; the mountpoint field was shifted by an unescaped byte")
	}
	// The same line without the odd byte must still be caught, so the test is not
	// merely detecting a parse refusal.
	plain := "50 25 0:44 /home/u/xetc /home/u/hidden rw,relatime - ext4 /dev/sda1 rw\n"
	if err := RejectUnder(strings.NewReader(plain), "/home/u"); err == nil {
		t.Fatal("RejectUnder accepted a plain mount under the root")
	}
	// And an unrelated mount must still pass, so it is not refusing everything.
	other := "50 25 0:44 / /var/lib/other rw,relatime - ext4 /dev/sda1 rw\n"
	if err := RejectUnder(strings.NewReader(other), "/home/u"); err != nil {
		t.Fatalf("RejectUnder rejected an unrelated mount: %v", err)
	}
}
