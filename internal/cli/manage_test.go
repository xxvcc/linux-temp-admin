package cli

import (
	"strings"
	"testing"
)

// TestManageUsersEmptyRegistryDoesNotPrompt: with nothing to act on there is
// nothing to choose, so the screen must not ask. Anything queued on stdin is a
// menu choice, and consuming it here would spend it on this prompt instead.
//
// It lives in the ordinary suite because it seeds nothing: every other test of
// this screen needs a registry row, and writing one means writing root-owned
// state, so they are in manage_root_test.go behind the integration tag.
func TestManageUsersEmptyRegistryDoesNotPrompt(t *testing.T) {
	a, out, errb := newTestApp(t, "1\n")
	if rc := a.manageUsers(); rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if !strings.Contains(out.String(), "(none)") {
		t.Errorf("want an empty list, got: %q", out.String())
	}
	// The prompt is written to stderr, so that is where its absence has to be
	// asserted; checking stdout would pass whether or not it prompted.
	if strings.Contains(errb.String(), "Enter returns") {
		t.Errorf("must not prompt with an empty list: %q", errb.String())
	}
}
