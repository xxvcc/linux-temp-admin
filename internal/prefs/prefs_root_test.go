//go:build integration

package prefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetLangCreatesTheConfiguredFileParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	root := t.TempDir()
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal(err)
	}
	old := File
	File = filepath.Join(root, "custom-state", "prefs")
	t.Cleanup(func() { File = old })

	if err := SetLang("en"); err != nil {
		t.Fatal(err)
	}
	if got := Lang(); got != "en" {
		t.Fatalf("Lang=%q, want en", got)
	}
	if _, err := os.Stat(filepath.Dir(File)); err != nil {
		t.Fatalf("configured preference parent was not created: %v", err)
	}
}
