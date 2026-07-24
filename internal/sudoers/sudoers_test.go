package sudoers

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOrphansFindsGrantsWhoseAccountIsGone pins the M1 fix. An orphaned
// NOPASSWD:ALL drop-in is the most dangerous leftover this tool can produce — it
// re-arms full root the instant its username is reused — so it must be findable.
func TestOrphansFindsGrantsWhoseAccountIsGone(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		filePrefix + "xxvcc-gone",  // ours, account deleted -> orphan
		filePrefix + "xxvcc-alive", // ours, account exists -> not an orphan
		"90-someone-elses-file",    // not ours: never report or remove it
		filePrefix + "BAD NAME",    // ours-looking but not a valid username -> ignore
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x ALL=(ALL) NOPASSWD:ALL\n"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{Dir: dir}
	orphans, err := m.Orphans(func(u string) (bool, error) { return u == "xxvcc-alive", nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 1 || orphans[0] != "xxvcc-gone" {
		t.Fatalf("orphans = %v, want exactly [xxvcc-gone]", orphans)
	}
}

// TestRemoveOnlyTouchesItsOwnFile: the sweep removes by username, so it must
// never reach a file this tool did not write.
func TestRemoveOnlyTouchesItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "90-someone-elses-file")
	if err := os.WriteFile(foreign, []byte("x\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	ours := filepath.Join(dir, filePrefix+"xxvcc-a1")
	if err := os.WriteFile(ours, []byte("x\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: dir}
	m.Remove("xxvcc-a1")
	if _, err := os.Lstat(ours); !os.IsNotExist(err) {
		t.Error("our own drop-in should be gone")
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Error("a file this tool does not own must survive")
	}
}
