package legacy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingsNoneWhenClean(t *testing.T) {
	d := &Detector{
		V1RegistryFile: filepath.Join(t.TempDir(), "users.tsv"), // absent
		SystemdDir:     t.TempDir(),                             // empty
	}
	if f := d.Findings(); len(f) != 0 {
		t.Errorf("expected no findings, got %v", f)
	}
}

func TestFindingsDetectsV1RegistryAndUnits(t *testing.T) {
	sd := t.TempDir()
	reg := filepath.Join(t.TempDir(), "users.tsv")
	if err := os.WriteFile(reg, []byte("legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// v1 units (should be flagged)
	for _, n := range []string{"linux-temp-admin-revoke-xxvcc-a1.service", "linux-temp-admin-revoke-xxvcc-a1.timer"} {
		os.WriteFile(filepath.Join(sd, n), []byte("x"), 0o644)
	}
	// v2 units and unrelated files (should NOT be flagged)
	os.WriteFile(filepath.Join(sd, "linux-temp-admin-v2-revoke-xxvcc-b2.timer"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(sd, "sshd.service"), []byte("x"), 0o644)

	d := &Detector{V1RegistryFile: reg, SystemdDir: sd}
	findings := d.Findings()
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "legacy v1 registry present") {
		t.Errorf("registry not reported: %v", findings)
	}
	if !strings.Contains(joined, "linux-temp-admin-revoke-xxvcc-a1.service") ||
		!strings.Contains(joined, "linux-temp-admin-revoke-xxvcc-a1.timer") {
		t.Errorf("v1 units not reported: %v", findings)
	}
	if strings.Contains(joined, "-v2-revoke-") {
		t.Errorf("v2 unit was wrongly flagged as legacy: %v", findings)
	}
}
