package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
)

func TestDoctorStageFailuresAccumulate(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	sshdErr := errors.New("injected doctor sshd stage failure")
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) { return nil, sshdErr }
	if err := os.Mkdir(a.Registry.File, 0o700); err != nil {
		t.Fatal(err)
	}

	var combined doctorResult
	sshdResult := a.doctorSSHDProbe()
	_, registryResult := a.doctorRegistryIdentity()
	combined.merge(sshdResult)
	combined.merge(registryResult)

	if sshdResult.failures != 1 || registryResult.failures != 1 || combined.failures != 2 {
		t.Fatalf("stage failures = sshd %d registry %d combined %d, want 1, 1, 2",
			sshdResult.failures, registryResult.failures, combined.failures)
	}
	if status := combined.status(); status != 1 {
		t.Fatalf("combined doctor status = %d, want 1", status)
	}
	diagnostics := errb.String()
	sshdAt := strings.Index(diagnostics, sshdErr.Error())
	registryAt := strings.Index(diagnostics, "cannot read registry")
	if sshdAt < 0 || registryAt < 0 || sshdAt >= registryAt {
		t.Fatalf("stage diagnostics were missing or reordered: %q", diagnostics)
	}
}

func TestDoctorOrphanStageUsesConfiguredSudoersDirectory(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	sudoersDir := filepath.Join(t.TempDir(), "missing-sudoers")
	a.Sudoers = &sudoers.Manager{Dir: sudoersDir}

	result := a.doctorOrphanedArtifacts()
	if result.status() != 0 {
		t.Fatalf("unavailable sudoers directory status = %d, want warning-only status 0", result.status())
	}
	if got := errb.String(); !strings.Contains(got, sudoersDir) {
		t.Fatalf("sudoers safety check did not use configured directory %q: %q", sudoersDir, got)
	}
}

func TestDoctorOrphanStageReportsSafeConfiguredSudoersDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root-owned temporary sudoers directory")
	}
	a, out, _ := newTestApp(t, "")
	sudoersDir := t.TempDir()
	a.Sudoers = &sudoers.Manager{Dir: sudoersDir}

	result := a.doctorOrphanedArtifacts()
	if result.status() != 0 {
		t.Fatalf("safe sudoers directory status = %d, want 0", result.status())
	}
	if got := out.String(); !strings.Contains(got, sudoersDir+" looks safe") {
		t.Fatalf("safe sudoers diagnostic did not report configured directory %q: %q", sudoersDir, got)
	}
}
