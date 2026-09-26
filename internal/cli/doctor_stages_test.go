package cli

import (
	"bytes"
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

// doctor runs in its own process and never calls Registry.Init, so a lost
// registry has to be observed from the host rather than from a flag only invite
// and revoke can set. What matters is the sentence the operator reads.
func TestDoctorReportsALostRegistryDataFileItNeverInitialized(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root-owned identity-sequence metadata requires root")
	}
	newHost := func(t *testing.T, sequence string) (*App, *bytes.Buffer) {
		t.Helper()
		a, _, errb := newTestApp(t, "")
		if sequence != "" {
			if err := os.WriteFile(filepath.Join(a.Registry.Dir, "identity-sequence"), []byte(sequence), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return a, errb
	}

	t.Run("sequence records prior allocations while the data file is gone", func(t *testing.T) {
		a, errb := newHost(t, "# linux-temp-admin identity sequence v1\nhighest\t1500\nsafe-after\tnone\n")
		_, result := a.doctorRegistryIdentity()
		got := errb.String()
		if !strings.Contains(got, "the registry data file was missing") || !strings.Contains(got, "1500") {
			t.Fatalf("doctor output = %q, want the lost-registry warning naming the high-water mark", got)
		}
		if !strings.Contains(got, "Restore the registry from trusted backup") {
			t.Fatalf("doctor output = %q, want the operator told what to do", got)
		}
		if result.status() == 0 {
			t.Fatal("doctor exited 0 on a host whose registry rows are gone")
		}
	})

	t.Run("a migrated v2 sequence proves prior use through its deadline alone", func(t *testing.T) {
		a, errb := newHost(t, "# linux-temp-admin identity sequence v1\nhighest\t0\nsafe-after\t2026-08-01T12:01:05Z\n")
		_, result := a.doctorRegistryIdentity()
		if got := errb.String(); !strings.Contains(got, "the registry data file was missing") {
			t.Fatalf("doctor output = %q, want the warning for a migrated-v2 host too", got)
		}
		if result.status() == 0 {
			t.Fatal("doctor exited 0 on a migrated host whose registry rows are gone")
		}
	})

	t.Run("a fresh install says nothing about a lost registry", func(t *testing.T) {
		a, errb := newHost(t, "# linux-temp-admin identity sequence v1\nhighest\t0\nsafe-after\tnone\n")
		a.doctorRegistryIdentity()
		if got := errb.String(); strings.Contains(got, "the registry data file was missing") {
			t.Fatalf("doctor output = %q, want no lost-registry warning on a fresh install", got)
		}
	})
}
