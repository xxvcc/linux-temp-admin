package buildinfo

import (
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

func TestWitnessedReleaseVersion(t *testing.T) {
	previous := ReleaseVersionWitness
	t.Cleanup(func() { ReleaseVersionWitness = previous })
	maxVersion := "2.3.4-" + strings.Repeat("a", validate.MaxReleaseVersionBytes-len("2.3.4-"))
	for _, tc := range []struct {
		witness string
		want    string
		ok      bool
	}{
		{witness: "unreleased"},
		{witness: "LTA_RELEASE_VERSION_V1{2.9.5}", want: "2.9.5", ok: true},
		{witness: "LTA_RELEASE_VERSION_V1{12.34.56-rc.10}", want: "12.34.56-rc.10", ok: true},
		{witness: "LTA_RELEASE_VERSION_V1{" + maxVersion + "}", want: maxVersion, ok: true},
		{witness: "LTA_RELEASE_VERSION_V1{" + maxVersion + "a}"},
		{witness: "LTA_RELEASE_VERSION_V1{}"},
		{witness: "LTA_RELEASE_VERSION_V1{02.9.5}"},
		{witness: "LTA_RELEASE_VERSION_V1{2.9.5+build}"},
		{witness: "LTA_RELEASE_VERSION_V1{2.9.5}junk"},
		{witness: "LTA_RELEASE_VERSION_V1{2.9.5\n}"},
	} {
		ReleaseVersionWitness = tc.witness
		if got, ok := WitnessedReleaseVersion(); got != tc.want || ok != tc.ok {
			t.Errorf("WitnessedReleaseVersion(%q) = %q,%v, want %q,%v", tc.witness, got, ok, tc.want, tc.ok)
		}
	}
}

func TestVersionMetadataConsistent(t *testing.T) {
	previousVersion := Version
	previousWitness := ReleaseVersionWitness
	t.Cleanup(func() {
		Version = previousVersion
		ReleaseVersionWitness = previousWitness
	})

	for _, tc := range []struct {
		name    string
		version string
		witness string
		want    bool
	}{
		{name: "development defaults", version: "0.0.0-dev", witness: "unreleased", want: true},
		{name: "release", version: "2.9.5", witness: "LTA_RELEASE_VERSION_V1{2.9.5}", want: true},
		{name: "release witness missing", version: "2.9.5", witness: "unreleased"},
		{name: "development version with release witness", version: "0.0.0-dev", witness: "LTA_RELEASE_VERSION_V1{2.9.5}"},
		{name: "mismatched release", version: "2.9.5", witness: "LTA_RELEASE_VERSION_V1{2.9.4}"},
		{name: "invalid version and witness", version: "02.9.5", witness: "LTA_RELEASE_VERSION_V1{02.9.5}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			Version = tc.version
			ReleaseVersionWitness = tc.witness
			if got := VersionMetadataConsistent(); got != tc.want {
				t.Fatalf("VersionMetadataConsistent() = %v, want %v", got, tc.want)
			}
		})
	}
}
