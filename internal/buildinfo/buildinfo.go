// Package buildinfo holds the single source of truth for the program's identity
// and version. The version is overridable at link time (-X) by the release
// pipeline; the default marks an unreleased development build.
package buildinfo

import (
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

// Name is the program / installed-command name.
const Name = "linux-temp-admin"

// Version is the semantic version. Overridden at build time via
// -ldflags "-X github.com/xxvcc/linux-temp-admin/internal/buildinfo.Version=x.y.z".
var Version = developmentVersion

// ReleaseVersionWitness is embedded only in release builds. Its framed value is
// authenticated by the detached signature and can be read without executing a
// downloaded candidate, allowing downgrade policy to run before a version probe.
// Release build commands override it with LTA_RELEASE_VERSION_V1{x.y.z}.
var ReleaseVersionWitness = unreleasedWitness

const (
	developmentVersion          = "0.0.0-dev"
	unreleasedWitness           = "unreleased"
	releaseVersionWitnessPrefix = "LTA_RELEASE_VERSION_V1{"
)

// WitnessedReleaseVersion returns the version carried by a canonical release
// witness. Development builds deliberately have no witnessed release version.
func WitnessedReleaseVersion() (string, bool) {
	witness := ReleaseVersionWitness
	if !strings.HasPrefix(witness, releaseVersionWitnessPrefix) ||
		!strings.HasSuffix(witness, "}") {
		return "", false
	}
	version := strings.TrimSuffix(strings.TrimPrefix(witness, releaseVersionWitnessPrefix), "}")
	if !validate.ReleaseVersion(version) {
		return "", false
	}
	return version, true
}

// VersionMetadataConsistent reports whether a build has either the exact
// development defaults or a canonical release witness matching its version.
// Any link-time override must therefore provide both release metadata values.
func VersionMetadataConsistent() bool {
	if Version == developmentVersion && ReleaseVersionWitness == unreleasedWitness {
		return true
	}
	witnessed, ok := WitnessedReleaseVersion()
	return ok && witnessed == Version
}
