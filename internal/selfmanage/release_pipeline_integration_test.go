//go:build integration

package selfmanage

import "testing"

// These installer tests deliberately exercise root-owned destinations below
// /usr/local/lib. Keep their discoverable test entry points out of ordinary
// `go test` runs, while sharing the release-pipeline fixtures and assertions.
func TestInstallerPinnedReleaseEndToEnd(t *testing.T) {
	InstallerPinnedReleaseEndToEnd(t)
}

func TestInstallerOfficialMirrorFallbackBoundary(t *testing.T) {
	InstallerOfficialMirrorFallbackBoundary(t)
}
