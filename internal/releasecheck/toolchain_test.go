package releasecheck

import (
	"regexp"
	"testing"
)

// Release and independent reconstruction must use the same patched toolchain.
// A floating ordinary CI version does not protect an accidentally stale release
// pin. Keep the module's security floor as the shared version contract.
func TestReleaseToolchainsMatchModuleSecurityFloor(t *testing.T) {
	module := readReleaseFile(t, "../../go.mod")
	version := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+\.[0-9]+)$`).FindStringSubmatch(module)
	if len(version) != 2 {
		t.Fatal("go.mod must declare an exact patched Go security floor")
	}
	for _, source := range []struct {
		path    string
		pattern string
	}{
		{"../../.github/workflows/release.yml", `(?m)^\s+go-version: '([0-9]+\.[0-9]+\.[0-9]+)'$`},
		{"../../scripts/prepare-release.sh", `(?m)^GO_VERSION="go([0-9]+\.[0-9]+\.[0-9]+)"$`},
	} {
		matches := regexp.MustCompile(source.pattern).FindAllStringSubmatch(readReleaseFile(t, source.path), -1)
		if len(matches) != 1 || matches[0][1] != version[1] {
			t.Errorf("%s must pin exactly Go %s; found %v", source.path, version[1], matches)
		}
	}
}
