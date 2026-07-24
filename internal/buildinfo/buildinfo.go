// Package buildinfo holds the single source of truth for the program's identity
// and version. The version is overridable at link time (-X) by the release
// pipeline; the default marks an unreleased development build.
package buildinfo

// Name is the program / installed-command name.
const Name = "linux-temp-admin"

// Version is the semantic version. Overridden at build time via
// -ldflags "-X github.com/xxvcc/linux-temp-admin/internal/buildinfo.Version=x.y.z".
var Version = "0.0.0-dev"
