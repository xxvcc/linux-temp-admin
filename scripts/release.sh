#!/usr/bin/env bash
# Build, sign, and stage v2 release binaries (linux amd64 + arm64).
#
# Prereqs:
#   - Go toolchain
#   - LTA_SIGN_KEY = path to the ed25519 private key file produced by
#     `go run ./cmd/lta-release keygen <file>` (keep it OFFLINE)
#   - the matching public key already pasted into
#     internal/selfmanage/release_pubkey.hex and committed
#
# Usage:  LTA_SIGN_KEY=~/.lta/signing.key scripts/release.sh 2.0.0
set -Eeuo pipefail

VERSION="${1:?usage: release.sh X.Y.Z}"
: "${LTA_SIGN_KEY:?set LTA_SIGN_KEY to the ed25519 private key file}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] \
  || { echo "version must be X.Y.Z or X.Y.Z-prerelease" >&2; exit 1; }

cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist
go build -o dist/lta-release ./cmd/lta-release

for arch in amd64 arm64; do
  out="dist/linux-temp-admin-linux-${arch}"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -trimpath -tags osusergo,netgo \
    -ldflags "-s -w -X github.com/xxvcc/linux-temp-admin/internal/buildinfo.Version=${VERSION}" \
    -o "$out" ./cmd/linux-temp-admin
  ./dist/lta-release sign "$LTA_SIGN_KEY" "$out"   # writes ${out}.sig
  echo "built + signed $out"
done

( cd dist && sha256sum linux-temp-admin-linux-* > SHA256SUMS )
rm -f dist/lta-release

echo
echo "Artifacts staged in dist/. Publish with:"
echo "  gh release create v${VERSION} dist/linux-temp-admin-linux-* dist/SHA256SUMS --title v${VERSION}"
