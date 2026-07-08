#!/usr/bin/env bash
# Second half of a v2 release — run on the maintainer's OFFLINE machine.
#
# The release workflow (.github/workflows/release.yml) builds the static
# binaries + SHA256SUMS on tag push and stages them in a DRAFT GitHub Release.
# This script signs those exact CI-built binaries with the offline ed25519 key
# (which never leaves this machine) and publishes the release:
#
#   1. download the draft's binaries + SHA256SUMS,
#   2. verify the checksums,
#   3. sign each binary  -> <binary>.sig (raw 64-byte ed25519),
#   4. verify each .sig against the embedded public key (fail closed),
#   5. refresh SHA256SUMS to also cover the .sig files,
#   6. upload the signatures + refreshed SHA256SUMS,
#   7. flip the release from draft to published (and mark it latest).
#
# Because it signs the bytes CI actually published, the signature is valid for
# the exact assets users download — no reproducible-build assumption needed.
#
# Prereqs: gh (authenticated, write access), Go toolchain,
#          LTA_SIGN_KEY = path to the ed25519 private key file (keep OFFLINE).
# Usage:   LTA_SIGN_KEY=~/.lta/signing.key scripts/sign-release.sh v2.0.1
set -Eeuo pipefail

TAG="${1:?usage: sign-release.sh vX.Y.Z}"
: "${LTA_SIGN_KEY:?set LTA_SIGN_KEY to the ed25519 private key file}"

cd "$(dirname "$0")/.."
PUBHEX="internal/selfmanage/release_pubkey.hex"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo ">> [1/7] downloading draft assets for $TAG"
gh release download "$TAG" \
  --pattern 'linux-temp-admin-linux-amd64' \
  --pattern 'linux-temp-admin-linux-arm64' \
  --pattern 'SHA256SUMS' \
  --dir "$work"

echo ">> [2/7] verifying checksums"
( cd "$work" && sha256sum -c SHA256SUMS )

echo ">> [3/7] building the signer (lta-release)"
go build -o "$work/lta-release" ./cmd/lta-release

echo ">> [4/7] signing binaries offline"
for arch in amd64 arm64; do
  bin="$work/linux-temp-admin-linux-${arch}"
  "$work/lta-release" sign "$LTA_SIGN_KEY" "$bin"   # writes ${bin}.sig
done

echo ">> [5/7] verifying signatures against the embedded public key (fail closed)"
for arch in amd64 arm64; do
  bin="$work/linux-temp-admin-linux-${arch}"
  "$work/lta-release" verify "$PUBHEX" "$bin" "${bin}.sig"
done

echo ">> refreshing SHA256SUMS to cover the .sig files"
( cd "$work" && sha256sum linux-temp-admin-linux-* > SHA256SUMS )

echo ">> [6/7] uploading signatures + refreshed SHA256SUMS"
gh release upload "$TAG" \
  "$work/linux-temp-admin-linux-amd64.sig" \
  "$work/linux-temp-admin-linux-arm64.sig" \
  "$work/SHA256SUMS" --clobber

echo ">> [7/7] publishing release $TAG"
gh release edit "$TAG" --draft=false --latest

echo "done: $TAG published with verified signatures."
