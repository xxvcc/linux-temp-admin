#!/usr/bin/env bash
# Second half of a v2 release — run on the maintainer's OFFLINE machine.
#
# The release workflow (.github/workflows/release.yml) builds the static
# binaries + SHA256SUMS on tag push and stages them in a DRAFT GitHub Release.
# This script signs those exact CI-built binaries with the offline ed25519 key
# (which never leaves this machine) and publishes the release:
#
#   1. prove local HEAD/tag, the remote tag, and the draft all agree,
#   2. download the draft's binaries + SHA256SUMS,
#   3. verify the checksums,
#   4. sign each binary  -> <binary>.sig (raw 64-byte ed25519),
#   5. verify each .sig against the embedded public key (fail closed),
#   6. refresh SHA256SUMS to also cover the .sig files,
#   7. upload the signatures + refreshed SHA256SUMS,
#   8. flip the release from draft to published (stable tags become latest).
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
[[ "$TAG" =~ ^v([0-9]+)\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] \
  || { echo "tag must be vX.Y.Z or vX.Y.Z-prerelease" >&2; exit 1; }
major="${BASH_REMATCH[1]}"
(( 10#$major >= 2 )) || { echo "release tags below v2 are not supported" >&2; exit 1; }

cd "$(dirname "$0")/.."
PUBHEX="internal/selfmanage/release_pubkey.hex"
REPO="xxvcc/linux-temp-admin"

require_draft() {
  [[ "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq '.isDraft')" == "true" ]] \
    || { echo "release $TAG is not a draft; refusing to sign or replace published assets" >&2; exit 1; }
}

echo ">> [1/8] verifying source, tag, and draft state"
git rev-parse --verify "refs/tags/${TAG}^{commit}" >/dev/null
if [[ -n "$(git status --porcelain)" ]]; then
  echo "worktree must be clean before signing a release" >&2
  exit 1
fi
[[ "$(git rev-parse HEAD)" == "$(git rev-parse "refs/tags/${TAG}^{commit}")" ]] \
  || { echo "HEAD must be checked out at $TAG before signing" >&2; exit 1; }
remote_tag="$(gh api "repos/${REPO}/git/ref/tags/${TAG}" --jq '.object.sha')"
[[ "$(git rev-parse "refs/tags/${TAG}")" == "$remote_tag" ]] \
  || { echo "local tag $TAG does not match the tag on GitHub" >&2; exit 1; }
[[ "$(gh release view "$TAG" --repo "$REPO" --json tagName --jq '.tagName')" == "$TAG" ]] \
  || { echo "GitHub Release tag does not match $TAG" >&2; exit 1; }
require_draft

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo ">> [2/8] downloading draft assets for $TAG"
gh release download "$TAG" \
  --repo "$REPO" \
  --pattern 'linux-temp-admin-linux-amd64' \
  --pattern 'linux-temp-admin-linux-arm64' \
  --pattern 'SHA256SUMS' \
  --dir "$work"

echo ">> [3/8] verifying checksums"
( cd "$work" && sha256sum -c SHA256SUMS )

echo ">> [4/8] building the signer (lta-release)"
go build -o "$work/lta-release" ./cmd/lta-release

echo ">> [5/8] signing binaries offline"
for arch in amd64 arm64; do
  bin="$work/linux-temp-admin-linux-${arch}"
  "$work/lta-release" sign "$LTA_SIGN_KEY" "$bin"   # writes ${bin}.sig
done

echo ">> [6/8] verifying signatures against the embedded public key (fail closed)"
for arch in amd64 arm64; do
  bin="$work/linux-temp-admin-linux-${arch}"
  "$work/lta-release" verify "$PUBHEX" "$bin" "${bin}.sig"
done

echo ">> refreshing SHA256SUMS to cover the .sig files"
( cd "$work" && sha256sum linux-temp-admin-linux-* > SHA256SUMS )

echo ">> [7/8] uploading signatures + refreshed SHA256SUMS"
require_draft
gh release upload "$TAG" \
  --repo "$REPO" \
  "$work/linux-temp-admin-linux-amd64.sig" \
  "$work/linux-temp-admin-linux-arm64.sig" \
  "$work/SHA256SUMS" --clobber

echo ">> [8/8] publishing release $TAG"
if [[ "$TAG" == *-* ]]; then
  gh release edit "$TAG" --repo "$REPO" --draft=false --prerelease
else
  gh release edit "$TAG" --repo "$REPO" --draft=false --latest
fi

echo "done: $TAG published with verified signatures."
