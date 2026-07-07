#!/usr/bin/env sh
# One-line installer for linux-temp-admin (v2).
#
# Downloads the latest signed release binary for this architecture over HTTPS and
# verifies its SHA-256 against the published SHA256SUMS before installing. After
# install, `linux-temp-admin upgrade` verifies an ed25519 signature natively.
#
# Run as root:  curl -fsSL https://.../scripts/install.sh | sudo sh
set -eu

BASE="https://github.com/xxvcc/linux-temp-admin/releases/latest/download"
DEST="${DEST:-/usr/local/sbin/linux-temp-admin}"

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
asset="linux-temp-admin-linux-${arch}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --proto-redir '=https' "$1" -o "$2"
  else
    wget -qO "$2" "$1"
  fi
}

fetch "${BASE}/${asset}" "$tmp/bin"
fetch "${BASE}/SHA256SUMS" "$tmp/sums"

want="$(grep " ${asset}\$" "$tmp/sums" | awk '{print $1}')"
got="$(sha256sum "$tmp/bin" | awk '{print $1}')"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "checksum verification failed for ${asset}" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"
cp "$tmp/bin" "${DEST}.new"
chmod 0755 "${DEST}.new"
chown root:root "${DEST}.new" 2>/dev/null || true
mv "${DEST}.new" "$DEST"
echo "installed ${DEST}"
"$DEST" version
