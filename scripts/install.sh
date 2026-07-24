#!/usr/bin/env sh
# One-line installer for linux-temp-admin (v2).
#
# Downloads the latest signed release binary for this architecture over HTTPS,
# verifies its SHA-256 against the published SHA256SUMS, AND verifies a detached
# ed25519 signature against the release public key embedded below (the same key
# `upgrade` uses) before installing — failing closed on any mismatch. So the very
# first install carries the same signature-based trust as later `upgrade`s: a
# tampered or maliciously re-published binary is rejected even if the release host
# is compromised, because only the offline private key can produce a valid sig.
#
# Run as root:  curl -fsSL https://.../scripts/install.sh | sudo sh
#
# Signature verification needs openssl >= 3.0 (for `pkeyutl -rawin`). If it is
# unavailable the install fails closed, unless you explicitly accept checksum-only
# trust by setting LTA_ALLOW_UNVERIFIED=1.
set -eu

BASE="https://github.com/xxvcc/linux-temp-admin/releases/latest/download"
DEST="${DEST:-/usr/local/sbin/linux-temp-admin}"
MAX_DOWNLOAD_BYTES=67108864

if [ "$(id -u)" -ne 0 ]; then
  echo "run this installer as root" >&2
  exit 1
fi

# Release signing public key (ed25519) as a SubjectPublicKeyInfo PEM — the same key
# as internal/selfmanage/release_pubkey.hex, in the form openssl reads. Keep the two
# in sync. To regenerate this block after a key rotation:
#   hex=$(grep -v '^#' internal/selfmanage/release_pubkey.hex | tr -d '[:space:]')
#   python3 -c 'import base64,sys;k=bytes.fromhex("302a300506032b6570032100"+sys.argv[1]);print("-----BEGIN PUBLIC KEY-----");print(base64.encodebytes(k).decode().strip());print("-----END PUBLIC KEY-----")' "$hex"
RELEASE_PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAmCRx+wyfgvdhQ8idBF+KkxGA+Myifa1ShrsgAGFOrxw=
-----END PUBLIC KEY-----'

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
asset="linux-temp-admin-linux-${arch}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Choose a downloader that can enforce HTTPS redirects and a response-size cap.
if command -v curl >/dev/null 2>&1; then
  DL=curl
elif command -v wget >/dev/null 2>&1 \
     && wget --help 2>&1 | grep -q -- '--https-only' \
     && wget --help 2>&1 | grep -q -- '--max-filesize'; then
  DL=wget
else
  echo "need curl or wget with HTTPS-only redirects and download-size limits" >&2
  exit 1
fi

fetch() {
  case "$DL" in
    curl) curl -fsSL --proto '=https' --proto-redir '=https' \
            --max-filesize "$MAX_DOWNLOAD_BYTES" "$1" -o "$2" ;;
    wget) wget --https-only --max-filesize="$MAX_DOWNLOAD_BYTES" -qO "$2" "$1" ;;
  esac
}

# can_verify_sig succeeds only if openssl can do ed25519 detached verification,
# which needs the one-shot `-rawin` mode (OpenSSL 3.0+).
can_verify_sig() {
  command -v openssl >/dev/null 2>&1 || return 1
  openssl pkeyutl -help 2>&1 | grep -q -- '-rawin' || return 1
}

fetch "${BASE}/${asset}" "$tmp/bin"
fetch "${BASE}/SHA256SUMS" "$tmp/sums"

# 1) Integrity: SHA-256 against the published SHA256SUMS.
want="$(grep " ${asset}\$" "$tmp/sums" | awk '{print $1}')"
got="$(sha256sum "$tmp/bin" | awk '{print $1}')"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "checksum verification failed for ${asset}" >&2
  exit 1
fi

# 2) Authenticity: detached ed25519 signature against the embedded release key.
if can_verify_sig; then
  if ! fetch "${BASE}/${asset}.sig" "$tmp/sig"; then
    echo "could not download ${asset}.sig; refusing to install unverified" >&2
    exit 1
  fi
  printf '%s\n' "$RELEASE_PUBKEY_PEM" > "$tmp/release.pem"
  if openssl pkeyutl -verify -pubin -inkey "$tmp/release.pem" -rawin \
       -in "$tmp/bin" -sigfile "$tmp/sig" >/dev/null 2>&1; then
    echo "signature verified for ${asset}"
  else
    echo "SIGNATURE VERIFICATION FAILED for ${asset}; refusing to install" >&2
    exit 1
  fi
elif [ "${LTA_ALLOW_UNVERIFIED:-}" = "1" ]; then
  echo "WARNING: openssl >= 3.0 not available; skipping the ed25519 signature check" >&2
  echo "WARNING: proceeding with checksum-only trust (LTA_ALLOW_UNVERIFIED=1)" >&2
else
  echo "cannot verify the release signature: openssl >= 3.0 (pkeyutl -rawin) not found." >&2
  echo "install openssl, or re-run with LTA_ALLOW_UNVERIFIED=1 to accept checksum-only trust." >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"
cp "$tmp/bin" "${DEST}.new"
chmod 0755 "${DEST}.new"
chown root:root "${DEST}.new"
mv "${DEST}.new" "$DEST"
echo "installed ${DEST}"
"$DEST" version
