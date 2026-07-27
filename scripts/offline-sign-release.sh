#!/bin/bash -p
# Offline phase. Run a separately installed, audited copy of this script on an
# air-gapped machine. Candidate files are data only; none are executed.
[[ $- == *p* ]] || { echo "execute offline-sign-release.sh directly; privileged Bash mode is required" >&2; exit 2; }
set -Eeuo pipefail
umask 077
ulimit -c 0 || { echo "cannot disable core dumps for the trusted signing phase" >&2; exit 1; }
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset TAR_OPTIONS GZIP BZIP2 BZIP XZ_OPT
hash -r

MAX_BINARY_BYTES=67108864
MAX_METADATA_BYTES=1048576
LOCAL_COMMAND_TIMEOUT_SECONDS=120
SIGNER_TIMEOUT_SECONDS=300

for command_name in awk chmod cp dirname grep mkdir mktemp readlink rm sha256sum stat timeout wc; do
  command -v "$command_name" >/dev/null 2>&1 \
    || { echo "required command not found: $command_name" >&2; exit 1; }
done
timeout -k 1 1 /bin/true \
  || { echo "timeout does not support the required kill-after option" >&2; exit 1; }

local_with_timeout() {
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" "$@"
}

require_trusted_tmp() {
  local tmp_meta tmp_uid tmp_mode
  [[ -d /tmp && ! -L /tmp ]] || { echo "/tmp must be a real directory" >&2; return 1; }
  tmp_meta="$(local_with_timeout stat -Lc '%u %a' -- /tmp)" \
    || { echo "cannot inspect /tmp" >&2; return 1; }
  read -r tmp_uid tmp_mode <<<"$tmp_meta"
  [[ "$tmp_uid" == 0 && "$tmp_mode" =~ ^[0-7]{4}$ ]] \
    || { echo "/tmp must be owned by root and have a valid sticky mode" >&2; return 1; }
  (( (8#$tmp_mode & 8#7000) == 8#1000 )) \
    || { echo "/tmp must have exactly the sticky special bit" >&2; return 1; }
}
require_trusted_tmp

require_safe_directory_path() {
  local path=$1 label=$2 allow_sticky_leaf=${3:-0} canonical meta type uid mode extra parent leaf=1
  canonical="$(local_with_timeout readlink -f -- "$path")" \
    || { echo "cannot resolve $label: $path" >&2; return 1; }
  [[ "$canonical" == "$path" ]] \
    || { echo "$label must be canonical and contain no symlinked ancestor: $path" >&2; return 1; }
  while :; do
    meta="$(local_with_timeout stat -c '%F|%u|%a' -- "$path")" \
      || { echo "cannot inspect $label ancestor: $path" >&2; return 1; }
    IFS='|' read -r type uid mode extra <<<"$meta"
    [[ "$meta" == "$type|$uid|$mode" && "$type" == directory && "$uid" =~ ^[0-9]+$ \
       && "$mode" =~ ^[0-7]{3,4}$ && -z "$extra" ]] \
      || { echo "$label ancestor has invalid metadata: $path" >&2; return 1; }
    if (( uid == 0 && (8#$mode & 8#7000) == 8#1000 )); then
      (( leaf == 0 || allow_sticky_leaf == 1 )) \
        || { echo "$label leaf must not be a shared sticky directory: $path" >&2; return 1; }
    elif (( (uid == 0 || uid == EUID) && (8#$mode & 8#7022) == 0 )); then
      :
    else
      echo "$label ancestor is owned or writable by an untrusted account: $path" >&2
      return 1
    fi
    [[ "$path" == / ]] && break
    parent="$(dirname -- "$path")"
    [[ "$parent" != "$path" ]] || { echo "cannot resolve $label ancestry" >&2; return 1; }
    path=$parent
    leaf=0
  done
}

require_regular_file_path() {
  local path=$1 label=$2 canonical type
  canonical="$(local_with_timeout readlink -f -- "$path")" \
    || { echo "cannot resolve $label: $path" >&2; return 1; }
  [[ "$canonical" == "$path" ]] \
    || { echo "$label must be canonical and contain no symlinked ancestor" >&2; return 1; }
  type="$(local_with_timeout stat -c '%F' -- "$path")" \
    || { echo "cannot inspect $label: $path" >&2; return 1; }
  [[ "$type" == "regular file" ]] \
    || { echo "$label must be a regular non-symlink file" >&2; return 1; }
}

require_safe_file_path() {
  local path=$1 label=$2 parent
  require_regular_file_path "$path" "$label"
  parent="$(dirname -- "$path")"
  require_safe_directory_path "$parent" "$label parent"
}

require_real_directory_path() {
  local path=$1 label=$2 canonical type
  canonical="$(local_with_timeout readlink -f -- "$path")" \
    || { echo "cannot resolve $label: $path" >&2; return 1; }
  [[ "$canonical" == "$path" ]] \
    || { echo "$label must be canonical and contain no symlinked ancestor" >&2; return 1; }
  type="$(local_with_timeout stat -c '%F' -- "$path")" \
    || { echo "cannot inspect $label: $path" >&2; return 1; }
  [[ "$type" == directory ]] || { echo "$label must be a real directory" >&2; return 1; }
}

require_safe_new_output_path() {
  local path=$1 label=$2 canonical parent path_status
  [[ "$path" == /* && "$path" != / && "$path" != */ ]] \
    || { echo "$label must be a new canonical absolute path other than /" >&2; return 1; }
  canonical="$(local_with_timeout readlink -m -- "$path")" \
    || { echo "cannot resolve $label: $path" >&2; return 1; }
  [[ "$canonical" == "$path" ]] \
    || { echo "$label must be a new canonical absolute path other than /" >&2; return 1; }
  if local_with_timeout stat -c '%F' -- "$path" >/dev/null 2>&1; then
    path_status=0
  else
    path_status=$?
  fi
  [[ "$path_status" -eq 1 ]] \
    || { echo "$label already exists or could not be inspected: $path" >&2; return 1; }
  parent="$(dirname -- "$path")"
  require_safe_directory_path "$parent" "$label parent" 1
}

PREPARED_DIR="${1:?usage: offline-sign-release.sh /absolute/prepared-dir /absolute/signed-dir}"
SIGNED_DIR="${2:?usage: offline-sign-release.sh /absolute/prepared-dir /absolute/signed-dir}"
: "${LTA_SIGN_KEY:?set LTA_SIGN_KEY to the offline ed25519 private key}"
: "${LTA_TRUSTED_SIGNER:?set LTA_TRUSTED_SIGNER to the fixed audited lta-release binary}"
: "${LTA_TRUSTED_SIGNER_SHA256:?set the offline-recorded SHA-256 of LTA_TRUSTED_SIGNER}"
: "${LTA_EXPECTED_TAG:?set the independently recorded release tag}"
: "${LTA_EXPECTED_COMMIT:?set the independently recorded 40-hex release commit}"
: "${LTA_EXPECTED_PREPARED_MANIFEST_SHA256:?set the manifest hash printed by trusted preparation}"
: "${LTA_EXPECTED_RELEASE_SIGNER_PUBKEY:?set the independently recorded ed25519 public key for this release}"

for online_var in GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy \
  SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GH_CONFIG_DIR; do
  [[ -z "${!online_var:-}" ]] || { echo "$online_var must not be present during offline signing" >&2; exit 1; }
done
[[ "$PREPARED_DIR" == /* ]] \
  || { echo "prepared input must be a real absolute directory" >&2; exit 1; }
[[ "$SIGNED_DIR" == /* && "$SIGNED_DIR" != / && "$SIGNED_DIR" != */ ]] \
  || { echo "signed output must be a new absolute directory other than /" >&2; exit 1; }
[[ "$LTA_TRUSTED_SIGNER" == /* ]] \
  || { echo "trusted signer must be an absolute regular non-symlink file" >&2; exit 1; }
[[ "$LTA_SIGN_KEY" == /* ]] \
  || { echo "offline private key must be an absolute regular non-symlink file" >&2; exit 1; }
[[ "$LTA_TRUSTED_SIGNER_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid trusted signer SHA-256" >&2; exit 1; }
[[ "$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" =~ ^[0-9A-Fa-f]{64}$ ]] \
  || { echo "invalid expected release-signer public key" >&2; exit 1; }
LTA_EXPECTED_RELEASE_SIGNER_PUBKEY="${LTA_EXPECTED_RELEASE_SIGNER_PUBKEY,,}"
require_real_directory_path "$PREPARED_DIR" "prepared input"
require_safe_file_path "$LTA_TRUSTED_SIGNER" "trusted signer"
require_regular_file_path "$LTA_SIGN_KEY" "offline private key"
require_safe_new_output_path "$SIGNED_DIR" "signed output"

prepared_files=(COMMIT TAG VERSION release_pubkey.hex linux-temp-admin-linux-amd64 linux-temp-admin-linux-arm64)
for name in "${prepared_files[@]}" PREPARED_SHA256SUMS; do
  require_regular_file_path "$PREPARED_DIR/$name" "prepared file $name" \
    || { echo "missing regular prepared file: $name" >&2; exit 1; }
done

# The removable input stays untrusted and mutable. Copy its allow-listed files
# once, then validate and sign only the private snapshot.
work="$(mktemp -d /tmp/lta-offline-sign.XXXXXX)"
snapshot="$work/prepared"
signed_work="$work/signed"
mkdir -m 0700 "$snapshot" "$signed_work"
out_created=0
complete=0
cleanup() {
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" rm -rf -- "$work" \
    || echo "warning: could not remove private signing workspace within timeout: $work" >&2
  if (( out_created == 1 && complete == 0 )); then
    timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" rm -rf -- "$SIGNED_DIR" \
      || echo "warning: could not remove incomplete signed output within timeout: $SIGNED_DIR" >&2
  fi
}
trap cleanup EXIT

bounded_copy() {
  local source=$1 destination=$2 max=$3 blocks size
  blocks=$(( (max + 1023) / 1024 ))
  if ! ( ulimit -f "$blocks"; timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" \
    cp --reflink=never --sparse=never -- "$source" "$destination" ); then
    echo "input exceeds its snapshot limit or could not be copied: $source" >&2
    return 1
  fi
  size="$(timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" stat -Lc '%s' -- "$destination")" \
    || { echo "copied file could not be measured: $destination" >&2; return 1; }
  (( size <= max )) || { echo "input exceeds its snapshot limit: $source" >&2; return 1; }
}

# Pin the audited executable by an open descriptor. Hashing and every later
# execution address this same inode even if its pathname is replaced.
exec {trusted_signer_fd}<"$LTA_TRUSTED_SIGNER"
trusted_signer="/proc/$$/fd/${trusted_signer_fd}"
[[ -f "$trusted_signer" && -x "$trusted_signer" ]] \
  || { echo "trusted signer descriptor is not an executable regular file" >&2; exit 1; }
read -r trusted_signer_uid trusted_signer_mode < <(local_with_timeout stat -Lc '%u %a' -- "$trusted_signer")
[[ "$trusted_signer_uid" == 0 || "$trusted_signer_uid" == "$EUID" ]] \
  || { echo "trusted signer is owned by an unexpected uid" >&2; exit 1; }
if [[ ! "$trusted_signer_mode" =~ ^[0-7]{3}$ ]] \
   || (( (8#$trusted_signer_mode & 8#022) != 0 )); then
  echo "trusted signer has unsafe group/world-write or special mode bits" >&2
  exit 1
fi
[[ "$(timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" sha256sum "$trusted_signer" | awk '{print $1}')" == "$LTA_TRUSTED_SIGNER_SHA256" ]] \
  || { echo "trusted signer hash mismatch" >&2; exit 1; }
signer_with_timeout() {
  timeout -k 5 "$SIGNER_TIMEOUT_SECONDS" "$trusted_signer" "$@"
}
[[ "$(signer_with_timeout version)" == "lta-release-offline-v1" ]] \
  || { echo "unsupported trusted signer protocol" >&2; exit 1; }

for name in "${prepared_files[@]}" PREPARED_SHA256SUMS; do
  limit=$MAX_METADATA_BYTES
  [[ "$name" != linux-temp-admin-linux-amd64 && "$name" != linux-temp-admin-linux-arm64 ]] \
    || limit=$MAX_BINARY_BYTES
  bounded_copy "$PREPARED_DIR/$name" "$snapshot/$name" "$limit"
done

[[ "$(awk 'NF {print $2}' "$snapshot/PREPARED_SHA256SUMS")" == $'COMMIT\nTAG\nVERSION\nrelease_pubkey.hex\nlinux-temp-admin-linux-amd64\nlinux-temp-admin-linux-arm64' ]] \
  || { echo "prepared manifest has unexpected entries" >&2; exit 1; }
( cd "$snapshot" && sha256sum -c --strict PREPARED_SHA256SUMS )
for arch in amd64 arm64; do
  asset="$snapshot/linux-temp-admin-linux-${arch}"
  [[ -s "$asset" && "$(wc -c < "$asset")" -le "$MAX_BINARY_BYTES" ]] \
    || { echo "prepared ${arch} binary is empty or exceeds the 64 MiB client limit" >&2; exit 1; }
done
TAG="$(<"$snapshot/TAG")"
VERSION="$(<"$snapshot/VERSION")"
[[ "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z]+([.-][0-9A-Za-z]+)*))?$ \
   && "$VERSION" == "${TAG#v}" ]] \
  || { echo "invalid or inconsistent prepared tag/version" >&2; exit 1; }
major="${BASH_REMATCH[1]}"
(( ${#major} > 1 || 10#$major >= 2 )) || { echo "release tags below v2 are not supported" >&2; exit 1; }
[[ "$TAG" == "$LTA_EXPECTED_TAG" ]] || { echo "prepared tag differs from the independently recorded tag" >&2; exit 1; }
[[ "$(<"$snapshot/COMMIT")" == "$LTA_EXPECTED_COMMIT" && "$LTA_EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "prepared commit differs from the independently recorded commit" >&2; exit 1; }
[[ "$LTA_EXPECTED_PREPARED_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ \
   && "$(sha256sum "$snapshot/PREPARED_SHA256SUMS" | awk '{print $1}')" == "$LTA_EXPECTED_PREPARED_MANIFEST_SHA256" ]] \
  || { echo "prepared manifest hash differs from the independently recorded value" >&2; exit 1; }

signing_pub="$(signer_with_timeout pubkey "$LTA_SIGN_KEY")"
[[ "$signing_pub" == "$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" ]] \
  || { echo "private key is not the independently selected release-signing key" >&2; exit 1; }
awk '
  /^[[:space:]]*(#|$)/ { next }
  { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if (length($0) != 64 || $0 !~ /^[0-9A-Fa-f]+$/ || seen[tolower($0)]++) exit 1; count++ }
  END { if (!count) exit 1 }
' "$snapshot/release_pubkey.hex" || { echo "prepared release keyring is malformed or duplicated" >&2; exit 1; }
awk '/^[[:space:]]*(#|$)/ {next} {gsub(/[[:space:]]/, ""); print tolower($0)}' "$snapshot/release_pubkey.hex" \
  | grep -Fqx "$signing_pub" \
  || { echo "private key public half is not present in the candidate keyring" >&2; exit 1; }

for name in "${prepared_files[@]}" PREPARED_SHA256SUMS; do
  cp -- "$snapshot/$name" "$signed_work/$name"
done
printf '%s\n' "$LTA_TRUSTED_SIGNER_SHA256" > "$signed_work/SIGNER_SHA256"
printf '%s\n' "$signing_pub" > "$signed_work/RELEASE_SIGNER_PUBKEY"

for arch in amd64 arm64; do
  signer_with_timeout sign "$LTA_SIGN_KEY" "$signed_work/linux-temp-admin-linux-${arch}"
  signer_with_timeout verify "$signed_work/RELEASE_SIGNER_PUBKEY" \
    "$signed_work/linux-temp-admin-linux-${arch}" "$signed_work/linux-temp-admin-linux-${arch}.sig"
done
( cd "$signed_work" && sha256sum linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig \
    linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig > SHA256SUMS )
( cd "$signed_work" && sha256sum COMMIT PREPARED_SHA256SUMS RELEASE_SIGNER_PUBKEY SHA256SUMS SIGNER_SHA256 TAG VERSION \
    release_pubkey.hex linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig \
    linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig > SIGNED_BUNDLE_SHA256SUMS )
signed_manifest_sha256="$(sha256sum "$signed_work/SIGNED_BUNDLE_SHA256SUMS" | awk '{print $1}')"

require_safe_new_output_path "$SIGNED_DIR" "signed output"
timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" mkdir -m 0700 -- "$SIGNED_DIR"
out_created=1
require_safe_directory_path "$SIGNED_DIR" "signed output"
for name in COMMIT PREPARED_SHA256SUMS RELEASE_SIGNER_PUBKEY SHA256SUMS SIGNER_SHA256 TAG VERSION release_pubkey.hex \
  linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig \
  linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig SIGNED_BUNDLE_SHA256SUMS; do
  limit=$MAX_METADATA_BYTES
  [[ "$name" != linux-temp-admin-linux-amd64 && "$name" != linux-temp-admin-linux-arm64 ]] \
    || limit=$MAX_BINARY_BYTES
  bounded_copy "$signed_work/$name" "$SIGNED_DIR/$name" "$limit"
done
for name in COMMIT PREPARED_SHA256SUMS RELEASE_SIGNER_PUBKEY SHA256SUMS SIGNER_SHA256 TAG VERSION release_pubkey.hex \
  linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig \
  linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig SIGNED_BUNDLE_SHA256SUMS; do
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" chmod 0600 "$SIGNED_DIR/$name"
done
[[ "$(timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" sha256sum "$SIGNED_DIR/SIGNED_BUNDLE_SHA256SUMS" | awk '{print $1}')" == "$signed_manifest_sha256" ]] \
  || { echo "signed output manifest changed during transfer" >&2; exit 1; }
timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" /bin/sh -c \
  'cd -- "$1" && exec sha256sum -c --strict SIGNED_BUNDLE_SHA256SUMS' sh "$SIGNED_DIR"
complete=1
echo "signed release data: $SIGNED_DIR"
echo "signed bundle manifest SHA-256: $signed_manifest_sha256"
echo "remove the private key/media, then transfer this directory to the online publisher"
