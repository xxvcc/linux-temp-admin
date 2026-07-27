#!/bin/bash -p
# Online, keyless phase: verify a signed bundle, replace the still-draft assets,
# publish, then independently download and verify public versioned/Latest bytes.
[[ $- == *p* ]] || { echo "execute publish-release.sh directly; privileged Bash mode is required" >&2; exit 2; }
set -Eeuo pipefail
umask 077
ulimit -c 0 || { echo "cannot disable core dumps for the trusted publication phase" >&2; exit 1; }
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
while IFS= read -r inherited_name; do
  [[ "$inherited_name" == GIT_* ]] && unset "$inherited_name"
done < <(compgen -A variable)
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
unset SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS
unset GH_CONFIG_DIR XDG_CONFIG_HOME GIT_SSL_CAINFO GIT_SSL_CAPATH
unset TAR_OPTIONS GZIP BZIP2 BZIP XZ_OPT
GIT_NO_REPLACE_OBJECTS=1
GIT_NO_LAZY_FETCH=1
GIT_TERMINAL_PROMPT=0
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_SYSTEM=/dev/null
GIT_ASKPASS=/bin/false
SSH_ASKPASS=/bin/false
GIT_PAGER='cat'
GIT_OPTIONAL_LOCKS=0
OPENSSL_CONF=/dev/null
GH_HOST=github.com
GH_PROMPT_DISABLED=1
GH_PAGER='cat'
export PATH LC_ALL GIT_NO_REPLACE_OBJECTS GIT_NO_LAZY_FETCH GIT_TERMINAL_PROMPT \
  GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_ASKPASS SSH_ASKPASS \
  GIT_PAGER GIT_OPTIONAL_LOCKS OPENSSL_CONF GH_HOST GH_PROMPT_DISABLED GH_PAGER
unset OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES
unset GPG_TTY
hash -r

MAX_BINARY_BYTES=67108864
MAX_METADATA_BYTES=1048576
LOCAL_COMMAND_TIMEOUT_SECONDS=120
SIGNER_TIMEOUT_SECONDS=300

SIGNED_DIR="${1:?usage: publish-release.sh /absolute/signed-dir /absolute/source/repo}"
SOURCE_DIR="${2:?usage: publish-release.sh /absolute/signed-dir /absolute/source/repo}"
REPO="xxvcc/linux-temp-admin"
: "${LTA_TRUSTED_SIGNER:?set LTA_TRUSTED_SIGNER to the fixed audited lta-release verifier}"
: "${LTA_TRUSTED_SIGNER_SHA256:?set its independently recorded SHA-256}"
: "${LTA_EXPECTED_SIGNED_BUNDLE_MANIFEST_SHA256:?set the independently recorded signed-bundle manifest SHA-256}"
: "${LTA_EXPECTED_TAG_SIGNER_FINGERPRINT:?set the independently recorded OpenPGP tag-signer fingerprint}"
: "${LTA_EXPECTED_RELEASE_SIGNER_PUBKEY:?set the independently recorded ed25519 public key used for this release}"

[[ -z "${LTA_SIGN_KEY:-}" ]] || { echo "LTA_SIGN_KEY must not be present on the online publishing machine" >&2; exit 1; }
[[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]] \
  || { echo "set GH_TOKEN to a short-lived github.com release token" >&2; exit 1; }
GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
export GH_TOKEN
[[ "$SIGNED_DIR" == /* ]] || { echo "signed bundle must be a real absolute directory" >&2; exit 1; }
[[ "$SOURCE_DIR" == /* ]] || { echo "source repo must be an absolute directory" >&2; exit 1; }
[[ "$LTA_TRUSTED_SIGNER" == /* ]] \
  || { echo "trusted verifier must be an absolute regular non-symlink file" >&2; exit 1; }
[[ "$LTA_TRUSTED_SIGNER_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid trusted verifier SHA-256" >&2; exit 1; }
[[ "$LTA_EXPECTED_SIGNED_BUNDLE_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "invalid expected signed-bundle manifest SHA-256" >&2; exit 1; }
[[ "$LTA_EXPECTED_TAG_SIGNER_FINGERPRINT" =~ ^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$ ]] \
  || { echo "invalid expected OpenPGP tag-signer fingerprint" >&2; exit 1; }
[[ "$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" =~ ^[0-9A-Fa-f]{64}$ ]] \
  || { echo "invalid expected release-signer public key" >&2; exit 1; }
LTA_EXPECTED_TAG_SIGNER_FINGERPRINT="${LTA_EXPECTED_TAG_SIGNER_FINGERPRINT,,}"
LTA_EXPECTED_RELEASE_SIGNER_PUBKEY="${LTA_EXPECTED_RELEASE_SIGNER_PUBKEY,,}"

for command_name in awk cat cmp cp curl diff dirname gh git grep mkdir mktemp readlink rm sha256sum sleep sort stat timeout wc; do
  command -v "$command_name" >/dev/null 2>&1 \
    || { echo "required command not found: $command_name" >&2; exit 1; }
done
curl -q --proto '=https' --proto-redir '=https' --connect-timeout 1 --max-time 1 --version >/dev/null 2>&1 \
  || { echo "curl does not support the required HTTPS and timeout options" >&2; exit 1; }
timeout -k 1 1 /bin/true \
	|| { echo "timeout does not support the required kill-after option" >&2; exit 1; }
sleep 0 || { echo "sleep command is not usable" >&2; exit 1; }
[[ -x /usr/bin/gpg ]] || { echo "required trusted command not found: /usr/bin/gpg" >&2; exit 1; }

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

require_safe_source_repo() {
  require_safe_directory_path "$SOURCE_DIR" "source repo"
  require_safe_directory_path "$SOURCE_DIR/.git" "source Git directory"
  local external_git_store
  for external_git_store in "$SOURCE_DIR/.git/commondir" \
    "$SOURCE_DIR/.git/objects/info/alternates" "$SOURCE_DIR/.git/objects/info/http-alternates"; do
    [[ ! -e "$external_git_store" && ! -L "$external_git_store" ]] \
      || { echo "source repo uses an external Git object or metadata store: $external_git_store" >&2; return 1; }
  done
}
require_real_directory_path "$SIGNED_DIR" "signed bundle"
require_safe_file_path "$LTA_TRUSTED_SIGNER" "trusted verifier"
require_safe_source_repo

gh_with_timeout() {
	timeout -k 5 300 gh "$@"
}
git_with_timeout() {
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" git \
    -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.attributesFile=/dev/null \
    -c core.pager=cat -c pager.branch=false -c pager.tag=false "$@"
}

bundle_files=(COMMIT PREPARED_SHA256SUMS RELEASE_SIGNER_PUBKEY SHA256SUMS SIGNER_SHA256 TAG VERSION release_pubkey.hex \
  linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig \
  linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig)
for name in "${bundle_files[@]}" SIGNED_BUNDLE_SHA256SUMS; do
  require_regular_file_path "$SIGNED_DIR/$name" "signed-bundle file $name" \
    || { echo "missing regular signed-bundle file: $name" >&2; exit 1; }
done

# Snapshot the removable transfer once. Every subsequent check, upload, and
# comparison uses only this private directory, so a writer cannot swap a valid
# old bundle into the publication path after validation.
work="$(mktemp -d /tmp/lta-publish-release.XXXXXX)"
mkdir -m 0700 "$work/gh-config"
GH_CONFIG_DIR="$work/gh-config"
export GH_CONFIG_DIR
gpg_wrapper="$work/gpg-batch"
printf '%s\n' '#!/bin/sh' 'exec /usr/bin/gpg --batch --no-auto-key-retrieve "$@"' > "$gpg_wrapper"
chmod 0700 "$gpg_wrapper"
LATEST_PROMOTION_ATTEMPTED=0
PUBLISH_COMPLETE=0
cleanup() {
  local status=$?
  trap - EXIT
  if (( status != 0 && LATEST_PROMOTION_ATTEMPTED == 1 && PUBLISH_COMPLETE == 0 )); then
    echo "stable publication failed after a mutation that could affect Latest; restoring the exact highest stable release other than $TAG" >&2
    if ! restore_latest_after_failed_promotion; then
      echo "CRITICAL: automatic Latest restoration failed; keep the release unannounced and follow docs/releasing.md recovery" >&2
    fi
  fi
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" rm -rf -- "$work" \
    || echo "warning: could not remove private publication workspace within timeout: $work" >&2
  exit "$status"
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
  size="$(local_with_timeout stat -Lc '%s' -- "$destination")" \
    || { echo "copied file could not be measured: $destination" >&2; return 1; }
  (( size <= max )) || { echo "input exceeds its snapshot limit: $source" >&2; return 1; }
}

# Pin the verifier by descriptor so the inode hashed here is the one every
# subsequent verify command executes.
exec {trusted_signer_fd}<"$LTA_TRUSTED_SIGNER"
trusted_signer="/proc/$$/fd/${trusted_signer_fd}"
[[ -f "$trusted_signer" && -x "$trusted_signer" ]] \
  || { echo "trusted verifier descriptor is not an executable regular file" >&2; exit 1; }
read -r trusted_signer_uid trusted_signer_mode < <(local_with_timeout stat -Lc '%u %a' -- "$trusted_signer")
[[ "$trusted_signer_uid" == 0 || "$trusted_signer_uid" == "$EUID" ]] \
  || { echo "trusted verifier is owned by an unexpected uid" >&2; exit 1; }
if [[ ! "$trusted_signer_mode" =~ ^[0-7]{3}$ ]] \
   || (( (8#$trusted_signer_mode & 8#022) != 0 )); then
  echo "trusted verifier has unsafe group/world-write or special mode bits" >&2
  exit 1
fi
[[ "$(timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" sha256sum "$trusted_signer" | awk '{print $1}')" == "$LTA_TRUSTED_SIGNER_SHA256" ]] \
  || { echo "trusted verifier hash mismatch" >&2; exit 1; }
signer_with_timeout() {
  timeout -k 5 "$SIGNER_TIMEOUT_SECONDS" "$trusted_signer" "$@"
}
[[ "$(signer_with_timeout version)" == "lta-release-offline-v1" ]] \
  || { echo "unsupported trusted verifier protocol" >&2; exit 1; }

BUNDLE_DIR="$work/bundle"
mkdir -m 0700 "$BUNDLE_DIR"
for name in "${bundle_files[@]}" SIGNED_BUNDLE_SHA256SUMS; do
  limit=$MAX_METADATA_BYTES
  [[ "$name" != linux-temp-admin-linux-amd64 && "$name" != linux-temp-admin-linux-arm64 ]] \
    || limit=$MAX_BINARY_BYTES
  bounded_copy "$SIGNED_DIR/$name" "$BUNDLE_DIR/$name" "$limit"
done

[[ "$(sha256sum "$BUNDLE_DIR/SIGNED_BUNDLE_SHA256SUMS" | awk '{print $1}')" == "$LTA_EXPECTED_SIGNED_BUNDLE_MANIFEST_SHA256" ]] \
  || { echo "signed-bundle manifest differs from the independently recorded value" >&2; exit 1; }
[[ "$(awk 'NF {print $2}' "$BUNDLE_DIR/SIGNED_BUNDLE_SHA256SUMS")" == $'COMMIT\nPREPARED_SHA256SUMS\nRELEASE_SIGNER_PUBKEY\nSHA256SUMS\nSIGNER_SHA256\nTAG\nVERSION\nrelease_pubkey.hex\nlinux-temp-admin-linux-amd64\nlinux-temp-admin-linux-amd64.sig\nlinux-temp-admin-linux-arm64\nlinux-temp-admin-linux-arm64.sig' ]] \
  || { echo "signed bundle manifest has unexpected entries" >&2; exit 1; }
( cd "$BUNDLE_DIR" && sha256sum -c --strict SIGNED_BUNDLE_SHA256SUMS )
[[ "$(<"$BUNDLE_DIR/SIGNER_SHA256")" == "$LTA_TRUSTED_SIGNER_SHA256" ]] || { echo "bundle used another signer" >&2; exit 1; }
[[ "$(<"$BUNDLE_DIR/RELEASE_SIGNER_PUBKEY")" == "$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" ]] \
  || { echo "bundle was signed by a different release key" >&2; exit 1; }

TAG="$(<"$BUNDLE_DIR/TAG")"
VERSION="$(<"$BUNDLE_DIR/VERSION")"
COMMIT="$(<"$BUNDLE_DIR/COMMIT")"
[[ "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z]+([.-][0-9A-Za-z]+)*))?$ && "$VERSION" == "${TAG#v}" ]] \
  || { echo "invalid or inconsistent bundle tag/version" >&2; exit 1; }
major="${BASH_REMATCH[1]}"
(( ${#major} > 1 || 10#$major >= 2 )) || { echo "release tags below v2 are not supported" >&2; exit 1; }
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid bundle commit" >&2; exit 1; }
[[ "$(awk 'NF {print $2}' "$BUNDLE_DIR/SHA256SUMS")" == $'linux-temp-admin-linux-amd64\nlinux-temp-admin-linux-amd64.sig\nlinux-temp-admin-linux-arm64\nlinux-temp-admin-linux-arm64.sig' ]] \
  || { echo "release SHA256SUMS has unexpected entries" >&2; exit 1; }
( cd "$BUNDLE_DIR" && sha256sum -c --strict SHA256SUMS )
[[ "$(wc -l < "$BUNDLE_DIR/RELEASE_SIGNER_PUBKEY")" -eq 1 ]] \
  || { echo "release-signer key file must contain exactly one line" >&2; exit 1; }
grep -Fqx "$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" "$BUNDLE_DIR/RELEASE_SIGNER_PUBKEY" \
  || { echo "release-signer key file is malformed" >&2; exit 1; }
awk '/^[[:space:]]*(#|$)/ {next} {gsub(/[[:space:]]/, ""); print tolower($0)}' "$BUNDLE_DIR/release_pubkey.hex" \
  | grep -Fqx "$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" \
  || { echo "selected release signer is absent from the tagged keyring" >&2; exit 1; }
awk '
  /^[[:space:]]*(#|$)/ { next }
  { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if (length($0) != 64 || $0 !~ /^[0-9A-Fa-f]+$/ || seen[tolower($0)]++) exit 1; count++ }
  END { if (!count) exit 1 }
' "$BUNDLE_DIR/release_pubkey.hex" || { echo "signed-bundle release keyring is malformed or duplicated" >&2; exit 1; }
for arch in amd64 arm64; do
  asset="$BUNDLE_DIR/linux-temp-admin-linux-${arch}"
  [[ -s "$asset" && "$(wc -c < "$asset")" -le "$MAX_BINARY_BYTES" ]] \
    || { echo "signed ${arch} binary is empty or exceeds the 64 MiB client limit" >&2; exit 1; }
  [[ "$(wc -c < "$BUNDLE_DIR/linux-temp-admin-linux-${arch}.sig")" -eq 64 ]] || { echo "invalid ${arch} signature size" >&2; exit 1; }
  signer_with_timeout verify "$BUNDLE_DIR/RELEASE_SIGNER_PUBKEY" \
    "$BUNDLE_DIR/linux-temp-admin-linux-${arch}" "$BUNDLE_DIR/linux-temp-admin-linux-${arch}.sig"
done

if ! tag_object="$(git_with_timeout -C "$SOURCE_DIR" rev-parse --verify "refs/tags/${TAG}^{tag}")"; then
  echo "$TAG must resolve to an annotated tag object" >&2
  exit 1
fi
tag_commit="$(git_with_timeout -C "$SOURCE_DIR" rev-parse --verify "${tag_object}^{commit}")"
[[ "$tag_commit" == "$COMMIT" ]] || { echo "bundle commit differs from local tag" >&2; exit 1; }
git_with_timeout -C "$SOURCE_DIR" ls-tree -r -z "$tag_commit" > "$work/tag-tree"
while IFS= read -r -d '' tree_entry; do
  tree_mode=${tree_entry%% *}
  [[ "$tree_mode" != 120000 && "$tree_mode" != 160000 ]] \
    || { echo "$TAG contains a symlink or submodule; release source must be self-contained" >&2; exit 1; }
done < "$work/tag-tree"
embedded_tag="$(git_with_timeout -C "$SOURCE_DIR" cat-file tag "$tag_object" | awk '
  /^$/ { headers=0 }
  headers != 0 && /^tag / { if (found++) exit 2; sub(/^tag /, ""); value=$0 }
  NR == 1 { headers=1 }
  END { if (found != 1) exit 1; print value }
')"
[[ "$embedded_tag" == "$TAG" ]] \
  || { echo "annotated tag object names $embedded_tag, not $TAG" >&2; exit 1; }
if ! tag_status="$(git_with_timeout -c gpg.format=openpgp -c gpg.program="$gpg_wrapper" \
  -c gpg.openpgp.program="$gpg_wrapper" \
  -C "$SOURCE_DIR" verify-tag --raw "$tag_object" 2>&1)"; then
  printf '%s\n' "$tag_status" >&2
  echo "$TAG does not have a valid OpenPGP signature" >&2
  exit 1
fi
printf '%s\n' "$tag_status" | awk -v expected="$LTA_EXPECTED_TAG_SIGNER_FINGERPRINT" '
  $1 == "[GNUPG:]" && $2 == "VALIDSIG" && (tolower($3) == expected || tolower($NF) == expected) { matched++ }
  END { exit(matched == 1 ? 0 : 1) }
' || { echo "$TAG was not signed by the independently pinned OpenPGP key" >&2; exit 1; }
remote_tag="$(gh_with_timeout api "repos/${REPO}/git/ref/tags/${TAG}" --jq '.object.sha')"
[[ "$tag_object" == "$remote_tag" ]] || { echo "local and GitHub tag objects differ" >&2; exit 1; }
ancestry="$(gh_with_timeout api "repos/${REPO}/compare/${tag_commit}...main" --jq '.status')"
[[ "$ancestry" == identical || "$ancestry" == ahead ]] \
  || { echo "$TAG is not contained in GitHub main" >&2; exit 1; }
successful_sha="$(gh_with_timeout run list --repo "$REPO" --workflow release.yml --branch "$TAG" --event push --limit 100 \
  --json conclusion,headSha,headBranch \
  --jq "first(.[] | select(.conclusion == \"success\" and .headSha == \"$tag_commit\" and .headBranch == \"$TAG\")) | .headSha // \"\"")"
[[ "$successful_sha" == "$tag_commit" ]] || { echo "no successful Release workflow for $TAG at $tag_commit" >&2; exit 1; }
git_with_timeout -C "$SOURCE_DIR" show "$tag_commit:internal/selfmanage/release_pubkey.hex" > "$work/tag-keyring.hex"
cmp "$work/tag-keyring.hex" "$BUNDLE_DIR/release_pubkey.hex" || { echo "bundle keyring differs from tagged source" >&2; exit 1; }

decimal_gt() {
  local left=$1 right=$2
  (( ${#left} > ${#right} )) && return 0
  (( ${#left} < ${#right} )) && return 1
  [[ "$left" > "$right" ]]
}

stable_tag_gt() {
  local newer=$1 older=$2 nmajor nminor npatch omajor ominor opatch pair left right
  [[ "$newer" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
  nmajor=${BASH_REMATCH[1]}; nminor=${BASH_REMATCH[2]}; npatch=${BASH_REMATCH[3]}
  [[ "$older" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
  omajor=${BASH_REMATCH[1]}; ominor=${BASH_REMATCH[2]}; opatch=${BASH_REMATCH[3]}
  for pair in "$nmajor:$omajor" "$nminor:$ominor" "$npatch:$opatch"; do
    left=${pair%%:*}; right=${pair#*:}
    decimal_gt "$left" "$right" && return 0
    decimal_gt "$right" "$left" && return 1
  done
  return 1
}

highest_stable_release_excluding() {
  local excluded=${1:-} release_tags tag highest=""
  release_tags="$(gh_with_timeout api --paginate "repos/${REPO}/releases?per_page=100" \
    --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name')" || return 1
  while IFS= read -r tag; do
    [[ -n "$tag" ]] || continue
    [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
      || { echo "published stable release has a non-canonical tag: $tag" >&2; return 1; }
    [[ -z "$excluded" || "$tag" != "$excluded" ]] || continue
    if [[ -z "$highest" ]] || stable_tag_gt "$tag" "$highest"; then
      highest=$tag
    fi
  done <<<"$release_tags"
  printf '%s\n' "$highest"
}

current_latest_tag() {
  local latest response_file api_status status_count not_found_count
  response_file="$work/latest-api-response"
  if latest="$(gh_with_timeout release view --repo "$REPO" --json tagName --jq '.tagName' 2>"$work/latest-view-error")"; then
    [[ "$latest" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
      || { echo "Latest has a non-canonical stable tag: $latest" >&2; return 1; }
    printf '%s\n' "$latest"
    return 0
  fi

  # gh release view exits nonzero when the repository has no Latest release.
  # Confirm the exact REST 404 so authentication, transport, and API failures
  # can never be mistaken for the valid empty-Latest state.
  if gh_with_timeout api --include "repos/${REPO}/releases/latest" >"$response_file" 2>&1; then
    api_status=0
  else
    api_status=$?
  fi
  if [[ "$api_status" -eq 0 ]]; then
    echo "Latest lookup was inconsistent: release view failed but the REST route succeeded" >&2
    return 1
  fi
  if [[ "$api_status" -ne 1 ]]; then
    cat "$work/latest-view-error" "$response_file" >&2
    echo "Latest REST lookup failed with unexpected status $api_status" >&2
    return 1
  fi
  status_count="$(grep -Ec '^HTTP/[0-9.]+ [0-9]{3}([[:space:]]|$)' "$response_file" || true)"
  not_found_count="$(grep -Ec '^HTTP/[0-9.]+ 404([[:space:]]|$)' "$response_file" || true)"
  if [[ "$status_count" -eq 1 && "$not_found_count" -eq 1 ]]; then
    printf '\n'
    return 0
  fi
  cat "$work/latest-view-error" "$response_file" >&2
  echo "could not determine the exact Latest release" >&2
  return 1
}

require_latest_exact() {
  local expected=$1 context=$2 actual expected_display actual_display
  actual="$(current_latest_tag)" || return 1
  expected_display=${expected:-<none>}
  actual_display=${actual:-<none>}
  [[ "$actual" == "$expected" ]] \
    || { echo "$context: Latest is $actual_display, expected exactly $expected_display" >&2; return 1; }
}

restore_latest_after_failed_promotion() {
  local expected
  expected="$(highest_stable_release_excluding "$TAG")" \
    || { echo "could not enumerate the stable release to restore" >&2; return 1; }
  if [[ -n "$expected" ]]; then
    gh_with_timeout release edit "$expected" --repo "$REPO" --latest \
      || { echo "could not restore $expected as Latest" >&2; return 1; }
  else
    gh_with_timeout release edit "$TAG" --repo "$REPO" --latest=false \
      || { echo "could not clear Latest when no other stable release exists" >&2; return 1; }
  fi
  require_latest_exact "$expected" "Latest restoration failed" || return 1
  echo "restored Latest to ${expected:-<none>}" >&2
}

release_state() {
  gh_with_timeout release view "$TAG" --repo "$REPO" --json isDraft,isPrerelease,tagName \
    --jq '. | (.isDraft|tostring) + " " + (.isPrerelease|tostring) + " " + .tagName'
}

require_draft() {
  [[ "$(gh_with_timeout release view "$TAG" --repo "$REPO" --json isDraft,tagName --jq '. | (.isDraft|tostring) + " " + .tagName')" == "true $TAG" ]] \
    || { echo "release is no longer the expected draft" >&2; exit 1; }
}
require_remote_tag_object() {
  [[ "$(gh_with_timeout api "repos/${REPO}/git/ref/tags/${TAG}" --jq '.object.sha')" == "$tag_object" ]] \
    || { echo "GitHub tag object changed during publication" >&2; exit 1; }
}
remote_asset_names() {
  gh_with_timeout release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name' | LC_ALL=C sort
}
require_initial_remote_assets() {
  local got
  got="$(remote_asset_names)"
  printf '%s\n' "$got" | awk '
    $0 == "SHA256SUMS" || $0 == "linux-temp-admin-linux-amd64" ||
      $0 == "linux-temp-admin-linux-amd64.sig" || $0 == "linux-temp-admin-linux-arm64" ||
      $0 == "linux-temp-admin-linux-arm64.sig" { seen[$0]=1; next }
    { invalid=1 }
    END {
      if (invalid || !seen["SHA256SUMS"] || !seen["linux-temp-admin-linux-amd64"] ||
          !seen["linux-temp-admin-linux-arm64"]) exit 1
    }
  ' || { echo "release is missing a core unsigned asset or contains an unexpected asset" >&2; printf '%s\n' "$got" >&2; exit 1; }
}
require_exact_signed_assets() {
  local got expected
  got="$(remote_asset_names)"
  expected=$'SHA256SUMS\nlinux-temp-admin-linux-amd64\nlinux-temp-admin-linux-amd64.sig\nlinux-temp-admin-linux-arm64\nlinux-temp-admin-linux-arm64.sig'
  [[ "$got" == "$expected" ]] \
    || { echo "release does not contain exactly the signed release assets" >&2; printf '%s\n' "$got" >&2; exit 1; }
}
require_remote_asset_digests() {
  local got expected name digest size
  got="$(gh_with_timeout release view "$TAG" --repo "$REPO" --json assets \
    --jq '.assets[] | [.name, (.digest // ""), (.size|tostring)] | @tsv' | LC_ALL=C sort)"
  expected="$({
    for name in SHA256SUMS linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig \
      linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig; do
      digest="$(sha256sum "$BUNDLE_DIR/$name" | awk '{print $1}')"
      size="$(wc -c < "$BUNDLE_DIR/$name")"
      printf '%s\tsha256:%s\t%s\n' "$name" "$digest" "$size"
    done
  } | LC_ALL=C sort)"
  [[ "$got" == "$expected" ]] \
    || { echo "remote release asset digests differ from the signed bundle" >&2; diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$got") >&2 || true; exit 1; }
}
download_draft_asset() {
  local name=$1 max=$2 out=$3 record advertised_size api_url blocks actual_size
  record="$(gh_with_timeout release view "$TAG" --repo "$REPO" --json assets \
    --jq ".assets[] | select(.name == \"$name\") | [(.size|tostring), .apiUrl] | @tsv")"
  IFS=$'\t' read -r advertised_size api_url <<<"$record"
  [[ "$advertised_size" =~ ^[0-9]+$ && "$advertised_size" -gt 0 && "$advertised_size" -le "$max" ]] \
    || { echo "invalid or oversized advertised draft asset: $name" >&2; return 1; }
  [[ "$api_url" == "https://api.github.com/repos/${REPO}/releases/assets/"* ]] \
    || { echo "unexpected GitHub asset API URL for $name" >&2; return 1; }
  blocks=$(( (max + 1023) / 1024 ))
  ( ulimit -f "$blocks"; gh_with_timeout api -H 'Accept: application/octet-stream' "$api_url" > "$out" ) \
    || { echo "bounded draft download failed: $name" >&2; return 1; }
  actual_size="$(wc -c < "$out")"
  [[ "$actual_size" -eq "$advertised_size" && "$actual_size" -le "$max" ]] \
    || { echo "draft asset size changed during download: $name" >&2; return 1; }
}
if [[ "$TAG" == *-* ]]; then
  expected_prerelease=true
else
  expected_prerelease=false
fi

REMOTE_RELEASE_STATE="$(release_state)"
case "$REMOTE_RELEASE_STATE" in
  "true false $TAG"|"true true $TAG") RELEASE_WAS_DRAFT=1 ;;
  "false $expected_prerelease $TAG") RELEASE_WAS_DRAFT=0 ;;
  *)
    echo "release is neither the expected draft nor an exactly matching published release: $REMOTE_RELEASE_STATE" >&2
    exit 1
    ;;
esac

BASELINE_HIGHEST_TAG="$(highest_stable_release_excluding "$TAG")"
BASELINE_LATEST_TAG="$(current_latest_tag)"
RESUMING_ALREADY_LATEST=0
if [[ "$TAG" != *-* && "$RELEASE_WAS_DRAFT" -eq 0 && "$BASELINE_LATEST_TAG" == "$TAG" ]]; then
  # A previous run completed the promotion. Verification failures during this
  # read-only resume must not demote a release that was already Latest at entry.
  RESUMING_ALREADY_LATEST=1
else
  require_latest_exact "$BASELINE_HIGHEST_TAG" "invalid publication baseline"
fi
if [[ "$TAG" != *-* && -n "$BASELINE_HIGHEST_TAG" ]]; then
  stable_tag_gt "$TAG" "$BASELINE_HIGHEST_TAG" \
    || { echo "stable release $TAG must be newer than highest other release $BASELINE_HIGHEST_TAG" >&2; exit 1; }
fi

if (( RELEASE_WAS_DRAFT == 1 )); then
  require_draft
  require_initial_remote_assets
  echo ">> [publish 1/4] replace draft with the exact signed bytes"
  gh_with_timeout release upload "$TAG" --repo "$REPO" --clobber \
    "$BUNDLE_DIR/linux-temp-admin-linux-amd64" "$BUNDLE_DIR/linux-temp-admin-linux-amd64.sig" \
    "$BUNDLE_DIR/linux-temp-admin-linux-arm64" "$BUNDLE_DIR/linux-temp-admin-linux-arm64.sig" \
    "$BUNDLE_DIR/SHA256SUMS"
  require_draft
  require_exact_signed_assets
  mkdir "$work/draft"
  for name in SHA256SUMS linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig; do
    limit=$MAX_METADATA_BYTES
    [[ "$name" != linux-temp-admin-linux-amd64 && "$name" != linux-temp-admin-linux-arm64 ]] \
      || limit=$MAX_BINARY_BYTES
    download_draft_asset "$name" "$limit" "$work/draft/$name"
    cmp "$work/draft/$name" "$BUNDLE_DIR/$name" || { echo "draft asset changed during upload: $name" >&2; exit 1; }
  done
  require_remote_asset_digests

  echo ">> [publish 2/4] publish only after authenticated draft verification"
  require_draft
  require_exact_signed_assets
  require_remote_asset_digests
  require_remote_tag_object
  require_latest_exact "$BASELINE_HIGHEST_TAG" "Latest changed during publication preparation"
  if [[ "$TAG" == *-* ]]; then
    gh_with_timeout release edit "$TAG" --repo "$REPO" --draft=false --prerelease --latest=false
  else
    # Keep the new stable version off Latest until its public versioned route
    # has passed byte-for-byte and signature verification. Set the restoration
    # guard before the call because a failed response can still follow an
    # applied server-side mutation.
    LATEST_PROMOTION_ATTEMPTED=1
    gh_with_timeout release edit "$TAG" --repo "$REPO" --draft=false --prerelease=false --latest=false
  fi
else
  echo ">> [publish 1/4] resume exactly matching published release (no asset mutation)"
  require_exact_signed_assets
  require_remote_asset_digests
  echo ">> [publish 2/4] published state already present; continue independent verification"
fi

[[ "$(release_state)" == "false $expected_prerelease $TAG" ]] \
  || { echo "release did not publish as expected" >&2; exit 1; }
require_remote_tag_object
require_exact_signed_assets
require_remote_asset_digests

public_fetch() {
  local url=$1 out=$2 max=$3 attempt blocks fetch_url
  # Bash expresses RLIMIT_FSIZE in 1024-byte units. Exact byte checks below
  # handle the final partial block and remain authoritative.
  blocks=$(( (max + 1023) / 1024 ))
  for attempt in 1 2 3 4 5 6; do
    rm -f -- "$out"
    fetch_url="$url"
    if (( attempt >= 4 )); then
      fetch_url="${url}?download=1"
    fi
    if ( ulimit -f "$blocks"; timeout -k 5 120 curl -q -fsSL --connect-timeout 10 --max-time 120 \
         --proto '=https' --proto-redir '=https' "$fetch_url" -o "$out" ) \
       && [[ -s "$out" && "$(wc -c < "$out")" -le "$max" ]]; then
      return 0
    fi
    sleep "$attempt"
  done
  return 1
}

verify_public_set() {
  local base=$1 dir=$2 name arch
  mkdir "$dir"
  public_fetch "$base/SHA256SUMS" "$dir/SHA256SUMS" 1048576
  for arch in amd64 arm64; do
    name="linux-temp-admin-linux-${arch}"
    public_fetch "$base/$name" "$dir/$name" 67108864
    public_fetch "$base/$name.sig" "$dir/$name.sig" 256
  done
  for name in SHA256SUMS linux-temp-admin-linux-amd64 linux-temp-admin-linux-amd64.sig linux-temp-admin-linux-arm64 linux-temp-admin-linux-arm64.sig; do
    cmp "$dir/$name" "$BUNDLE_DIR/$name" || { echo "public asset differs: $name" >&2; return 1; }
  done
  ( cd "$dir" && sha256sum -c --strict SHA256SUMS )
  for arch in amd64 arm64; do
    signer_with_timeout verify "$BUNDLE_DIR/RELEASE_SIGNER_PUBKEY" \
      "$dir/linux-temp-admin-linux-${arch}" "$dir/linux-temp-admin-linux-${arch}.sig"
  done
}

echo ">> [publish 3/4] independently verify public versioned assets"
verify_public_set "https://github.com/${REPO}/releases/download/${TAG}" "$work/public-versioned"
if [[ "$TAG" != *-* ]]; then
  echo ">> [publish 4/4] promote and independently verify the stable Latest route"
  if (( RESUMING_ALREADY_LATEST == 0 )); then
    require_latest_exact "$BASELINE_HIGHEST_TAG" "Latest changed before final promotion; refusing to overwrite it"
    [[ "$(highest_stable_release_excluding "$TAG")" == "$BASELINE_HIGHEST_TAG" ]] \
      || { echo "the stable release baseline changed before final promotion" >&2; exit 1; }
    [[ "$(highest_stable_release_excluding "")" == "$TAG" ]] \
      || { echo "a higher stable release appeared; refusing to promote $TAG" >&2; exit 1; }
    # Set this before the mutating call: gh can fail after the server applied
    # the update. The EXIT trap must restore even in that ambiguous outcome.
    LATEST_PROMOTION_ATTEMPTED=1
    gh_with_timeout release edit "$TAG" --repo "$REPO" --latest
  else
    echo "resuming a previously promoted $TAG after exact asset verification"
  fi

  final_highest="$(highest_stable_release_excluding "")"
  if [[ "$final_highest" != "$TAG" ]]; then
    LATEST_PROMOTION_ATTEMPTED=1
    if restore_latest_after_failed_promotion; then
      LATEST_PROMOTION_ATTEMPTED=0
      echo "a higher stable release appeared during Latest promotion; restored the exact highest alternative" >&2
    else
      echo "a higher stable release appeared and immediate Latest restoration failed; the EXIT trap will retry" >&2
    fi
    exit 1
  fi
  require_latest_exact "$TAG" "published stable release did not become Latest"
  verify_public_set "https://github.com/${REPO}/releases/latest/download" "$work/public-latest"
  require_remote_tag_object
  require_exact_signed_assets
  require_remote_asset_digests
  final_highest="$(highest_stable_release_excluding "")"
  if [[ "$final_highest" != "$TAG" ]]; then
    LATEST_PROMOTION_ATTEMPTED=1
    if restore_latest_after_failed_promotion; then
      LATEST_PROMOTION_ATTEMPTED=0
      echo "a higher stable release appeared during final verification; restored the exact highest alternative" >&2
    else
      echo "a higher stable release appeared and immediate Latest restoration failed; the EXIT trap will retry" >&2
    fi
    exit 1
  fi
  require_latest_exact "$TAG" "Latest changed during final verification"
else
  require_remote_tag_object
  require_exact_signed_assets
  require_remote_asset_digests
  [[ "$(highest_stable_release_excluding "$TAG")" == "$BASELINE_HIGHEST_TAG" ]] \
    || { echo "the stable release set changed while publishing a prerelease" >&2; exit 1; }
  require_latest_exact "$BASELINE_HIGHEST_TAG" "publishing a prerelease unexpectedly changed Latest"
  echo ">> [publish 4/4] prerelease correctly excluded from Latest verification"
fi
PUBLISH_COMPLETE=1
echo "published and independently verified: $TAG"
