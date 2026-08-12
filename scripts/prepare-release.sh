#!/bin/bash -p
# Online, keyless phase: independently rebuild an immutable tag and byte-compare
# it with the CI draft before preparing data for the offline signer.
[[ $- == *p* ]] || { echo "execute prepare-release.sh directly; privileged Bash mode is required" >&2; exit 2; }
set -Eeuo pipefail
umask 077
ulimit -c 0 || { echo "cannot disable core dumps for the trusted preparation phase" >&2; exit 1; }
PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
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
unset GOROOT GOEXPERIMENT GOFIPS140 GO111MODULE GOCACHE GOMODCACHE GOPATH GOTMPDIR
unset GOPROXY GOSUMDB GONOSUMDB GOPRIVATE GONOPROXY GOINSECURE GOVCS GOAUTH GOTELEMETRY
hash -r

TAG="${1:?usage: prepare-release.sh vX.Y.Z /absolute/source/repo /absolute/prepared-dir}"
SOURCE_DIR="${2:?usage: prepare-release.sh vX.Y.Z /absolute/source/repo /absolute/prepared-dir}"
OUT_DIR="${3:?usage: prepare-release.sh vX.Y.Z /absolute/source/repo /absolute/prepared-dir}"
REPO="xxvcc/linux-temp-admin"
GO_VERSION="go1.26.5"
MAX_BINARY_BYTES=67108864
MAX_METADATA_BYTES=1048576
MAX_SOURCE_ARCHIVE_BYTES=134217728
MAX_RELEASE_VERSION_BYTES=128
LOCAL_COMMAND_TIMEOUT_SECONDS=120
GO_BUILD_TIMEOUT_SECONDS=900
: "${LTA_EXPECTED_TAG_SIGNER_FINGERPRINT:?set the independently recorded OpenPGP tag-signer fingerprint}"

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

[[ -z "${LTA_SIGN_KEY:-}" ]] || { echo "LTA_SIGN_KEY must not be present on the online preparation machine" >&2; exit 1; }
[[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]] \
  || { echo "set GH_TOKEN to a short-lived github.com release token" >&2; exit 1; }
GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
export GH_TOKEN
(( ${#TAG} <= MAX_RELEASE_VERSION_BYTES + 1 )) \
  || { echo "tag exceeds 129 ASCII bytes" >&2; exit 1; }
[[ "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z]+([.-][0-9A-Za-z]+)*))?$ ]] \
  || { echo "tag must be vX.Y.Z or vX.Y.Z-prerelease" >&2; exit 1; }
major="${BASH_REMATCH[1]}"
(( ${#major} > 1 || 10#$major >= 2 )) || { echo "release tags below v2 are not supported" >&2; exit 1; }
VERSION="${TAG#v}"
[[ "$SOURCE_DIR" == /* ]] || { echo "source repo must be an absolute directory" >&2; exit 1; }
[[ "$OUT_DIR" == /* && "$OUT_DIR" != / && "$OUT_DIR" != */ ]] \
  || { echo "prepared output must be a new absolute directory other than /" >&2; exit 1; }
[[ "$LTA_EXPECTED_TAG_SIGNER_FINGERPRINT" =~ ^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$ ]] \
  || { echo "invalid expected OpenPGP tag-signer fingerprint" >&2; exit 1; }
LTA_EXPECTED_TAG_SIGNER_FINGERPRINT="${LTA_EXPECTED_TAG_SIGNER_FINGERPRINT,,}"

decimal_gt() {
  local left=$1 right=$2
  (( ${#left} > ${#right} )) && return 0
  (( ${#left} < ${#right} )) && return 1
  [[ "$left" > "$right" ]]
}

stable_tag_gt() {
  local newer=$1 older=$2 nmajor nminor npatch omajor ominor opatch
  (( ${#newer} <= MAX_RELEASE_VERSION_BYTES + 1 )) \
    && [[ "$newer" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
  nmajor=${BASH_REMATCH[1]}; nminor=${BASH_REMATCH[2]}; npatch=${BASH_REMATCH[3]}
  (( ${#older} <= MAX_RELEASE_VERSION_BYTES + 1 )) \
    && [[ "$older" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
  omajor=${BASH_REMATCH[1]}; ominor=${BASH_REMATCH[2]}; opatch=${BASH_REMATCH[3]}
  for pair in "$nmajor:$omajor" "$nminor:$ominor" "$npatch:$opatch"; do
    local left=${pair%%:*} right=${pair#*:}
    decimal_gt "$left" "$right" && return 0
    decimal_gt "$right" "$left" && return 1
  done
  return 1
}

for command_name in awk chmod cmp cp dirname gh git go grep mkdir mktemp readlink rm sha256sum sort stat sync tar timeout wc; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "required command not found: $command_name" >&2; exit 1; }
done
timeout -k 1 1 /bin/true \
	|| { echo "timeout does not support the required kill-after option" >&2; exit 1; }
[[ -x /usr/bin/gpg ]] || { echo "required trusted command not found: /usr/bin/gpg" >&2; exit 1; }
require_trusted_tmp
require_safe_source_repo
require_safe_new_output_path "$OUT_DIR" "prepared output"

gh_with_timeout() {
	timeout -k 5 300 gh "$@"
}
git_with_timeout() {
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" git \
    -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.attributesFile=/dev/null \
    -c core.pager=cat -c pager.branch=false -c pager.tag=false "$@"
}
go_version_output="$(timeout -k 5 30 env GOENV=off GOTOOLCHAIN=local GOFLAGS= GOWORK=off go version)" \
  || { echo "could not execute the trusted Go toolchain" >&2; exit 1; }
[[ "$(awk '{print $3}' <<<"$go_version_output")" == "$GO_VERSION" ]] \
  || { echo "release rebuild requires exactly $GO_VERSION" >&2; exit 1; }

work="$(mktemp -d /tmp/lta-prepare-release.XXXXXX)"
mkdir -m 0700 "$work/go-cache" "$work/lta-module-cache" "$work/go-path" "$work/go-tmp" "$work/gh-config"
GH_CONFIG_DIR="$work/gh-config"
export GH_CONFIG_DIR
gpg_wrapper="$work/gpg-batch"
printf '%s\n' '#!/bin/sh' 'exec /usr/bin/gpg --batch --no-auto-key-retrieve "$@"' > "$gpg_wrapper"
chmod 0700 "$gpg_wrapper"
out_created=0
complete=0
cleanup() {
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" rm -rf -- "$work" \
    || echo "warning: could not remove private preparation workspace within timeout: $work" >&2
  if (( out_created == 1 && complete == 0 )); then
    timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" rm -rf -- "$OUT_DIR" \
      || echo "warning: could not remove incomplete prepared output within timeout: $OUT_DIR" >&2
  fi
}
trap cleanup EXIT

current_latest_tag() {
  local latest response_file api_status status_count not_found_count
  response_file="$work/latest-api-response"
  if latest="$(gh_with_timeout release view --repo "$REPO" --json tagName --jq '.tagName' 2>"$work/latest-view-error")"; then
    [[ ${#latest} -le $((MAX_RELEASE_VERSION_BYTES + 1)) \
       && "$latest" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
      || { echo "Latest has a non-canonical stable tag: $latest" >&2; return 1; }
    printf '%s\n' "$latest"
    return 0
  fi
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

bounded_copy() {
  local source=$1 destination=$2 max=$3 blocks size
  blocks=$(( (max + 1023) / 1024 ))
  if ! ( ulimit -f "$blocks"; timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" \
    cp --reflink=never --sparse=never -- "$source" "$destination" ); then
    echo "file exceeds its transfer limit or could not be copied: $source" >&2
    return 1
  fi
  size="$(timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" stat -Lc '%s' -- "$destination")" \
    || { echo "copied file could not be measured: $destination" >&2; return 1; }
  (( size <= max )) || { echo "file exceeds its transfer limit: $source" >&2; return 1; }
}

sync_output_directory() {
  local directory=$1 label=$2 path parent
  shift 2
  for path in "$@"; do
    local_with_timeout sync -- "$directory/$path" \
      || { echo "cannot sync $label file: $path" >&2; return 1; }
  done
  local_with_timeout sync -- "$directory" \
    || { echo "cannot sync $label directory: $directory" >&2; return 1; }
  parent="$(dirname -- "$directory")"
  local_with_timeout sync -- "$parent" \
    || { echo "cannot sync $label parent directory: $parent" >&2; return 1; }
}

echo ">> [prepare 1/6] authenticate tag, main ancestry, workflow, and draft"
if ! tag_object="$(git_with_timeout -C "$SOURCE_DIR" rev-parse --verify "refs/tags/${TAG}^{tag}")"; then
  echo "$TAG must resolve to an annotated tag object" >&2
  exit 1
fi
tag_commit="$(git_with_timeout -C "$SOURCE_DIR" rev-parse --verify "${tag_object}^{commit}")"
embedded_tag="$(git_with_timeout -C "$SOURCE_DIR" cat-file tag "$tag_object" | awk '
  /^$/ { headers=0 }
  headers != 0 && /^tag / { if (found++) exit 2; sub(/^tag /, ""); value=$0 }
  NR == 1 { headers=1 }
  END { if (found != 1) exit 1; print value }
')"
[[ "$embedded_tag" == "$TAG" ]] \
  || { echo "annotated tag object names $embedded_tag, not $TAG" >&2; exit 1; }
git_with_timeout -C "$SOURCE_DIR" ls-tree -r -z "$tag_commit" > "$work/tag-tree"
while IFS= read -r -d '' tree_entry; do
  tree_mode=${tree_entry%% *}
  [[ "$tree_mode" != 120000 && "$tree_mode" != 160000 ]] \
    || { echo "$TAG contains a symlink or submodule; release source must be self-contained" >&2; exit 1; }
done < "$work/tag-tree"
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
[[ "$tag_object" == "$remote_tag" ]] \
  || { echo "local and GitHub tag objects differ" >&2; exit 1; }
ancestry="$(gh_with_timeout api "repos/${REPO}/compare/${tag_commit}...main" --jq '.status')"
[[ "$ancestry" == identical || "$ancestry" == ahead ]] \
  || { echo "$TAG is not contained in GitHub main" >&2; exit 1; }
[[ "$(gh_with_timeout release view "$TAG" --repo "$REPO" --json isDraft,tagName --jq '. | (.isDraft|tostring) + " " + .tagName')" == "true $TAG" ]] \
  || { echo "GitHub release is missing, published, or points at another tag" >&2; exit 1; }
draft_assets="$(gh_with_timeout release view "$TAG" --repo "$REPO" --json assets \
  --jq '.assets[] | [.name, (.size|tostring), .apiUrl] | @tsv' | LC_ALL=C sort)"
[[ "$(awk -F $'\t' '{print $1}' <<<"$draft_assets")" == $'SHA256SUMS\nlinux-temp-admin-linux-amd64\nlinux-temp-admin-linux-arm64' ]] \
  || { echo "CI draft contains missing, signed, or unexpected assets" >&2; exit 1; }
if [[ "$TAG" != *-* ]]; then
  latest_tag="$(current_latest_tag)"
  if [[ -n "$latest_tag" ]]; then
    stable_tag_gt "$TAG" "$latest_tag" \
      || { echo "stable release $TAG must be newer than current Latest $latest_tag" >&2; exit 1; }
  else
    published_stable_tags="$(gh_with_timeout api --paginate "repos/${REPO}/releases?per_page=100" \
      --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name')"
    [[ -z "$published_stable_tags" ]] \
      || { echo "published stable releases exist but GitHub has no exact Latest release" >&2; exit 1; }
  fi
fi
successful_sha="$(gh_with_timeout run list --repo "$REPO" --workflow release.yml --branch "$TAG" --event push --limit 100 \
  --json conclusion,headSha,headBranch \
  --jq "first(.[] | select(.conclusion == \"success\" and .headSha == \"$tag_commit\" and .headBranch == \"$TAG\")) | .headSha // \"\"")"
[[ "$successful_sha" == "$tag_commit" ]] || { echo "no successful Release workflow for $TAG at $tag_commit" >&2; exit 1; }

echo ">> [prepare 2/6] download and strictly validate CI draft assets"
mkdir "$work/ci"
download_draft_asset() {
  local name=$1 max=$2 record advertised_size api_url blocks actual_size
  record="$(awk -F $'\t' -v wanted="$name" '$1 == wanted { print $2 "\t" $3 }' <<<"$draft_assets")"
  IFS=$'\t' read -r advertised_size api_url <<<"$record"
  [[ "$advertised_size" =~ ^[0-9]+$ && "$advertised_size" -gt 0 && "$advertised_size" -le "$max" ]] \
    || { echo "invalid or oversized advertised draft asset: $name" >&2; return 1; }
  [[ "$api_url" == "https://api.github.com/repos/${REPO}/releases/assets/"* ]] \
    || { echo "unexpected GitHub asset API URL for $name" >&2; return 1; }
  blocks=$(( (max + 1023) / 1024 ))
  ( ulimit -f "$blocks"; gh_with_timeout api -H 'Accept: application/octet-stream' "$api_url" > "$work/ci/$name" ) \
    || { echo "bounded draft download failed: $name" >&2; return 1; }
  actual_size="$(wc -c < "$work/ci/$name")"
  [[ "$actual_size" -eq "$advertised_size" && "$actual_size" -le "$max" ]] \
    || { echo "draft asset size changed during download: $name" >&2; return 1; }
}
download_draft_asset linux-temp-admin-linux-amd64 "$MAX_BINARY_BYTES"
download_draft_asset linux-temp-admin-linux-arm64 "$MAX_BINARY_BYTES"
download_draft_asset SHA256SUMS "$MAX_METADATA_BYTES"
for name in linux-temp-admin-linux-amd64 linux-temp-admin-linux-arm64 SHA256SUMS; do
  [[ -f "$work/ci/$name" && ! -L "$work/ci/$name" ]] || { echo "missing regular CI asset: $name" >&2; exit 1; }
done
[[ "$(awk 'NF {print $2}' "$work/ci/SHA256SUMS")" == $'linux-temp-admin-linux-amd64\nlinux-temp-admin-linux-arm64' ]] \
  || { echo "CI SHA256SUMS must name exactly amd64 and arm64, in order" >&2; exit 1; }
( cd "$work/ci" && sha256sum -c --strict SHA256SUMS )
for arch in amd64 arm64; do
  asset="$work/ci/linux-temp-admin-linux-${arch}"
  [[ -s "$asset" && "$(wc -c < "$asset")" -le "$MAX_BINARY_BYTES" ]] \
    || { echo "CI ${arch} binary is empty or exceeds the 64 MiB client limit" >&2; exit 1; }
done

echo ">> [prepare 3/6] export committed source only (no candidate scripts executed)"
mkdir "$work/source"
source_archive="$work/source.tar"
source_blocks=$(( (MAX_SOURCE_ARCHIVE_BYTES + 1023) / 1024 ))
( ulimit -f "$source_blocks"; git_with_timeout -C "$SOURCE_DIR" archive --format=tar "$tag_commit" > "$source_archive" ) \
  || { echo "tag source archive is oversized or could not be exported" >&2; exit 1; }
[[ -s "$source_archive" && "$(wc -c < "$source_archive")" -le "$MAX_SOURCE_ARCHIVE_BYTES" ]] \
  || { echo "tag source archive is empty or oversized" >&2; exit 1; }
timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" tar --extract --file="$source_archive" \
  --directory="$work/source" --no-same-owner --no-same-permissions
while IFS= read -r -d '' tree_entry; do
  tree_header=${tree_entry%%$'\t'*}
  tree_path=${tree_entry#*$'\t'}
  read -r tree_mode tree_type tree_object <<<"$tree_header"
  [[ "$tree_type" == blob && -f "$work/source/$tree_path" && ! -L "$work/source/$tree_path" ]] \
    || { echo "exported source is missing a regular tagged file: $tree_path" >&2; exit 1; }
  extracted_object="$(git_with_timeout -C "$SOURCE_DIR" hash-object --no-filters -- "$work/source/$tree_path")"
  [[ "$extracted_object" == "$tree_object" ]] \
    || { echo "exported source differs from tagged Git object: $tree_path" >&2; exit 1; }
done < "$work/tag-tree"

echo ">> [prepare 4/6] reproducibly rebuild with fixed toolchain and flags"
mkdir "$work/local"
for arch in amd64 arm64; do
  case "$arch" in
    amd64) arch_tune="GOAMD64=v1" ;;
    arm64) arch_tune="GOARM64=v8.0" ;;
  esac
  # shellcheck disable=SC2086 # arch_tune is one deliberate NAME=value assignment.
  ( cd "$work/source" && timeout -k 30 "$GO_BUILD_TIMEOUT_SECONDS" \
      env GOENV=off GOTOOLCHAIN=local GOFLAGS= GOWORK=off GO111MODULE=on \
      GOEXPERIMENT= GOFIPS140=off GOTELEMETRY=off GOAUTH=off GOVCS='*:off' \
      GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GONOPROXY= GOINSECURE= \
      GOCACHE="$work/go-cache" GOMODCACHE="$work/lta-module-cache" GOPATH="$work/go-path" GOTMPDIR="$work/go-tmp" \
      CGO_ENABLED=0 GOOS=linux GOARCH="$arch" $arch_tune \
      go build -mod=readonly -buildvcs=false -trimpath -tags osusergo,netgo \
      -ldflags "-s -w -X github.com/xxvcc/linux-temp-admin/internal/buildinfo.Version=${VERSION} -X github.com/xxvcc/linux-temp-admin/internal/buildinfo.ReleaseVersionWitness=LTA_RELEASE_VERSION_V1{${VERSION}}" \
      -o "$work/local/linux-temp-admin-linux-${arch}" ./cmd/linux-temp-admin )
done

echo ">> [prepare 5/6] compare every CI byte with the independent rebuild"
for arch in amd64 arm64; do
  cmp "$work/ci/linux-temp-admin-linux-${arch}" "$work/local/linux-temp-admin-linux-${arch}" \
    || { echo "CI ${arch} binary is not reproducible from $TAG" >&2; exit 1; }
done

keyring="$work/source/internal/selfmanage/release_pubkey.hex"
awk '
  /^[[:space:]]*(#|$)/ { next }
  { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if (length($0) != 64 || $0 !~ /^[0-9A-Fa-f]+$/ || seen[tolower($0)]++) exit 1; count++ }
  END { if (!count) exit 1 }
' "$keyring" || { echo "candidate release keyring is malformed or duplicated" >&2; exit 1; }

echo ">> [prepare 6/6] create non-executable transfer directory"
prepared_work="$work/prepared-output"
mkdir -m 0700 "$prepared_work"
bounded_copy "$work/ci/linux-temp-admin-linux-amd64" "$prepared_work/linux-temp-admin-linux-amd64" "$MAX_BINARY_BYTES"
bounded_copy "$work/ci/linux-temp-admin-linux-arm64" "$prepared_work/linux-temp-admin-linux-arm64" "$MAX_BINARY_BYTES"
bounded_copy "$keyring" "$prepared_work/release_pubkey.hex" "$MAX_METADATA_BYTES"
printf '%s\n' "$TAG" > "$prepared_work/TAG"
printf '%s\n' "$VERSION" > "$prepared_work/VERSION"
printf '%s\n' "$tag_commit" > "$prepared_work/COMMIT"
( cd "$prepared_work" && sha256sum COMMIT TAG VERSION release_pubkey.hex \
    linux-temp-admin-linux-amd64 linux-temp-admin-linux-arm64 > PREPARED_SHA256SUMS )
chmod 0600 "$prepared_work"/*
prepared_manifest_sha256="$(sha256sum "$prepared_work/PREPARED_SHA256SUMS" | awk '{print $1}')"

require_safe_new_output_path "$OUT_DIR" "prepared output"
timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" mkdir -m 0700 -- "$OUT_DIR"
out_created=1
require_safe_directory_path "$OUT_DIR" "prepared output"
prepared_output_files=(COMMIT TAG VERSION release_pubkey.hex linux-temp-admin-linux-amd64 linux-temp-admin-linux-arm64 PREPARED_SHA256SUMS)
for name in "${prepared_output_files[@]}"; do
  limit=$MAX_METADATA_BYTES
  [[ "$name" != linux-temp-admin-linux-amd64 && "$name" != linux-temp-admin-linux-arm64 ]] \
    || limit=$MAX_BINARY_BYTES
  bounded_copy "$prepared_work/$name" "$OUT_DIR/$name" "$limit"
  timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" chmod 0600 "$OUT_DIR/$name"
done
[[ "$(timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" sha256sum "$OUT_DIR/PREPARED_SHA256SUMS" | awk '{print $1}')" == "$prepared_manifest_sha256" ]] \
  || { echo "prepared output manifest changed during transfer" >&2; exit 1; }
timeout -k 5 "$LOCAL_COMMAND_TIMEOUT_SECONDS" /bin/sh -c \
  'cd -- "$1" && exec sha256sum -c --strict PREPARED_SHA256SUMS' sh "$OUT_DIR"
sync_output_directory "$OUT_DIR" "prepared output" "${prepared_output_files[@]}"
complete=1
echo "prepared release data: $OUT_DIR"
echo "release tag: $TAG"
echo "release commit: $tag_commit"
echo "prepared manifest SHA-256: $prepared_manifest_sha256"
echo "transfer this directory to the offline signing machine as data only"
