# Canonical generation input for trusted release-script safety functions.
# Release scripts embed selected components and must never source this file.

# BEGIN COMPONENT core_paths
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
# END COMPONENT core_paths

# BEGIN COMPONENT input_paths
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
# END COMPONENT input_paths

# BEGIN COMPONENT source_repo
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
# END COMPONENT source_repo

# BEGIN COMPONENT new_output
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
# END COMPONENT new_output

# BEGIN COMPONENT bounded_copy
bounded_copy() {
  local source=$1 destination=$2 max=$3 blocks size
  blocks=$(( (max + 1023) / 1024 ))
  if ! ( ulimit -f "$blocks" || exit 1; local_with_timeout \
    cp --reflink=never --sparse=never -- "$source" "$destination" ); then
    echo "file exceeds its bounded-copy limit or could not be copied: $source" >&2
    return 1
  fi
  size="$(local_with_timeout stat -Lc '%s' -- "$destination")" \
    || { echo "copied file could not be measured: $destination" >&2; return 1; }
  (( size <= max )) \
    || { echo "file exceeds its bounded-copy limit: $source" >&2; return 1; }
}
# END COMPONENT bounded_copy

# BEGIN COMPONENT sync_output
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
# END COMPONENT sync_output
