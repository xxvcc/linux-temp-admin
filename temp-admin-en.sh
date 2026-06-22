#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

SCRIPT_NAME="temp-admin-en.sh"
VERSION="0.8.3"
DEFAULT_PREFIX="xxvcc"
DEFAULT_EXPIRE_HOURS="24"
MAX_EXPIRE_HOURS="8760"
DEFAULT_SHELL="/bin/bash"
MANAGED_TAG="linux-temp-admin"
REGISTRY_DIR="/var/lib/linux-temp-admin"
REGISTRY_FILE="$REGISTRY_DIR/users.tsv"
REGISTRY_LOCK_FILE="$REGISTRY_DIR/users.lock"
INSTALL_PATH="/usr/local/sbin/linux-temp-admin"
SYSTEMD_DIR="/etc/systemd/system"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
NC=$'\033[0m'

info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
success() { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*" >&2; }
err() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Please run as root: sudo bash $SCRIPT_NAME"
    exit 1
  fi
}

usage() {
  cat <<EOF
$SCRIPT_NAME v$VERSION - Linux one-time temporary admin invite script

Usage
  bash $SCRIPT_NAME                         Interactive menu
  bash $SCRIPT_NAME invite                  Create one-time admin invite
  bash $SCRIPT_NAME revoke --user USER      Revoke/delete temp user
  bash $SCRIPT_NAME status [--user USER]    Show status
  bash $SCRIPT_NAME cleanup-expired         Show expiry/auto-revoke status
  bash $SCRIPT_NAME expiry-status           Show expiry/auto-revoke status
  bash $SCRIPT_NAME help                    Show help

Options
  --prefix PREFIX        Username prefix, default: $DEFAULT_PREFIX
  --user USER            Specify username
  --host HOST            Host shown in invite
  --port PORT            SSH port, auto-detected or 22
  --hours HOURS          Valid hours, default: $DEFAULT_EXPIRE_HOURS, max: $MAX_EXPIRE_HOURS
  --sudo                 Grant NOPASSWD sudo/wheel
  --no-sudo              Do not grant sudo/wheel
  --yes                  Skip confirmation
  --confirm-sudo USER    Required with --sudo --yes; repeat the full username
  --allow-non-tty-private-key-output
                         Allow private key output when stdout is not a TTY (dangerous)
  --install-deps         Auto-install missing dependencies
  --no-install-deps      Never install dependencies
  --auto-revoke          Auto-delete user on expiry, default
  --no-auto-revoke       Disable auto-delete, keep account expiry only
  --force                Allow revoke of unregistered users (dangerous)
  --confirm-force USER   Required with --force --yes for unregistered users; repeat the full username

Examples
  bash $SCRIPT_NAME invite
  bash $SCRIPT_NAME invite --prefix xxvcc --hours 12 --sudo
  bash $SCRIPT_NAME revoke --user xxvcc-a1b2c3
  bash $SCRIPT_NAME status --user xxvcc-a1b2c3
EOF
}

confirm_yes() {
  local prompt="$1"
  local skip="${2:-false}"
  if [[ "$skip" == "true" ]]; then
    return 0
  fi
  printf "\n${YELLOW}%s${NC}\n" "$prompt"
  read -r -p "Type YES to confirm: " ans
  [[ "$ans" == "YES" ]]
}

require_value() {
  local opt="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    err "Missing value for option $opt."
    usage
    exit 1
  fi
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

pkg_manager() {
  if command_exists apt-get; then echo "apt";
  elif command_exists dnf; then echo "dnf";
  elif command_exists yum; then echo "yum";
  elif command_exists apk; then echo "apk";
  elif command_exists pacman; then echo "pacman";
  else echo ""; fi
}

install_packages() {
  local pm="$1"; shift
  local packages=("$@")
  case "$pm" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
      ;;
    dnf) dnf install -y "${packages[@]}" ;;
    yum) yum install -y "${packages[@]}" ;;
    apk) apk add --no-cache "${packages[@]}" ;;
    pacman) pacman -Syu --noconfirm --needed "${packages[@]}" ;;
    *) err "Unsupported package manager: $pm"; return 1 ;;
  esac
}

package_candidates_for_tool() {
  local tool="$1" pm="$2"
  case "$tool" in
    ssh-keygen)
      case "$pm" in
        apt) echo "openssh-client" ;;
        dnf|yum) echo "openssh-clients" ;;
        apk) echo "openssh-keygen" ;;
        pacman) echo "openssh" ;;
      esac
      ;;
    useradd|userdel|usermod|chage)
      case "$pm" in
        apt) echo "passwd" ;;
        dnf|yum) echo "shadow-utils" ;;
        apk) echo "shadow" ;;
        pacman) echo "shadow" ;;
      esac
      ;;
    adduser)
      case "$pm" in
        apt) echo "adduser" ;;
        dnf|yum) echo "shadow-utils" ;;
        apk) echo "shadow" ;;
        pacman) echo "shadow" ;;
      esac
      ;;
    sudo) echo "sudo" ;;
    curl) echo "curl" ;;
    flock)
      case "$pm" in
        apt|dnf|yum|pacman) echo "util-linux" ;;
        apk) echo "util-linux-misc" ;;
        *) echo "" ;;
      esac
      ;;
    at) echo "at" ;;
  esac
}

unique_words() {
  tr ' ' '
' | awk 'NF && !seen[$0]++' | tr '
' ' ' | sed 's/[[:space:]]*$//'
}

ensure_dependencies() {
  local mode="${1:-ask}" need_sudo="${2:-false}"
  local missing=()

  command_exists bash || missing+=("bash")
  command_exists ssh-keygen || missing+=("ssh-keygen")
  if ! command_exists useradd && ! command_exists adduser; then
    missing+=("useradd/adduser")
  fi
  command_exists usermod || missing+=("usermod")
  if ! command_exists userdel && ! command_exists deluser; then
    missing+=("userdel/deluser")
  fi
  command_exists chage || missing+=("chage")
  command_exists flock || missing+=("flock")

  if [[ "$need_sudo" == "true" ]]; then
    command_exists sudo || missing+=("sudo")
  fi

  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi

  warn "Missing dependencies detected: ${missing[*]}"

  local pm
  pm=$(pkg_manager)
  if [[ -z "$pm" ]]; then
    err "No supported package manager found (apt/dnf/yum/apk/pacman). Please install missing dependencies manually and retry."
    return 1
  fi

  local install="false"
  case "$mode" in
    auto) install="true" ;;
    never)
      err "Dependencies are missing and auto-install is disabled."
      return 1
      ;;
    ask|*)
      read -r -p "Use $pm to install missing dependencies automatically? Type YES to confirm: " ans
      if [[ "$ans" == "YES" ]]; then install="true"; fi
      ;;
  esac

  if [[ "$install" != "true" ]]; then
    err "Dependency installation cancelled. Please install manually and retry."
    return 1
  fi

  local pkgs_text=""
  local item tool candidates
  for item in "${missing[@]}"; do
    if [[ "$item" == "useradd/adduser" || "$item" == "userdel/deluser" ]]; then
      tool="useradd"
    else
      tool="$item"
    fi
    candidates=$(package_candidates_for_tool "$tool" "$pm" || true)
    [[ -n "$candidates" ]] && pkgs_text+=" $candidates"
  done
  pkgs_text=$(printf '%s' "$pkgs_text" | unique_words)
  if [[ -z "$pkgs_text" ]]; then
    err "Could not map missing tools to packages: ${missing[*]}"
    return 1
  fi

  local pkgs=()
  read -r -a pkgs <<< "$pkgs_text"
  info "Installing dependency packages: $pkgs_text"
  install_packages "$pm" "${pkgs[@]}"

  local still_missing=()
  command_exists bash || still_missing+=("bash")
  command_exists ssh-keygen || still_missing+=("ssh-keygen")
  if ! command_exists useradd && ! command_exists adduser; then still_missing+=("useradd/adduser"); fi
  command_exists usermod || still_missing+=("usermod")
  if ! command_exists userdel && ! command_exists deluser; then still_missing+=("userdel/deluser"); fi
  command_exists chage || still_missing+=("chage")
  command_exists flock || still_missing+=("flock")
  if [[ "$need_sudo" == "true" ]] && ! command_exists sudo; then still_missing+=("sudo"); fi

  if [[ ${#still_missing[@]} -gt 0 ]]; then
    err "Still missing after install: ${still_missing[*]}. Please fix manually and retry."
    return 1
  fi

  success "Dependency check passed."
}

random_hex() {
  local bytes="${1:-3}"
  if command_exists openssl; then
    openssl rand -hex "$bytes"
  else
    head -c "$bytes" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

valid_username() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,30}[a-z0-9]$ ]]
}

valid_prefix() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,19}$ && "$1" != *- && "$1" != *_ ]]
}

valid_host() {
  local host="$1"
  [[ ${#host} -ge 1 && ${#host} -le 253 ]] || return 1
  [[ "$host" != *[[:space:]]* ]] || return 1
  [[ "$host" =~ ^[A-Za-z0-9._:-]+$ ]] || return 1

  # IPv6 literals
  if [[ "$host" == *:* ]]; then
    [[ "$host" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    # Reject three or more consecutive colons
    [[ "$host" != *:::* ]] || return 1
    # At most one :: compression
    local tmp="$host" count=0
    while [[ "$tmp" == *::* ]]; do
      count=$((count + 1))
      tmp="${tmp/::/:}"
    done
    [[ $count -le 1 ]] || return 1
    # Each group max 4 hex chars; total groups with :: <= 8
    local IFS=':' groups
    read -r -a groups <<< "$host"
    local non_empty=0
    local group
    for group in "${groups[@]}"; do
      [[ ${#group} -le 4 ]] || return 1
      [[ -z "$group" || "$group" =~ ^[0-9A-Fa-f]+$ ]] || return 1
      [[ -n "$group" ]] && non_empty=$((non_empty + 1))
    done
    # With ::, compressed block counts as at least 1 group
    if [[ $count -eq 1 ]]; then
      [[ $((non_empty + 1)) -le 8 ]] || return 1
    else
      [[ ${#groups[@]} -eq 8 ]] || return 1
    fi
    return 0
  fi

  # IPv4 literals: four decimal octets in 0..255.
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    local IFS=. octets octet
    read -r -a octets <<< "$host"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    for octet in "${octets[@]}"; do
      [[ "$octet" =~ ^[0-9]+$ && $((10#$octet)) -le 255 ]] || return 1
    done
    return 0
  fi

  # DNS hostname: labels 1..63 chars, alnum at edges, hyphen allowed inside.
  [[ "$host" != .* && "$host" != *..* && "$host" != *. ]] || return 1
  local label labels IFS=.
  read -r -a labels <<< "$host"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
  return 0
}

sudo_group() {
  if getent group sudo >/dev/null 2>&1; then
    echo "sudo"
  elif getent group wheel >/dev/null 2>&1; then
    echo "wheel"
  else
    echo ""
  fi
}

user_exists() { id -- "$1" >/dev/null 2>&1; }

terminate_user_processes() {
  local user="$1" uid
  uid=$(id -u -- "$user" 2>/dev/null || true)
  if [[ -z "$uid" || ! "$uid" =~ ^[0-9]+$ ]]; then
    warn "Unable to get UID; skipping process termination for: $user"
    return 0
  fi
  pkill -TERM -u "$uid" 2>/dev/null || true
  sleep 2
  pkill -KILL -u "$uid" 2>/dev/null || true
}

is_protected_revoke_target() {
  local user="$1" _registered="${2:-false}" uid
  case "$user" in
    root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd-*|dbus|sshd|polkitd)
      return 0
      ;;
  esac
  uid=$(id -u -- "$user" 2>/dev/null || true)
  [[ "$uid" == "0" ]] && return 0
  if [[ "$uid" =~ ^[0-9]+$ && "$uid" -lt 1000 ]]; then
    return 0
  fi
  return 1
}

sanitize_registry_field() {
  local value="${1:-}"
  value=${value//$'\t'/ }
  value=${value//$'\r'/ }
  value=${value//$'\n'/ }
  printf '%s' "$value"
}

registry_contains_user() {
  local target="$1"
  registry_plain_file_exists "$REGISTRY_FILE" || return 1
  awk -F '\t' -v u="$target" '$1 == u {found=1; exit} END {exit found ? 0 : 1}' "$REGISTRY_FILE"
}

registry_plain_file_exists() {
  local file="$1"
  [[ -f "$file" && ! -L "$file" ]]
}

registry_init() {
  if [[ -L "$REGISTRY_DIR" ]]; then
    err "Security check failed: registry directory is a symlink; refusing to use it: $REGISTRY_DIR"
    return 1
  fi
  if [[ -e "$REGISTRY_DIR" && ! -d "$REGISTRY_DIR" ]]; then
    err "Security check failed: registry path is not a directory: $REGISTRY_DIR"
    return 1
  fi
  install -d -m 700 -o root -g root "$REGISTRY_DIR"
  if [[ -L "$REGISTRY_DIR" || ! -d "$REGISTRY_DIR" ]]; then
    err "Security check failed: registry directory is unsafe: $REGISTRY_DIR"
    return 1
  fi
  chown root:root "$REGISTRY_DIR" 2>/dev/null || true
  chmod 700 "$REGISTRY_DIR"

  local f
  for f in "$REGISTRY_FILE" "$REGISTRY_LOCK_FILE"; do
    if [[ -L "$f" ]]; then
      err "Security check failed: registry file is a symlink; refusing to use it: $f"
      return 1
    fi
    if [[ -e "$f" && ! -f "$f" ]]; then
      err "Security check failed: registry path is not a regular file: $f"
      return 1
    fi
    if [[ ! -e "$f" ]]; then
      : > "$f"
    fi
    if [[ -L "$f" || ! -f "$f" ]]; then
      err "Security check failed: registry file is unsafe: $f"
      return 1
    fi
    chown root:root "$f" 2>/dev/null || true
    chmod 600 "$f"
  done
}

registry_lock() {
  local __fd_var="$1"
  registry_init || return 1
  printf -v "$__fd_var" '%s' ""
  if ! command_exists flock; then
    warn "flock not found; registry concurrent-write protection is degraded."
    return 0
  fi
  if [[ -L "$REGISTRY_LOCK_FILE" || ! -f "$REGISTRY_LOCK_FILE" ]]; then
    err "Registry lock file is unsafe: $REGISTRY_LOCK_FILE"
    return 1
  fi
  local fd
  exec {fd}>"$REGISTRY_LOCK_FILE"
  if ! flock "$fd"; then
    warn "Failed to acquire registry lock; concurrent-write risk."
    exec {fd}>&-
    return 1
  fi
  printf -v "$__fd_var" '%s' "$fd"
}

registry_unlock() {
  local fd="${1:-}"
  [[ -n "$fd" ]] || return 0
  flock -u "$fd" 2>/dev/null || true
  exec {fd}>&-
}

registry_remove_user_unlocked() {
  local user="$1"
  registry_plain_file_exists "$REGISTRY_FILE" || return 0
  local tmp
  tmp=$(mktemp "${REGISTRY_DIR}/users.tsv.tmp.XXXXXX")
  awk -F '\t' -v u="$user" '$1 != u {print}' "$REGISTRY_FILE" > "$tmp"
  chown root:root "$tmp" 2>/dev/null || true
  chmod 600 "$tmp"
  if [[ -L "$REGISTRY_FILE" || ! -f "$REGISTRY_FILE" ]]; then
    rm -f "$tmp"
    warn "Registry path became unsafe; write cancelled."
    return 1
  fi
  mv -f "$tmp" "$REGISTRY_FILE"
  chown root:root "$REGISTRY_FILE" 2>/dev/null || true
  chmod 600 "$REGISTRY_FILE"
}

registry_record_user() {
  local user="$1" expires="$2" sudo_enabled="$3" nopasswd="$4" host="$5" port="$6" fingerprint="$7" auto_revoke="$8" auto_unit="$9"
  user=$(sanitize_registry_field "$user")
  expires=$(sanitize_registry_field "$expires")
  sudo_enabled=$(sanitize_registry_field "$sudo_enabled")
  nopasswd=$(sanitize_registry_field "$nopasswd")
  host=$(sanitize_registry_field "$host")
  port=$(sanitize_registry_field "$port")
  fingerprint=$(sanitize_registry_field "$fingerprint")
  auto_revoke=$(sanitize_registry_field "$auto_revoke")
  auto_unit=$(sanitize_registry_field "$auto_unit")
  local lock_fd
  registry_lock lock_fd || return 1
  if ! registry_remove_user_unlocked "$user" 2>/dev/null; then
    warn "Failed to remove old registry record while updating; append cancelled."
    registry_unlock "$lock_fd"
    return 1
  fi
  if [[ -L "$REGISTRY_FILE" || ! -f "$REGISTRY_FILE" ]]; then
    warn "Registry path is unsafe; ignoring append."
    registry_unlock "$lock_fd"
    return 1
  fi
  local created
  created=$(date '+%F %T %Z')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$user" "$created" "$expires" "$sudo_enabled" "$nopasswd" "$host" "$port" "$fingerprint" "$auto_revoke" "$auto_unit" >> "$REGISTRY_FILE"
  chown root:root "$REGISTRY_FILE" 2>/dev/null || true
  chmod 600 "$REGISTRY_FILE"
  registry_unlock "$lock_fd"
}

registry_remove_user() {
  local user="$1"
  local lock_fd rc=0
  registry_lock lock_fd || return 1
  registry_remove_user_unlocked "$user" || rc=$?
  registry_unlock "$lock_fd"
  return "$rc"
}

registry_unit_for_user() {
  local target="$1"
  registry_plain_file_exists "$REGISTRY_FILE" || return 1
  awk -F '\t' -v u="$target" '$1 == u {print $10; exit}' "$REGISTRY_FILE"
}

registry_has_users() {
  registry_plain_file_exists "$REGISTRY_FILE" && [[ -s "$REGISTRY_FILE" ]]
}

registry_list_users() {
  if ! registry_has_users; then
    warn "No registered temporary users."
    return 1
  fi
  local i=0 user created expires sudo_enabled _legacy_nopasswd host port fingerprint auto_revoke auto_unit state
  while IFS=$'\t' read -r user created expires sudo_enabled _legacy_nopasswd host port fingerprint auto_revoke auto_unit; do
    [[ -z "${user:-}" ]] && continue
    i=$((i + 1))
    if user_exists "$user"; then state="active"; else state="missing"; fi
    printf '%2d) %-20s status=%-7s sudo=%-3s auto=%-3s expires=%s host=%s port=%s key=%s unit=%s\n' \
      "$i" "$user" "$state" "${sudo_enabled:-?}" "${auto_revoke:-no}" "${expires:-?}" "${host:-?}" "${port:-?}" "${fingerprint:-?}" "${auto_unit:-}"
  done < "$REGISTRY_FILE"
}

registry_select_user() {
  local users=()
  if registry_has_users; then
    while IFS=$'\t' read -r user _rest; do
      [[ -z "${user:-}" ]] && continue
      user_exists "$user" && users+=("$user")
    done < "$REGISTRY_FILE"
  fi

  if [[ ${#users[@]} -eq 0 ]]; then
    warn "No existing registered temporary users found."
    read -r -p "Enter username to revoke/delete: " user
    printf '%s\n' "$user"
    return 0
  fi

  echo "Registered temporary users" >&2
  local idx
  for idx in "${!users[@]}"; do
    printf '%2d) %s\n' "$((idx + 1))" "${users[$idx]}" >&2
  done
  echo "You can also type a username directly." >&2
  local choice
  read -r -p "Select number or username to delete: " choice
  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#users[@]} )); then
    printf '%s\n' "${users[$((choice - 1))]}"
  else
    printf '%s\n' "$choice"
  fi
}

auto_revoke_unit_name() {
  local user="$1" escaped=""
  if command_exists systemd-escape && escaped=$(systemd-escape -- "$user" 2>/dev/null) && [[ -n "$escaped" ]]; then
    printf '%s-revoke-%s' "$MANAGED_TAG" "$escaped"
  else
    # Fallback: strip unsafe chars to prevent path traversal
    local safe="${user//[^a-zA-Z0-9_-]/}"
    [[ -n "$safe" ]] || safe="unknown"
    printf '%s-revoke-%s' "$MANAGED_TAG" "$safe"
  fi
}

auto_revoke_service_path() {
  local unit="$1"
  if [[ "$unit" == *"/"* ]]; then
    err "systemd unit name contains illegal characters: $unit"
    return 1
  fi
  printf '%s/%s.service' "$SYSTEMD_DIR" "$unit"
}

auto_revoke_timer_path() {
  local unit="$1"
  if [[ "$unit" == *"/"* ]]; then
    err "systemd unit name contains illegal characters: $unit"
    return 1
  fi
  printf '%s/%s.timer' "$SYSTEMD_DIR" "$unit"
}

shell_quote_arg() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

systemd_quote_arg() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\r'/ }
  value=${value//$'\n'/ }
  printf '"%s"' "$value"
}

show_installed_revoke_status() {
  if [[ -L "$INSTALL_PATH" ]]; then
    warn "Stable revoke command is a symlink; refusing to execute it for safety: $INSTALL_PATH"
    return 0
  fi
  if [[ ! -f "$INSTALL_PATH" ]]; then
    warn "Stable revoke command is not installed: $INSTALL_PATH; auto-delete task creation installs it automatically."
    return 0
  fi
  local installed_version="unknown" mode_owner=""
  if command_exists stat; then
    mode_owner=$(stat -c 'mode=%a owner=%U:%G' "$INSTALL_PATH" 2>/dev/null || true)
  fi
  if [[ -x "$INSTALL_PATH" ]]; then
    installed_version=$("$INSTALL_PATH" version 2>/dev/null || true)
    [[ -n "$installed_version" ]] || installed_version="unknown"
  else
    installed_version="not-executable-by-current-user"
  fi
  info "Stable revoke command: $INSTALL_PATH version=$installed_version current=$VERSION ${mode_owner:-}"
  if [[ "$installed_version" != "unknown" && "$installed_version" != "not-executable-by-current-user" && "$installed_version" != "$VERSION" ]]; then
    warn "Stable revoke command version differs from the current script; the next auto-delete task creation will reinstall the current script."
  fi
}

install_self_for_revoke() {
  local src="${BASH_SOURCE[0]}" install_dir tmp
  if [[ ! -f "$src" || -L "$src" ]]; then
    warn "Cannot safely locate current script file; unable to install stable revoke command."
    return 1
  fi
  install_dir=$(dirname -- "$INSTALL_PATH")
  if [[ -L "$install_dir" || ( -e "$install_dir" && ! -d "$install_dir" ) ]]; then
    warn "Install directory is unsafe; refusing stable revoke installation: $install_dir"
    return 1
  fi
  install -d -m 755 -o root -g root "$install_dir"
  if [[ -L "$INSTALL_PATH" || ( -e "$INSTALL_PATH" && ! -f "$INSTALL_PATH" ) ]]; then
    warn "$INSTALL_PATH is not a safe regular file; refusing installation to prevent TOCTOU attack."
    return 1
  fi
  tmp=$(mktemp "${install_dir}/.linux-temp-admin.XXXXXX")
  install -m 700 -o root -g root "$src" "$tmp"
  if [[ -L "$INSTALL_PATH" || ( -e "$INSTALL_PATH" && ! -f "$INSTALL_PATH" ) ]]; then
    rm -f "$tmp"
    warn "$INSTALL_PATH safety state changed; refusing overwrite."
    return 1
  fi
  mv -f "$tmp" "$INSTALL_PATH"
  chown root:root "$INSTALL_PATH" 2>/dev/null || true
  chmod 700 "$INSTALL_PATH"
}

schedule_at_revoke() {
  local user="$1" hours="$2"
  if ! [[ "$hours" =~ ^[0-9]+$ && "$hours" -ge 1 && "$hours" -le "$MAX_EXPIRE_HOURS" ]]; then
    warn "Invalid hours value, cannot create at auto-revoke task."
    return 1
  fi
  if ! command_exists at; then
    warn "at not found; fallback auto-delete task cannot be created; account expiry only."
    return 1
  fi
  if ! install_self_for_revoke; then
    warn "Failed to install $INSTALL_PATH; fallback auto-delete task cannot be created; account expiry only."
    return 1
  fi
  local output job_id install_arg user_arg
  install_arg=$(shell_quote_arg "$INSTALL_PATH")
  user_arg=$(shell_quote_arg "$user")
  if ! output=$(printf "%s revoke --user %s --yes\n" "$install_arg" "$user_arg" | at now + "$hours" hours 2>&1); then
    warn "Failed to create at auto-revoke job: $output"
    return 1
  fi
  # Try multiple output formats for compatibility with different at versions
  job_id=$(awk '/^job[[:space:]]+[0-9]+/ {print $2; exit}' <<< "$output")
  [[ -n "$job_id" && "$job_id" =~ ^[0-9]+$ ]] || job_id=$(awk 'NF && $1 ~ /^[0-9]+$/ {print $1; exit}' <<< "$output")
  if [[ -z "$job_id" || ! "$job_id" =~ ^[0-9]+$ ]]; then
    warn "Unable to parse at job id: $output"
    return 1
  fi
  printf 'at:%s\n' "$job_id"
}

schedule_auto_revoke() {
  local user="$1" hours="$2"
  if ! command_exists systemctl; then
    warn "systemctl not found; trying at fallback auto-delete task."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! install_self_for_revoke; then
    warn "Failed to install $INSTALL_PATH; trying at fallback auto-delete task."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! valid_username "$user"; then
    warn "Invalid auto-delete username; refusing to create systemd unit: $user"
    return 1
  fi
  local unit service_path timer_path timer_schedule on_calendar exec_start
  unit=$(auto_revoke_unit_name "$user")
  if ! service_path=$(auto_revoke_service_path "$unit") || [[ -z "$service_path" ]]; then
    warn "Failed to generate systemd service path; falling back to at."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! timer_path=$(auto_revoke_timer_path "$unit") || [[ -z "$timer_path" ]]; then
    warn "Failed to generate systemd timer path; falling back to at."
    rm -f "$service_path"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  exec_start="$(systemd_quote_arg "$INSTALL_PATH") revoke --user $(systemd_quote_arg "$user") --yes"
  if on_calendar=$(date -d "+${hours} hours" '+%Y-%m-%d %H:%M:%S' 2>/dev/null); then
    timer_schedule="OnCalendar=$on_calendar
Persistent=true"
  else
    warn "date -d is not supported; using a relative systemd timer. Missed shutdown time will not be replayed."
    timer_schedule="OnActiveSec=${hours}h"
  fi

  if [[ -L "$service_path" || ( -e "$service_path" && ! -f "$service_path" ) || -L "$timer_path" || ( -e "$timer_path" && ! -f "$timer_path" ) ]]; then
    warn "systemd unit path is unsafe; trying at fallback auto-delete task."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi

  if ! cat <<EOF_SERVICE | safe_write_root_file "$service_path" 644
[Unit]
Description=linux-temp-admin auto revoke $user
Documentation=https://github.com/xxvcc/linux-temp-admin

[Service]
Type=oneshot
NoNewPrivileges=yes
PrivateTmp=yes
User=root
ExecStart=$exec_start
EOF_SERVICE
  then
    warn "Failed to write systemd service; trying at fallback auto-delete task."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi

  if ! cat <<EOF_TIMER | safe_write_root_file "$timer_path" 644
[Unit]
Description=linux-temp-admin auto revoke timer for $user
Documentation=https://github.com/xxvcc/linux-temp-admin

[Timer]
$timer_schedule
AccuracySec=1min
Unit=$unit.service

[Install]
WantedBy=timers.target
EOF_TIMER
  then
    rm -f "$service_path"
    warn "Failed to write systemd timer; trying at fallback auto-delete task."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if command_exists systemd-analyze; then
    systemd-analyze verify "$service_path" "$timer_path" >/dev/null || {
      rm -f "$service_path" "$timer_path"
      warn "systemd unit validation failed; trying at fallback auto-delete task."
      schedule_at_revoke "$user" "$hours"
      return $?
    }
  fi
  if ! systemctl daemon-reload >/dev/null; then
    rm -f "$service_path" "$timer_path"
    warn "systemd daemon-reload failed; trying at fallback auto-delete task."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! systemctl enable --now "$unit.timer" >/dev/null; then
    rm -f "$service_path" "$timer_path"
    systemctl daemon-reload >/dev/null 2>&1 || true
    warn "Failed to enable systemd timer; trying at fallback auto-delete task."
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  printf '%s\n' "$unit"
}

cancel_auto_revoke() {
  local user="$1" unit="${2:-}" service_path timer_path
  [[ -n "$unit" ]] || unit=$(registry_unit_for_user "$user" 2>/dev/null || true)
  if [[ "$unit" == at:* ]]; then
    local job_id="${unit#at:}"
    if [[ "$job_id" =~ ^[0-9]+$ ]] && command_exists atrm; then
      atrm "$job_id" >/dev/null 2>&1 || true
    fi
    return 0
  fi
  [[ -n "$unit" ]] || unit=$(auto_revoke_unit_name "$user")
  if [[ "$unit" != ${MANAGED_TAG}-revoke-* || "$unit" == *"/"* ]]; then
    warn "Auto-delete unit is outside this tool's managed namespace; skipping cleanup: $unit"
    return 0
  fi
  if command_exists systemctl; then
    # Stop only the timer. Do not stop the service: auto-revoke may be running inside it.
    systemctl disable --now "${unit}.timer" >/dev/null 2>&1 || true
    systemctl reset-failed "${unit}.timer" "${unit}.service" >/dev/null 2>&1 || true
  fi
  service_path=$(auto_revoke_service_path "$unit" 2>/dev/null || true)
  timer_path=$(auto_revoke_timer_path "$unit" 2>/dev/null || true)
  [[ -n "$timer_path" && "$timer_path" == "$SYSTEMD_DIR"/* && ! -L "$timer_path" ]] && rm -f "$timer_path" 2>/dev/null || true
  [[ -n "$service_path" && "$service_path" == "$SYSTEMD_DIR"/* && ! -L "$service_path" ]] && rm -f "$service_path" 2>/dev/null || true
  if command_exists systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

show_auto_revoke_timers() {
  if command_exists systemctl; then
    systemctl list-timers --all --no-pager 2>/dev/null | grep -F -- "$MANAGED_TAG-revoke-" || true
  fi
  if command_exists atq; then
    atq 2>/dev/null | sed 's/^/at job: /' || true
  fi
}

get_ssh_port() {
  local port=""
  if command_exists sshd; then
    port=$(sshd -T 2>/dev/null | awk 'tolower($1)=="port" && $2 ~ /^[0-9]+$/ {print $2; exit}' || true)
  fi
  if [[ -z "$port" && -f /etc/ssh/sshd_config ]]; then
    port=$(awk '
      /^[[:space:]]*#/ {next}
      tolower($1)=="port" && $2 ~ /^[0-9]+$/ {p=$2}
      END {if (p) print p}
    ' /etc/ssh/sshd_config 2>/dev/null || true)
  fi
  echo "${port:-22}"
}

is_public_ipv4() {
  local ip="$1" IFS=. octets
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  read -r -a octets <<< "$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  local o
  for o in "${octets[@]}"; do
    [[ "$o" =~ ^[0-9]+$ && $((10#$o)) -le 255 ]] || return 1
  done
  case "${octets[0]}" in
    0|10|127|224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239|240|241|242|243|244|245|246|247|248|249|250|251|252|253|254|255) return 1 ;;
  esac
  [[ "${octets[0]}" -eq 100 && "${octets[1]}" -ge 64 && "${octets[1]}" -le 127 ]] && return 1
  [[ "${octets[0]}" -eq 169 && "${octets[1]}" -eq 254 ]] && return 1
  [[ "${octets[0]}" -eq 172 && "${octets[1]}" -ge 16 && "${octets[1]}" -le 31 ]] && return 1
  [[ "${octets[0]}" -eq 192 && "${octets[1]}" -eq 168 ]] && return 1
  [[ "${octets[0]}" -eq 198 && ( "${octets[1]}" -eq 18 || "${octets[1]}" -eq 19 ) ]] && return 1
  return 0
}

ip_probe_debug() {
  if [[ -n "${LINUX_TEMP_ADMIN_DEBUG_IP:-${LINUX_TEMP_ADMIN_DEBUG:-}}" ]]; then
    warn "IP probe diagnostics: $*"
  fi
}

get_url_text() {
  local url="$1" max_time="${2:-3}" connect_timeout="${3:-1}"
  local output="" status=0 tmp_err err=""
  tmp_err=$(mktemp -t linux-temp-admin.XXXXXX)
  if command_exists curl; then
    if output=$(curl -fsS --connect-timeout "$connect_timeout" --max-time "$max_time" "$url" 2>"$tmp_err" | tr -d '\r\n'); then
      status=0
    else
      status=$?
    fi
  elif command_exists wget; then
    if output=$(wget -qO- --timeout="$max_time" "$url" 2>"$tmp_err" | tr -d '\r\n'); then
      status=0
    else
      status=$?
    fi
  else
    rm -f "$tmp_err"
    ip_probe_debug "curl/wget not found; cannot request $url"
    return 1
  fi
  err=$(tr '\n' ' ' < "$tmp_err" | sed 's/[[:space:]]*$//')
  rm -f "$tmp_err"
  if [[ "$status" -eq 0 && -n "$output" ]]; then
    printf '%s\n' "$output"
    return 0
  fi
  if [[ "$status" -eq 0 ]]; then
    err="empty response"
  fi
  ip_probe_debug "$url failed exit=$status${err:+ error=$err}"
  return 1
}

get_local_public_ip() {
  local ip="" service
  local metadata_services=(
    "http://metadata.tencentyun.com/latest/meta-data/public-ipv4"
    "http://169.254.169.254/latest/meta-data/public-ipv4"
    "http://100.100.100.200/latest/meta-data/eipv4"
  )
  for service in "${metadata_services[@]}"; do
    if ip=$(get_url_text "$service" 2 1); then
      if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
        printf '%s\n' "$ip"
        return 0
      fi
      ip_probe_debug "$service returned non-public IPv4: ${ip:0:80}"
    fi
  done

  if command_exists ip; then
    while IFS= read -r ip; do
      if is_public_ipv4 "$ip"; then
        printf '%s\n' "$ip"
        return 0
      fi
    done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')

    ip_probe_debug "No public IPv4 on local interfaces; checking default-route source address."
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' || true)
    if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
    [[ -n "$ip" ]] && ip_probe_debug "Default-route source address is not public IPv4: $ip"
  else
    ip_probe_debug "ip command not found; cannot inspect local interface addresses."
  fi
  return 1
}

get_public_ip() {
  local ip="" service
  local services=("https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com")
  for service in "${services[@]}"; do
    if ip=$(get_url_text "$service" 5 2); then
      if [[ -n "$ip" ]] && valid_host "$ip"; then
        printf '%s\n' "$ip"
        return 0
      fi
      ip_probe_debug "$service returned invalid host: ${ip:0:80}"
    fi
    ip=""
  done
  return 1
}

ssh_host_for_command() {
  local host="$1"
  if [[ "$host" == *:* ]]; then
    printf '[%s]' "$host"
  else
    printf '%s' "$host"
  fi
}

expire_date_from_hours() {
  local hours="$1"
  # chage -E expires on the date at 00:00. If created in the evening
  # (e.g. 21:00), ceil(hours/24)=1 causes chage to lock the account
  # at 00:00 the next day -- only 3 hours later, far before the
  # systemd timer fires. Add one extra day as buffer so the timer
  # triggers first and chage acts only as a final safeguard.
  local days=$(( (hours + 23) / 24 ))
  days=$(( days + 1 ))
  (( days < 2 )) && days=2
  if date -u -d "+${days} days" +%F >/dev/null 2>&1; then
    date -u -d "+${days} days" +%F
  elif command_exists python3; then
    python3 - "$days" <<'PY'
import datetime
import sys
print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=int(sys.argv[1]))).date().isoformat())
PY
  else
    return 1
  fi
}

expire_datetime_local() {
  local hours="$1"
  if date -d "+${hours} hours" '+%F %T %Z' >/dev/null 2>&1; then
    date -d "+${hours} hours" '+%F %T %Z'
  elif command_exists python3; then
    python3 - "$hours" <<'PYCODE'
import datetime
import sys
print((datetime.datetime.now().astimezone() + datetime.timedelta(hours=int(sys.argv[1]))).strftime('%F %T %Z'))
PYCODE
  else
    printf 'unknown (+%s hours)' "$hours"
  fi
}

resolve_login_shell() {
  if [[ -x "$DEFAULT_SHELL" ]]; then
    printf '%s\n' "$DEFAULT_SHELL"
  elif command_exists bash; then
    command -v bash
  elif [[ -x /bin/sh ]]; then
    printf '%s\n' /bin/sh
  else
    err "No usable login shell found."
    return 1
  fi
}

create_user_if_needed() {
  local user="$1"
  local shell_path="$2"
  if user_exists "$user"; then
    err "User already exists: $user"
    exit 1
  fi
  if command_exists useradd; then
    useradd -m -s "$shell_path" -c "${MANAGED_TAG} temporary admin" "$user"
  elif command_exists adduser; then
    adduser -D -s "$shell_path" -g "${MANAGED_TAG} temporary admin" "$user"
  else
    err "useradd/adduser not found; cannot create user."
    exit 1
  fi
}

lock_user_password() {
  local user="$1"
  if usermod -L "$user" >/dev/null 2>&1; then
    return 0
  fi
  warn "Failed to lock account password; please check manually: $user"
  return 1
}

set_user_expiry() {
  local user="$1"
  local hours="$2"
  local date_only
  if ! date_only=$(expire_date_from_hours "$hours"); then
    err "Could not calculate account expiry date; install GNU date or python3 and retry."
    return 1
  fi
  if command_exists chage; then
    chage -E "$date_only" "$user" || {
      err "Failed to set account expiry; stopping creation and rolling back."
      return 1
    }
  else
    err "chage not found; cannot safely set account expiry."
    return 1
  fi
}

safe_write_root_file() {
  local path="$1" mode="$2" dir base tmp
  dir=$(dirname -- "$path")
  base=$(basename -- "$path")
  if [[ -L "$dir" || ! -d "$dir" ]]; then
    warn "Target directory is unsafe; refusing write: $dir"
    return 1
  fi
  if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    warn "Target file is unsafe; refusing write: $path"
    return 1
  fi
  tmp=$(mktemp "${dir}/.${base}.XXXXXX")
  cat > "$tmp"
  chown root:root "$tmp" 2>/dev/null || true
  chmod "$mode" "$tmp"
  if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    rm -f "$tmp"
    warn "Target file safety state changed; refusing overwrite: $path"
    return 1
  fi
  mv -f "$tmp" "$path"
  chown root:root "$path" 2>/dev/null || true
  chmod "$mode" "$path"
}

add_sudo() {
  local user="$1"
  local group
  group=$(sudo_group)
  if [[ -z "$group" ]]; then
    warn "sudo/wheel group not found; skipping sudo grant."
    return 1
  fi
  if [[ -L /etc/sudoers.d || ! -d /etc/sudoers.d ]]; then
    warn "/etc/sudoers.d does not exist or is unsafe; cannot configure NOPASSWD sudo."
    return 1
  fi
  usermod -aG "$group" "$user"
  local file="/etc/sudoers.d/${MANAGED_TAG}-${user}"
  if ! printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" | safe_write_root_file "$file" 440; then
    return 1
  fi
  if command_exists visudo; then
    visudo -cf "$file" >/dev/null || {
      rm -f "$file"
      err "sudoers validation failed, removed $file"
      return 1
    }
  fi
}

remove_sudoers_file() {
  local user="$1" file
  file="/etc/sudoers.d/${MANAGED_TAG}-${user}"
  if [[ "$file" == /etc/sudoers.d/${MANAGED_TAG}-* ]]; then
    rm -f "$file" 2>/dev/null || true
  fi
}

write_ssh_key() {
  local user="$1"
  local pubkey_file="$2"
  local home_dir uid gid ssh_dir auth_file tmp_auth backup_file
  home_dir=$(getent passwd "$user" | cut -d: -f6 | head -n1)
  if [[ -z "$home_dir" || ! -d "$home_dir" || -L "$home_dir" ]]; then
    err "Safe home directory not found: $user"
    return 1
  fi
  uid=$(id -u -- "$user" 2>/dev/null || true)
  gid=$(id -g -- "$user" 2>/dev/null || true)
  if [[ -z "$uid" || -z "$gid" || ! "$uid" =~ ^[0-9]+$ || ! "$gid" =~ ^[0-9]+$ ]]; then
    err "Unable to get UID/GID: $user"
    return 1
  fi
  ssh_dir="$home_dir/.ssh"
  auth_file="$ssh_dir/authorized_keys"
  if [[ -L "$ssh_dir" || ( -e "$ssh_dir" && ! -d "$ssh_dir" ) ]]; then
    err "User .ssh path is unsafe: $ssh_dir"
    return 1
  fi
  install -d -m 700 -o "$uid" -g "$gid" "$ssh_dir"
  if [[ -L "$auth_file" || ( -e "$auth_file" && ! -f "$auth_file" ) ]]; then
    err "authorized_keys path is unsafe: $auth_file"
    return 1
  fi
  # Backup existing authorized_keys if present
  if [[ -f "$auth_file" ]]; then
    backup_file="$ssh_dir/authorized_keys.backup.$(date +%s).$$"
    cp -p -- "$auth_file" "$backup_file"
    chown "$uid:$gid" "$backup_file"
    chmod 600 "$backup_file"
  fi
  tmp_auth=$(mktemp "${ssh_dir}/.authorized_keys.XXXXXX")
  cat "$pubkey_file" > "$tmp_auth"
  chown "$uid:$gid" "$tmp_auth"
  chmod 600 "$tmp_auth"
  if [[ -L "$auth_file" || ( -e "$auth_file" && ! -f "$auth_file" ) ]]; then
    rm -f "$tmp_auth"
    err "authorized_keys safety state changed; refusing overwrite: $auth_file"
    return 1
  fi
  mv -f "$tmp_auth" "$auth_file"
  chown "$uid:$gid" "$auth_file"
  chmod 600 "$auth_file"
}


delete_user_with_home() {
  local user="$1"
  if command_exists deluser && deluser --remove-home "$user" >/dev/null 2>&1; then
    return 0
  fi
  if command_exists userdel && userdel -r -- "$user" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

rollback_created_user() {
  local user="$1" unit="${2:-}"
  [[ -n "${user:-}" ]] || return 0
  warn "Creation failed; rolling back temporary user: $user"
  cancel_auto_revoke "$user" "$unit" || true
  terminate_user_processes "$user"
  remove_sudoers_file "$user" || true
  if user_exists "$user"; then
    delete_user_with_home "$user" || warn "Rollback failed to remove user; please check manually: $user"
  fi
  registry_remove_user "$user" || true
}

print_invite() {
  local host="$1" port="$2" user="$3" expires="$4" sudo_enabled="$5" private_key_file="$6" revoke_cmd="$7" auto_revoke="$8" auto_unit="$9"
  local ssh_host
  ssh_host=$(ssh_host_for_command "$host")
  cat <<EOF

----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: $host
Port: $port
User: $user
Expires: $expires
Sudo: $sudo_enabled
Login: SSH key only
Password login: locked
Auto revoke: $auto_revoke
Auto revoke unit: $auto_unit

SSH login command:
ssh -i ./${user}.key -p $port ${user}@${ssh_host}

Save private key command:
cat > './${user}.key' <<'EOF_KEY'
$(cat "$private_key_file")
EOF_KEY
chmod 600 './${user}.key'

EOF
  if [[ "$sudo_enabled" == "yes" ]]; then
    cat <<EOF
Sudo note:
NOPASSWD sudo is enabled. This account can log in only with the SSH key; account password is locked.

EOF
  else
    cat <<EOF
Sudo note:
sudo was not granted; this is a normal user. Account password is locked.

EOF
  fi
  if [[ "$auto_revoke" != "yes" ]]; then
    cat <<EOF
Auto-delete note:
No auto-delete task was created; account expiry only blocks later login and does not delete the user or home directory. Run the revoke command manually when needed.

EOF
  fi
  cat <<EOF
Revoke command:
$revoke_cmd

Security notes:
- The private key is shown only once and is not stored on the server.
- Account password is locked; no account/sudo password is printed.
- Send only via trusted private chat; never post in groups or public pages.
- Run the revoke command immediately after use.
- The server stores only the public key; deleting the user invalidates this key immediately.

----- END LINUX TEMP ADMIN INVITE -----
EOF
}

invite() {
  need_root
  local prefix="$DEFAULT_PREFIX" user="" host="" port="" hours="$DEFAULT_EXPIRE_HOURS"
  local grant_sudo="ask" assume_yes="false" deps_mode="ask" auto_revoke="ask"
  local confirm_sudo="" allow_non_tty_key_output="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix) require_value "$1" "${2-}"; prefix="$2"; shift 2 ;;
      --user) require_value "$1" "${2-}"; user="$2"; shift 2 ;;
      --host) require_value "$1" "${2-}"; host="$2"; shift 2 ;;
      --port) require_value "$1" "${2-}"; port="$2"; shift 2 ;;
      --hours) require_value "$1" "${2-}"; hours="$2"; shift 2 ;;
      --sudo) grant_sudo="yes"; shift ;;
      --no-sudo) grant_sudo="no"; shift ;;
      --nopasswd-sudo) warn "--nopasswd-sudo is deprecated: --sudo now uses NOPASSWD sudo by default."; grant_sudo="yes"; shift ;;
      --yes|-y) assume_yes="true"; shift ;;
      --confirm-sudo) require_value "$1" "${2-}"; confirm_sudo="$2"; shift 2 ;;
      --allow-non-tty-private-key-output) allow_non_tty_key_output="true"; shift ;;
      --install-deps) deps_mode="auto"; shift ;;
      --no-install-deps) deps_mode="never"; shift ;;
      --auto-revoke) auto_revoke="yes"; shift ;;
      --no-auto-revoke) auto_revoke="no"; shift ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  if [[ ! "$hours" =~ ^[0-9]{1,4}$ || "$hours" -lt 1 || "$hours" -gt "$MAX_EXPIRE_HOURS" ]]; then
    err "--hours must be an integer between 1 and $MAX_EXPIRE_HOURS"
    exit 1
  fi
  if ! valid_prefix "$prefix"; then
    err "Invalid username prefix: $prefix. Use lowercase letters, digits, underscore, and hyphen only; start with a letter/underscore; do not end with '-' or '_'; max 20 chars."
    exit 1
  fi

  if [[ -z "$user" ]]; then
    local attempt
    for ((attempt = 1; attempt <= 20; attempt++)); do
      user="${prefix}-$(random_hex 5)"
      if ! user_exists "$user"; then
        break
      fi
      user=""
    done
    if [[ -z "$user" ]]; then
      err "Random username generation collided repeatedly; specify --user."
      exit 1
    fi
  fi
  if ! valid_username "$user"; then
    err "Invalid username: $user"
    exit 1
  fi

  if [[ -z "$host" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      err "--yes mode will not contact external services to detect public IP; pass --host explicitly."
      exit 1
    else
      warn "Automatic detection first tries local interfaces and cloud metadata; if that fails, it contacts external services: https://api.ipify.org, https://ifconfig.me/ip, https://icanhazip.com"
      read -r -p "Detect public IP automatically?[y/N]: " ans_host
      if [[ "$ans_host" =~ ^[Yy]$ ]]; then
        if host=$(get_local_public_ip); then
          info "Detected public IP via local/cloud metadata: $host"
        elif host=$(get_public_ip); then
          info "Detected public IP via external service: $host"
        else
          warn "Automatic public IP detection failed; please enter server public IP/domain manually."
          host=""
        fi
      fi
    fi
  fi
  if [[ -z "$host" ]]; then
    read -r -p "Enter server public IP/domain: " host
  fi
  if ! valid_host "$host"; then
    err "Invalid host: $host. Use a normal domain, IPv4, or IPv6 address without ports, spaces, quotes, or shell metacharacters."
    exit 1
  fi
  if [[ -z "$port" ]]; then
    port=$(get_ssh_port)
  fi
  if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt 1 || "$port" -gt 65535 ]]; then
    err "Invalid SSH port: $port"
    exit 1
  fi

  if [[ "$grant_sudo" == "ask" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      grant_sudo="no"
    else
      read -r -p "Grant sudo admin privileges?[y/N]: " ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then grant_sudo="yes"; else grant_sudo="no"; fi
    fi
  fi
  if [[ "$grant_sudo" == "yes" && "$assume_yes" == "true" && "$confirm_sudo" != "$user" ]]; then
    err "Refusing to grant sudo via --sudo --yes: also pass --confirm-sudo $user."
    exit 1
  fi
  if [[ ! -t 1 && "$allow_non_tty_key_output" != "true" ]]; then
    err "stdout is not a TTY; refusing to print one-time private key. If the output channel is safe, add --allow-non-tty-private-key-output."
    exit 1
  fi

  if [[ "$auto_revoke" == "ask" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      auto_revoke="yes"
    else
      read -r -p "Auto-delete this user on expiry?[Y/n]: " ans3
      if [[ -z "$ans3" || "$ans3" =~ ^[Yy]$ ]]; then auto_revoke="yes"; else auto_revoke="no"; fi
    fi
  fi

  cat <<EOF

About to create one-time temporary account
- User: $user
- Host: $host
- SSH port: $port
- Valid for: $hours hours
- sudo: $grant_sudo
- auto-delete on expiry: $auto_revoke

EOF
  confirm_yes "sudo/SSH accounts are high-privilege access. Type YES to confirm." "$assume_yes" || {
    warn "Cancelled."
    exit 0
  }

  if [[ "$grant_sudo" == "yes" ]]; then
    ensure_dependencies "$deps_mode" true
  else
    ensure_dependencies "$deps_mode" false
  fi

  local tmpdir keyfile pubfile expires revoke_cmd sudo_text fingerprint auto_text auto_unit login_shell
  local created_user="" invite_completed="false"
  login_shell=$(resolve_login_shell)
  tmpdir=$(mktemp -d)
  chmod 700 "$tmpdir"
  keyfile="$tmpdir/${user}.key"
  pubfile="$keyfile.pub"
  cleanup_invite_error() {
    local code=$?
    trap - ERR EXIT
    if [[ "$invite_completed" != "true" && -n "$created_user" ]]; then
      rollback_created_user "$created_user" "$auto_unit"
    fi
    rm -rf "$tmpdir"
    exit "$code"
  }
  trap cleanup_invite_error ERR
  trap 'rm -rf "$tmpdir"' EXIT

  ssh-keygen -t ed25519 -N '' -C "${user}-${MANAGED_TAG}" -f "$keyfile" >/dev/null
  chmod 600 "$keyfile"
  chmod 644 "$pubfile"

  create_user_if_needed "$user" "$login_shell"
  created_user="$user"
  lock_user_password "$user"
  write_ssh_key "$user" "$pubfile"
  set_user_expiry "$user" "$hours"

  sudo_text="no"
  if [[ "$grant_sudo" == "yes" ]]; then
    add_sudo "$user"
    sudo_text="yes"
  fi

  expires=$(expire_datetime_local "$hours")
  revoke_cmd="sudo $INSTALL_PATH revoke --user $user"
  fingerprint=$(ssh-keygen -lf "$pubfile" 2>/dev/null | awk '{print $2}' || true)
  auto_text="no"
  auto_unit=""
  if [[ "$auto_revoke" == "yes" ]]; then
    if auto_unit=$(schedule_auto_revoke "$user" "$hours"); then
      auto_text="yes"
      revoke_cmd="sudo $INSTALL_PATH revoke --user $user"
    else
      warn "Auto-delete task creation failed: account expiry only; expiry will not delete the user or home directory. Run the revoke command manually when needed."
      auto_text="no"
      revoke_cmd="sudo bash $SCRIPT_NAME revoke --user $user"
    fi
  fi
  registry_record_user "$user" "$expires" "$sudo_text" "no" "$host" "$port" "${fingerprint:-unknown}" "$auto_text" "$auto_unit"

  invite_completed="true"
  trap - ERR
  success "Temporary account created and registered: $user"
  print_invite "$host" "$port" "$user" "$expires" "$sudo_text" "$keyfile" "$revoke_cmd" "$auto_text" "${auto_unit:-none}"
  rm -rf "$tmpdir"
  trap - EXIT
}

revoke_user() {
  need_root
  local user="" assume_yes="false" force="false" confirm_force=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) require_value "$1" "${2-}"; user="$2"; shift 2 ;;
      --yes|-y) assume_yes="true"; shift ;;
      --force) force="true"; shift ;;
      --confirm-force) require_value "$1" "${2-}"; confirm_force="$2"; shift 2 ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
  if [[ -z "$user" ]]; then
    user=$(registry_select_user)
  fi
  if ! valid_username "$user"; then
    err "Invalid username; refusing deletion: $user"
    exit 1
  fi
  local registered="false"
  if registry_contains_user "$user"; then
    registered="true"
  fi
  if [[ "$force" != "true" && "$registered" != "true" ]]; then
    err "Refusing to delete an unregistered user: $user. Use --force if you need to delete a default-prefix or other user."
    exit 1
  fi
  if [[ "$force" == "true" && "$registered" != "true" && "$assume_yes" == "true" && "$confirm_force" != "$user" ]]; then
    err "Refusing to delete an unregistered user via --force --yes: also pass --confirm-force $user."
    exit 1
  fi
  if ! user_exists "$user"; then
    warn "User does not exist; cleaning registry and auto-delete task if present."
    cancel_auto_revoke "$user"
    registry_remove_user "$user"
    exit 0
  fi
  if [[ "$assume_yes" != "true" ]]; then
    if [[ "$force" == "true" && "$registered" != "true" ]]; then
      printf "
${RED}DANGER: user %s is not registered by this script; --force will delete a real system user and its home directory.${NC}
" "$user"
    fi
    printf "
${YELLOW}Will force logout and delete user %s and its home directory.${NC}
" "$user"
    read -r -p "Type full username $user to confirm deletion: " confirm_user
    if [[ "$confirm_user" != "$user" ]]; then
      warn "Confirmation mismatch; cancelled."
      exit 0
    fi
  fi
  if is_protected_revoke_target "$user" "$registered"; then
    err "Refusing to delete a protected or system user: $user"
    exit 1
  fi
  cancel_auto_revoke "$user"
  terminate_user_processes "$user"
  remove_sudoers_file "$user"
  if ! delete_user_with_home "$user"; then
    warn "Failed to remove user: $user"
    exit 1
  fi
  registry_remove_user "$user"
  success "User revoked and deleted: $user"
}

status_user() {
  local user=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) require_value "$1" "${2-}"; user="$2"; shift 2 ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
  if [[ -n "$user" ]]; then
    if ! valid_username "$user"; then
      err "Invalid username: $user"
      exit 1
    fi
    if user_exists "$user"; then
      id -- "$user"
      getent passwd "$user"
      local home_dir
      home_dir=$(getent passwd "$user" | cut -d: -f6 | head -n1)
      if [[ -d "$home_dir/.ssh" ]]; then
        stat -c '.ssh mode=%a owner=%U:%G path=%n' "$home_dir/.ssh" 2>/dev/null || ls -ld "$home_dir/.ssh"
        [[ -f "$home_dir/.ssh/authorized_keys" ]] && stat -c 'authorized_keys mode=%a owner=%U:%G path=%n' "$home_dir/.ssh/authorized_keys" 2>/dev/null || true
      fi
      if command_exists chage; then chage -l "$user" || true; fi
      local unit
      unit=$(registry_unit_for_user "$user" 2>/dev/null || true)
      if [[ "$unit" == at:* ]] && command_exists atq; then
        atq 2>/dev/null | awk -v job="${unit#at:}" '$1 == job {print}' || true
      elif [[ -n "$unit" ]] && command_exists systemctl; then
        systemctl list-timers --all --no-pager 2>/dev/null | grep -F -- "$unit" || true
      fi
      show_installed_revoke_status
    else
      err "User does not exist: $user"
      exit 1
    fi
    return
  fi
  info "Registered temporary users:"
  registry_list_users || true
  printf '\n'
  info "System users matching prefix $DEFAULT_PREFIX-"
  getent passwd | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1 "\t" $6 "\t" $7}' || true
  printf '\n'
  info "Auto-delete timers"
  show_auto_revoke_timers || true
  printf '\n'
  show_installed_revoke_status
}

cleanup_expired() {
  need_root
  if [[ $# -gt 0 ]]; then
    err "cleanup-expired does not accept extra arguments: $*"
    usage
    exit 1
  fi
  warn "This only shows account expiry and auto-delete status; it does not delete users."
  if ! command_exists chage; then
    warn "chage not found; cannot inspect expiry."
    return 0
  fi
  local users=()
  if registry_has_users; then
    while IFS=$'\t' read -r user _rest; do
      [[ -z "${user:-}" ]] && continue
      users+=("$user")
    done < "$REGISTRY_FILE"
  fi
  while IFS= read -r user; do
    [[ -z "$user" ]] && continue
    local found="false"
    local u
    for u in "${users[@]}"; do
      [[ "$u" == "$user" ]] && found="true" && break
    done
    [[ "$found" == "false" ]] && users+=("$user")
  done < <(getent passwd | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1}')
  if [[ ${#users[@]} -eq 0 ]]; then
    info "No registered temporary users or system default-prefix users."
    return 0
  fi
  for user in "${users[@]}"; do
    printf '\n--- %s ---\n' "$user"
    if user_exists "$user"; then
      chage -l "$user" | sed -n '1,8p' || true
    else
      info "User does not exist: $user"
    fi
  done
  info "Note: account expiry only blocks later login; auto-delete calls revoke to delete user, home, and SSH key."
  show_auto_revoke_timers || true
  show_installed_revoke_status
}

menu() {
  need_root
  while true; do
    cat <<EOF

${BOLD}Linux Temporary Admin Manager${NC} v$VERSION

1) Create one-time temp admin invite
2) Revoke/delete temp user
3) Show user status
4) Show expiry/auto-delete status
5) Exit
EOF
    read -r -p "Select [1-5]: " choice
    case "$choice" in
      1) invite ;;
      2) revoke_user ;;
      3) read -r -p "Username (blank lists ${DEFAULT_PREFIX}-*): " u; if [[ -n "$u" ]]; then status_user --user "$u"; else status_user; fi ;;
      4) cleanup_expired ;;
      5) exit 0 ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    "" ) menu ;;
    invite|create) shift; invite "$@" ;;
    revoke|delete-user|remove) shift; revoke_user "$@" ;;
    status) shift; status_user "$@" ;;
    cleanup-expired|expiry-status) shift; cleanup_expired "$@" ;;
    help|-h|--help) usage ;;
    version|--version) echo "$VERSION" ;;
    *) err "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
