#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="temp-admin-en.sh"
VERSION="0.5.2"
DEFAULT_PREFIX="xxvcc"
DEFAULT_EXPIRE_HOURS="24"
DEFAULT_SHELL="/bin/bash"
MANAGED_TAG="linux-temp-admin"
REGISTRY_DIR="/var/lib/linux-temp-admin"
REGISTRY_FILE="$REGISTRY_DIR/users.tsv"
INSTALL_PATH="/usr/local/sbin/linux-temp-admin"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
NC=$'\033[0m'

info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
success() { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
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
  bash $SCRIPT_NAME help                    Show help

Options
  --prefix PREFIX        Username prefix, default: $DEFAULT_PREFIX
  --user USER            Specify username
  --host HOST            Host shown in invite
  --port PORT            SSH port, auto-detected or 22
  --hours HOURS          Valid hours, default: $DEFAULT_EXPIRE_HOURS
  --sudo                 Grant sudo/wheel
  --no-sudo              Do not grant sudo/wheel
  --nopasswd-sudo        Passwordless sudo, high risk
  --yes                  Skip confirmation
  --install-deps         Auto-install missing dependencies
  --no-install-deps      Never install dependencies
  --auto-revoke          Auto-delete user on expiry, default
  --no-auto-revoke       Disable auto-delete, keep account expiry only

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
    pacman) pacman -Sy --noconfirm "${packages[@]}" ;;
    *) err "Unsupported package manager$pm"; return 1 ;;
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
    useradd|chpasswd|usermod|chage)
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
  command_exists chpasswd || missing+=("chpasswd")
  command_exists usermod || missing+=("usermod")
  command_exists chage || missing+=("chage")

  if [[ "$need_sudo" == "true" ]]; then
    if ! command_exists sudo && [[ ! -d /etc/sudoers.d ]]; then
      missing+=("sudo")
    fi
  fi

  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi

  warn "Missing dependencies detected${missing[*]}"

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
      read -r -p "Use $pm to install missing dependencies automatically?[Y/n]: " ans
      if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then install="true"; fi
      ;;
  esac

  if [[ "$install" != "true" ]]; then
    err "Dependency installation cancelled. Please install manually and retry."
    return 1
  fi

  local pkgs=""
  local item tool candidates
  for item in "${missing[@]}"; do
    if [[ "$item" == "useradd/adduser" ]]; then
      tool="useradd"
    else
      tool="$item"
    fi
    candidates=$(package_candidates_for_tool "$tool" "$pm" || true)
    [[ -n "$candidates" ]] && pkgs+=" $candidates"
  done
  pkgs=$(printf '%s' "$pkgs" | unique_words)
  if [[ -z "$pkgs" ]]; then
    err "Could not map missing tools to packages${missing[*]}"
    return 1
  fi

  info "Installing dependency packages$pkgs"
  # shellcheck disable=SC2086
  install_packages "$pm" $pkgs

  local still_missing=()
  command_exists bash || still_missing+=("bash")
  command_exists ssh-keygen || still_missing+=("ssh-keygen")
  if ! command_exists useradd && ! command_exists adduser; then still_missing+=("useradd/adduser"); fi
  command_exists chpasswd || still_missing+=("chpasswd")
  command_exists usermod || still_missing+=("usermod")
  if [[ "$need_sudo" == "true" ]] && ! command_exists sudo && [[ ! -d /etc/sudoers.d ]]; then still_missing+=("sudo"); fi

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

random_password() {
  if command_exists openssl; then
    openssl rand -base64 24 | tr -d '\n'
  else
    tr -dc 'A-Za-z0-9_@%+=:,.^-' </dev/urandom | head -c 32
  fi
}

valid_username() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{1,30}$ ]]
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

user_exists() { id "$1" >/dev/null 2>&1; }

registry_init() {
  mkdir -p "$REGISTRY_DIR"
  chmod 700 "$REGISTRY_DIR"
  touch "$REGISTRY_FILE"
  chmod 600 "$REGISTRY_FILE"
}

registry_record_user() {
  local user="$1" expires="$2" sudo_enabled="$3" nopasswd="$4" host="$5" port="$6" fingerprint="$7" auto_revoke="$8" auto_unit="$9"
  registry_init
  registry_remove_user "$user" 2>/dev/null || true
  local created
  created=$(date '+%F %T %Z')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$user" "$created" "$expires" "$sudo_enabled" "$nopasswd" "$host" "$port" "$fingerprint" "$auto_revoke" "$auto_unit" >> "$REGISTRY_FILE"
}

registry_remove_user() {
  local user="$1"
  [[ -f "$REGISTRY_FILE" ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk -F '\t' -v u="$user" '$1 != u {print}' "$REGISTRY_FILE" > "$tmp"
  cat "$tmp" > "$REGISTRY_FILE"
  chmod 600 "$REGISTRY_FILE"
  rm -f "$tmp"
}

registry_unit_for_user() {
  local target="$1"
  [[ -f "$REGISTRY_FILE" ]] || return 1
  awk -F '\t' -v u="$target" '$1 == u {print $10; exit}' "$REGISTRY_FILE"
}

registry_has_users() {
  [[ -s "$REGISTRY_FILE" ]]
}

registry_list_users() {
  if ! registry_has_users; then
    warn "No registered temporary users."
    return 1
  fi
  local i=0 user created expires sudo_enabled nopasswd host port fingerprint auto_revoke auto_unit state
  while IFS=$'\t' read -r user created expires sudo_enabled nopasswd host port fingerprint auto_revoke auto_unit; do
    [[ -z "${user:-}" ]] && continue
    i=$((i + 1))
    if user_exists "$user"; then state="active"; else state="missing"; fi
    printf '%2d) %-20s status=%-7s sudo=%-3s auto=%-3s expires=%s host=%s port=%s key=%s unit=%s\n' \
      "$i" "$user" "$state" "${sudo_enabled:-?}" "${auto_revoke:-no}" "${expires:-?}" "${host:-?}" "${port:-?}" "${fingerprint:-?}" "${auto_unit:-}"
  done < "$REGISTRY_FILE"
}

registry_select_user() {
  local users=()
  if [[ -s "$REGISTRY_FILE" ]]; then
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
  local user="$1"
  printf '%s-revoke-%s' "$MANAGED_TAG" "$user"
}

install_self_for_revoke() {
  local src="${BASH_SOURCE[0]}"
  if [[ ! -f "$src" ]]; then
    warn "Cannot locate current script file; cannot install stable revoke command."
    return 1
  fi
  install -m 700 -o root -g root "$src" "$INSTALL_PATH"
}

schedule_auto_revoke() {
  local user="$1" hours="$2"
  if ! command_exists systemd-run; then
    warn "systemd-run not found; auto-delete task cannot be created; account expiry only."
    return 1
  fi
  if ! install_self_for_revoke; then
    warn "Failed to install $INSTALL_PATH; auto-delete task cannot be created; account expiry only."
    return 1
  fi
  local unit
  unit=$(auto_revoke_unit_name "$user")
  systemd-run \
    --unit="$unit" \
    --description="linux-temp-admin auto revoke $user" \
    --on-active="${hours}h" \
    "$INSTALL_PATH" revoke --user "$user" --yes >/dev/null 2>&1
  printf '%s\n' "$unit"
}

cancel_auto_revoke() {
  local user="$1" unit="${2:-}"
  [[ -n "$unit" ]] || unit=$(registry_unit_for_user "$user" 2>/dev/null || true)
  [[ -n "$unit" ]] || unit=$(auto_revoke_unit_name "$user")
  if command_exists systemctl; then
    # Stop only the timer. Do not stop ${unit}.service here: auto-revoke runs inside
    # that transient service, and stopping it could kill the cleanup in progress.
    systemctl stop "${unit}.timer" >/dev/null 2>&1 || true
    systemctl reset-failed "${unit}.timer" "${unit}.service" >/dev/null 2>&1 || true
  fi
}

show_auto_revoke_timers() {
  if command_exists systemctl; then
    systemctl list-timers --all --no-pager 2>/dev/null | grep "$MANAGED_TAG-revoke-" || true
  fi
}

get_ssh_port() {
  local port=""
  if [[ -f /etc/ssh/sshd_config ]]; then
    port=$(awk '
      /^[[:space:]]*#/ {next}
      tolower($1)=="port" && $2 ~ /^[0-9]+$/ {p=$2}
      END {if (p) print p}
    ' /etc/ssh/sshd_config 2>/dev/null || true)
  fi
  echo "${port:-22}"
}

get_public_ip() {
  local ip=""
  if command_exists curl; then
    ip=$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)
  fi
  if [[ -z "$ip" ]] && command_exists wget; then
    ip=$(wget -qO- --timeout=3 https://api.ipify.org 2>/dev/null || true)
  fi
  echo "$ip"
}

expire_date_from_hours() {
  local hours="$1"
  if date -u -d "+${hours} hours" +%F >/dev/null 2>&1; then
    date -u -d "+${hours} hours" +%F
  else
    # BusyBox/macOS fallbackFallback when precise account expiry date is unsupported
    date -u +%F
  fi
}

expire_datetime_local() {
  local hours="$1"
  if date -d "+${hours} hours" '+%F %T %Z' >/dev/null 2>&1; then
    date -d "+${hours} hours" '+%F %T %Z'
  else
    date '+%F %T %Z'
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
    useradd -m -s "$shell_path" -c "$MANAGED_TAG temporary admin" "$user"
  elif command_exists adduser; then
    adduser -D -s "$shell_path" -g "$MANAGED_TAG temporary admin" "$user"
  else
    err "useradd/adduser not found; cannot create user."
    exit 1
  fi
}

set_user_password() {
  local user="$1"
  local pass="$2"
  if command_exists chpasswd; then
    printf '%s:%s\n' "$user" "$pass" | chpasswd
  else
    warn "chpasswd not found; password not set; sudo password elevation may not work."
  fi
}

set_user_expiry() {
  local user="$1"
  local hours="$2"
  local date_only
  date_only=$(expire_date_from_hours "$hours")
  if command_exists chage; then
    chage -E "$date_only" "$user" || warn "Failed to set account expiry; please check chage manually."
  else
    warn "chage not found; account expiry not set."
  fi
}

add_sudo() {
  local user="$1"
  local nopasswd="$2"
  local group
  group=$(sudo_group)
  if [[ -z "$group" ]]; then
    warn "sudo/wheel group not found; skipping sudo grant."
    return 1
  fi
  usermod -aG "$group" "$user"
  if [[ "$nopasswd" == "true" ]]; then
    if [[ ! -d /etc/sudoers.d ]]; then
      warn "/etc/sudoers.d does not exist; cannot configure passwordless sudo."
      return 0
    fi
    local file="/etc/sudoers.d/${MANAGED_TAG}-${user}"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" > "$file"
    chmod 440 "$file"
    if command_exists visudo; then
      visudo -cf "$file" >/dev/null || {
        rm -f "$file"
        err "sudoers validation failed; removed $file"
        exit 1
      }
    fi
  fi
}

remove_sudoers_file() {
  local user="$1"
  rm -f "/etc/sudoers.d/${MANAGED_TAG}-${user}" 2>/dev/null || true
}

write_ssh_key() {
  local user="$1"
  local pubkey_file="$2"
  local home_dir
  home_dir=$(getent passwd "$user" | cut -d: -f6)
  if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
    err "User home directory not found: $user"
    exit 1
  fi
  install -d -m 700 -o "$user" -g "$user" "$home_dir/.ssh"
  cat "$pubkey_file" > "$home_dir/.ssh/authorized_keys"
  chown "$user:$user" "$home_dir/.ssh/authorized_keys"
  chmod 600 "$home_dir/.ssh/authorized_keys"
}

print_invite() {
  local host="$1" port="$2" user="$3" expires="$4" sudo_enabled="$5" nopasswd="$6" password="$7" private_key_file="$8" revoke_cmd="$9" auto_revoke="${10}" auto_unit="${11}"
  cat <<EOF

----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: $host
Port: $port
User: $user
Expires: $expires
Sudo: $sudo_enabled
Passwordless sudo: $nopasswd
Auto revoke: $auto_revoke
Auto revoke unit: $auto_unit

SSH login command:
ssh -i ./${user}.key -p $port ${user}@${host}

Save private key command:
cat > ${user}.key <<'EOF_KEY'
$(cat "$private_key_file")
EOF_KEY
chmod 600 ${user}.key

EOF
  if [[ "$sudo_enabled" == "yes" && "$nopasswd" != "yes" ]]; then
    cat <<EOF
Account/Sudo password:
$password

EOF
  elif [[ "$sudo_enabled" == "yes" && "$nopasswd" == "yes" ]]; then
    cat <<EOF
Sudo note:
Passwordless sudo is enabled. This is highly privileged; revoke it immediately after use.

EOF
  else
    cat <<EOF
Sudo note:
sudo was not granted; this is a normal user.

EOF
  fi
  cat <<EOF
Revoke command:
$revoke_cmd

Security notes:
- The private key and sudo password above are shown only once.
- Send only via trusted private chat; never post in groups or public pages.
- Run the revoke command immediately after use.
- The server stores only the public key, not the private key.

----- END LINUX TEMP ADMIN INVITE -----
EOF
}

invite() {
  need_root
  local prefix="$DEFAULT_PREFIX" user="" host="" port="" hours="$DEFAULT_EXPIRE_HOURS"
  local grant_sudo="ask" nopasswd="false" assume_yes="false" deps_mode="ask" auto_revoke="ask"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix) prefix="$2"; shift 2 ;;
      --user) user="$2"; shift 2 ;;
      --host) host="$2"; shift 2 ;;
      --port) port="$2"; shift 2 ;;
      --hours) hours="$2"; shift 2 ;;
      --sudo) grant_sudo="yes"; shift ;;
      --no-sudo) grant_sudo="no"; shift ;;
      --nopasswd-sudo) nopasswd="true"; grant_sudo="yes"; shift ;;
      --yes|-y) assume_yes="true"; shift ;;
      --install-deps) deps_mode="auto"; shift ;;
      --no-install-deps) deps_mode="never"; shift ;;
      --auto-revoke) auto_revoke="yes"; shift ;;
      --no-auto-revoke) auto_revoke="no"; shift ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  if [[ ! "$hours" =~ ^[0-9]+$ || "$hours" -lt 1 ]]; then
    err "--hours must be an integer greater than 0"
    exit 1
  fi

  if [[ -z "$user" ]]; then
    user="${prefix}-$(random_hex 3)"
  fi
  if ! valid_username "$user"; then
    err "Invalid username: $user"
    exit 1
  fi

  if [[ -z "$host" ]]; then
    host=$(get_public_ip)
  fi
  if [[ -z "$host" ]]; then
    read -r -p "Enter server public IP/domain: " host
  fi
  if [[ -z "$port" ]]; then
    port=$(get_ssh_port)
  fi

  if [[ "$grant_sudo" == "ask" ]]; then
    read -r -p "Grant sudo admin privileges?[y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then grant_sudo="yes"; else grant_sudo="no"; fi
  fi

  if [[ "$grant_sudo" == "yes" && "$nopasswd" != "true" ]]; then
    read -r -p "Enable passwordless sudo? High risk, not recommended.[y/N]: " ans2
    if [[ "$ans2" =~ ^[Yy]$ ]]; then nopasswd="true"; fi
  fi

  if [[ "$auto_revoke" == "ask" ]]; then
    read -r -p "Auto-delete this user on expiry?[Y/n]: " ans3
    if [[ -z "$ans3" || "$ans3" =~ ^[Yy]$ ]]; then auto_revoke="yes"; else auto_revoke="no"; fi
  fi

  if [[ "$grant_sudo" == "yes" ]]; then
    ensure_dependencies "$deps_mode" true
  else
    ensure_dependencies "$deps_mode" false
  fi

  cat <<EOF

About to create one-time temporary account
- User$user
- Host$host
- SSH port$port
- Valid for$hours hours
- sudo$grant_sudo
- passwordless sudo$nopasswd
- auto-delete on expiry$auto_revoke

EOF
  confirm_yes "sudo/SSH accounts are high-privilege access. Type YES to confirm." "$assume_yes" || {
    warn "Cancelled."
    exit 0
  }

  local tmpdir keyfile pubfile password expires revoke_cmd sudo_text nopasswd_text fingerprint auto_text auto_unit
  tmpdir=$(mktemp -d)
  keyfile="$tmpdir/${user}.key"
  pubfile="$keyfile.pub"
  trap 'rm -rf "$tmpdir"' RETURN

  password=$(random_password)
  ssh-keygen -t ed25519 -N '' -C "${user}-${MANAGED_TAG}" -f "$keyfile" >/dev/null

  create_user_if_needed "$user" "$DEFAULT_SHELL"
  set_user_password "$user" "$password"
  write_ssh_key "$user" "$pubfile"
  set_user_expiry "$user" "$hours"

  sudo_text="no"
  nopasswd_text="no"
  if [[ "$grant_sudo" == "yes" ]]; then
    if add_sudo "$user" "$nopasswd"; then
      sudo_text="yes"
      [[ "$nopasswd" == "true" ]] && nopasswd_text="yes"
    fi
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
      auto_text="no"
      revoke_cmd="sudo bash $SCRIPT_NAME revoke --user $user"
    fi
  fi
  registry_record_user "$user" "$expires" "$sudo_text" "$nopasswd_text" "$host" "$port" "${fingerprint:-unknown}" "$auto_text" "$auto_unit"

  success "Temporary account created and registered: $user"
  print_invite "$host" "$port" "$user" "$expires" "$sudo_text" "$nopasswd_text" "$password" "$keyfile" "$revoke_cmd" "$auto_text" "${auto_unit:-none}"
}

revoke_user() {
  need_root
  local user="" assume_yes="false"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) user="$2"; shift 2 ;;
      --yes|-y) assume_yes="true"; shift ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
  if [[ -z "$user" ]]; then
    user=$(registry_select_user)
  fi
  if ! user_exists "$user"; then
    warn "User does not exist; cleaning registry and auto-delete task if present."
    cancel_auto_revoke "$user"
    registry_remove_user "$user"
    exit 0
  fi
  if [[ "$assume_yes" != "true" ]]; then
    printf "
${YELLOW}Will force logout and delete user %s and its home directory.${NC}
" "$user"
    read -r -p "Type full username $user to confirm deletion: " confirm_user
    if [[ "$confirm_user" != "$user" ]]; then
      warn "Confirmation mismatch; cancelled."
      exit 0
    fi
  fi
  cancel_auto_revoke "$user"
  pkill -KILL -u "$user" 2>/dev/null || true
  remove_sudoers_file "$user"
  if command_exists deluser; then
    deluser --remove-home "$user" || userdel -r "$user"
  else
    userdel -r "$user"
  fi
  registry_remove_user "$user"
  success "User revoked and deleted: $user"
}

status_user() {
  local user=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) user="$2"; shift 2 ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
  if [[ -n "$user" ]]; then
    if user_exists "$user"; then
      id "$user"
      getent passwd "$user"
      local home_dir
      home_dir=$(getent passwd "$user" | cut -d: -f6)
      [[ -d "$home_dir/.ssh" ]] && ls -la "$home_dir/.ssh"
      if command_exists chage; then chage -l "$user" || true; fi
      local unit
      unit=$(registry_unit_for_user "$user" 2>/dev/null || true)
      if [[ -n "$unit" ]] && command_exists systemctl; then
        systemctl list-timers --all --no-pager 2>/dev/null | grep "$unit" || true
      fi
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
}

cleanup_expired() {
  need_root
  warn "This only shows account expiry and auto-delete status; it does not delete users."
  if ! command_exists chage; then
    warn "chage not found; cannot inspect expiry."
    return 0
  fi
  local today
  today=$(date -u +%F)
  getent passwd | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1}' | while read -r user; do
    [[ -z "$user" ]] && continue
    printf '\n--- %s ---\n' "$user"
    chage -l "$user" | sed -n '1,8p'
  done
  info "Note: account expiry only blocks later login; auto-delete calls revoke to delete user, home, and SSH key."
  show_auto_revoke_timers || true
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
    cleanup-expired) shift; cleanup_expired "$@" ;;
    help|-h|--help) usage ;;
    version|--version) echo "$VERSION" ;;
    *) err "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
