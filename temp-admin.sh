#!/usr/bin/env bash
#
# DEPRECATED (v1). This bash implementation is no longer maintained. Use the v2
# Go rewrite instead — a single static binary with signature-verified upgrades:
#   https://github.com/xxvcc/linux-temp-admin
# It still runs and emits a deprecation warning at startup (suppress with
# LTA_SUPPRESS_DEPRECATION=1). No new features or fixes will land here.
#
set -Eeuo pipefail
# Capture the caller's locale before forcing LC_ALL=C, to default the UI language.
LINUX_TEMP_ADMIN_ORIG_LOCALE="${LC_ALL:-${LANG:-}}"
export LC_ALL=C
umask 077

SCRIPT_NAME="temp-admin.sh"
VERSION="1.2.3"
DEFAULT_PREFIX="xxvcc"
DEFAULT_EXPIRE_HOURS="24"
MAX_EXPIRE_HOURS="8760"
MAX_UPGRADE_BYTES="1048576"
DEFAULT_SHELL="/bin/bash"
MANAGED_TAG="linux-temp-admin"
REGISTRY_DIR="/var/lib/linux-temp-admin"
REGISTRY_FILE="$REGISTRY_DIR/users.tsv"
REGISTRY_LOCK_FILE="$REGISTRY_DIR/users.lock"
INSTALL_PATH="/usr/local/sbin/linux-temp-admin"
SYSTEMD_DIR="/etc/systemd/system"
DEFAULT_UPGRADE_URL="https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
NC=$'\033[0m'

# --- i18n ----------------------------------------------------------------
# Active UI language: "zh" or "en". Resolved (first match wins): --lang flag >
# LINUX_TEMP_ADMIN_LANG env > interactive prompt (menu or any operational
# subcommand, when on a TTY) > caller locale > English.
LANG_SEL=""
LANG_LOCKED="false"
set_language() {
  local v="${1,,}"
  case "$v" in
    zh*|cn*) LANG_SEL="zh" ;;
    en*)     LANG_SEL="en" ;;
    *) return 1 ;;
  esac
}
resolve_language() {
  [[ -n "$LANG_SEL" ]] && return 0
  if set_language "${LINUX_TEMP_ADMIN_LANG:-}"; then LANG_LOCKED="true"; return 0; fi
  set_language "${LINUX_TEMP_ADMIN_ORIG_LOCALE:-}" && return 0
  LANG_SEL="en"
}
# Ask for the UI language interactively. No-op when the language is locked (via
# --lang or LINUX_TEMP_ADMIN_LANG) or stdin is not a terminal, so piped and
# automated runs are never blocked. The prompt is written to stderr so stdout
# stays clean for subcommands whose output may be captured (e.g. the invite pack).
prompt_language() {
  [[ "$LANG_LOCKED" == "true" || ! -t 0 ]] && return 0
  printf '%s\n' "Select language / 选择语言:  1) English  2) 中文" >&2
  local _lc
  read -r -p "Choice [1-2] (Enter = $LANG_SEL): " _lc
  case "$_lc" in 2|zh*|中*) LANG_SEL="zh" ;; 1|en*) LANG_SEL="en" ;; esac
}
# m "<zh>" "<en>" -> prints the active language's text (caller expands variables).
m() { if [[ "$LANG_SEL" == "zh" ]]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }

info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
success() { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*" >&2; }
err() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "$(m "请使用 root 运行：sudo bash $SCRIPT_NAME" "Please run as root: sudo bash $SCRIPT_NAME")"
    exit 1
  fi
}

usage() {
  if [[ "$LANG_SEL" == "zh" ]]; then
  cat <<EOF
$SCRIPT_NAME v$VERSION - Linux 一次性临时管理员邀请脚本

用法：
  bash $SCRIPT_NAME                         交互式菜单
  bash $SCRIPT_NAME invite                  创建一次性临时管理员邀请
  bash $SCRIPT_NAME revoke --user USER      撤销/删除临时用户
  bash $SCRIPT_NAME status [--user USER]    查看状态
  bash $SCRIPT_NAME cleanup-expired [--compact]  查看过期/自动删除状态（--compact 清理已失效登记）
  bash $SCRIPT_NAME expiry-status [--compact]  查看过期/自动删除状态（同 cleanup-expired）
  bash $SCRIPT_NAME doctor                  检查依赖与系统配置
  bash $SCRIPT_NAME install [--force]       安装/更新本地稳定命令
  bash $SCRIPT_NAME upgrade [--yes] [--force] [--url URL]  从 GitHub 下载并升级稳定命令
  bash $SCRIPT_NAME uninstall [--force]     卸载本地稳定命令
  bash $SCRIPT_NAME help                    显示帮助
  bash $SCRIPT_NAME version                 显示版本号

常用参数：
  --prefix PREFIX        用户名前缀，默认：$DEFAULT_PREFIX
  --user USER            指定用户名
  --host HOST            邀请包中显示的服务器地址
  --port PORT            SSH 端口，自动探测，失败则 22
  --hours HOURS          有效期小时数，默认：$DEFAULT_EXPIRE_HOURS，最大：$MAX_EXPIRE_HOURS
  --sudo                 授予 NOPASSWD sudo 权限
  --no-sudo              不授予 sudo 权限
  --yes                  跳过确认
  --confirm-sudo USER    与 --sudo --yes 一起授予 sudo 时，必须重复完整用户名
  --allow-non-tty-private-key-output
                         允许 stdout 非 TTY 时输出私钥（危险）
  --install-deps         自动安装缺失依赖
  --no-install-deps      不安装缺失依赖
  --auto-revoke          到期自动删除用户，默认
  --no-auto-revoke       不自动删除，仅设置账号过期
  --force                revoke 删除未登记用户；install/upgrade/uninstall 强制覆盖或删除（危险）
  --confirm-force USER   与 --force --yes 一起删除未登记用户时，必须重复完整用户名
  --url URL              upgrade 使用的脚本下载地址（默认：$DEFAULT_UPGRADE_URL）
  --lang zh|en           界面语言，默认跟随环境；也可用环境变量 LINUX_TEMP_ADMIN_LANG

示例：
  bash $SCRIPT_NAME invite
  bash $SCRIPT_NAME invite --prefix xxvcc --hours 12 --sudo
  bash $SCRIPT_NAME revoke --user xxvcc-a1b2c3
  bash $SCRIPT_NAME status --user xxvcc-a1b2c3
  bash $SCRIPT_NAME doctor
  bash $SCRIPT_NAME upgrade
EOF
  else
  cat <<EOF
$SCRIPT_NAME v$VERSION - Linux one-time temporary admin invite script

Usage
  bash $SCRIPT_NAME                         Interactive menu
  bash $SCRIPT_NAME invite                  Create one-time admin invite
  bash $SCRIPT_NAME revoke --user USER      Revoke/delete temp user
  bash $SCRIPT_NAME status [--user USER]    Show status
  bash $SCRIPT_NAME cleanup-expired [--compact]  Show expiry/auto-delete status (--compact prunes stale registry entries)
  bash $SCRIPT_NAME expiry-status [--compact]  Show expiry/auto-delete status (alias of cleanup-expired)
  bash $SCRIPT_NAME doctor                  Check dependencies and system configuration
  bash $SCRIPT_NAME install [--force]       Install/update the stable local command
  bash $SCRIPT_NAME upgrade [--yes] [--force] [--url URL]  Download from GitHub and upgrade the stable command
  bash $SCRIPT_NAME uninstall [--force]     Uninstall the stable local command
  bash $SCRIPT_NAME help                    Show help
  bash $SCRIPT_NAME version                 Show version number

Options
  --prefix PREFIX        Username prefix, default: $DEFAULT_PREFIX
  --user USER            Specify username
  --host HOST            Host shown in invite
  --port PORT            SSH port, auto-detected or 22
  --hours HOURS          Valid hours, default: $DEFAULT_EXPIRE_HOURS, max: $MAX_EXPIRE_HOURS
  --sudo                 Grant NOPASSWD sudo
  --no-sudo              Do not grant sudo
  --yes                  Skip confirmation
  --confirm-sudo USER    Required with --sudo --yes; repeat the full username
  --allow-non-tty-private-key-output
                         Allow private key output when stdout is not a TTY (dangerous)
  --install-deps         Auto-install missing dependencies
  --no-install-deps      Never install dependencies
  --auto-revoke          Auto-delete user on expiry, default
  --no-auto-revoke       Disable auto-delete, keep account expiry only
  --force                revoke unregistered users; force-replace/remove for install/upgrade/uninstall (dangerous)
  --confirm-force USER   Required with --force --yes for unregistered users; repeat the full username
  --url URL              Script download URL for upgrade (default: $DEFAULT_UPGRADE_URL)
  --lang zh|en           UI language (defaults to the environment; also LINUX_TEMP_ADMIN_LANG)

Examples
  bash $SCRIPT_NAME invite
  bash $SCRIPT_NAME invite --prefix xxvcc --hours 12 --sudo
  bash $SCRIPT_NAME revoke --user xxvcc-a1b2c3
  bash $SCRIPT_NAME status --user xxvcc-a1b2c3
  bash $SCRIPT_NAME doctor
  bash $SCRIPT_NAME upgrade
EOF
  fi
}

confirm_yes() {
  local prompt="$1"
  local skip="${2:-false}"
  if [[ "$skip" == "true" ]]; then
    return 0
  fi
  printf "\n${YELLOW}%s${NC}\n" "$prompt"
  read -r -p "$(m "请输入 YES 确认继续: " "Type YES to confirm: ")" ans
  [[ "$ans" == "YES" ]]
}

require_value() {
  local opt="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    err "$(m "参数 $opt 缺少值。" "Missing value for option $opt.")"
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
    *) err "$(m "不支持的包管理器：$pm" "Unsupported package manager: $pm")"; return 1 ;;
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
    install)
      case "$pm" in
        apt|dnf|yum|pacman) echo "coreutils" ;;
        apk) echo "coreutils" ;;
        *) echo "" ;;
      esac
      ;;
    flock)
      case "$pm" in
        apt|dnf|yum|pacman) echo "util-linux" ;;
        apk) echo "util-linux-misc" ;;
        *) echo "" ;;
      esac
      ;;
    at) echo "at" ;;
    date-compute)
      case "$pm" in
        apt|dnf|yum|pacman) echo "coreutils" ;;
        apk) echo "coreutils" ;;
        *) echo "" ;;
      esac
      ;;
  esac
}

unique_words() {
  tr ' ' '
' | awk 'NF && !seen[$0]++' | tr '
' ' ' | sed 's/[[:space:]]*$//'
}

can_compute_future_date() {
  # Setting account expiry needs computing a future date: prefer GNU date, then python3.
  # Probe the SAME compound relative form expire_date_from_hours uses ("+H hours
  # +1 day"), so a date impl that accepts "+1 day" but not the compound form is
  # not mis-reported as OK and then failing mid-invite. busybox date supports
  # neither, so it correctly falls through to python3.
  date -u -d "+0 hours +1 day" +%F >/dev/null 2>&1 || command_exists python3
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
  command_exists install || missing+=("install")
  can_compute_future_date || missing+=("date-compute")

  if [[ "$need_sudo" == "true" ]]; then
    command_exists sudo || missing+=("sudo")
  fi

  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi

  warn "$(m "检测到缺少依赖：${missing[*]}" "Missing dependencies detected: ${missing[*]}")"

  local pm
  pm=$(pkg_manager)
  if [[ -z "$pm" ]]; then
    err "$(m "未找到支持的包管理器（apt/dnf/yum/apk/pacman）。请手动安装缺失依赖后重试。" "No supported package manager found (apt/dnf/yum/apk/pacman). Please install missing dependencies manually and retry.")"
    return 1
  fi

  local install="false"
  case "$mode" in
    auto) install="true" ;;
    never)
      err "$(m "依赖缺失且已指定不自动安装。" "Dependencies are missing and auto-install is disabled.")"
      return 1
      ;;
    ask|*)
      read -r -p "$(m "是否使用 $pm 自动安装缺失依赖？请输入 YES 确认: " "Use $pm to install missing dependencies automatically? Type YES to confirm: ")" ans
      if [[ "$ans" == "YES" ]]; then install="true"; fi
      ;;
  esac

  if [[ "$install" != "true" ]]; then
    err "$(m "已取消安装依赖。请手动安装后重试。" "Dependency installation cancelled. Please install manually and retry.")"
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
    err "$(m "无法映射缺失依赖到安装包：${missing[*]}" "Could not map missing tools to packages: ${missing[*]}")"
    return 1
  fi

  local pkgs=()
  read -r -a pkgs <<< "$pkgs_text"
  info "$(m "安装依赖包：$pkgs_text" "Installing dependency packages: $pkgs_text")"
  install_packages "$pm" "${pkgs[@]}"
  hash -r 2>/dev/null || true

  local still_missing=()
  command_exists bash || still_missing+=("bash")
  command_exists ssh-keygen || still_missing+=("ssh-keygen")
  if ! command_exists useradd && ! command_exists adduser; then still_missing+=("useradd/adduser"); fi
  command_exists usermod || still_missing+=("usermod")
  if ! command_exists userdel && ! command_exists deluser; then still_missing+=("userdel/deluser"); fi
  command_exists chage || still_missing+=("chage")
  command_exists flock || still_missing+=("flock")
  command_exists install || still_missing+=("install")
  can_compute_future_date || still_missing+=("date-compute")
  if [[ "$need_sudo" == "true" ]] && ! command_exists sudo; then still_missing+=("sudo"); fi

  if [[ ${#still_missing[@]} -gt 0 ]]; then
    err "$(m "安装后仍缺少：${still_missing[*]}。请手动处理后重试。" "Still missing after install: ${still_missing[*]}. Please fix manually and retry.")"
    return 1
  fi

  success "$(m "依赖检查通过。" "Dependency check passed.")"
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

  # IPv6 literals (optionally with an embedded IPv4 tail, e.g. ::ffff:1.2.3.4)
  if [[ "$host" == *:* ]]; then
    local v6="$host"
    # Split off and validate an embedded IPv4 tail if present, then represent
    # it as two synthetic hextets so the colon/group checks below still apply.
    if [[ "$host" == *.* ]]; then
      local v4tail="${host##*:}" o4 oct
      [[ "$v4tail" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
      local IFS=.
      read -r -a o4 <<< "$v4tail"
      [[ ${#o4[@]} -eq 4 ]] || return 1
      for oct in "${o4[@]}"; do
        [[ "$oct" =~ ^(0|[1-9][0-9]{0,2})$ && $((10#$oct)) -le 255 ]] || return 1
      done
      v6="${host%:*}:0:0"
    fi
    [[ "$v6" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    # Reject three or more consecutive colons
    [[ "$v6" != *:::* ]] || return 1
    # At most one :: compression
    local tmp="$v6" count=0
    while [[ "$tmp" == *::* ]]; do
      count=$((count + 1))
      tmp="${tmp/::/:}"
    done
    [[ $count -le 1 ]] || return 1
    # Each group max 4 hex chars; total groups with :: <= 8
    local IFS=':' groups
    read -r -a groups <<< "$v6"
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

  # IPv4 literals: four decimal octets in 0..255, no leading zeros (the SSH
  # resolver would otherwise re-interpret e.g. 010.0.0.5 as octal).
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    local IFS=. octets octet
    read -r -a octets <<< "$host"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    for octet in "${octets[@]}"; do
      [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ && $((10#$octet)) -le 255 ]] || return 1
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

user_exists() { id -- "$1" >/dev/null 2>&1; }

# Resolve a single passwd entry by name. getent is not a busybox applet and is
# often absent on musl/Alpine, so fall back to /etc/passwd. Accounts managed by
# this tool are always local, so /etc/passwd is authoritative for them. The
# username is validated ([a-z0-9_-]) before it reaches here; awk matches it as a
# literal field, avoiding any pattern-injection concern.
passwd_entry() {
  local user="$1" line
  if command_exists getent; then
    # Use getent's output whenever it produced any, regardless of its exit code,
    # so a non-zero exit from a partly-failing NSS backend doesn't drop a found
    # entry or cause a duplicating fall-through. `|| true` keeps a non-zero getent
    # from aborting this assignment under errexit before the emptiness check.
    line=$(getent passwd "$user" 2>/dev/null) || true
    [[ -n "$line" ]] && { printf '%s\n' "$line"; return 0; }
  fi
  awk -F: -v u="$user" '$1 == u {print; exit}' /etc/passwd 2>/dev/null
}

# Enumerate the local passwd database, with the same getent->/etc/passwd fallback.
passwd_db() {
  local out
  if command_exists getent; then
    out=$(getent passwd 2>/dev/null) || true
    [[ -n "$out" ]] && { printf '%s\n' "$out"; return 0; }
  fi
  cat /etc/passwd 2>/dev/null || true
}

# Send a signal to every process whose real OR effective UID matches, by
# scanning /proc. Fallback for systems without pkill (not a busybox applet;
# absent on Alpine). Matching either uid covers both `pkill -u` (effective) and
# `pkill -U` (real) semantics so no session process is missed.
signal_uid_processes() {
  local sig="$1" uid="$2" proc pid ruid euid
  # Refuse a non-numeric, empty, or root (0) uid: an empty uid would match the
  # empty ruid of a process that vanished mid-scan (killing an arbitrary pid),
  # and uid 0 would signal every root process.
  [[ "$uid" =~ ^[0-9]+$ && "$uid" -ge 1 ]] || return 0
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/status" ]] || continue
    ruid=""; euid=""
    # `|| true` must be OUTSIDE the <(): it has to catch read's own non-zero
    # (empty input when the process vanished mid-scan), not just awk's, or
    # errexit would abort the whole revoke/rollback here.
    read -r ruid euid < <(awk '/^Uid:/ {print $2, $3; exit}' "$proc/status" 2>/dev/null) || true
    if [[ "$ruid" == "$uid" || "$euid" == "$uid" ]]; then
      pid=${proc#/proc/}
      kill "-$sig" "$pid" 2>/dev/null || true
    fi
  done
}

terminate_user_processes() {
  local user="$1" uid
  uid=$(id -u -- "$user" 2>/dev/null || true)
  if [[ -z "$uid" || ! "$uid" =~ ^[0-9]+$ || "$uid" -eq 0 ]]; then
    warn "$(m "无法获取有效 UID（或为 0），跳过终止用户进程：$user" "Could not get a valid non-root UID; skipping process termination for: $user")"
    return 0
  fi
  if command_exists pkill; then
    pkill -TERM -u "$uid" 2>/dev/null || true
    sleep 2
    pkill -KILL -u "$uid" 2>/dev/null || true
    return 0
  fi
  # pkill missing (busybox/Alpine): signal by scanning /proc so the account's
  # live sessions are still forced off before the account is deleted.
  signal_uid_processes TERM "$uid"
  sleep 2
  signal_uid_processes KILL "$uid"
}

account_is_managed() {
  # An account is considered tool-managed only if its GECOS carries the exact tag
  # this tool sets (useradd -c / adduser -g "${MANAGED_TAG} temporary admin"),
  # not merely the bare tag substring, so a self-set partial GECOS cannot pose as
  # managed.
  local user="$1" gecos
  gecos=$(passwd_entry "$user" | cut -d: -f5)
  [[ "$gecos" == *"$MANAGED_TAG temporary admin"* ]]
}

is_protected_revoke_target() {
  local user="$1" registered="${2:-false}" uid
  case "$user" in
    root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd-*|dbus|sshd|polkitd)
      return 0
      ;;
  esac
  uid=$(id -u -- "$user" 2>/dev/null || true)
  [[ "$uid" == "0" ]] && return 0
  # System-range UIDs are protected unless this is a registered, managed temp account.
  if [[ "$uid" =~ ^[0-9]+$ && "$uid" -lt 1000 ]]; then
    if [[ "$registered" == "true" ]] && account_is_managed "$user"; then
      return 1
    fi
    return 0
  fi
  # Real UID>=1000 accounts this tool did NOT create are protected: neither
  # registered nor GECOS-tagged means it is almost certainly a real human/service
  # account, so refuse to delete it even with --force.
  if [[ "$registered" != "true" ]] && ! account_is_managed "$user"; then
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
    err "$(m "安全检查失败：注册表目录是符号链接，拒绝使用：$REGISTRY_DIR" "Security check failed: registry directory is a symlink; refusing to use it: $REGISTRY_DIR")"
    return 1
  fi
  if [[ -e "$REGISTRY_DIR" && ! -d "$REGISTRY_DIR" ]]; then
    err "$(m "安全检查失败：注册表路径不是目录：$REGISTRY_DIR" "Security check failed: registry path is not a directory: $REGISTRY_DIR")"
    return 1
  fi
  if ! install -d -m 700 -o root -g root "$REGISTRY_DIR"; then
    err "$(m "创建注册表目录失败：$REGISTRY_DIR" "Failed to create registry directory: $REGISTRY_DIR")"
    return 1
  fi
  if [[ -L "$REGISTRY_DIR" || ! -d "$REGISTRY_DIR" ]]; then
    err "$(m "安全检查失败：注册表目录不安全：$REGISTRY_DIR" "Security check failed: registry directory is unsafe: $REGISTRY_DIR")"
    return 1
  fi
  chown root:root "$REGISTRY_DIR" 2>/dev/null || true
  if ! chmod 700 "$REGISTRY_DIR"; then
    err "$(m "设置注册表目录权限失败：$REGISTRY_DIR" "Failed to set registry directory permissions: $REGISTRY_DIR")"
    return 1
  fi

  local f
  for f in "$REGISTRY_FILE" "$REGISTRY_LOCK_FILE"; do
    if [[ -L "$f" ]]; then
      err "$(m "安全检查失败：注册表文件是符号链接，拒绝使用：$f" "Security check failed: registry file is a symlink; refusing to use it: $f")"
      return 1
    fi
    if [[ -e "$f" && ! -f "$f" ]]; then
      err "$(m "安全检查失败：注册表路径不是普通文件：$f" "Security check failed: registry path is not a regular file: $f")"
      return 1
    fi
    if [[ ! -e "$f" ]]; then
      if ! : > "$f"; then
        err "$(m "创建注册表文件失败：$f" "Failed to create registry file: $f")"
        return 1
      fi
    fi
    if [[ -L "$f" || ! -f "$f" ]]; then
      err "$(m "安全检查失败：注册表文件不安全：$f" "Security check failed: registry file is unsafe: $f")"
      return 1
    fi
    chown root:root "$f" 2>/dev/null || true
    if ! chmod 600 "$f"; then
      err "$(m "设置注册表文件权限失败：$f" "Failed to set registry file permissions: $f")"
      return 1
    fi
  done
}

registry_lock() {
  local __fd_var="$1"
  registry_init || return 1
  printf -v "$__fd_var" '%s' ""
  if ! command_exists flock; then
    warn "$(m "找不到 flock，登记文件并发保护已降级。" "flock not found; registry concurrent-write protection is degraded.")"
    return 0
  fi
  if [[ -L "$REGISTRY_LOCK_FILE" || ! -f "$REGISTRY_LOCK_FILE" ]]; then
    err "$(m "注册表锁文件不安全：$REGISTRY_LOCK_FILE" "Registry lock file is unsafe: $REGISTRY_LOCK_FILE")"
    return 1
  fi
  local fd
  exec {fd}>"$REGISTRY_LOCK_FILE"
  if ! flock "$fd"; then
    warn "$(m "获取注册表锁失败，操作可能存在并发风险。" "Failed to acquire registry lock; concurrent-write risk.")"
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
  if ! tmp=$(mktemp "${REGISTRY_DIR}/users.tsv.tmp.XXXXXX"); then
    warn "$(m "创建注册表临时文件失败，已取消写入。" "Failed to create registry temporary file; write cancelled.")"
    return 1
  fi
  if ! awk -F '\t' -v u="$user" '$1 != u {print}' "$REGISTRY_FILE" > "$tmp"; then
    rm -f "$tmp"
    warn "$(m "重写注册表失败（awk 退出非零，可能磁盘已满），已取消写入以避免截断注册表。" "Failed to rewrite the registry (awk exited non-zero, disk may be full); aborted the write to avoid truncating the registry.")"
    return 1
  fi
  chown root:root "$tmp" 2>/dev/null || true
  if ! chmod 600 "$tmp"; then
    rm -f "$tmp"
    warn "$(m "设置注册表临时文件权限失败，已取消写入。" "Failed to set registry temporary file permissions; write cancelled.")"
    return 1
  fi
  if [[ -L "$REGISTRY_FILE" || ! -f "$REGISTRY_FILE" ]]; then
    rm -f "$tmp"
    warn "$(m "注册表路径不再安全，已取消写入。" "Registry path became unsafe; write cancelled.")"
    return 1
  fi
  if ! mv -f "$tmp" "$REGISTRY_FILE"; then
    rm -f "$tmp"
    warn "$(m "替换注册表失败，已取消写入。" "Failed to replace the registry; write cancelled.")"
    return 1
  fi
  chown root:root "$REGISTRY_FILE" 2>/dev/null || true
  if ! chmod 600 "$REGISTRY_FILE"; then
    warn "$(m "设置注册表权限失败：$REGISTRY_FILE" "Failed to set registry permissions: $REGISTRY_FILE")"
    return 1
  fi
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
    warn "$(m "更新注册表时删除旧记录失败，已取消追加。" "Failed to remove old registry record while updating; append cancelled.")"
    registry_unlock "$lock_fd"
    return 1
  fi
  if [[ -L "$REGISTRY_FILE" || ! -f "$REGISTRY_FILE" ]]; then
    warn "$(m "注册表路径不安全，已忽略追加。" "Registry path is unsafe; ignoring append.")"
    registry_unlock "$lock_fd"
    return 1
  fi
  local created
  created=$(date '+%F %T %Z')
  if ! printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$user" "$created" "$expires" "$sudo_enabled" "$nopasswd" "$host" "$port" "$fingerprint" "$auto_revoke" "$auto_unit" >> "$REGISTRY_FILE"; then
    warn "$(m "追加注册表失败（可能磁盘已满或权限异常），账号已创建但未登记。" "Failed to append to the registry (disk may be full or permissions invalid); account was created but not registered.")"
    registry_unlock "$lock_fd"
    return 1
  fi
  chown root:root "$REGISTRY_FILE" 2>/dev/null || true
  if ! chmod 600 "$REGISTRY_FILE"; then
    warn "$(m "设置注册表权限失败：$REGISTRY_FILE" "Failed to set registry permissions: $REGISTRY_FILE")"
    registry_unlock "$lock_fd"
    return 1
  fi
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
    warn "$(m "暂无脚本登记的临时用户。" "No registered temporary users.")"
    return 1
  fi
  local i=0 user created expires sudo_enabled _legacy_nopasswd host port fingerprint auto_revoke auto_unit state
  while IFS=$'\t' read -r user created expires sudo_enabled _legacy_nopasswd host port fingerprint auto_revoke auto_unit _overflow; do
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
    warn "$(m "没有找到仍存在的已登记临时用户。" "No existing registered temporary users found.")"
    read -r -p "$(m "请输入要撤销/删除的用户名: " "Enter username to revoke/delete: ")" user
    printf '%s\n' "$user"
    return 0
  fi

  printf '%s\n' "$(m "已登记的临时用户：" "Registered temporary users")" >&2
  local idx
  for idx in "${!users[@]}"; do
    printf '%2d) %s\n' "$((idx + 1))" "${users[$idx]}" >&2
  done
  printf '%s\n' "$(m "也可以直接输入用户名。" "You can also type a username directly.")" >&2
  local choice
  read -r -p "$(m "请选择要删除的编号/用户名: " "Select number or username to delete: ")" choice
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
    err "$(m "systemd unit 名称含有非法字符: $unit" "systemd unit name contains illegal characters: $unit")"
    return 1
  fi
  printf '%s/%s.service' "$SYSTEMD_DIR" "$unit"
}

auto_revoke_timer_path() {
  local unit="$1"
  if [[ "$unit" == *"/"* ]]; then
    err "$(m "systemd unit 名称含有非法字符: $unit" "systemd unit name contains illegal characters: $unit")"
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

path_mode_owner() {
  local path="$1"
  if command_exists stat; then
    stat -c 'mode=%a owner=%U:%G' -- "$path" 2>/dev/null || true
  fi
}

path_owned_by_root_not_group_world_writable() {
  local path="$1" kind="$2" uid mode perms group_digit other_digit
  case "$kind" in
    file) [[ -f "$path" && ! -L "$path" ]] || return 1 ;;
    dir) [[ -d "$path" && ! -L "$path" ]] || return 1 ;;
    *) return 1 ;;
  esac
  command_exists stat || return 1
  read -r uid mode < <(stat -c '%u %a' -- "$path" 2>/dev/null) || return 1
  [[ "$uid" == "0" && "$mode" =~ ^[0-9]+$ ]] || return 1
  perms="${mode: -3}"
  [[ ${#perms} -eq 3 ]] || return 1
  group_digit="${perms:1:1}"
  other_digit="${perms:2:1}"
  [[ ! "$group_digit" =~ [2367] && ! "$other_digit" =~ [2367] ]]
}

root_safe_file() {
  path_owned_by_root_not_group_world_writable "$1" file
}

root_safe_dir() {
  path_owned_by_root_not_group_world_writable "$1" dir
}

valid_installed_version() {
  # Exactly three numeric components (+ optional suffix) to match version_gt's
  # X.Y.Z parser, so a valid-but-uncomparable 2- or 4-part version can't slip
  # through extract_script_version and confuse the upgrade comparison.
  [[ "$1" =~ ^[0-9]+([.][0-9]+){2}([._+~-][A-Za-z0-9._+~-]+)?$ ]]
}

extract_script_version() {
  local script="$1" version_line version
  [[ -f "$script" && ! -L "$script" ]] || return 1
  version_line=$(awk -F= '$1 == "VERSION" {print $2; exit}' "$script" 2>/dev/null) || return 1
  version="${version_line%\"}"
  version="${version#\"}"
  valid_installed_version "$version" || return 1
  printf '%s\n' "$version"
}

version_gt() {
  local newer="$1" older="$2"
  [[ "$newer" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]] || return 1
  local newer_major="${BASH_REMATCH[1]}" newer_minor="${BASH_REMATCH[2]}" newer_patch="${BASH_REMATCH[3]}" newer_suffix="${BASH_REMATCH[4]}"
  [[ "$older" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]] || return 1
  local older_major="${BASH_REMATCH[1]}" older_minor="${BASH_REMATCH[2]}" older_patch="${BASH_REMATCH[3]}" older_suffix="${BASH_REMATCH[4]}"
  (( 10#$newer_major > 10#$older_major )) && return 0
  (( 10#$newer_major < 10#$older_major )) && return 1
  (( 10#$newer_minor > 10#$older_minor )) && return 0
  (( 10#$newer_minor < 10#$older_minor )) && return 1
  (( 10#$newer_patch > 10#$older_patch )) && return 0
  (( 10#$newer_patch < 10#$older_patch )) && return 1
  [[ -z "$newer_suffix" && -n "$older_suffix" ]] && return 0
  [[ -n "$newer_suffix" && -z "$older_suffix" ]] && return 1
  [[ "$newer_suffix" > "$older_suffix" ]]
}

valid_upgrade_url() {
  local url="$1"
  [[ ${#url} -ge 8 && ${#url} -le 2048 ]] || return 1
  [[ "$url" == https://* ]] || return 1
  case "$url" in
    *[[:space:]]*|*\"*|*"'"*|*\`*|*\<*|*\>*|*\|*) return 1 ;;
    *) return 0 ;;
  esac
}

download_script_to_file() {
  local url="$1" dest="$2"
  valid_upgrade_url "$url" || {
    err "$(m "升级地址不安全或不合法：$url" "Upgrade URL is unsafe or invalid: $url")"
    return 1
  }
  if command_exists curl; then
    if ! curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 30 --max-filesize "$MAX_UPGRADE_BYTES" "$url" -o "$dest"; then
      rm -f "$dest"
      err "$(m "下载升级脚本失败：$url" "Failed to download upgrade script: $url")"
      return 1
    fi
  elif command_exists wget; then
    # curl (preferred, above) confines redirects to https via --proto-redir, so
    # a hostile origin cannot 3xx-downgrade the fetch to http. wget has no
    # per-download equivalent (--https-only only governs recursive mode), so on
    # GNU wget forbid redirects outright with --max-redirect=0; busybox wget
    # lacks that flag, so probe --help before adding it rather than breaking
    # minimal builds. Also bound the write with head: wget has no reliable
    # per-file size cap (--quota is only checked between files), so a hostile URL
    # could otherwise fill the (tmpfs) download dir before the post-download size
    # check runs. Reading one byte past the limit keeps that check able to reject
    # an oversized download.
    local wget_help wget_opts wget_pre
    wget_help=$(wget --help 2>&1 || true)
    wget_opts=(-qO-)
    wget_pre=()
    # GNU wget uses --tries/--timeout; busybox wget rejects those long options.
    # Its -T flag is unreliable (segfaults on some builds), so instead bound the
    # whole fetch with timeout(1) when available rather than passing -T.
    if [[ "$wget_help" == *--timeout* ]]; then
      wget_opts+=(--tries=1 --timeout=30)
    elif command_exists timeout; then
      wget_pre=(timeout 30)
    else
      # busybox wget with no way to bound the fetch would block for minutes on a
      # stalled connect. The pre-1.2.3 code passed --timeout (which busybox
      # rejects = instant fail); preserve that fail-fast instead of hanging.
      err "$(m "无法为下载设置超时（无 timeout 命令且 wget 不支持 --timeout），已放弃以避免长时间挂起。" "Cannot bound the download with a timeout (no timeout command and wget lacks --timeout); aborting to avoid a long hang.")"
      return 1
    fi
    [[ "$wget_help" == *--max-redirect* ]] && wget_opts+=(--max-redirect=0)
    if ! ${wget_pre[@]+"${wget_pre[@]}"} wget "${wget_opts[@]}" "$url" 2>/dev/null \
        | head -c "$((MAX_UPGRADE_BYTES + 1))" > "$dest"; then
      rm -f "$dest"
      err "$(m "下载升级脚本失败：$url" "Failed to download upgrade script: $url")"
      return 1
    fi
  else
    err "$(m "找不到 curl/wget，无法下载升级脚本。" "curl/wget not found; cannot download upgrade script.")"
    return 1
  fi
  local bytes
  bytes=$(wc -c < "$dest" 2>/dev/null | tr -d '[:space:]' || printf '0')
  if [[ ! "$bytes" =~ ^[0-9]+$ || "$bytes" -le 0 || "$bytes" -gt "$MAX_UPGRADE_BYTES" ]]; then
    rm -f "$dest"
    err "$(m "下载的脚本大小异常：${bytes:-0} bytes" "Downloaded script size is invalid: ${bytes:-0} bytes")"
    return 1
  fi
}

installed_revoke_version() {
  # __ver must not collide with any caller's variable name: printf -v writes
  # through $__var by name, and a same-named local here would shadow the caller's
  # variable (bash dynamic scope), silently discarding the result. Callers pass
  # installed_ver / installed_version, so keep this internal name distinct.
  local __var="$1" __ver
  root_safe_file "$INSTALL_PATH" || return 1
  [[ -x "$INSTALL_PATH" ]] || return 1
  __ver=$("$INSTALL_PATH" version 2>/dev/null) || return 1
  valid_installed_version "$__ver" || return 1
  printf -v "$__var" '%s' "$__ver"
}

install_script_file_for_revoke() {
  local src="$1" replace="${2:-false}" reuse_existing="${3:-true}" install_dir tmp installed_ver src_ver
  [[ -f "$src" && ! -L "$src" ]] || {
    warn "$(m "无法安全定位源脚本文件：$src" "Cannot safely locate source script file: $src")"
    return 1
  }
  if ! src_ver=$(extract_script_version "$src"); then
    warn "$(m "源脚本缺少有效版本号，拒绝安装：$src" "Source script has no valid version; refusing installation: $src")"
    return 1
  fi
  if ! bash -n "$src"; then
    warn "$(m "源脚本语法检查失败，拒绝安装：$src" "Source script failed Bash syntax validation; refusing installation: $src")"
    return 1
  fi
  install_dir=$(dirname -- "$INSTALL_PATH")
  if [[ -L "$install_dir" || ( -e "$install_dir" && ! -d "$install_dir" ) ]]; then
    warn "$(m "安装目录不安全，拒绝安装稳定撤销命令：$install_dir" "Install directory is unsafe; refusing stable revoke installation: $install_dir")"
    return 1
  fi
  install -d -m 755 -o root -g root "$install_dir"
  if ! root_safe_dir "$install_dir"; then
    warn "$(m "安装目录不是 root 拥有的安全目录，拒绝安装稳定撤销命令：$install_dir $(path_mode_owner "$install_dir")" "Install directory is not a safely root-owned directory; refusing stable revoke installation: $install_dir $(path_mode_owner "$install_dir")")"
    return 1
  fi
  if [[ -L "$INSTALL_PATH" || ( -e "$INSTALL_PATH" && ! -f "$INSTALL_PATH" ) ]]; then
    warn "$(m "$INSTALL_PATH 不是安全的普通文件，拒绝安装以防止 TOCTOU 攻击。" "$INSTALL_PATH is not a safe regular file; refusing installation to prevent TOCTOU attack.")"
    return 1
  fi
  if [[ -f "$INSTALL_PATH" && ! -L "$INSTALL_PATH" ]]; then
    local differs="unknown"
    if command_exists cmp; then
      if cmp -s -- "$src" "$INSTALL_PATH"; then
        differs="false"
      else
        differs="true"
      fi
    fi
    if [[ "$differs" != "false" ]]; then
      local diff_zh="与源脚本不同" diff_en="differs from the source script"
      if [[ "$differs" == "unknown" ]]; then
        diff_zh="无法确认是否与源脚本不同"
        diff_en="cannot be confirmed whether it differs from the source script"
      fi
      if [[ "$replace" != "true" ]]; then
        if [[ "$reuse_existing" == "true" ]] && installed_revoke_version installed_ver; then
          warn "$(m "$INSTALL_PATH 已存在且$diff_zh（installed=$installed_ver source=$src_ver）；为避免影响其他用户的撤销任务，复用现有命令、未覆盖。如需替换请设 LINUX_TEMP_ADMIN_REINSTALL=1 或使用 install/upgrade --force。" "$INSTALL_PATH already exists and $diff_en (installed=$installed_ver source=$src_ver); reusing the existing command without overwriting to avoid disrupting other users' revoke tasks. Set LINUX_TEMP_ADMIN_REINSTALL=1 or use install/upgrade --force to replace it.")"
          return 0
        fi
        warn "$(m "$INSTALL_PATH 已存在且$diff_zh；未覆盖。确认要替换时请使用 --force。" "$INSTALL_PATH already exists and $diff_en; not overwritten. Use --force to replace it.")"
        return 1
      fi
      warn "$(m "正在用源脚本覆盖已安装的稳定撤销命令：$INSTALL_PATH (source=$src_ver)" "Overwriting the installed stable revoke command with the source script: $INSTALL_PATH (source=$src_ver)")"
    fi
  fi
  if ! tmp=$(mktemp "${install_dir}/.linux-temp-admin.XXXXXX"); then
    warn "$(m "创建安装临时文件失败：$install_dir" "Failed to create install temporary file: $install_dir")"
    return 1
  fi
  if ! install -m 700 -o root -g root "$src" "$tmp"; then
    rm -f "$tmp"
    warn "$(m "复制源脚本到安装临时文件失败：$tmp" "Failed to copy source script to install temporary file: $tmp")"
    return 1
  fi
  if [[ -L "$INSTALL_PATH" || ( -e "$INSTALL_PATH" && ! -f "$INSTALL_PATH" ) ]]; then
    rm -f "$tmp"
    warn "$(m "$INSTALL_PATH 安全状态变化，拒绝覆盖。" "$INSTALL_PATH safety state changed; refusing overwrite.")"
    return 1
  fi
  if ! mv -f "$tmp" "$INSTALL_PATH"; then
    rm -f "$tmp"
    warn "$(m "安装稳定命令失败，未能替换：$INSTALL_PATH" "Failed to install stable command; could not replace: $INSTALL_PATH")"
    return 1
  fi
  chown root:root "$INSTALL_PATH" 2>/dev/null || true
  if ! chmod 700 "$INSTALL_PATH"; then
    warn "$(m "设置稳定命令权限失败：$INSTALL_PATH" "Failed to set stable command permissions: $INSTALL_PATH")"
    return 1
  fi
  # Write to stderr, not stdout: install_self_for_revoke runs inside
  # schedule_auto_revoke/schedule_at_revoke whose stdout is captured as the
  # auto-revoke unit name. Leaking this banner there corrupts the recorded unit
  # so later revoke/status cannot find and clean up the timer/at job.
  success "$(m "稳定命令已安装：$INSTALL_PATH version=$src_ver" "Stable command installed: $INSTALL_PATH version=$src_ver")" >&2
}

show_installed_revoke_status() {
  if [[ -L "$INSTALL_PATH" ]]; then
    warn "$(m "稳定撤销命令是符号链接，出于安全考虑不执行：$INSTALL_PATH" "Stable revoke command is a symlink; refusing to execute it for safety: $INSTALL_PATH")"
    return 0
  fi
  if [[ ! -f "$INSTALL_PATH" ]]; then
    warn "$(m "稳定撤销命令未安装：$INSTALL_PATH；创建自动删除任务时会自动安装。" "Stable revoke command is not installed: $INSTALL_PATH; auto-delete task creation installs it automatically.")"
    return 0
  fi
  local installed_version="unknown" mode_owner=""
  mode_owner=$(path_mode_owner "$INSTALL_PATH")
  if ! root_safe_file "$INSTALL_PATH"; then
    warn "$(m "稳定撤销命令不是 root 拥有的安全文件，出于安全考虑不执行：$INSTALL_PATH ${mode_owner:-}" "Stable revoke command is not a safely root-owned file; refusing to execute it: $INSTALL_PATH ${mode_owner:-}")"
    return 0
  fi
  if [[ -x "$INSTALL_PATH" ]]; then
    if ! installed_revoke_version installed_version; then
      installed_version="unknown-or-invalid"
    fi
  else
    installed_version="not-executable-by-current-user"
  fi
  info "$(m "稳定撤销命令：$INSTALL_PATH version=$installed_version current=$VERSION ${mode_owner:-}" "Stable revoke command: $INSTALL_PATH version=$installed_version current=$VERSION ${mode_owner:-}")"
  if [[ "$installed_version" != "unknown-or-invalid" && "$installed_version" != "not-executable-by-current-user" && "$installed_version" != "$VERSION" ]]; then
    warn "$(m "稳定撤销命令版本与当前脚本不同；自动删除任务会复用现有命令，除非显式使用 --force 或 LINUX_TEMP_ADMIN_REINSTALL=1。" "Stable revoke command version differs from the current script; auto-delete tasks will reuse the existing command unless --force or LINUX_TEMP_ADMIN_REINSTALL=1 is used.")"
  fi
}

install_self_for_revoke() {
  local src="${BASH_SOURCE[0]}" installed_ver replace="false"
  # If the source script cannot be safely located (e.g. run via `curl | bash`),
  # reuse an already-installed valid managed binary instead of failing outright.
  if [[ ! -f "$src" || -L "$src" ]]; then
    if installed_revoke_version installed_ver; then
      warn "$(m "无法定位当前脚本文件，复用已安装的稳定撤销命令：$INSTALL_PATH (version=$installed_ver)" "Cannot locate the current script file; reusing the already-installed stable revoke command: $INSTALL_PATH (version=$installed_ver)")"
      return 0
    fi
    warn "$(m "无法安全定位当前脚本文件，且无可复用的已安装命令，不能安装稳定撤销命令。" "Cannot safely locate the current script file and no reusable installed command exists; cannot install the stable revoke command.")"
    return 1
  fi
  [[ "${LINUX_TEMP_ADMIN_REINSTALL:-}" == "1" ]] && replace="true"
  install_script_file_for_revoke "$src" "$replace" true
}

ensure_atd_running() {
  # at jobs depend on the atd daemon; many distros install at but leave atd disabled.
  # Best-effort to confirm/start atd across init systems so queued jobs actually fire.
  if command_exists systemctl; then
    systemctl is-active --quiet atd 2>/dev/null && return 0
    systemctl enable --now atd >/dev/null 2>&1 && return 0
  fi
  if command_exists rc-service; then
    rc-service atd status >/dev/null 2>&1 && return 0
    if command_exists rc-update; then rc-update add atd >/dev/null 2>&1 || true; fi
    rc-service atd start >/dev/null 2>&1 && return 0
  fi
  if command_exists service; then
    service atd status >/dev/null 2>&1 && return 0
    if command_exists chkconfig; then chkconfig atd on >/dev/null 2>&1 || true; fi
    if command_exists update-rc.d; then update-rc.d atd enable >/dev/null 2>&1 || true; fi
    service atd start >/dev/null 2>&1 && return 0
  fi
  if command_exists pgrep; then
    pgrep -x atd >/dev/null 2>&1 && return 0
  fi
  return 1
}

schedule_at_revoke() {
  local user="$1" hours="$2"
  if ! [[ "$hours" =~ ^[0-9]+$ && "$hours" -ge 1 && "$hours" -le "$MAX_EXPIRE_HOURS" ]]; then
    warn "$(m "无效的小时数，无法创建 at 自动删除任务。" "Invalid hours value, cannot create at auto-revoke task.")"
    return 1
  fi
  if ! command_exists at; then
    warn "$(m "找不到 at，无法创建备用自动删除任务；仅设置账号过期。" "at not found; fallback auto-delete task cannot be created; account expiry only.")"
    return 1
  fi
  if ! ensure_atd_running; then
    warn "$(m "atd 守护进程未运行且无法自动启动；放弃 at 自动删除任务，仅设置账号过期。请手动启动 atd 或改用 systemd。" "atd daemon is not running and could not be started automatically; giving up on the at auto-delete task, account expiry only. Please start atd manually or use systemd.")"
    return 1
  fi
  if ! install_self_for_revoke; then
    warn "$(m "安装 $INSTALL_PATH 失败，无法创建备用自动删除任务；仅设置账号过期。" "Failed to install $INSTALL_PATH; fallback auto-delete task cannot be created; account expiry only.")"
    return 1
  fi
  local output job_id install_arg user_arg
  install_arg=$(shell_quote_arg "$INSTALL_PATH")
  user_arg=$(shell_quote_arg "$user")
  if ! output=$(printf "%s revoke --user %s --yes\n" "$install_arg" "$user_arg" | at now + "$hours" hours 2>&1); then
    warn "$(m "创建 at 自动删除任务失败：$output" "Failed to create at auto-revoke job: $output")"
    return 1
  fi
  # Try multiple output formats for compatibility with different at versions
  job_id=$(awk '/^job[[:space:]]+[0-9]+/ {print $2; exit}' <<< "$output")
  [[ -n "$job_id" && "$job_id" =~ ^[0-9]+$ ]] || job_id=$(awk 'NF && $1 ~ /^[0-9]+$/ {print $1; exit}' <<< "$output")
  if [[ -z "$job_id" || ! "$job_id" =~ ^[0-9]+$ ]]; then
    warn "$(m "无法识别 at 自动删除任务编号：$output" "Unable to parse at job id: $output")"
    return 1
  fi
  printf 'at:%s\n' "$job_id"
}

schedule_auto_revoke() {
  local user="$1" hours="$2"
  if ! command_exists systemctl; then
    warn "$(m "找不到 systemctl，将尝试使用 at 创建备用自动删除任务。" "systemctl not found; trying at fallback auto-delete task.")"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! install_self_for_revoke; then
    warn "$(m "安装 $INSTALL_PATH 失败，将尝试使用 at 创建备用自动删除任务。" "Failed to install $INSTALL_PATH; trying at fallback auto-delete task.")"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! valid_username "$user"; then
    warn "$(m "自动删除任务用户名不合法，拒绝创建 systemd unit：$user" "Invalid auto-delete username; refusing to create systemd unit: $user")"
    return 1
  fi
  local unit service_path timer_path timer_schedule on_calendar exec_start
  unit=$(auto_revoke_unit_name "$user")
  if ! service_path=$(auto_revoke_service_path "$unit") || [[ -z "$service_path" ]]; then
    warn "$(m "生成 systemd service 路径失败，将尝试使用 at 创建备用自动删除任务。" "Failed to generate systemd service path; falling back to at.")"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! timer_path=$(auto_revoke_timer_path "$unit") || [[ -z "$timer_path" ]]; then
    warn "$(m "生成 systemd timer 路径失败，将尝试使用 at 创建备用自动删除任务。" "Failed to generate systemd timer path; falling back to at.")"
    rm -f "$service_path"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  exec_start="$(systemd_quote_arg "$INSTALL_PATH") revoke --user $(systemd_quote_arg "$user") --yes"
  if on_calendar=$(date -u -d "+${hours} hours" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null); then
    # Absolute UTC anchor: the trigger instant is immune to later timezone/DST
    # changes and stays aligned with the UTC-based chage expiry date.
    timer_schedule="OnCalendar=$on_calendar
Persistent=true"
  else
    on_calendar=""
    if command_exists python3; then
      on_calendar=$(python3 - "$hours" <<'PY'
import datetime, sys
print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=int(sys.argv[1]))).strftime('%Y-%m-%d %H:%M:%S UTC'))
PY
)
    fi
    if [[ -n "$on_calendar" ]]; then
      timer_schedule="OnCalendar=$on_calendar
Persistent=true"
    else
      warn "$(m "无法计算绝对到期时间，将使用相对 systemd timer；每次重启会重置倒计时，账号可能延迟删除。" "Cannot compute an absolute expiry time; falling back to a relative systemd timer whose countdown resets on every reboot, so deletion may be delayed.")"
      timer_schedule="OnActiveSec=${hours}h"
    fi
  fi

  if [[ -L "$service_path" || ( -e "$service_path" && ! -f "$service_path" ) || -L "$timer_path" || ( -e "$timer_path" && ! -f "$timer_path" ) ]]; then
    warn "$(m "systemd unit 路径不安全，将尝试使用 at 创建备用自动删除任务。" "systemd unit path is unsafe; trying at fallback auto-delete task.")"
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
    warn "$(m "写入 systemd service 失败，将尝试使用 at 创建备用自动删除任务。" "Failed to write systemd service; trying at fallback auto-delete task.")"
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
    warn "$(m "写入 systemd timer 失败，将尝试使用 at 创建备用自动删除任务。" "Failed to write systemd timer; trying at fallback auto-delete task.")"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if command_exists systemd-analyze; then
    systemd-analyze verify "$service_path" "$timer_path" >/dev/null || {
      rm -f "$service_path" "$timer_path"
      warn "$(m "systemd unit 校验失败，将尝试使用 at 创建备用自动删除任务。" "systemd unit validation failed; trying at fallback auto-delete task.")"
      schedule_at_revoke "$user" "$hours"
      return $?
    }
  fi
  if ! systemctl daemon-reload >/dev/null; then
    rm -f "$service_path" "$timer_path"
    warn "$(m "systemd daemon-reload 失败，将尝试使用 at 创建备用自动删除任务。" "systemd daemon-reload failed; trying at fallback auto-delete task.")"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! systemctl enable --now "$unit.timer" >/dev/null; then
    rm -f "$service_path" "$timer_path"
    systemctl daemon-reload >/dev/null 2>&1 || true
    warn "$(m "启用 systemd timer 失败，将尝试使用 at 创建备用自动删除任务。" "Failed to enable systemd timer; trying at fallback auto-delete task.")"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  printf '%s\n' "$unit"
}

remove_at_jobs_for_user() {
  # Sweep any at-job whose body runs revoke for this exact user, so a reused
  # username cannot leave a stale at-job (of a different scheduler type than the
  # currently recorded unit) behind to later delete a freshly created account.
  local user="$1" job _rest body needle
  if ! command_exists atq || ! command_exists at || ! command_exists atrm; then
    return 0
  fi
  # Match the exact command schedule_at_revoke queues (install path + quoted
  # user + --yes), not a loose substring, so an unrelated at-job that merely
  # embeds "revoke --user X --yes" is never removed.
  needle="$(shell_quote_arg "$INSTALL_PATH") revoke --user $(shell_quote_arg "$user") --yes"
  while read -r job _rest; do
    [[ "$job" =~ ^[0-9]+$ ]] || continue
    body=$(at -c "$job" 2>/dev/null) || true
    if [[ "$body" == *"$needle"* ]]; then
      atrm "$job" >/dev/null 2>&1 || true
    fi
  done < <(atq 2>/dev/null || true)
}

cancel_auto_revoke() {
  local user="$1" unit="${2:-}" service_path timer_path derived
  [[ -n "$unit" ]] || unit=$(registry_unit_for_user "$user" 2>/dev/null || true)
  # Remove a recorded at-job by id.
  if [[ "$unit" == at:* ]]; then
    local job_id="${unit#at:}"
    if [[ "$job_id" =~ ^[0-9]+$ ]] && command_exists atrm; then
      atrm "$job_id" >/dev/null 2>&1 || true
    fi
  fi
  # Always also sweep at-jobs targeting this user (covers a stale at-job when the
  # recorded unit is a systemd name, or vice versa).
  remove_at_jobs_for_user "$user"
  # Always also clean the systemd derived-name units. auto_revoke_unit_name is
  # deterministic per user, so this covers both a recorded systemd unit and a
  # stale one left from a previous invite of the same username.
  derived=$(auto_revoke_unit_name "$user")
  if [[ -z "$derived" || "$derived" != ${MANAGED_TAG}-revoke-* || "$derived" == *"/"* ]]; then
    return 0
  fi
  if command_exists systemctl; then
    # Stop only the timer. Do not stop the service: auto-revoke may be running inside it.
    systemctl disable --now "${derived}.timer" >/dev/null 2>&1 || true
    systemctl reset-failed "${derived}.timer" "${derived}.service" >/dev/null 2>&1 || true
  fi
  service_path=$(auto_revoke_service_path "$derived" 2>/dev/null || true)
  timer_path=$(auto_revoke_timer_path "$derived" 2>/dev/null || true)
  if [[ -n "$timer_path" && "$timer_path" == "$SYSTEMD_DIR"/* && ! -L "$timer_path" ]]; then
    rm -f "$timer_path" 2>/dev/null || true
  fi
  # When invoked from within the firing systemd service (INVOCATION_ID is set by
  # systemd), leave the .service file and skip daemon-reload so we don't disturb the
  # unit currently executing us; the next manual revoke/cleanup will remove it.
  if [[ -z "${INVOCATION_ID:-}" ]]; then
    if [[ -n "$service_path" && "$service_path" == "$SYSTEMD_DIR"/* && ! -L "$service_path" ]]; then
      rm -f "$service_path" 2>/dev/null || true
    fi
    if command_exists systemctl; then
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
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
    [[ "$o" =~ ^(0|[1-9][0-9]{0,2})$ && $((10#$o)) -le 255 ]] || return 1
  done
  case "${octets[0]}" in
    0|10|127|224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239|240|241|242|243|244|245|246|247|248|249|250|251|252|253|254|255) return 1 ;;
  esac
  [[ "${octets[0]}" -eq 100 && "${octets[1]}" -ge 64 && "${octets[1]}" -le 127 ]] && return 1
  [[ "${octets[0]}" -eq 169 && "${octets[1]}" -eq 254 ]] && return 1
  [[ "${octets[0]}" -eq 172 && "${octets[1]}" -ge 16 && "${octets[1]}" -le 31 ]] && return 1
  [[ "${octets[0]}" -eq 192 && "${octets[1]}" -eq 0 && "${octets[2]}" -eq 0 ]] && return 1
  [[ "${octets[0]}" -eq 192 && "${octets[1]}" -eq 0 && "${octets[2]}" -eq 2 ]] && return 1
  [[ "${octets[0]}" -eq 192 && "${octets[1]}" -eq 88 && "${octets[2]}" -eq 99 ]] && return 1
  [[ "${octets[0]}" -eq 192 && "${octets[1]}" -eq 168 ]] && return 1
  [[ "${octets[0]}" -eq 198 && ( "${octets[1]}" -eq 18 || "${octets[1]}" -eq 19 ) ]] && return 1
  [[ "${octets[0]}" -eq 198 && "${octets[1]}" -eq 51 && "${octets[2]}" -eq 100 ]] && return 1
  [[ "${octets[0]}" -eq 203 && "${octets[1]}" -eq 0 && "${octets[2]}" -eq 113 ]] && return 1
  return 0
}

ip_probe_debug() {
  if [[ -n "${LINUX_TEMP_ADMIN_DEBUG_IP:-${LINUX_TEMP_ADMIN_DEBUG:-}}" ]]; then
    warn "$(m "IP 探测诊断：$*" "IP probe diagnostics: $*")"
  fi
}

get_url_text() {
  local url="$1" max_time="${2:-3}" connect_timeout="${3:-1}"
  local output="" status=0 tmp_err err=""
  if ! tmp_err=$(mktemp -t linux-temp-admin.XXXXXX); then
    ip_probe_debug "$(m "创建临时错误日志失败，无法请求 $url" "Failed to create temporary error log; cannot request $url")"
    return 1
  fi
  if command_exists curl; then
    if output=$(curl -fsS --connect-timeout "$connect_timeout" --max-time "$max_time" "$url" 2>"$tmp_err" | tr -d '\r\n'); then
      status=0
    else
      status=$?
    fi
  elif command_exists wget; then
    # GNU wget accepts --timeout/--tries/--dns-timeout/--connect-timeout; busybox
    # wget rejects those long options (making probes fail outright), and its -T is
    # unreliable (segfaults on some builds), so bound the fetch with timeout(1)
    # when available instead. Keeps IP autodetection working on busybox.
    local wget_help wget_opts wget_pre
    wget_help=$(wget --help 2>&1 || true)
    wget_opts=(-qO-)
    wget_pre=()
    if [[ "$wget_help" == *--timeout* ]]; then
      wget_opts+=(--tries=1 --timeout="$max_time" --dns-timeout="$connect_timeout" --connect-timeout="$connect_timeout")
    elif command_exists timeout; then
      wget_pre=(timeout "$max_time")
    else
      # No way to bound busybox wget; a bare fetch could block for minutes on a
      # stalled connect. This is a best-effort probe with fallbacks, so skip it.
      rm -f "$tmp_err"
      ip_probe_debug "$(m "无法为 wget 设置超时，跳过该探测以避免挂起：$url" "Cannot bound wget with a timeout; skipping this probe to avoid a hang: $url")"
      return 1
    fi
    if output=$(${wget_pre[@]+"${wget_pre[@]}"} wget "${wget_opts[@]}" "$url" 2>"$tmp_err" | tr -d '\r\n'); then
      status=0
    else
      status=$?
    fi
  else
    rm -f "$tmp_err"
    ip_probe_debug "$(m "找不到 curl/wget，无法请求 $url" "curl/wget not found; cannot request $url")"
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
  ip_probe_debug "$(m "$url 失败 exit=$status${err:+ error=$err}" "$url failed exit=$status${err:+ error=$err}")"
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
      ip_probe_debug "$(m "$service 返回非公网 IPv4：${ip:0:80}" "$service returned non-public IPv4: ${ip:0:80}")"
    fi
  done

  if command_exists ip; then
    while IFS= read -r ip; do
      if is_public_ipv4 "$ip"; then
        printf '%s\n' "$ip"
        return 0
      fi
    done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')

    ip_probe_debug "$(m "本地网卡未发现公网 IPv4，继续检查默认路由源地址。" "No public IPv4 on local interfaces; checking default-route source address.")"
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' || true)
    if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
    [[ -n "$ip" ]] && ip_probe_debug "$(m "默认路由源地址不是公网 IPv4：$ip" "Default-route source address is not public IPv4: $ip")"
  else
    ip_probe_debug "$(m "找不到 ip 命令，无法检查本地网卡地址。" "ip command not found; cannot inspect local interface addresses.")"
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
      ip_probe_debug "$(m "$service 返回无效 Host：${ip:0:80}" "$service returned invalid host: ${ip:0:80}")"
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
  # chage -E is day-granular and locks the account at 00:00 UTC of the given
  # date. Anchor to the first midnight strictly after now+hours (the date of
  # now+hours, plus one day) so the account stays usable for at least the
  # requested window on every timezone/creation-time, is NEVER locked
  # prematurely, and still stays as tight as day granularity allows (at most ~1
  # extra day). When an auto-delete timer is set it fires precisely at now+hours;
  # chage only backstops it and must not lock before it.
  if date -u -d "+${hours} hours +1 day" +%F >/dev/null 2>&1; then
    date -u -d "+${hours} hours +1 day" +%F
  elif command_exists python3; then
    python3 - "$hours" <<'PY'
import datetime
import sys
now = datetime.datetime.now(datetime.timezone.utc)
print((now + datetime.timedelta(hours=int(sys.argv[1]), days=1)).date().isoformat())
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
    python3 - "$hours" <<'PY'
import datetime
import sys
print((datetime.datetime.now().astimezone() + datetime.timedelta(hours=int(sys.argv[1]))).strftime('%F %T %Z'))
PY
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
    err "$(m "找不到可用登录 shell。" "No usable login shell found.")"
    return 1
  fi
}

create_user_if_needed() {
  local user="$1"
  local shell_path="$2"
  if user_exists "$user"; then
    err "$(m "用户已存在：$user" "User already exists: $user")"
    exit 1
  fi
  if command_exists useradd; then
    useradd -m -s "$shell_path" -c "${MANAGED_TAG} temporary admin" "$user"
  elif command_exists adduser; then
    adduser -D -s "$shell_path" -g "${MANAGED_TAG} temporary admin" "$user"
  else
    err "$(m "找不到 useradd/adduser，无法创建用户" "useradd/adduser not found; cannot create user.")"
    exit 1
  fi
}

lock_user_password() {
  local user="$1"
  if usermod -L "$user" >/dev/null 2>&1; then
    return 0
  fi
  warn "$(m "锁定账号密码失败：$user。已停止创建并准备回滚。" "Failed to lock the account password: $user. Aborting creation and preparing to roll back.")"
  return 1
}

set_user_expiry() {
  local user="$1"
  local hours="$2"
  local date_only
  if ! date_only=$(expire_date_from_hours "$hours"); then
    err "$(m "无法计算账号过期日期，请安装 GNU date 或 python3 后重试。" "Could not calculate account expiry date; install GNU date or python3 and retry.")"
    return 1
  fi
  if command_exists chage; then
    chage -E "$date_only" "$user" || {
      err "$(m "设置账号过期时间失败，已停止创建并准备回滚。" "Failed to set account expiry; stopping creation and rolling back.")"
      return 1
    }
  else
    err "$(m "找不到 chage，无法安全设置账号过期时间。" "chage not found; cannot safely set account expiry.")"
    return 1
  fi
}

safe_write_root_file() {
  local path="$1" mode="$2" dir base tmp
  dir=$(dirname -- "$path")
  base=$(basename -- "$path")
  if [[ -L "$dir" || ! -d "$dir" ]]; then
    warn "$(m "目标目录不安全，拒绝写入：$dir" "Target directory is unsafe; refusing write: $dir")"
    return 1
  fi
  if ! root_safe_dir "$dir"; then
    warn "$(m "目标目录不是 root 拥有的安全目录，拒绝写入：$dir $(path_mode_owner "$dir")" "Target directory is not a safely root-owned directory; refusing write: $dir $(path_mode_owner "$dir")")"
    return 1
  fi
  if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    warn "$(m "目标文件不安全，拒绝写入：$path" "Target file is unsafe; refusing write: $path")"
    return 1
  fi
  if ! tmp=$(mktemp "${dir}/.${base}.XXXXXX"); then
    warn "$(m "创建临时文件失败，拒绝写入：$path" "Failed to create temporary file; refusing write: $path")"
    return 1
  fi
  if ! cat > "$tmp"; then
    rm -f "$tmp"
    warn "$(m "写入临时文件失败，已清理：$path" "Failed to write the temporary file, cleaned up: $path")"
    return 1
  fi
  chown root:root "$tmp" 2>/dev/null || true
  if ! chmod "$mode" "$tmp"; then
    rm -f "$tmp"
    warn "$(m "设置临时文件权限失败，已清理：$path" "Failed to set temporary file permissions, cleaned up: $path")"
    return 1
  fi
  if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    rm -f "$tmp"
    warn "$(m "目标文件安全状态变化，拒绝覆盖：$path" "Target file safety state changed; refusing overwrite: $path")"
    return 1
  fi
  if ! mv -f "$tmp" "$path"; then
    rm -f "$tmp"
    warn "$(m "替换目标文件失败，已清理临时文件：$path" "Failed to replace target file; temporary file cleaned up: $path")"
    return 1
  fi
  chown root:root "$path" 2>/dev/null || true
  if ! chmod "$mode" "$path"; then
    warn "$(m "设置目标文件权限失败：$path" "Failed to set target file permissions: $path")"
    return 1
  fi
}

add_sudo() {
  local user="$1" file sudo_policy
  if ! command_exists sudo; then
    warn "$(m "未找到 sudo 命令，跳过 sudo 授权。" "sudo command not found; skipping sudo grant.")"
    return 1
  fi
  if [[ -L /etc/sudoers.d || ! -d /etc/sudoers.d ]]; then
    warn "$(m "/etc/sudoers.d 不存在或不安全，无法配置 NOPASSWD sudo。" "/etc/sudoers.d does not exist or is unsafe; cannot configure NOPASSWD sudo.")"
    return 1
  fi
  file="/etc/sudoers.d/${MANAGED_TAG}-${user}"
  if ! printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" | safe_write_root_file "$file" 440; then
    return 1
  fi
  if command_exists visudo; then
    visudo -cf "$file" >/dev/null || {
      rm -f "$file"
      err "$(m "sudoers 校验失败，已删除 $file" "sudoers validation failed, removed $file")"
      return 1
    }
  fi
  if ! sudo_policy=$(sudo -n -l -U "$user" 2>/dev/null) || [[ ! "$sudo_policy" =~ (^|[[:space:]])NOPASSWD: ]]; then
    rm -f "$file"
    err "$(m "sudoers 策略未实际授予 $user NOPASSWD sudo，已删除 $file。请确认 /etc/sudoers 包含 /etc/sudoers.d。" "sudoers policy did not actually grant $user NOPASSWD sudo; removed $file. Ensure /etc/sudoers includes /etc/sudoers.d.")"
    return 1
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
  local home_dir uid gid ssh_dir auth_file tmp_auth
  home_dir=$(passwd_entry "$user" | cut -d: -f6 | head -n1)
  if [[ -z "$home_dir" || ! -d "$home_dir" || -L "$home_dir" ]]; then
    err "$(m "找不到安全的用户家目录：$user" "Safe home directory not found: $user")"
    return 1
  fi
  uid=$(id -u -- "$user" 2>/dev/null || true)
  gid=$(id -g -- "$user" 2>/dev/null || true)
  if [[ -z "$uid" || -z "$gid" || ! "$uid" =~ ^[0-9]+$ || ! "$gid" =~ ^[0-9]+$ ]]; then
    err "$(m "无法获取 UID/GID：$user" "Unable to get UID/GID: $user")"
    return 1
  fi
  ssh_dir="$home_dir/.ssh"
  auth_file="$ssh_dir/authorized_keys"
  if [[ -L "$ssh_dir" || ( -e "$ssh_dir" && ! -d "$ssh_dir" ) ]]; then
    err "$(m "用户 .ssh 路径不安全：$ssh_dir" "User .ssh path is unsafe: $ssh_dir")"
    return 1
  fi
  if ! install -d -m 700 -o "$uid" -g "$gid" "$ssh_dir"; then
    err "$(m "创建用户 .ssh 目录失败：$ssh_dir" "Failed to create user .ssh directory: $ssh_dir")"
    return 1
  fi
  if [[ -L "$auth_file" || ( -e "$auth_file" && ! -f "$auth_file" ) ]]; then
    err "$(m "authorized_keys 路径不安全：$auth_file" "authorized_keys path is unsafe: $auth_file")"
    return 1
  fi
  # write_ssh_key only ever runs for a freshly created user, so authorized_keys
  # never pre-exists (no backup needed). Build a temp file, set its owner/mode,
  # then atomically rename into place. rename(2) preserves the temp file's owner
  # and mode, so we deliberately do NOT chown/chmod the destination by name after
  # the mv — doing so would follow an attacker-planted symlink in the user-owned
  # .ssh directory and chown/chmod an arbitrary root file.
  if ! tmp_auth=$(mktemp "${ssh_dir}/.authorized_keys.XXXXXX"); then
    err "$(m "创建 authorized_keys 临时文件失败：$ssh_dir" "Failed to create authorized_keys temporary file: $ssh_dir")"
    return 1
  fi
  if ! cat "$pubkey_file" > "$tmp_auth"; then
    rm -f "$tmp_auth"
    err "$(m "写入 authorized_keys 临时文件失败：$auth_file" "Failed to write authorized_keys temporary file: $auth_file")"
    return 1
  fi
  if ! chown "$uid:$gid" "$tmp_auth" || ! chmod 600 "$tmp_auth"; then
    rm -f "$tmp_auth"
    err "$(m "设置 authorized_keys 临时文件权限失败：$auth_file" "Failed to set authorized_keys temporary file ownership/permissions: $auth_file")"
    return 1
  fi
  if [[ -L "$auth_file" || ( -e "$auth_file" && ! -f "$auth_file" ) ]]; then
    rm -f "$tmp_auth"
    err "$(m "authorized_keys 安全状态变化，拒绝覆盖：$auth_file" "authorized_keys safety state changed; refusing overwrite: $auth_file")"
    return 1
  fi
  if ! mv -f "$tmp_auth" "$auth_file"; then
    rm -f "$tmp_auth"
    err "$(m "替换 authorized_keys 失败：$auth_file" "Failed to replace authorized_keys: $auth_file")"
    return 1
  fi
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
  warn "$(m "创建过程中出错，正在回滚临时用户：$user" "Creation failed; rolling back temporary user: $user")"
  cancel_auto_revoke "$user" "$unit" || true
  terminate_user_processes "$user"
  remove_sudoers_file "$user" || true
  if user_exists "$user"; then
    delete_user_with_home "$user" || warn "$(m "回滚时删除用户失败，请手动检查：$user" "Rollback failed to remove user; please check manually: $user")"
  fi
  registry_remove_user "$user" || true
}

print_invite() {
  local host="$1" port="$2" user="$3" expires="$4" sudo_enabled="$5" private_key_file="$6" revoke_cmd="$7" auto_revoke="$8" auto_unit="$9"
  local ssh_host
  ssh_host=$(ssh_host_for_command "$host")
  if [[ "$LANG_SEL" == "zh" ]]; then
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

SSH 登录命令:
ssh -i ./${user}.key -p $port ${user}@${ssh_host}

保存私钥命令:
cat > './${user}.key' <<'EOF_KEY'
$(cat "$private_key_file")
EOF_KEY
chmod 600 './${user}.key'

EOF
  else
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
  fi
  if [[ "$sudo_enabled" == "yes" ]]; then
    if [[ "$LANG_SEL" == "zh" ]]; then
    cat <<EOF
Sudo 提示:
已启用 NOPASSWD sudo。此账号只能通过 SSH key 登录；账号密码已锁定。
注意：NOPASSWD sudo 等于完整 root 权限——该账号可提权为 root，并可能留下 root 拥有的进程、cron、systemd 单元或 SUID 文件等持久化。撤销只删除此账号本身，不会自动清理它以 root 身份创建的东西。

EOF
    else
    cat <<EOF
Sudo note:
NOPASSWD sudo is enabled. This account can log in only with the SSH key; account password is locked.
Note: NOPASSWD sudo is equivalent to full root — this account can escalate to root and may leave behind root-owned processes, cron jobs, systemd units, or SUID files. Revoking only deletes this account itself; it does not clean up anything it created as root.

EOF
    fi
  else
    if [[ "$LANG_SEL" == "zh" ]]; then
    cat <<EOF
Sudo 提示:
未授予 sudo 权限，此账号是普通用户；账号密码已锁定。

EOF
    else
    cat <<EOF
Sudo note:
sudo was not granted; this is a normal user. Account password is locked.

EOF
    fi
  fi
  if [[ "$auto_revoke" != "yes" ]]; then
    if [[ "$LANG_SEL" == "zh" ]]; then
    cat <<EOF
自动删除提示:
未创建自动删除任务；账号过期只会阻止后续登录，不会删除用户和家目录。请按需手动执行撤销命令。

EOF
    else
    cat <<EOF
Auto-delete note:
No auto-delete task was created; account expiry only blocks later login and does not delete the user or home directory. Run the revoke command manually when needed.

EOF
    fi
  fi
  if [[ "$LANG_SEL" == "zh" ]]; then
  cat <<EOF
撤销命令:
$revoke_cmd

安全提醒:
- 私钥只显示这一次，服务器不保存私钥。
- 账号密码已锁定，不会输出账号/Sudo 密码。
- 只通过可信私聊发送，不要发群里或公开页面。
- 用完请立即执行撤销命令。
- 服务器上只保存公钥，删除用户后这把私钥立即失效。

----- END LINUX TEMP ADMIN INVITE -----
EOF
  else
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
  fi
}

secure_cleanup_tmpdir() {
  # Best-effort secure removal of the working dir that briefly holds the one-time
  # private key. shred helps when it landed on a real disk; on tmpfs it is RAM.
  local d="${1:-}"
  [[ -n "$d" && -d "$d" ]] || return 0
  if command_exists shred; then
    find "$d" -type f -exec shred -u -- {} + 2>/dev/null || true
  fi
  rm -rf "$d"
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
      --nopasswd-sudo) warn "$(m "--nopasswd-sudo 已废弃：--sudo 现在默认使用 NOPASSWD sudo。" "--nopasswd-sudo is deprecated: --sudo now uses NOPASSWD sudo by default.")"; grant_sudo="yes"; shift ;;
      --yes|-y) assume_yes="true"; shift ;;
      --confirm-sudo) require_value "$1" "${2-}"; confirm_sudo="$2"; shift 2 ;;
      --allow-non-tty-private-key-output) allow_non_tty_key_output="true"; shift ;;
      --install-deps) deps_mode="auto"; shift ;;
      --no-install-deps) deps_mode="never"; shift ;;
      --auto-revoke) auto_revoke="yes"; shift ;;
      --no-auto-revoke) auto_revoke="no"; shift ;;
      *) err "$(m "未知参数：$1" "Unknown option: $1")"; usage; exit 1 ;;
    esac
  done

  if [[ ! "$hours" =~ ^[0-9]{1,4}$ || "$hours" -lt 1 || "$hours" -gt "$MAX_EXPIRE_HOURS" ]]; then
    err "$(m "--hours 必须是 1 到 $MAX_EXPIRE_HOURS 之间的整数" "--hours must be an integer between 1 and $MAX_EXPIRE_HOURS")"
    exit 1
  fi
  if ! valid_prefix "$prefix"; then
    err "$(m "用户名前缀不合法：$prefix。只能使用小写字母、数字、下划线、连字符，需以字母/下划线开头，不能以 '-' 或 '_' 结尾，最长 20 字符。" "Invalid username prefix: $prefix. Use lowercase letters, digits, underscore, and hyphen only; start with a letter/underscore; do not end with '-' or '_'; max 20 chars.")"
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
      err "$(m "多次生成随机用户名均发生冲突，请指定 --user。" "Random username generation collided repeatedly; specify --user.")"
      exit 1
    fi
  fi
  if ! valid_username "$user"; then
    err "$(m "用户名不合法：$user。只能使用小写字母、数字、下划线、连字符，且以字母/下划线开头。" "Invalid username: $user")"
    exit 1
  fi

  if [[ -z "$host" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      err "$(m "--yes 模式不会自动访问外部服务探测公网 IP，请显式传入 --host。" "--yes mode will not contact external services to detect public IP; pass --host explicitly.")"
      exit 1
    else
      warn "$(m "自动探测会先尝试本地网卡和云厂商 metadata；失败后才访问外部服务：https://api.ipify.org、https://ifconfig.me/ip、https://icanhazip.com" "Automatic detection first tries local interfaces and cloud metadata; if that fails, it contacts external services: https://api.ipify.org, https://ifconfig.me/ip, https://icanhazip.com")"
      read -r -p "$(m "是否自动探测公网 IP？[y/N]: " "Detect public IP automatically?[y/N]: ")" ans_host
      if [[ "$ans_host" =~ ^[Yy]$ ]]; then
        if host=$(get_local_public_ip); then
          info "$(m "已通过本地/云元数据探测公网 IP：$host" "Detected public IP via local/cloud metadata: $host")"
        elif host=$(get_public_ip); then
          info "$(m "已通过外部服务探测公网 IP：$host" "Detected public IP via external service: $host")"
        else
          warn "$(m "自动探测公网 IP 失败，请手动输入服务器公网 IP/域名。" "Automatic public IP detection failed; please enter server public IP/domain manually.")"
          host=""
        fi
      fi
    fi
  fi
  if [[ -z "$host" ]]; then
    read -r -p "$(m "请输入服务器公网 IP/域名: " "Enter server public IP/domain: ")" host
  fi
  if ! valid_host "$host"; then
    err "$(m "Host 不合法：$host。请使用普通域名、IPv4 或 IPv6 地址，不要包含端口、空格、引号或 shell 符号。" "Invalid host: $host. Use a normal domain, IPv4, or IPv6 address without ports, spaces, quotes, or shell metacharacters.")"
    exit 1
  fi
  if [[ -z "$port" ]]; then
    port=$(get_ssh_port)
  fi
  if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt 1 || "$port" -gt 65535 ]]; then
    err "$(m "SSH 端口不合法：$port" "Invalid SSH port: $port")"
    exit 1
  fi

  if [[ "$grant_sudo" == "ask" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      grant_sudo="no"
    else
      read -r -p "$(m "是否授予 sudo 管理员权限？[y/N]: " "Grant sudo admin privileges?[y/N]: ")" ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then grant_sudo="yes"; else grant_sudo="no"; fi
    fi
  fi
  if [[ "$grant_sudo" == "yes" && "$assume_yes" == "true" && "$confirm_sudo" != "$user" ]]; then
    err "$(m "拒绝通过 --sudo --yes 授予 sudo：必须同时传入 --confirm-sudo $user。" "Refusing to grant sudo via --sudo --yes: also pass --confirm-sudo $user.")"
    exit 1
  fi
  if [[ ! -t 1 && "$allow_non_tty_key_output" != "true" ]]; then
    err "$(m "stdout 不是 TTY，拒绝输出一次性私钥。若确认输出通道安全，请加 --allow-non-tty-private-key-output。" "stdout is not a TTY; refusing to print one-time private key. If the output channel is safe, add --allow-non-tty-private-key-output.")"
    exit 1
  fi

  if [[ "$auto_revoke" == "ask" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      auto_revoke="yes"
    else
      read -r -p "$(m "是否到期后自动删除该用户？[Y/n]: " "Auto-delete this user on expiry?[Y/n]: ")" ans3
      if [[ -z "$ans3" || "$ans3" =~ ^[Yy]$ ]]; then auto_revoke="yes"; else auto_revoke="no"; fi
    fi
  fi

  if [[ "$LANG_SEL" == "zh" ]]; then
  cat <<EOF

即将创建一次性临时账号：
- 用户名：$user
- Host：$host
- SSH 端口：$port
- 有效期：$hours 小时
- sudo 权限：$grant_sudo
- 到期自动删除：$auto_revoke

EOF
  else
  cat <<EOF

About to create one-time temporary account
- User: $user
- Host: $host
- SSH port: $port
- Valid for: $hours hours
- sudo: $grant_sudo
- auto-delete on expiry: $auto_revoke

EOF
  fi
  confirm_yes "$(m "sudo/SSH 账号属于高权限入口。确认创建请输入 YES。" "sudo/SSH accounts are high-privilege access. Type YES to confirm.")" "$assume_yes" || {
    warn "$(m "已取消。" "Cancelled.")"
    exit 0
  }

  if [[ "$grant_sudo" == "yes" ]]; then
    ensure_dependencies "$deps_mode" true || exit 1
  else
    ensure_dependencies "$deps_mode" false || exit 1
  fi

  local tmpdir keyfile pubfile expires revoke_cmd sudo_text fingerprint auto_text login_shell
  local created_user="" invite_completed="false" auto_unit="" registry_recorded="false"
  login_shell=$(resolve_login_shell) || exit 1
  # Prefer tmpfs (/dev/shm) for the one-time private key so it never hits a real
  # disk; fall back to /tmp. Explicit -p avoids a hostile inherited $TMPDIR.
  if ! tmpdir=$(mktemp -d -p /dev/shm 2>/dev/null || mktemp -d -p /tmp); then
    err "$(m "创建临时目录失败，无法生成一次性私钥。" "Failed to create temporary directory; cannot generate one-time private key.")"
    exit 1
  fi
  if ! chmod 700 "$tmpdir"; then
    secure_cleanup_tmpdir "$tmpdir"
    err "$(m "设置临时目录权限失败：$tmpdir" "Failed to set temporary directory permissions: $tmpdir")"
    exit 1
  fi
  keyfile="$tmpdir/${user}.key"
  pubfile="$keyfile.pub"
  cleanup_invite_error() {
    local code=$?
    trap - ERR EXIT INT TERM HUP
    if [[ "$invite_completed" != "true" && -n "$created_user" ]]; then
      rollback_created_user "$created_user" "${auto_unit:-}"
    fi
    secure_cleanup_tmpdir "$tmpdir"
    exit "$code"
  }
  trap cleanup_invite_error ERR EXIT INT TERM HUP

  ssh-keygen -t ed25519 -N '' -C "${user}-${MANAGED_TAG}" -f "$keyfile" >/dev/null || exit 1
  chmod 600 "$keyfile" || exit 1
  chmod 644 "$pubfile" || exit 1

  create_user_if_needed "$user" "$login_shell" || exit 1
  created_user="$user"
  lock_user_password "$user" || exit 1
  write_ssh_key "$user" "$pubfile" || exit 1
  set_user_expiry "$user" "$hours" || exit 1

  sudo_text="no"
  if [[ "$grant_sudo" == "yes" ]]; then
    if add_sudo "$user"; then
      sudo_text="yes"
    else
      warn "$(m "未能授予 sudo 权限（可能缺少 sudo、/etc/sudoers.d 未启用或策略校验失败）；已创建为普通账号：$user" "Could not grant sudo (sudo missing, /etc/sudoers.d not enabled, or policy validation failed); created as a normal account: $user")"
      sudo_text="no"
    fi
  fi

  expires=$(expire_datetime_local "$hours")
  revoke_cmd="sudo $INSTALL_PATH revoke --user $user"
  fingerprint=$(ssh-keygen -lf "$pubfile" 2>/dev/null | awk '{print $2}' || true)
  # Clear any stale auto-revoke job/timer left over for a reused username so an old
  # at-job/timer cannot later delete this freshly created account.
  cancel_auto_revoke "$user" >/dev/null 2>&1 || true
  auto_text="no"
  auto_unit=""
  if [[ "$auto_revoke" == "yes" ]]; then
    if auto_unit=$(schedule_auto_revoke "$user" "$hours"); then
      auto_text="yes"
      revoke_cmd="sudo $INSTALL_PATH revoke --user $user"
    else
      warn "$(m "自动删除任务创建失败：仅设置账号过期；账号过期不会删除用户和家目录，请按需手动执行撤销命令。" "Auto-delete task creation failed: account expiry only; expiry will not delete the user or home directory. Run the revoke command manually when needed.")"
      auto_text="no"
      revoke_cmd="sudo bash $SCRIPT_NAME revoke --user $user"
    fi
  fi
  if registry_record_user "$user" "$expires" "$sudo_text" "no" "$host" "$port" "${fingerprint:-unknown}" "$auto_text" "$auto_unit"; then
    registry_recorded="true"
  else
    # The auto-delete task runs `revoke --user X --yes` WITHOUT --force, which
    # refuses an unregistered user. With no registry entry that task can never
    # delete the account, so cancel it rather than leave an orphan timer/at-job;
    # the account keeps its chage expiry and the operator revokes with --force.
    if [[ "$auto_text" == "yes" ]]; then
      cancel_auto_revoke "$user" "${auto_unit:-}" >/dev/null 2>&1 || true
      auto_text="no"
      auto_unit=""
      revoke_cmd="sudo bash $SCRIPT_NAME revoke --user $user --force"
    fi
    warn "$(m "登记注册表失败：账号已创建但未登记，已取消自动删除任务（无法删除未登记用户）；请用 status 核对，并用 revoke --force 手动撤销。" "Failed to record in the registry: the account was created but not registered; the auto-delete task was cancelled (it cannot delete an unregistered user). Verify with status and revoke manually with --force.")"
  fi

  invite_completed="true"
  if [[ "$registry_recorded" == "true" ]]; then
    success "$(m "临时账号已创建并登记：$user" "Temporary account created and registered: $user")"
  else
    warn "$(m "临时账号已创建但未登记：$user" "Temporary account created but not registered: $user")"
  fi
  print_invite "$host" "$port" "$user" "$expires" "$sudo_text" "$keyfile" "$revoke_cmd" "$auto_text" "${auto_unit:-none}" || exit 1
  secure_cleanup_tmpdir "$tmpdir"
  trap - ERR EXIT INT TERM HUP
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
      *) err "$(m "未知参数：$1" "Unknown option: $1")"; usage; exit 1 ;;
    esac
  done
  if [[ -z "$user" ]]; then
    user=$(registry_select_user)
  fi
  if ! valid_username "$user"; then
    err "$(m "用户名不合法，拒绝删除：$user" "Invalid username; refusing deletion: $user")"
    exit 1
  fi
  local registered="false"
  if registry_contains_user "$user"; then
    registered="true"
  fi
  if [[ "$force" != "true" && "$registered" != "true" ]]; then
    err "$(m "拒绝删除未登记用户：$user。若确认需要删除默认前缀或其他用户，请加 --force。" "Refusing to delete an unregistered user: $user. Use --force if you need to delete a default-prefix or other user.")"
    exit 1
  fi
  if [[ "$force" == "true" && "$registered" != "true" && "$assume_yes" == "true" && "$confirm_force" != "$user" ]]; then
    err "$(m "拒绝通过 --force --yes 删除未登记用户：必须同时传入 --confirm-force $user。" "Refusing to delete an unregistered user via --force --yes: also pass --confirm-force $user.")"
    exit 1
  fi
  if ! user_exists "$user"; then
    warn "$(m "用户不存在：$user。将清理登记记录、sudoers 文件和自动删除任务（如果存在）。" "User does not exist: $user. Cleaning up the registry entry, sudoers file, and auto-delete task (if any).")"
    cancel_auto_revoke "$user"
    remove_sudoers_file "$user"
    registry_remove_user "$user" || warn "$(m "清理注册表记录失败，请手动检查：$user" "Failed to clean up registry record; please check manually: $user")"
    exit 0
  fi
  if [[ "$assume_yes" != "true" ]]; then
    if [[ "$force" == "true" && "$registered" != "true" ]]; then
      printf '\n%s\n' "${RED}$(m "危险：用户 $user 未在脚本登记中，--force 将删除真实系统用户及其家目录。" "DANGER: user $user is not registered by this script; --force will delete a real system user and its home directory.")${NC}"
    fi
    printf '\n%s\n' "${YELLOW}$(m "将强制下线并删除用户 $user 及其家目录。" "Will force logout and delete user $user and its home directory.")${NC}"
    read -r -p "$(m "请输入完整用户名 $user 以确认删除: " "Type full username $user to confirm deletion: ")" confirm_user
    if [[ "$confirm_user" != "$user" ]]; then
      warn "$(m "确认不匹配，已取消。" "Confirmation mismatch; cancelled.")"
      exit 0
    fi
  fi
  if is_protected_revoke_target "$user" "$registered"; then
    err "$(m "拒绝删除受保护或系统用户：$user" "Refusing to delete a protected or system user: $user")"
    exit 1
  fi
  cancel_auto_revoke "$user"
  terminate_user_processes "$user"
  remove_sudoers_file "$user"
  if ! delete_user_with_home "$user"; then
    warn "$(m "删除用户失败: $user" "Failed to remove user: $user")"
    exit 1
  fi
  registry_remove_user "$user" || warn "$(m "用户已删除，但清理注册表记录失败，请手动检查：$user" "User was deleted, but registry cleanup failed; please check manually: $user")"
  success "$(m "已撤销并删除用户：$user" "User revoked and deleted: $user")"
}

status_user() {
  local user=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) require_value "$1" "${2-}"; user="$2"; shift 2 ;;
      *) err "$(m "未知参数：$1" "Unknown option: $1")"; usage; exit 1 ;;
    esac
  done
  if [[ -n "$user" ]]; then
    if ! valid_username "$user"; then
      err "$(m "用户名不合法：$user" "Invalid username: $user")"
      exit 1
    fi
    if user_exists "$user"; then
      id -- "$user"
      passwd_entry "$user"
      local home_dir
      home_dir=$(passwd_entry "$user" | cut -d: -f6 | head -n1)
      if [[ -d "$home_dir/.ssh" ]]; then
        stat -c '.ssh mode=%a owner=%U:%G path=%n' "$home_dir/.ssh" 2>/dev/null || ls -ld "$home_dir/.ssh"
        if [[ -f "$home_dir/.ssh/authorized_keys" ]]; then
          stat -c 'authorized_keys mode=%a owner=%U:%G path=%n' "$home_dir/.ssh/authorized_keys" 2>/dev/null || true
        fi
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
      err "$(m "用户不存在：$user" "User does not exist: $user")"
      exit 1
    fi
    return
  fi
  info "$(m "脚本登记的临时用户：" "Registered temporary users:")"
  registry_list_users || true
  printf '\n'
  info "$(m "系统中匹配前缀 $DEFAULT_PREFIX- 的用户：" "System users matching prefix $DEFAULT_PREFIX-")"
  passwd_db | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1 "\t" $6 "\t" $7}' || true
  printf '\n'
  info "$(m "自动删除 timer：" "Auto-delete timers")"
  show_auto_revoke_timers || true
  printf '\n'
  show_installed_revoke_status
}

cleanup_expired() {
  need_root
  local compact="false"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --compact) compact="true"; shift ;;
      *) err "$(m "cleanup-expired 不支持的参数：$1" "cleanup-expired: unsupported argument: $1")"; usage; exit 1 ;;
    esac
  done
  warn "$(m "这里只查看账号过期和自动删除状态，不主动删除用户，避免误删。" "This only shows account expiry and auto-delete status; it does not delete users.")"
  if ! command_exists chage; then
    warn "$(m "找不到 chage，无法检查过期时间。" "chage not found; cannot inspect expiry.")"
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
    for u in ${users[@]+"${users[@]}"}; do
      [[ "$u" == "$user" ]] && found="true" && break
    done
    [[ "$found" == "false" ]] && users+=("$user")
  done < <(passwd_db | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1}')
  if [[ ${#users[@]} -eq 0 ]]; then
    info "$(m "没有登记的临时用户或系统默认前缀用户。" "No registered temporary users or system default-prefix users.")"
    return 0
  fi
  for user in "${users[@]}"; do
    printf '\n--- %s ---\n' "$user"
    if user_exists "$user"; then
      chage -l "$user" | sed -n '1,8p' || true
    else
      info "$(m "用户不存在：$user" "User does not exist: $user")"
    fi
  done
  if [[ "$compact" == "true" ]]; then
    local removed=0 cu _crest lock_fd snapshot
    # Prune under a single held lock and re-check existence inside it, so a
    # concurrent invite re-creating a username cannot have its fresh registry
    # entry dropped by a decision made on now-stale state.
    if registry_has_users && registry_lock lock_fd; then
      snapshot=$(cat "$REGISTRY_FILE" 2>/dev/null || true)
      while IFS=$'\t' read -r cu _crest; do
        [[ -z "${cu:-}" ]] && continue
        if ! user_exists "$cu"; then
          if registry_remove_user_unlocked "$cu"; then removed=$((removed + 1)); fi
        fi
      done <<< "$snapshot"
      registry_unlock "$lock_fd"
    fi
    info "$(m "已压实注册表：移除 $removed 条指向已不存在用户的记录（仅清理登记表，不影响任何账号）。" "Compacted the registry: removed $removed entries pointing to users that no longer exist (registry only, no account is touched).")"
  fi
  info "$(m "说明：账号过期只会阻止后续登录；自动删除任务会调用 revoke 删除用户、家目录和 SSH key。" "Note: account expiry only blocks later login; auto-delete calls revoke to delete user, home, and SSH key.")"
  show_auto_revoke_timers || true
  show_installed_revoke_status
}

doctor_command() {
  local rc=0 arg
  while [[ $# -gt 0 ]]; do
    case "$1" in
      *) err "$(m "doctor 不支持的参数：$1" "doctor: unsupported argument: $1")"; usage; exit 1 ;;
    esac
  done

  info "$(m "linux-temp-admin 诊断报告 v$VERSION" "linux-temp-admin doctor report v$VERSION")"
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    success "$(m "当前以 root 运行。" "Running as root.")"
  else
    warn "$(m "当前不是 root；invite/revoke/install/upgrade/uninstall 需要 root。" "Not running as root; invite/revoke/install/upgrade/uninstall require root.")"
  fi

  for arg in bash ssh-keygen usermod chage flock install; do
    if command_exists "$arg"; then
      success "$(m "依赖存在：$arg" "Dependency found: $arg")"
    else
      warn "$(m "缺少依赖：$arg" "Missing dependency: $arg")"
      rc=1
    fi
  done
  if command_exists useradd || command_exists adduser; then
    success "$(m "依赖存在：useradd/adduser" "Dependency found: useradd/adduser")"
  else
    warn "$(m "缺少依赖：useradd/adduser" "Missing dependency: useradd/adduser")"
    rc=1
  fi
  if command_exists userdel || command_exists deluser; then
    success "$(m "依赖存在：userdel/deluser" "Dependency found: userdel/deluser")"
  else
    warn "$(m "缺少依赖：userdel/deluser" "Missing dependency: userdel/deluser")"
    rc=1
  fi
  if can_compute_future_date; then
    success "$(m "可以计算未来日期。" "Future date calculation is available.")"
  else
    warn "$(m "无法计算未来日期；请安装 GNU date/coreutils 或 python3。" "Cannot compute future dates; install GNU date/coreutils or python3.")"
    rc=1
  fi
  if command_exists sudo; then
    success "$(m "sudo 命令存在。" "sudo command found.")"
  else
    warn "$(m "sudo 命令不存在；--sudo 邀请会降级为普通账号。" "sudo command not found; --sudo invites will fall back to normal accounts.")"
  fi

  if [[ -d /etc/sudoers.d && ! -L /etc/sudoers.d ]] && root_safe_dir /etc/sudoers.d; then
    success "$(m "/etc/sudoers.d 看起来安全。" "/etc/sudoers.d looks safe.")"
  else
    warn "$(m "/etc/sudoers.d 不存在、是符号链接或权限/属主不安全；NOPASSWD sudo 可能不可用。" "/etc/sudoers.d is missing, a symlink, or has unsafe owner/mode; NOPASSWD sudo may be unavailable.")"
  fi

  if [[ -e "$REGISTRY_DIR" ]]; then
    if [[ -d "$REGISTRY_DIR" && ! -L "$REGISTRY_DIR" ]]; then
      success "$(m "注册表目录存在且不是符号链接：$REGISTRY_DIR" "Registry directory exists and is not a symlink: $REGISTRY_DIR")"
    else
      warn "$(m "注册表路径不安全：$REGISTRY_DIR" "Registry path is unsafe: $REGISTRY_DIR")"
      rc=1
    fi
  else
    info "$(m "注册表目录尚未创建：$REGISTRY_DIR" "Registry directory has not been created yet: $REGISTRY_DIR")"
  fi

  if command_exists systemctl; then
    success "$(m "systemctl 存在，可尝试 systemd 自动删除任务。" "systemctl found; systemd auto-delete tasks can be attempted.")"
  elif command_exists at; then
    warn "$(m "systemctl 不存在，将依赖 at 备用自动删除任务。" "systemctl not found; at fallback auto-delete tasks will be used.")"
  else
    warn "$(m "systemctl 和 at 都不存在；只能设置账号过期，不能自动删除用户。" "Neither systemctl nor at is available; only account expiry can be set, not automatic user deletion.")"
  fi

  # Compute once: m expands BOTH language arguments, so an inline $(get_ssh_port)
  # in each would run sshd -T twice per doctor.
  local detected_port; detected_port=$(get_ssh_port)
  info "$(m "探测到 SSH 端口：$detected_port" "Detected SSH port: $detected_port")"
  show_installed_revoke_status
  return "$rc"
}

install_command() {
  local force="false" src="${BASH_SOURCE[0]}"
  # Validate arguments before the privilege check, so an unsupported argument is
  # reported even when run as non-root (matches doctor).
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force) force="true"; shift ;;
      *) err "$(m "install 不支持的参数：$1" "install: unsupported argument: $1")"; usage; exit 1 ;;
    esac
  done
  need_root
  if [[ ! -f "$src" || -L "$src" ]]; then
    err "$(m "无法安全定位当前脚本文件，不能安装。请先下载为本地文件后运行。" "Cannot safely locate the current script file; cannot install. Download it as a local file first.")"
    exit 1
  fi
  install_script_file_for_revoke "$src" "$force" false || exit 1
  show_installed_revoke_status
}

uninstall_command() {
  local force="false" assume_yes="false" installed_ver="unknown"
  # Validate arguments before the privilege check (matches doctor/install).
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force) force="true"; shift ;;
      --yes|-y) assume_yes="true"; shift ;;
      *) err "$(m "uninstall 不支持的参数：$1" "uninstall: unsupported argument: $1")"; usage; exit 1 ;;
    esac
  done
  need_root
  if registry_has_users && [[ "$force" != "true" ]]; then
    err "$(m "检测到仍有登记用户，拒绝卸载稳定命令；请先 revoke/cleanup，或确认风险后使用 --force。" "Registered users still exist; refusing to uninstall the stable command. Revoke/cleanup first, or use --force after accepting the risk.")"
    exit 1
  fi
  if [[ ! -e "$INSTALL_PATH" ]]; then
    success "$(m "稳定命令未安装：$INSTALL_PATH" "Stable command is not installed: $INSTALL_PATH")"
    return 0
  fi
  if [[ -L "$INSTALL_PATH" || ! -f "$INSTALL_PATH" ]]; then
    err "$(m "稳定命令路径不安全，拒绝删除：$INSTALL_PATH" "Stable command path is unsafe; refusing to delete: $INSTALL_PATH")"
    exit 1
  fi
  if ! root_safe_file "$INSTALL_PATH"; then
    err "$(m "稳定命令不是 root 拥有的安全文件，拒绝删除：$INSTALL_PATH $(path_mode_owner "$INSTALL_PATH")" "Stable command is not a safely root-owned file; refusing to delete: $INSTALL_PATH $(path_mode_owner "$INSTALL_PATH")")"
    exit 1
  fi
  if ! installed_revoke_version installed_ver && [[ "$force" != "true" ]]; then
    err "$(m "稳定命令不像本工具的有效脚本，拒绝删除；确认要删除请加 --force。" "Stable command does not look like a valid script from this tool; refusing to delete. Use --force to remove it.")"
    exit 1
  fi
  if ! confirm_yes "$(m "将删除稳定命令：$INSTALL_PATH (version=$installed_ver)。确认请输入 YES。" "This will delete the stable command: $INSTALL_PATH (version=$installed_ver). Type YES to confirm.")" "$assume_yes"; then
    warn "$(m "已取消。" "Cancelled.")"
    return 0
  fi
  if ! rm -f "$INSTALL_PATH"; then
    err "$(m "删除稳定命令失败：$INSTALL_PATH" "Failed to remove stable command: $INSTALL_PATH")"
    exit 1
  fi
  success "$(m "已卸载稳定命令：$INSTALL_PATH" "Stable command uninstalled: $INSTALL_PATH")"
}

upgrade_command() {
  local url="$DEFAULT_UPGRADE_URL" force="false" assume_yes="false"
  local tmpdir tmpfile remote_ver installed_ver="none"
  # Validate arguments before the privilege check (matches doctor/install), so a
  # bad argument or an unsafe URL is reported regardless of who runs it.
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --url) require_value "$1" "${2-}"; url="$2"; shift 2 ;;
      --force) force="true"; shift ;;
      --yes|-y) assume_yes="true"; shift ;;
      *) err "$(m "upgrade 不支持的参数：$1" "upgrade: unsupported argument: $1")"; usage; exit 1 ;;
    esac
  done
  if ! valid_upgrade_url "$url"; then
    err "$(m "升级地址不安全或不合法：$url" "Upgrade URL is unsafe or invalid: $url")"
    exit 1
  fi
  need_root

  if ! tmpdir=$(mktemp -d -p /dev/shm 2>/dev/null || mktemp -d -p /tmp); then
    err "$(m "创建升级临时目录失败。" "Failed to create upgrade temporary directory.")"
    return 1
  fi
  if ! chmod 700 "$tmpdir"; then
    rm -rf "$tmpdir"
    err "$(m "设置升级临时目录权限失败：$tmpdir" "Failed to set upgrade temporary directory permissions: $tmpdir")"
    return 1
  fi
  cleanup_upgrade_error() {
    local code=$?
    trap - ERR EXIT INT TERM HUP
    rm -rf "$tmpdir"
    exit "$code"
  }
  cleanup_upgrade_tmpdir() {
    rm -rf "$tmpdir"
    trap - ERR EXIT INT TERM HUP
  }
  trap cleanup_upgrade_error ERR EXIT INT TERM HUP
  tmpfile="$tmpdir/temp-admin.sh"
  if ! download_script_to_file "$url" "$tmpfile"; then
    cleanup_upgrade_tmpdir
    return 1
  fi
  if ! chmod 600 "$tmpfile"; then
    cleanup_upgrade_tmpdir
    err "$(m "设置下载脚本权限失败，已放弃升级。" "Failed to set downloaded script permissions; upgrade aborted.")"
    return 1
  fi
  if ! remote_ver=$(extract_script_version "$tmpfile"); then
    cleanup_upgrade_tmpdir
    err "$(m "下载的脚本缺少有效版本号，已放弃升级。" "Downloaded script has no valid version; upgrade aborted.")"
    return 1
  fi
  if ! bash -n "$tmpfile"; then
    cleanup_upgrade_tmpdir
    err "$(m "下载的脚本语法检查失败，已放弃升级。" "Downloaded script failed Bash syntax validation; upgrade aborted.")"
    return 1
  fi

  if installed_revoke_version installed_ver; then
    if [[ "$force" != "true" ]] && ! version_gt "$remote_ver" "$installed_ver"; then
      success "$(m "稳定命令已是最新或更高版本：installed=$installed_ver downloaded=$remote_ver" "Stable command is already up to date or newer: installed=$installed_ver downloaded=$remote_ver")"
      cleanup_upgrade_tmpdir
      return 0
    fi
  elif [[ -e "$INSTALL_PATH" && "$force" != "true" ]]; then
    cleanup_upgrade_tmpdir
    err "$(m "已安装路径存在但不是可安全识别的本工具命令；确认替换请使用 --force。" "Install path exists but is not a safely recognized command from this tool; use --force to replace it.")"
    return 1
  fi

  info "$(m "准备升级稳定命令：installed=$installed_ver downloaded=$remote_ver url=$url" "Preparing to upgrade stable command: installed=$installed_ver downloaded=$remote_ver url=$url")"
  if ! confirm_yes "$(m "升级会覆盖 $INSTALL_PATH。确认请输入 YES。" "Upgrade will overwrite $INSTALL_PATH. Type YES to confirm.")" "$assume_yes"; then
    cleanup_upgrade_tmpdir
    warn "$(m "已取消。" "Cancelled.")"
    return 0
  fi
  if ! install_script_file_for_revoke "$tmpfile" true false; then
    cleanup_upgrade_tmpdir
    return 1
  fi
  cleanup_upgrade_tmpdir
  show_installed_revoke_status
}

menu() {
  need_root
  while true; do
    if [[ "$LANG_SEL" == "zh" ]]; then
    cat <<EOF

${BOLD}Linux 临时管理员管理器${NC} v$VERSION

1) 创建一次性临时管理员邀请
2) 撤销/删除临时用户
3) 查看用户状态
4) 查看账号过期/自动删除状态
5) 系统诊断
6) 安装/更新当前脚本为稳定命令
7) 从 GitHub 升级稳定命令
8) 卸载稳定命令
9) 退出
EOF
    else
    cat <<EOF

${BOLD}Linux Temporary Admin Manager${NC} v$VERSION

1) Create one-time temp admin invite
2) Revoke/delete temp user
3) Show user status
4) Show expiry/auto-delete status
5) Run system doctor
6) Install/update current script as stable command
7) Upgrade stable command from GitHub
8) Uninstall stable command
9) Exit
EOF
    fi
    read -r -p "$(m "请选择 [1-9]: " "Select [1-9]: ")" choice
    case "$choice" in
      1) ( invite ) || true ;;
      2) ( revoke_user ) || true ;;
      3) read -r -p "$(m "用户名（留空列出 ${DEFAULT_PREFIX}-*）: " "Username (blank lists ${DEFAULT_PREFIX}-*): ")" u
         if [[ -n "$u" ]]; then ( status_user --user "$u" ) || true; else ( status_user ) || true; fi ;;
      4) ( cleanup_expired ) || true ;;
      5) ( doctor_command ) || true ;;
      6) ( install_command ) || true ;;
      7) ( upgrade_command ) || true ;;
      8) ( uninstall_command ) || true ;;
      9) exit 0 ;;
      *) warn "$(m "无效选择" "Invalid choice")" ;;
    esac
  done
}

main() {
  # Pull an optional --lang from anywhere in the args (also honored via the
  # LINUX_TEMP_ADMIN_LANG env var); the remainder is the normal command line.
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --lang)
        shift
        if [[ $# -eq 0 || "$1" == --* ]]; then
          err "$(m "--lang 缺少值，请使用 zh 或 en。" "--lang requires a value: zh or en.")"
          usage
          exit 1
        fi
        if ! set_language "$1"; then
          err "$(m "--lang 只支持 zh 或 en：$1" "--lang only supports zh or en: $1")"
          usage
          exit 1
        fi
        LANG_LOCKED="true"
        shift
        ;;
      --lang=*)
        if ! set_language "${1#--lang=}"; then
          err "$(m "--lang 只支持 zh 或 en：${1#--lang=}" "--lang only supports zh or en: ${1#--lang=}")"
          usage
          exit 1
        fi
        LANG_LOCKED="true"
        shift
        ;;
      *) args+=("$1"); shift ;;
    esac
  done
  set -- "${args[@]}"
  resolve_language
  # v1 (this bash tool) is deprecated: the maintained implementation is the v2 Go
  # rewrite. Warn once per run (suppressible for tests/automation) but keep working.
  if [[ -z "${LTA_SUPPRESS_DEPRECATION:-}" ]]; then
    warn "$(m "bash 版(v1)已弃用、不再维护；请改用 v2 Go 版：https://github.com/xxvcc/linux-temp-admin" "The bash tool (v1) is DEPRECATED and no longer maintained; use the v2 Go tool instead: https://github.com/xxvcc/linux-temp-admin")"
  fi
  local cmd="${1:-}"
  # Offer an interactive language choice for the no-arg menu and every operational
  # command. Two extra guards beyond prompt_language()'s own (locked / non-TTY):
  # help/version are excluded, and a --yes/-y run is treated as non-interactive so
  # it never blocks on the prompt even when launched from a terminal.
  local a noninteractive="false"
  for a in "$@"; do case "$a" in --yes|-y) noninteractive="true"; break ;; esac; done
  if [[ "$noninteractive" != "true" ]]; then
    case "$cmd" in
      ""|invite|create|revoke|delete-user|remove|status|cleanup-expired|expiry-status|doctor|check|install|upgrade|update|uninstall)
        prompt_language ;;
    esac
  fi
  case "$cmd" in
    "" ) menu ;;
    invite|create) shift; invite "$@" ;;
    revoke|delete-user|remove) shift; revoke_user "$@" ;;
    status) shift; status_user "$@" ;;
    cleanup-expired|expiry-status) shift; cleanup_expired "$@" ;;
    doctor|check) shift; doctor_command "$@" ;;
    install) shift; install_command "$@" ;;
    upgrade|update) shift; upgrade_command "$@" ;;
    uninstall) shift; uninstall_command "$@" ;;
    help|-h|--help) usage ;;
    version|--version) echo "$VERSION" ;;
    *) err "$(m "未知命令：$cmd" "Unknown command: $cmd")"; usage; exit 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
