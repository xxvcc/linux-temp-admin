#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="temp-admin.sh"
VERSION="0.8.0"
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
    err "请使用 root 运行：sudo bash $SCRIPT_NAME"
    exit 1
  fi
}

usage() {
  cat <<EOF
$SCRIPT_NAME v$VERSION - Linux 一次性临时管理员邀请脚本

用法：
  bash $SCRIPT_NAME                         交互式菜单
  bash $SCRIPT_NAME invite                  创建一次性临时管理员邀请
  bash $SCRIPT_NAME revoke --user USER      撤销/删除临时用户
  bash $SCRIPT_NAME status [--user USER]    查看状态
  bash $SCRIPT_NAME cleanup-expired         查看过期/自动删除状态
  bash $SCRIPT_NAME expiry-status           查看过期/自动删除状态
  bash $SCRIPT_NAME help                    显示帮助

常用参数：
  --prefix PREFIX        用户名前缀，默认：$DEFAULT_PREFIX
  --user USER            指定用户名
  --host HOST            邀请包中显示的服务器地址
  --port PORT            SSH 端口，自动探测，失败则 22
  --hours HOURS          有效期小时数，默认：$DEFAULT_EXPIRE_HOURS，最大：$MAX_EXPIRE_HOURS
  --sudo                 授予 NOPASSWD sudo/wheel 权限
  --no-sudo              不授予 sudo/wheel 权限
  --yes                  跳过确认
  --confirm-sudo USER    与 --sudo --yes 一起授予 sudo 时，必须重复完整用户名
  --allow-non-tty-private-key-output
                         允许 stdout 非 TTY 时输出私钥（危险）
  --install-deps         自动安装缺失依赖
  --no-install-deps      不安装缺失依赖
  --auto-revoke          到期自动删除用户，默认
  --no-auto-revoke       不自动删除，仅设置账号过期
  --force                revoke 时允许删除未登记用户（危险）
  --confirm-force USER   与 --force --yes 一起删除未登记用户时，必须重复完整用户名

示例：
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
  read -r -p "请输入 YES 确认继续: " ans
  [[ "$ans" == "YES" ]]
}

require_value() {
  local opt="$1"
  local value="${2-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    err "参数 $opt 缺少值。"
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
    *) err "不支持的包管理器：$pm"; return 1 ;;
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
    useradd|usermod|chage)
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
  command_exists chage || missing+=("chage")
  command_exists flock || missing+=("flock")

  if [[ "$need_sudo" == "true" ]]; then
    command_exists sudo || missing+=("sudo")
  fi

  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi

  warn "检测到缺少依赖：${missing[*]}"

  local pm
  pm=$(pkg_manager)
  if [[ -z "$pm" ]]; then
    err "未找到支持的包管理器（apt/dnf/yum/apk/pacman）。请手动安装缺失依赖后重试。"
    return 1
  fi

  local install="false"
  case "$mode" in
    auto) install="true" ;;
    never)
      err "依赖缺失且已指定不自动安装。"
      return 1
      ;;
    ask|*)
      read -r -p "是否使用 $pm 自动安装缺失依赖？请输入 YES 确认: " ans
      if [[ "$ans" == "YES" ]]; then install="true"; fi
      ;;
  esac

  if [[ "$install" != "true" ]]; then
    err "已取消安装依赖。请手动安装后重试。"
    return 1
  fi

  local pkgs_text=""
  local item tool candidates
  for item in "${missing[@]}"; do
    if [[ "$item" == "useradd/adduser" ]]; then
      tool="useradd"
    else
      tool="$item"
    fi
    candidates=$(package_candidates_for_tool "$tool" "$pm" || true)
    [[ -n "$candidates" ]] && pkgs_text+=" $candidates"
  done
  pkgs_text=$(printf '%s' "$pkgs_text" | unique_words)
  if [[ -z "$pkgs_text" ]]; then
    err "无法映射缺失依赖到安装包：${missing[*]}"
    return 1
  fi

  local pkgs=()
  read -r -a pkgs <<< "$pkgs_text"
  info "安装依赖包：$pkgs_text"
  install_packages "$pm" "${pkgs[@]}"

  local still_missing=()
  command_exists bash || still_missing+=("bash")
  command_exists ssh-keygen || still_missing+=("ssh-keygen")
  if ! command_exists useradd && ! command_exists adduser; then still_missing+=("useradd/adduser"); fi
  command_exists usermod || still_missing+=("usermod")
  command_exists chage || still_missing+=("chage")
  command_exists flock || still_missing+=("flock")
  if [[ "$need_sudo" == "true" ]] && ! command_exists sudo; then still_missing+=("sudo"); fi

  if [[ ${#still_missing[@]} -gt 0 ]]; then
    err "安装后仍缺少：${still_missing[*]}。请手动处理后重试。"
    return 1
  fi

  success "依赖检查通过。"
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
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{1,30}$ ]]
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
      [[ "$octet" =~ ^[0-9]+$ && "$octet" -le 255 ]] || return 1
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

user_exists() { id "$1" >/dev/null 2>&1; }

sanitize_registry_field() {
  local value="${1:-}"
  value=${value//$'\t'/ }
  value=${value//$'\r'/ }
  value=${value//$'\n'/ }
  printf '%s' "$value"
}

registry_contains_user() {
  local target="$1"
  [[ -f "$REGISTRY_FILE" ]] || return 1
  awk -F '\t' -v u="$target" '$1 == u {found=1; exit} END {exit found ? 0 : 1}' "$REGISTRY_FILE"
}

registry_init() {
  mkdir -p "$REGISTRY_DIR"
  chmod 700 "$REGISTRY_DIR"
  touch "$REGISTRY_FILE" "$REGISTRY_LOCK_FILE"
  chmod 600 "$REGISTRY_FILE" "$REGISTRY_LOCK_FILE"
}

registry_lock() {
  local __fd_var="$1"
  registry_init
  printf -v "$__fd_var" '%s' ""
  if ! command_exists flock; then
    warn "找不到 flock，登记文件并发保护已降级。"
    return 0
  fi
  local fd
  exec {fd}>"$REGISTRY_LOCK_FILE"
  flock "$fd"
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
  [[ -f "$REGISTRY_FILE" ]] || return 0
  local tmp
  tmp=$(mktemp "${REGISTRY_DIR}/users.tsv.tmp.XXXXXX")
  awk -F '\t' -v u="$user" '$1 != u {print}' "$REGISTRY_FILE" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$REGISTRY_FILE"
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
  registry_lock lock_fd
  registry_remove_user_unlocked "$user" 2>/dev/null || true
  local created
  created=$(date '+%F %T %Z')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$user" "$created" "$expires" "$sudo_enabled" "$nopasswd" "$host" "$port" "$fingerprint" "$auto_revoke" "$auto_unit" >> "$REGISTRY_FILE"
  registry_unlock "$lock_fd"
}

registry_remove_user() {
  local user="$1"
  local lock_fd
  registry_lock lock_fd
  registry_remove_user_unlocked "$user"
  registry_unlock "$lock_fd"
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
    warn "暂无脚本登记的临时用户。"
    return 1
  fi
  local i=0 user created expires sudo_enabled legacy_nopasswd host port fingerprint auto_revoke auto_unit state
  while IFS=$'\t' read -r user created expires sudo_enabled legacy_nopasswd host port fingerprint auto_revoke auto_unit; do
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
    warn "没有找到仍存在的已登记临时用户。"
    read -r -p "请输入要撤销/删除的用户名: " user
    printf '%s\n' "$user"
    return 0
  fi

  echo "已登记的临时用户：" >&2
  local idx
  for idx in "${!users[@]}"; do
    printf '%2d) %s\n' "$((idx + 1))" "${users[$idx]}" >&2
  done
  echo "也可以直接输入用户名。" >&2
  local choice
  read -r -p "请选择要删除的编号/用户名: " choice
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
    printf '%s-revoke-%s' "$MANAGED_TAG" "$user"
  fi
}

auto_revoke_service_path() {
  local unit="$1"
  printf '%s/%s.service' "$SYSTEMD_DIR" "$unit"
}

auto_revoke_timer_path() {
  local unit="$1"
  printf '%s/%s.timer' "$SYSTEMD_DIR" "$unit"
}

install_self_for_revoke() {
  local src="${BASH_SOURCE[0]}"
  if [[ ! -f "$src" ]]; then
    warn "无法定位当前脚本文件，不能安装稳定撤销命令。"
    return 1
  fi
  install -m 700 -o root -g root "$src" "$INSTALL_PATH"
}

schedule_at_revoke() {
  local user="$1" hours="$2"
  if ! command_exists at; then
    warn "找不到 at，无法创建备用自动删除任务；仅设置账号过期。"
    return 1
  fi
  if ! install_self_for_revoke; then
    warn "安装 $INSTALL_PATH 失败，无法创建备用自动删除任务；仅设置账号过期。"
    return 1
  fi
  local output job_id
  if ! output=$(printf "'%s' revoke --user '%s' --yes\n" "$INSTALL_PATH" "$user" | at now + "$hours" hours 2>&1); then
    warn "创建 at 自动删除任务失败：$output"
    return 1
  fi
  job_id=$(awk '/^job[[:space:]]+[0-9]+/ {print $2; exit}' <<< "$output")
  if [[ -z "$job_id" || ! "$job_id" =~ ^[0-9]+$ ]]; then
    warn "无法识别 at 自动删除任务编号：$output"
    return 1
  fi
  printf 'at:%s\n' "$job_id"
}

schedule_auto_revoke() {
  local user="$1" hours="$2"
  if ! command_exists systemctl; then
    warn "找不到 systemctl，将尝试使用 at 创建备用自动删除任务。"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! install_self_for_revoke; then
    warn "安装 $INSTALL_PATH 失败，将尝试使用 at 创建备用自动删除任务。"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  local unit service_path timer_path timer_schedule on_calendar
  unit=$(auto_revoke_unit_name "$user")
  service_path=$(auto_revoke_service_path "$unit")
  timer_path=$(auto_revoke_timer_path "$unit")
  if on_calendar=$(date -d "+${hours} hours" '+%Y-%m-%d %H:%M:%S' 2>/dev/null); then
    timer_schedule="OnCalendar=$on_calendar
Persistent=true"
  else
    warn "当前系统 date 不支持 -d，将使用相对 systemd timer；关机期间不会补触发。"
    timer_schedule="OnActiveSec=${hours}h"
  fi

  cat > "$service_path" <<EOF_SERVICE
[Unit]
Description=linux-temp-admin auto revoke $user
Documentation=https://github.com/xxvcc/linux-temp-admin

[Service]
Type=oneshot
NoNewPrivileges=yes
PrivateTmp=yes
User=root
ExecStart=$INSTALL_PATH revoke --user $user --yes
EOF_SERVICE

  cat > "$timer_path" <<EOF_TIMER
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

  chmod 644 "$service_path" "$timer_path"
  if command_exists systemd-analyze; then
    systemd-analyze verify "$service_path" "$timer_path" >/dev/null || {
      rm -f "$service_path" "$timer_path"
      warn "systemd unit 校验失败，将尝试使用 at 创建备用自动删除任务。"
      schedule_at_revoke "$user" "$hours"
      return $?
    }
  fi
  if ! systemctl daemon-reload >/dev/null; then
    rm -f "$service_path" "$timer_path"
    warn "systemd daemon-reload 失败，将尝试使用 at 创建备用自动删除任务。"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  if ! systemctl enable --now "$unit.timer" >/dev/null; then
    rm -f "$service_path" "$timer_path"
    systemctl daemon-reload >/dev/null 2>&1 || true
    warn "启用 systemd timer 失败，将尝试使用 at 创建备用自动删除任务。"
    schedule_at_revoke "$user" "$hours"
    return $?
  fi
  printf '%s\n' "$unit"
}

cancel_auto_revoke() {
  local user="$1" unit="${2:-}"
  [[ -n "$unit" ]] || unit=$(registry_unit_for_user "$user" 2>/dev/null || true)
  if [[ "$unit" == at:* ]]; then
    local job_id="${unit#at:}"
    if [[ "$job_id" =~ ^[0-9]+$ ]] && command_exists atrm; then
      atrm "$job_id" >/dev/null 2>&1 || true
    fi
    return 0
  fi
  [[ -n "$unit" ]] || unit=$(auto_revoke_unit_name "$user")
  if command_exists systemctl; then
    # 只停止 timer，不主动 stop service；自动删除本身可能正在 service 内运行。
    systemctl disable --now "${unit}.timer" >/dev/null 2>&1 || true
    systemctl reset-failed "${unit}.timer" "${unit}.service" >/dev/null 2>&1 || true
  fi
  rm -f "$(auto_revoke_timer_path "$unit")" "$(auto_revoke_service_path "$unit")" 2>/dev/null || true
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
    [[ "$o" =~ ^[0-9]+$ && "$o" -le 255 ]] || return 1
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

get_url_text() {
  local url="$1"
  if command_exists curl; then
    curl -fsS --connect-timeout 1 --max-time 2 "$url" 2>/dev/null | tr -d '[:space:]' || true
  elif command_exists wget; then
    wget -qO- --timeout=2 "$url" 2>/dev/null | tr -d '[:space:]' || true
  fi
}

get_local_public_ip() {
  local ip="" service
  local metadata_services=(
    "http://metadata.tencentyun.com/latest/meta-data/public-ipv4"
    "http://169.254.169.254/latest/meta-data/public-ipv4"
    "http://100.100.100.200/latest/meta-data/eipv4"
  )
  for service in "${metadata_services[@]}"; do
    ip=$(get_url_text "$service")
    if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
  done

  if command_exists ip; then
    while IFS= read -r ip; do
      if is_public_ipv4 "$ip"; then
        printf '%s\n' "$ip"
        return 0
      fi
    done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')

    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' || true)
    if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
  fi
  return 1
}

get_public_ip() {
  local ip="" service
  local services=("https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com")
  for service in "${services[@]}"; do
    ip=$(get_url_text "$service")
    if [[ -n "$ip" ]] && valid_host "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
    ip=""
  done
  return 1
}

expire_date_from_hours() {
  local hours="$1"
  # chage -E 是按“日期”过期。这里用 ceil(hours/24) 天，避免短有效期
  # 因目标日期仍是“今天”而被立即过期。
  local days=$(( (hours + 23) / 24 ))
  (( days < 1 )) && days=1
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
    err "找不到可用登录 shell。"
    return 1
  fi
}

create_user_if_needed() {
  local user="$1"
  local shell_path="$2"
  if user_exists "$user"; then
    err "用户已存在：$user"
    exit 1
  fi
  if command_exists useradd; then
    useradd -m -s "$shell_path" -c "$MANAGED_TAG temporary admin" "$user"
  elif command_exists adduser; then
    adduser -D -s "$shell_path" -g "$MANAGED_TAG temporary admin" "$user"
  else
    err "找不到 useradd/adduser，无法创建用户"
    exit 1
  fi
}

lock_user_password() {
  local user="$1"
  if usermod -L "$user" >/dev/null 2>&1; then
    return 0
  fi
  warn "锁定账号密码失败，请手动检查：$user"
  return 1
}

set_user_expiry() {
  local user="$1"
  local hours="$2"
  local date_only
  if ! date_only=$(expire_date_from_hours "$hours"); then
    err "无法计算账号过期日期，请安装 GNU date 或 python3 后重试。"
    return 1
  fi
  if command_exists chage; then
    chage -E "$date_only" "$user" || {
      err "设置账号过期时间失败，已停止创建并准备回滚。"
      return 1
    }
  else
    err "找不到 chage，无法安全设置账号过期时间。"
    return 1
  fi
}

add_sudo() {
  local user="$1"
  local group
  group=$(sudo_group)
  if [[ -z "$group" ]]; then
    warn "未找到 sudo 或 wheel 组，跳过 sudo 授权。"
    return 1
  fi
  if [[ ! -d /etc/sudoers.d ]]; then
    warn "/etc/sudoers.d 不存在，无法配置 NOPASSWD sudo。"
    return 1
  fi
  usermod -aG "$group" "$user"
  local file="/etc/sudoers.d/${MANAGED_TAG}-${user}"
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" > "$file"
  chmod 440 "$file"
  if command_exists visudo; then
    visudo -cf "$file" >/dev/null || {
      rm -f "$file"
      err "sudoers 校验失败，已删除 $file"
      exit 1
    }
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
    err "找不到用户家目录：$user"
    exit 1
  fi
  install -d -m 700 -o "$user" -g "$user" "$home_dir/.ssh"
  cat "$pubkey_file" > "$home_dir/.ssh/authorized_keys"
  chown "$user:$user" "$home_dir/.ssh/authorized_keys"
  chmod 600 "$home_dir/.ssh/authorized_keys"
}


rollback_created_user() {
  local user="$1"
  [[ -n "${user:-}" ]] || return 0
  warn "创建过程中出错，正在回滚临时用户：$user"
  cancel_auto_revoke "$user" || true
  pkill -KILL -u "$user" 2>/dev/null || true
  remove_sudoers_file "$user" || true
  if user_exists "$user"; then
    if command_exists deluser; then
      deluser --remove-home "$user" >/dev/null 2>&1 || userdel -r "$user" >/dev/null 2>&1 || warn "回滚时删除用户失败，请手动检查：$user"
    else
      userdel -r "$user" >/dev/null 2>&1 || warn "回滚时删除用户失败，请手动检查：$user"
    fi
  fi
  registry_remove_user "$user" || true
}

print_invite() {
  local host="$1" port="$2" user="$3" expires="$4" sudo_enabled="$5" private_key_file="$6" revoke_cmd="$7" auto_revoke="$8" auto_unit="$9"
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
ssh -i ./${user}.key -p $port ${user}@${host}

保存私钥命令:
cat > './${user}.key' <<'EOF_KEY'
$(cat "$private_key_file")
EOF_KEY
chmod 600 './${user}.key'

EOF
  if [[ "$sudo_enabled" == "yes" ]]; then
    cat <<EOF
Sudo 提示:
已启用 NOPASSWD sudo。此账号只能通过 SSH key 登录；账号密码已锁定。

EOF
  else
    cat <<EOF
Sudo 提示:
未授予 sudo 权限，此账号是普通用户；账号密码已锁定。

EOF
  fi
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
      --nopasswd-sudo) warn "--nopasswd-sudo 已废弃：--sudo 现在默认使用 NOPASSWD sudo。"; grant_sudo="yes"; shift ;;
      --yes|-y) assume_yes="true"; shift ;;
      --confirm-sudo) require_value "$1" "${2-}"; confirm_sudo="$2"; shift 2 ;;
      --allow-non-tty-private-key-output) allow_non_tty_key_output="true"; shift ;;
      --install-deps) deps_mode="auto"; shift ;;
      --no-install-deps) deps_mode="never"; shift ;;
      --auto-revoke) auto_revoke="yes"; shift ;;
      --no-auto-revoke) auto_revoke="no"; shift ;;
      *) err "未知参数：$1"; usage; exit 1 ;;
    esac
  done

  if [[ ! "$hours" =~ ^[0-9]{1,4}$ || "$hours" -lt 1 || "$hours" -gt "$MAX_EXPIRE_HOURS" ]]; then
    err "--hours 必须是 1 到 $MAX_EXPIRE_HOURS 之间的整数"
    exit 1
  fi
  if ! valid_prefix "$prefix"; then
    err "用户名前缀不合法：$prefix。只能使用小写字母、数字、下划线、连字符，需以字母/下划线开头，不能以 '-' 或 '_' 结尾，最长 20 字符。"
    exit 1
  fi

  if [[ -z "$user" ]]; then
    local attempt
    for attempt in {1..20}; do
      user="${prefix}-$(random_hex 5)"
      if ! user_exists "$user"; then
        break
      fi
      user=""
    done
    if [[ -z "$user" ]]; then
      err "多次生成随机用户名均发生冲突，请指定 --user。"
      exit 1
    fi
  fi
  if ! valid_username "$user"; then
    err "用户名不合法：$user。只能使用小写字母、数字、下划线、连字符，且以字母/下划线开头。"
    exit 1
  fi

  if [[ -z "$host" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      err "--yes 模式不会自动访问外部服务探测公网 IP，请显式传入 --host。"
      exit 1
    else
      warn "自动探测会先尝试本地网卡和云厂商 metadata；失败后才访问外部服务：https://api.ipify.org、https://ifconfig.me/ip、https://icanhazip.com"
      read -r -p "是否自动探测公网 IP？[y/N]: " ans_host
      if [[ "$ans_host" =~ ^[Yy]$ ]]; then
        if host=$(get_local_public_ip); then
          info "已通过本地/云元数据探测公网 IP：$host"
        elif host=$(get_public_ip); then
          info "已通过外部服务探测公网 IP：$host"
        else
          warn "自动探测公网 IP 失败，请手动输入服务器公网 IP/域名。"
          host=""
        fi
      fi
    fi
  fi
  if [[ -z "$host" ]]; then
    read -r -p "请输入服务器公网 IP/域名: " host
  fi
  if ! valid_host "$host"; then
    err "Host 不合法：$host。请使用普通域名、IPv4 或 IPv6 地址，不要包含端口、空格、引号或 shell 符号。"
    exit 1
  fi
  if [[ -z "$port" ]]; then
    port=$(get_ssh_port)
  fi
  if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt 1 || "$port" -gt 65535 ]]; then
    err "SSH 端口不合法：$port"
    exit 1
  fi

  if [[ "$grant_sudo" == "ask" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      grant_sudo="no"
    else
      read -r -p "是否授予 sudo 管理员权限？[y/N]: " ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then grant_sudo="yes"; else grant_sudo="no"; fi
    fi
  fi
  if [[ "$grant_sudo" == "yes" && "$assume_yes" == "true" && "$confirm_sudo" != "$user" ]]; then
    err "拒绝通过 --sudo --yes 授予 sudo：必须同时传入 --confirm-sudo $user。"
    exit 1
  fi
  if [[ ! -t 1 && "$allow_non_tty_key_output" != "true" ]]; then
    err "stdout 不是 TTY，拒绝输出一次性私钥。若确认输出通道安全，请加 --allow-non-tty-private-key-output。"
    exit 1
  fi

  if [[ "$auto_revoke" == "ask" ]]; then
    if [[ "$assume_yes" == "true" ]]; then
      auto_revoke="yes"
    else
      read -r -p "是否到期后自动删除该用户？[Y/n]: " ans3
      if [[ -z "$ans3" || "$ans3" =~ ^[Yy]$ ]]; then auto_revoke="yes"; else auto_revoke="no"; fi
    fi
  fi

  cat <<EOF

即将创建一次性临时账号：
- 用户名：$user
- Host：$host
- SSH 端口：$port
- 有效期：$hours 小时
- sudo 权限：$grant_sudo
- 到期自动删除：$auto_revoke

EOF
  confirm_yes "sudo/SSH 账号属于高权限入口。确认创建请输入 YES。" "$assume_yes" || {
    warn "已取消。"
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
    trap - ERR
    if [[ "$invite_completed" != "true" && -n "$created_user" ]]; then
      rollback_created_user "$created_user"
    fi
    rm -rf "$tmpdir"
    exit "$code"
  }
  trap cleanup_invite_error ERR
  trap 'rm -rf "$tmpdir"' RETURN

  ssh-keygen -t ed25519 -N '' -C "${user}-${MANAGED_TAG}" -f "$keyfile" >/dev/null

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
      auto_text="no"
      revoke_cmd="sudo bash $SCRIPT_NAME revoke --user $user"
    fi
  fi
  registry_record_user "$user" "$expires" "$sudo_text" "no" "$host" "$port" "${fingerprint:-unknown}" "$auto_text" "$auto_unit"

  invite_completed="true"
  trap - ERR
  success "临时账号已创建并登记：$user"
  print_invite "$host" "$port" "$user" "$expires" "$sudo_text" "$keyfile" "$revoke_cmd" "$auto_text" "${auto_unit:-none}"
  rm -rf "$tmpdir"
  trap - RETURN
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
      *) err "未知参数：$1"; usage; exit 1 ;;
    esac
  done
  if [[ -z "$user" ]]; then
    user=$(registry_select_user)
  fi
  if ! valid_username "$user"; then
    err "用户名不合法，拒绝删除：$user"
    exit 1
  fi
  local registered="false"
  if registry_contains_user "$user"; then
    registered="true"
  fi
  if [[ "$force" != "true" && "$registered" != "true" ]]; then
    err "拒绝删除未登记用户：$user。若确认需要删除默认前缀或其他用户，请加 --force。"
    exit 1
  fi
  if [[ "$force" == "true" && "$registered" != "true" && "$assume_yes" == "true" && "$confirm_force" != "$user" ]]; then
    err "拒绝通过 --force --yes 删除未登记用户：必须同时传入 --confirm-force $user。"
    exit 1
  fi
  if ! user_exists "$user"; then
    warn "用户不存在：$user。将清理登记记录和自动删除任务（如果存在）。"
    cancel_auto_revoke "$user"
    registry_remove_user "$user"
    exit 0
  fi
  if [[ "$assume_yes" != "true" ]]; then
    if [[ "$force" == "true" && "$registered" != "true" ]]; then
      printf "
${RED}危险：用户 %s 未在脚本登记中，--force 将删除真实系统用户及其家目录。${NC}
" "$user"
    fi
    printf "
${YELLOW}将强制下线并删除用户 %s 及其家目录。${NC}
" "$user"
    read -r -p "请输入完整用户名 $user 以确认删除: " confirm_user
    if [[ "$confirm_user" != "$user" ]]; then
      warn "确认不匹配，已取消。"
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
  success "已撤销并删除用户：$user"
}

status_user() {
  local user=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) require_value "$1" "${2-}"; user="$2"; shift 2 ;;
      *) err "未知参数：$1"; usage; exit 1 ;;
    esac
  done
  if [[ -n "$user" ]]; then
    if user_exists "$user"; then
      id "$user"
      getent passwd "$user"
      local home_dir
      home_dir=$(getent passwd "$user" | cut -d: -f6)
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
    else
      err "用户不存在：$user"
      exit 1
    fi
    return
  fi
  info "脚本登记的临时用户："
  registry_list_users || true
  printf '\n'
  info "系统中匹配前缀 $DEFAULT_PREFIX- 的用户："
  getent passwd | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1 "\t" $6 "\t" $7}' || true
  printf '\n'
  info "自动删除 timer："
  show_auto_revoke_timers || true
}

cleanup_expired() {
  need_root
  if [[ $# -gt 0 ]]; then
    err "cleanup-expired 不接受额外参数：$*"
    usage
    exit 1
  fi
  warn "这里只查看账号过期和自动删除状态，不主动删除用户，避免误删。"
  if ! command_exists chage; then
    warn "找不到 chage，无法检查过期时间。"
    return 0
  fi
  local users=()
  if [[ -s "$REGISTRY_FILE" ]]; then
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
    info "没有登记的临时用户或系统默认前缀用户。"
    return 0
  fi
  for user in "${users[@]}"; do
    printf '\n--- %s ---\n' "$user"
    if user_exists "$user"; then
      chage -l "$user" | sed -n '1,8p' || true
    else
      info "用户不存在：$user"
    fi
  done
  info "说明：账号过期只会阻止后续登录；自动删除任务会调用 revoke 删除用户、家目录和 SSH key。"
  show_auto_revoke_timers || true
}

menu() {
  need_root
  while true; do
    cat <<EOF

${BOLD}Linux 临时管理员管理器${NC} v$VERSION

1) 创建一次性临时管理员邀请
2) 撤销/删除临时用户
3) 查看用户状态
4) 查看账号过期/自动删除状态
5) 退出
EOF
    read -r -p "请选择 [1-5]: " choice
    case "$choice" in
      1) invite ;;
      2) revoke_user ;;
      3) read -r -p "用户名（留空列出 ${DEFAULT_PREFIX}-*）: " u; if [[ -n "$u" ]]; then status_user --user "$u"; else status_user; fi ;;
      4) cleanup_expired ;;
      5) exit 0 ;;
      *) warn "无效选择" ;;
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
    *) err "未知命令：$cmd"; usage; exit 1 ;;
  esac
}

main "$@"
