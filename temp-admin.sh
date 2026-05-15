#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="temp-admin.sh"
VERSION="0.5.3"
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
  bash $SCRIPT_NAME help                    显示帮助

常用参数：
  --prefix PREFIX        用户名前缀，默认：$DEFAULT_PREFIX
  --user USER            指定用户名
  --host HOST            邀请包中显示的服务器地址
  --port PORT            SSH 端口，自动探测，失败则 22
  --hours HOURS          有效期小时数，默认：$DEFAULT_EXPIRE_HOURS
  --sudo                 授予 sudo/wheel 权限
  --no-sudo              不授予 sudo/wheel 权限
  --nopasswd-sudo        免密 sudo，高风险
  --yes                  跳过确认
  --install-deps         自动安装缺失依赖
  --no-install-deps      不安装缺失依赖
  --auto-revoke          到期自动删除用户，默认
  --no-auto-revoke       不自动删除，仅设置账号过期

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
      read -r -p "是否使用 $pm 自动安装缺失依赖？[Y/n]: " ans
      if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then install="true"; fi
      ;;
  esac

  if [[ "$install" != "true" ]]; then
    err "已取消安装依赖。请手动安装后重试。"
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
    err "无法映射缺失依赖到安装包：${missing[*]}"
    return 1
  fi

  info "安装依赖包：$pkgs"
  # shellcheck disable=SC2086
  install_packages "$pm" $pkgs

  local still_missing=()
  command_exists bash || still_missing+=("bash")
  command_exists ssh-keygen || still_missing+=("ssh-keygen")
  if ! command_exists useradd && ! command_exists adduser; then still_missing+=("useradd/adduser"); fi
  command_exists chpasswd || still_missing+=("chpasswd")
  command_exists usermod || still_missing+=("usermod")
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

random_password() {
  if command_exists openssl; then
    openssl rand -base64 24 | tr -d '\n'
  else
    local pass=""
    while [[ ${#pass} -lt 32 ]]; do
      pass+=$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9_@%+=:,.^-' || true)
    done
    printf '%s' "${pass:0:32}"
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
  tmp=$(mktemp "${REGISTRY_DIR}/users.tsv.tmp.XXXXXX")
  awk -F '\t' -v u="$user" '$1 != u {print}' "$REGISTRY_FILE" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$REGISTRY_FILE"
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
  local user="$1"
  printf '%s-revoke-%s' "$MANAGED_TAG" "$user"
}

install_self_for_revoke() {
  local src="${BASH_SOURCE[0]}"
  if [[ ! -f "$src" ]]; then
    warn "无法定位当前脚本文件，不能安装稳定撤销命令。"
    return 1
  fi
  install -m 700 -o root -g root "$src" "$INSTALL_PATH"
}

schedule_auto_revoke() {
  local user="$1" hours="$2"
  if ! command_exists systemd-run; then
    warn "找不到 systemd-run，无法创建自动删除任务；仅设置账号过期。"
    return 1
  fi
  if ! install_self_for_revoke; then
    warn "安装 $INSTALL_PATH 失败，无法创建自动删除任务；仅设置账号过期。"
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
  # chage -E 是按“日期”过期。这里用 ceil(hours/24) 天，避免短有效期
  # 因目标日期仍是“今天”而被立即过期。
  local days=$(( (hours + 23) / 24 ))
  (( days < 1 )) && days=1
  if date -u -d "+${days} days" +%F >/dev/null 2>&1; then
    date -u -d "+${days} days" +%F
  else
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

set_user_password() {
  local user="$1"
  local pass="$2"
  if command_exists chpasswd; then
    printf '%s:%s\n' "$user" "$pass" | chpasswd
  else
    warn "找不到 chpasswd，未设置用户密码；sudo 可能无法使用密码提权。"
  fi
}

set_user_expiry() {
  local user="$1"
  local hours="$2"
  local date_only
  date_only=$(expire_date_from_hours "$hours")
  if command_exists chage; then
    chage -E "$date_only" "$user" || warn "设置账号过期时间失败，请手动检查 chage。"
  else
    warn "找不到 chage，未设置系统账号过期时间。"
  fi
}

add_sudo() {
  local user="$1"
  local nopasswd="$2"
  local group
  group=$(sudo_group)
  if [[ -z "$group" ]]; then
    warn "未找到 sudo 或 wheel 组，跳过 sudo 授权。"
    return 1
  fi
  usermod -aG "$group" "$user"
  if [[ "$nopasswd" == "true" ]]; then
    if [[ ! -d /etc/sudoers.d ]]; then
      warn "/etc/sudoers.d 不存在，无法配置免密 sudo。"
      return 0
    fi
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

SSH 登录命令:
ssh -i ./${user}.key -p $port ${user}@${host}

保存私钥命令:
cat > ${user}.key <<'EOF_KEY'
$(cat "$private_key_file")
EOF_KEY
chmod 600 ${user}.key

EOF
  if [[ "$sudo_enabled" == "yes" && "$nopasswd" != "yes" ]]; then
    cat <<EOF
账号/Sudo 密码:
$password

EOF
  elif [[ "$sudo_enabled" == "yes" && "$nopasswd" == "yes" ]]; then
    cat <<EOF
Sudo 提示:
已开启免密 sudo。此权限很高，用完请立即撤销。

EOF
  else
    cat <<EOF
Sudo 提示:
未授予 sudo 权限，此账号是普通用户。

EOF
  fi
  cat <<EOF
撤销命令:
$revoke_cmd

安全提醒:
- 上面的私钥和 sudo 密码只显示这一次。
- 只通过可信私聊发送，不要发群里或公开页面。
- 用完请立即执行撤销命令。
- 服务器上只保存公钥，不保存私钥。

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
      *) err "未知参数：$1"; usage; exit 1 ;;
    esac
  done

  if [[ ! "$hours" =~ ^[0-9]+$ || "$hours" -lt 1 ]]; then
    err "--hours 必须是大于 0 的整数"
    exit 1
  fi

  if [[ -z "$user" ]]; then
    user="${prefix}-$(random_hex 3)"
  fi
  if ! valid_username "$user"; then
    err "用户名不合法：$user。只能使用小写字母、数字、下划线、连字符，且以字母/下划线开头。"
    exit 1
  fi

  if [[ -z "$host" ]]; then
    host=$(get_public_ip)
  fi
  if [[ -z "$host" ]]; then
    read -r -p "请输入服务器公网 IP/域名: " host
  fi
  if [[ -z "$port" ]]; then
    port=$(get_ssh_port)
  fi
    if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt 1 || "$port" -gt 65535 ]]; then
    err "SSH 端口不合法：$port"
    exit 1
  fi

  if [[ "$grant_sudo" == "ask" ]]; then
    read -r -p "是否授予 sudo 管理员权限？[y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then grant_sudo="yes"; else grant_sudo="no"; fi
  fi

  if [[ "$grant_sudo" == "yes" && "$nopasswd" != "true" ]]; then
    read -r -p "是否开启免密 sudo？高风险，不推荐。[y/N]: " ans2
    if [[ "$ans2" =~ ^[Yy]$ ]]; then nopasswd="true"; fi
  fi

  if [[ "$auto_revoke" == "ask" ]]; then
    read -r -p "是否到期后自动删除该用户？[Y/n]: " ans3
    if [[ -z "$ans3" || "$ans3" =~ ^[Yy]$ ]]; then auto_revoke="yes"; else auto_revoke="no"; fi
  fi

  if [[ "$grant_sudo" == "yes" ]]; then
    ensure_dependencies "$deps_mode" true
  else
    ensure_dependencies "$deps_mode" false
  fi

  cat <<EOF

即将创建一次性临时账号：
- 用户名：$user
- Host：$host
- SSH 端口：$port
- 有效期：$hours 小时
- sudo 权限：$grant_sudo
- 免密 sudo：$nopasswd
- 到期自动删除：$auto_revoke

EOF
  confirm_yes "sudo/SSH 账号属于高权限入口。确认创建请输入 YES。" "$assume_yes" || {
    warn "已取消。"
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

  success "临时账号已创建并登记：$user"
  print_invite "$host" "$port" "$user" "$expires" "$sudo_text" "$nopasswd_text" "$password" "$keyfile" "$revoke_cmd" "$auto_text" "${auto_unit:-none}"
}

revoke_user() {
  need_root
  local user="" assume_yes="false"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) user="$2"; shift 2 ;;
      --yes|-y) assume_yes="true"; shift ;;
      *) err "未知参数：$1"; usage; exit 1 ;;
    esac
  done
  if [[ -z "$user" ]]; then
    user=$(registry_select_user)
  fi
  if ! user_exists "$user"; then
    warn "用户不存在：$user。将清理登记记录和自动删除任务（如果存在）。"
    cancel_auto_revoke "$user"
    registry_remove_user "$user"
    exit 0
  fi
  if [[ "$assume_yes" != "true" ]]; then
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
      --user) user="$2"; shift 2 ;;
      *) err "未知参数：$1"; usage; exit 1 ;;
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
  warn "这里只查看账号过期和自动删除状态，不主动删除用户，避免误删。"
  if ! command_exists chage; then
    warn "找不到 chage，无法检查过期时间。"
    return 0
  fi
  getent passwd | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1}' | while read -r user; do
    [[ -z "$user" ]] && continue
    printf '\n--- %s ---\n' "$user"
    chage -l "$user" | sed -n '1,8p'
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
    cleanup-expired) shift; cleanup_expired "$@" ;;
    help|-h|--help) usage ;;
    version|--version) echo "$VERSION" ;;
    *) err "未知命令：$cmd"; usage; exit 1 ;;
  esac
}

main "$@"
