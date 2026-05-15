#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="temp-admin.sh"
VERSION="0.1.0"
DEFAULT_PREFIX="xxvcc"
DEFAULT_EXPIRE_HOURS="24"
DEFAULT_SHELL="/bin/bash"
MANAGED_TAG="linux-temp-admin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

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
  bash $SCRIPT_NAME                 交互式菜单
  bash $SCRIPT_NAME invite          创建一次性临时管理员邀请
  bash $SCRIPT_NAME revoke --user USER
  bash $SCRIPT_NAME status [--user USER]
  bash $SCRIPT_NAME cleanup-expired
  bash $SCRIPT_NAME help

常用参数：
  --prefix PREFIX        用户名前缀，默认：$DEFAULT_PREFIX，生成如 PREFIX-a1b2c3
  --user USER            指定用户名
  --host HOST            输出邀请包中的服务器地址
  --port PORT            SSH 端口，默认自动探测，失败则 22
  --hours HOURS          有效期小时数，默认：$DEFAULT_EXPIRE_HOURS
  --sudo                 授予 sudo/wheel 权限
  --no-sudo              不授予 sudo/wheel 权限
  --nopasswd-sudo        写入免密 sudoers（高风险，不推荐）
  --yes                  跳过 YES 二次确认

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
    # BusyBox/macOS fallback：账号过期日期不精确支持时用明天
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
  local host="$1" port="$2" user="$3" expires="$4" sudo_enabled="$5" nopasswd="$6" password="$7" private_key_file="$8" revoke_cmd="$9"
  cat <<EOF

${BOLD}====== 一次性临时管理员连接信息 ======${NC}

Host: $host
Port: $port
User: $user
Expires: $expires
Sudo: $sudo_enabled
Passwordless sudo: $nopasswd

SSH 登录命令：
ssh -i ./${user}.key -p $port ${user}@${host}

保存私钥命令：
cat > ${user}.key <<'EOF_KEY'
$(cat "$private_key_file")
EOF_KEY
chmod 600 ${user}.key

EOF
  if [[ "$sudo_enabled" == "yes" && "$nopasswd" != "yes" ]]; then
    cat <<EOF
Sudo 密码：
$password

EOF
  elif [[ "$sudo_enabled" == "yes" && "$nopasswd" == "yes" ]]; then
    cat <<EOF
Sudo 提示：
已开启免密 sudo。此权限很高，用完请立即撤销。

EOF
  else
    cat <<EOF
Sudo 提示：
未授予 sudo 权限，此账号是普通用户。

EOF
  fi
  cat <<EOF
撤销命令：
$revoke_cmd

${BOLD}安全提醒：${NC}
- 上面的私钥和 sudo 密码只显示这一次。
- 只通过可信私聊发送，不要发群里或公开页面。
- 用完请立即执行撤销命令。
- 服务器上只保存公钥，不保存私钥。

${BOLD}======================================${NC}
EOF
}

invite() {
  need_root
  local prefix="$DEFAULT_PREFIX" user="" host="" port="" hours="$DEFAULT_EXPIRE_HOURS"
  local grant_sudo="ask" nopasswd="false" assume_yes="false"

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

  if [[ "$grant_sudo" == "ask" ]]; then
    read -r -p "是否授予 sudo 管理员权限？[y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then grant_sudo="yes"; else grant_sudo="no"; fi
  fi

  if [[ "$grant_sudo" == "yes" && "$nopasswd" != "true" ]]; then
    read -r -p "是否开启免密 sudo？高风险，不推荐。[y/N]: " ans2
    if [[ "$ans2" =~ ^[Yy]$ ]]; then nopasswd="true"; fi
  fi

  cat <<EOF

即将创建一次性临时账号：
- 用户名：$user
- Host：$host
- SSH 端口：$port
- 有效期：$hours 小时
- sudo 权限：$grant_sudo
- 免密 sudo：$nopasswd

EOF
  confirm_yes "sudo/SSH 账号属于高权限入口。确认创建请输入 YES。" "$assume_yes" || {
    warn "已取消。"
    exit 0
  }

  local tmpdir keyfile pubfile password expires revoke_cmd sudo_text nopasswd_text
  tmpdir=$(mktemp -d)
  keyfile="$tmpdir/${user}.key"
  pubfile="$keyfile.pub"
  trap 'rm -rf "$tmpdir"' RETURN

  if ! command_exists ssh-keygen; then
    err "找不到 ssh-keygen，请先安装 openssh-client/openssh。"
    exit 1
  fi

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
  revoke_cmd="sudo bash $SCRIPT_NAME revoke --user $user"

  success "临时账号已创建：$user"
  print_invite "$host" "$port" "$user" "$expires" "$sudo_text" "$nopasswd_text" "$password" "$keyfile" "$revoke_cmd"
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
    read -r -p "请输入要撤销/删除的用户名: " user
  fi
  if ! user_exists "$user"; then
    err "用户不存在：$user"
    exit 1
  fi
  confirm_yes "将强制下线并删除用户 $user 及其家目录。" "$assume_yes" || {
    warn "已取消。"
    exit 0
  }
  pkill -KILL -u "$user" 2>/dev/null || true
  remove_sudoers_file "$user"
  if command_exists deluser; then
    deluser --remove-home "$user" || userdel -r "$user"
  else
    userdel -r "$user"
  fi
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
    else
      err "用户不存在：$user"
      exit 1
    fi
    return
  fi
  info "匹配前缀 $DEFAULT_PREFIX- 的用户："
  getent passwd | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1 "\t" $6 "\t" $7}' || true
}

cleanup_expired() {
  need_root
  warn "cleanup-expired 当前仅显示过期候选，不自动删除，避免误删。"
  if ! command_exists chage; then
    warn "找不到 chage，无法检查过期时间。"
    return 0
  fi
  local today
  today=$(date -u +%F)
  getent passwd | awk -F: -v p="^${DEFAULT_PREFIX}-" '$1 ~ p {print $1}' | while read -r user; do
    [[ -z "$user" ]] && continue
    printf '\n--- %s ---\n' "$user"
    chage -l "$user" | sed -n '1,8p'
  done
  info "如需删除，请执行：bash $SCRIPT_NAME revoke --user USER"
}

menu() {
  need_root
  while true; do
    cat <<EOF

${BOLD}Linux Temporary Admin Manager${NC} v$VERSION

1) 创建一次性临时管理员邀请
2) 撤销/删除临时用户
3) 查看用户状态
4) 查看过期候选
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
