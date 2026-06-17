# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 一次性 Linux 临时管理员邀请脚本：随机生成 SSH 密钥、创建临时用户、可选授予 NOPASSWD sudo，并默认安排到期自动删除。

**linux-temp-admin** 适合临时给可信协作者、运维人员或自动化助手开一个 SSH 管理入口。它会输出一份可私聊转发的邀请包；服务器端只保存公钥，不保存私钥。

**语言 / Languages**：中文 | [English](README.en.md)

## 一键使用

推荐先下载再执行，便于审阅脚本：

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
sudo bash temp-admin.sh
```

英文脚本 / English script:

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin-en.sh
chmod +x temp-admin-en.sh
sudo bash temp-admin-en.sh
```

直接创建带 sudo 的一次性邀请：

```bash
sudo bash temp-admin.sh invite --sudo
```

非交互创建 sudo 邀请时需要额外确认用户名，并显式允许非 TTY 输出私钥：

```bash
sudo bash temp-admin.sh invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 \
  --sudo \
  --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

---

## 为什么需要它？

临时给别人开 SSH 权限时，最容易出问题的是：

- 直接给 root 密码；
- 长期保留临时账号；
- 公钥留在 `authorized_keys` 里忘记删除；
- 不知道之前创建了哪些临时用户；
- 用完没有撤销 sudo 权限。

这个脚本把流程标准化：创建、输出邀请包、登记、查看、撤销、到期自动删除。

## 主要特性

- **每次随机生成 SSH 密钥对**。
- **默认用户名前缀 `xxvcc`**，生成如 `xxvcc-a1b2c3d4e5`。
- **可选 NOPASSWD sudo / wheel 权限**。
- **默认 24 小时有效期**。
- **默认尝试自动删除用户**：优先写入持久 systemd `.service/.timer`，失败时尽量使用 `at` 作为备用任务。
- **Key-only 登录**：账号密码默认锁定，不输出账号/Sudo 密码。
- **删除用户时删除家目录和 SSH key**。
- **防误删保护**：默认只允许删除脚本登记用户；删除未登记用户必须显式加 `--force`，非交互还必须加 `--confirm-force USER`。
- **创建失败自动回滚**：创建过程中出错时，会尽量删除已创建的临时用户。
- **本地登记临时用户**，删除时可编号选择。
- **依赖自动检测**，缺失时可交互安装；自动安装需要明确输入 `YES` 或传入 `--install-deps`。
- **非 TTY 私钥输出保护**：stdout 不是终端时默认拒绝输出私钥，需显式加 `--allow-non-tty-private-key-output`。
- **非交互 sudo 二次确认**：`--sudo --yes` 必须同时传入 `--confirm-sudo USER`。
- **独立中英文脚本**：`temp-admin.sh` 为中文默认脚本，`temp-admin-en.sh` 为英文脚本。
- **不修改 sshd_config，不改防火墙，不开放端口**。

## 工作方式

```text
运行脚本
  ↓
随机生成 SSH 私钥 + 公钥
  ↓
创建临时用户，例如 xxvcc-a1b2c3d4e5
  ↓
写入 /home/USER/.ssh/authorized_keys
  ↓
可选加入 sudo/wheel
  ↓
登记到 /var/lib/linux-temp-admin/users.tsv
  ↓
优先写入持久 systemd timer 安排到期自动 revoke；失败时尽量使用 at 备用任务
  ↓
输出一次性邀请包
```

脚本 **不会**：

- 保存私钥；
- 生成、输出、写入或记录账号/Sudo 密码；
- 修改 SSH 服务配置；
- 修改防火墙；
- 打开任何入站端口。

## 支持系统

### 主要支持

- Debian / Ubuntu
- 宝塔常见 Linux 环境
- RHEL / Rocky / AlmaLinux / Fedora

### 尽力支持

- Alpine
- Arch Linux

### 需要的工具

脚本会检测：

- `bash`
- `ssh-keygen`
- `useradd` 或 `adduser`
- `usermod`
- `chage`
- `flock`
- `at` / `atq` / `atrm`（仅在 systemd 自动撤销不可用时用于备用自动删除）
- `sudo`（仅在选择授予 sudo 权限时需要）

支持使用以下包管理器自动安装缺失依赖：

- `apt-get`
- `dnf`
- `yum`
- `apk`
- `pacman`

## 快速开始

### 1. 下载

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
```

### 2. 创建邀请

```bash
sudo bash temp-admin.sh invite --sudo
```

也可以指定有效期：

```bash
sudo bash temp-admin.sh invite --sudo --hours 12
```

指定用户名前缀（仅允许小写字母、数字、下划线和连字符，最长 20 字符）：

```bash
sudo bash temp-admin.sh invite --prefix ops --sudo
```

指定输出里的 Host 和端口：

```bash
sudo bash temp-admin.sh invite --host 203.0.113.10 --port 22 --sudo
```

### 3. 把邀请包私聊发给协作者

脚本会输出 SSH 登录命令、一次性私钥和撤销命令。账号密码默认锁定，不会输出账号/Sudo 密码。只通过可信私聊发送，不要发到群里或公开页面。

英文版使用：

```bash
sudo bash temp-admin-en.sh invite --sudo
```

## 非交互式示例

自动安装依赖并创建 sudo 邀请。非交互模式必须指定 `--host`，`--sudo --yes` 必须重复确认用户名，stdout 非 TTY 时还必须显式允许输出私钥：

```bash
sudo bash temp-admin.sh invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 \
  --port 22 \
  --hours 24 \
  --sudo \
  --install-deps \
  --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

关闭自动删除，仅设置账号过期：

```bash
sudo bash temp-admin.sh invite --sudo --no-auto-revoke
```

不授予 sudo：

```bash
sudo bash temp-admin.sh invite --no-sudo
```

## 输出邀请包示例（已脱敏）

下面只是格式示例，**不可用于登录**。真实私钥只会在脚本运行时随机生成，并在终端里显示一次。账号密码默认锁定，不会输出账号/Sudo 密码。

```text
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3d4e5
Expires: 2026-05-17 01:00:00 CST
Sudo: yes
Login: SSH key only
Password login: locked
Auto revoke: yes
Auto revoke unit: linux-temp-admin-revoke-xxvcc-a1b2c3d4e5

SSH 登录命令:
ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10

保存私钥命令:
cat > './xxvcc-a1b2c3d4e5.key' <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: 运行时生成的一次性私钥]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 './xxvcc-a1b2c3d4e5.key'

Sudo 提示:
已启用 NOPASSWD sudo。此账号只能通过 SSH key 登录；账号密码已锁定。

撤销命令:
sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5

安全提醒:
- 私钥只显示这一次，服务器不保存私钥。
- 账号密码已锁定，不会输出账号/Sudo 密码。
- 只通过可信私聊发送，不要发群里或公开页面。
- 用完请立即执行撤销命令。
- 服务器上只保存公钥，删除用户后这把私钥立即失效。

----- END LINUX TEMP ADMIN INVITE -----
```

## 日常操作

查看状态：

```bash
sudo bash temp-admin.sh status
```

从列表选择并删除用户：

```bash
sudo bash temp-admin.sh revoke
```

直接删除指定用户：

```bash
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3d4e5
```

默认情况下，`revoke` 只允许删除脚本登记过的用户。若确实要删除未登记用户，需要显式加 `--force`；如果还要配合 `--yes` 非交互执行，则必须重复完整用户名：

```bash
sudo bash temp-admin.sh revoke --user USER --force
sudo bash temp-admin.sh revoke --user USER --force --yes --confirm-force USER
```

查看账号过期和自动删除 timer：

```bash
sudo bash temp-admin.sh expiry-status
# 兼容旧命令：sudo bash temp-admin.sh cleanup-expired
```

## 关于“过期”和“自动删除”

默认有效期是 24 小时。脚本会尽量同时做两件事：

1. 通过 `chage -E` 设置 Linux 账号过期日期；
2. 优先写入 `/etc/systemd/system/linux-temp-admin-revoke-USER.service` 和 `.timer`，使用 `OnCalendar` + `Persistent=true` 创建持久自动删除任务；如果 systemd 不可用或创建失败，则尽量使用 `at` 创建备用自动删除任务。

需要注意：

- `chage -E` 通常按日期过期，不是精确到分钟/小时的定时删除；`--hours` 的精确自动撤销依赖 systemd timer。
- 过期通常会阻止后续登录，但不会删除用户和家目录。
- 自动删除任务会调用 `revoke`，删除用户、家目录、SSH key、sudoers 文件和登记记录。
- 如果系统没有 `systemctl` 或 systemd timer 创建失败，脚本会尝试使用 `at` 创建备用自动删除任务；如果 `at` 也不可用，才会降级为只设置账号过期，并提示手动删除。
- 如果无法设置账号过期日期（缺少 `chage` 或 `chage` 执行失败），脚本会停止创建并回滚刚创建的用户。
- 交互模式不传 `--host` 时，脚本会先询问是否自动探测；探测会优先尝试本地公网网卡地址和常见云厂商 metadata，失败后才依次访问 `https://api.ipify.org`、`https://ifconfig.me/ip`、`https://icanhazip.com`，成功或失败都会给出明确提示；`--yes` 非交互模式不会静默外联，必须显式传入 `--host`。
- `--host` 只接受普通域名、IPv4 或 IPv6 地址；不要带端口，端口请用 `--port` 单独指定。

## 安装后写入的内容

可能写入：

```text
/usr/local/sbin/linux-temp-admin
/var/lib/linux-temp-admin/users.tsv
/etc/systemd/system/linux-temp-admin-revoke-USER.service  # 包含 NoNewPrivileges/PrivateTmp 轻量限制
/etc/systemd/system/linux-temp-admin-revoke-USER.timer
at 任务队列中的备用自动删除任务              # 仅当 systemd timer 不可用且 at 可用时
/etc/sudoers.d/linux-temp-admin-USER       # 仅在启用免密 sudo 时
/home/USER/.ssh/authorized_keys
```

自动删除任务优先由持久 systemd timer 管理，可查看：

```bash
systemctl list-timers --all | grep linux-temp-admin
atq
```

## 安全说明

- 私钥只在创建时显示一次，服务器不保存私钥。
- 账号密码默认锁定，不输出账号/Sudo 密码。
- README 示例均为脱敏内容，不能登录任何服务器。
- 删除用户时会删除家目录和 SSH key。
- 默认防误删：`revoke` 只删除登记用户；未登记用户需要 `--force`，非交互删除还需要 `--confirm-force USER`。
- 如果本地登记文件丢失/损坏，撤销时也需要显式加 `--force`；非交互场景同时需要 `--confirm-force USER`。
- 创建过程中如果出错，脚本会尽量回滚并删除刚创建的临时用户。
- sudo 权限基本等同 root，请只给可信对象。
- 不要把真实邀请包提交到 GitHub、Notion、工单或群聊。
- 用完请立即执行 `revoke`，不要只依赖过期兜底。
- 交互模式不传 `--host` 会询问是否自动探测公网 IP；脚本会先尝试本地/云元数据，再按需查询外部公网 IP 服务，并明确提示成功或失败；`--yes` 模式必须手动指定 `--host`。
- stdout 不是 TTY 时默认拒绝输出一次性私钥；只有确认输出通道安全时才使用 `--allow-non-tty-private-key-output`。
- `--sudo --yes` 必须同时传入 `--confirm-sudo USER`，避免非交互误授予 sudo。

## 构建 / 校验

```bash
bash -n temp-admin.sh temp-admin-en.sh
```

如安装了 ShellCheck：

```bash
shellcheck temp-admin.sh
```

## 许可证

MIT。详见 [LICENSE](LICENSE)。
