# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 一次性 Linux 临时管理员邀请脚本：随机生成 SSH 密钥、创建临时用户、可选授予 sudo，并默认安排到期自动删除。

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
- **默认用户名前缀 `xxvcc`**，生成如 `xxvcc-a1b2c3`。
- **可选 sudo / wheel 权限**。
- **默认 24 小时有效期**。
- **默认尝试自动删除用户**：使用 `systemd-run` 创建一次性定时任务。
- **删除用户时删除家目录和 SSH key**。
- **本地登记临时用户**，删除时可编号选择。
- **依赖自动检测**，缺失时可交互安装。
- **独立中英文脚本**：`temp-admin.sh` 为中文默认脚本，`temp-admin-en.sh` 为英文脚本。
- **不修改 sshd_config，不改防火墙，不开放端口**。

## 工作方式

```text
运行脚本
  ↓
随机生成 SSH 私钥 + 公钥
  ↓
创建临时用户，例如 xxvcc-a1b2c3
  ↓
写入 /home/USER/.ssh/authorized_keys
  ↓
可选加入 sudo/wheel
  ↓
登记到 /var/lib/linux-temp-admin/users.tsv
  ↓
默认用 systemd-run 安排到期自动 revoke
  ↓
输出一次性邀请包
```

脚本 **不会**：

- 保存私钥；
- 把账号/Sudo 密码写入日志；
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
- `chpasswd`
- `usermod`
- `chage`
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

指定输出里的 Host 和端口：

```bash
sudo bash temp-admin.sh invite --host 203.0.113.10 --port 22 --sudo
```

### 3. 把邀请包私聊发给协作者

脚本会输出 SSH 登录命令、一次性私钥、账号/Sudo 密码和撤销命令。只通过可信私聊发送，不要发到群里或公开页面。

注意：默认非免密 sudo 模式下，这个密码是 Linux 账号密码，同时也用于 sudo。如果服务器开启了 SSH 密码登录，它理论上也可用于 SSH 密码登录。生产服务器建议禁用 SSH 密码登录，或只把邀请包发给完全可信对象。

英文版使用：

```bash
sudo bash temp-admin-en.sh invite --sudo
```

## 非交互式示例

自动安装依赖并创建 sudo 邀请：

```bash
sudo bash temp-admin.sh invite \
  --host 203.0.113.10 \
  --port 22 \
  --hours 24 \
  --sudo \
  --install-deps \
  --yes
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

下面只是格式示例，**不可用于登录**。真实私钥和账号/Sudo 密码只会在脚本运行时随机生成，并在终端里显示一次。

```text
====== One-time Temporary Admin Invite / 一次性临时管理员连接信息 ======

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3
Expires: 2026-05-17 01:00:00 CST
Sudo: yes
Passwordless sudo: no
Auto revoke: yes
Auto revoke unit: linux-temp-admin-revoke-xxvcc-a1b2c3

SSH login command / SSH 登录命令：
ssh -i ./xxvcc-a1b2c3.key -p 22 xxvcc-a1b2c3@203.0.113.10

Save private key command / 保存私钥命令：
cat > xxvcc-a1b2c3.key <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: one-time private key generated at runtime]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 xxvcc-a1b2c3.key

账号/Sudo 密码：
[REDACTED: one-time sudo password generated at runtime]

Revoke command / 撤销命令：
sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3
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
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3
```

查看账号过期和自动删除 timer：

```bash
sudo bash temp-admin.sh cleanup-expired
```

## 关于“过期”和“自动删除”

默认有效期是 24 小时。脚本会尽量同时做两件事：

1. 通过 `chage -E` 设置 Linux 账号过期日期；
2. 通过 `systemd-run --on-active=<hours>h` 创建一次性自动删除任务。

需要注意：

- `chage -E` 通常按日期过期，不是精确到分钟的定时删除。
- 过期通常会阻止后续登录，但不会删除用户和家目录。
- 自动删除任务会调用 `revoke`，删除用户、家目录、SSH key、sudoers 文件和登记记录。
- 如果系统没有 `systemd-run`，脚本会降级为只设置账号过期，并提示手动删除。

## 安装后写入的内容

可能写入：

```text
/usr/local/sbin/linux-temp-admin
/var/lib/linux-temp-admin/users.tsv
/etc/sudoers.d/linux-temp-admin-USER       # 仅在启用免密 sudo 时
/home/USER/.ssh/authorized_keys
```

自动删除任务由 systemd transient unit 管理，可查看：

```bash
systemctl list-timers --all | grep linux-temp-admin
```

## 安全说明

- 私钥只在创建时显示一次，服务器不保存私钥。
- 默认非免密 sudo 模式下，邀请包里的账号/Sudo 密码也是 Linux 账号密码；如果 SSH 密码登录开启，它也可能用于 SSH 密码登录。
- README 示例均为脱敏内容，不能登录任何服务器。
- 删除用户时会删除家目录和 SSH key。
- sudo 权限基本等同 root，请只给可信对象。
- 不要把真实邀请包提交到 GitHub、Notion、工单或群聊。
- 用完请立即执行 `revoke`，不要只依赖过期兜底。

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
