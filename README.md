# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 一条命令,给协作者开一个**有时限、用完自动删**的临时 SSH 管理员账号。脚本输出一份可私聊转发的邀请包;服务器只保存公钥,不保存私钥。

**linux-temp-admin** 适合临时给可信的协作者、运维或自动化助手开一个 SSH 管理入口——不发 root 密码、不留长期账号、到期自动回收。

中文 | [English](README.en.md)

## 目录

- [30 秒上手](#30-秒上手)
- [语言](#语言)
- [它解决什么问题](#它解决什么问题)
- [完整流程](#完整流程)
- [常用操作](#常用操作)
- [常见用法](#常见用法)
- [参考](#参考)
- [安全说明](#安全说明)
- [开发与许可证](#开发与许可证)

## 30 秒上手

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
sudo bash temp-admin.sh invite --sudo
```

就这样。脚本会:

1. 随机生成一对 SSH 密钥,创建一个临时用户(如 `xxvcc-a1b2c3d4e5`);
2. 在终端输出**一份邀请包**——私聊发给对方即可,对方照着里面两条命令就能登录,**不需要懂任何细节**;
3. 默认 **24 小时后自动删除**这个用户、家目录和密钥。

> 不带子命令直接 `sudo bash temp-admin.sh` 会进入交互菜单。脚本中英双语合一,见下方[语言](#语言)。

## 语言

脚本把中文和英文合在**一个文件**里。界面语言按以下顺序确定:`--lang zh|en` > 环境变量 `LINUX_TEMP_ADMIN_LANG` > 交互式语言选择(进入菜单**或运行任意操作类子命令**时,只要在终端里且没用上面两种方式锁定语言,都会先问一次) > 系统 locale 自动判断 > **默认英文**。

> 用管道跑(`curl ... | sudo bash`)、在 CI 等非终端环境里、或带了 `--yes`/`-y` 非交互运行时,都不会弹出语言提示,直接按 locale/默认走;此时想用中文请加 `--lang zh` 或设环境变量。`help`/`version` 也不会问。

中文环境(`zh_*` locale)会自动用中文;否则用 `--lang zh` 或设环境变量:

```bash
sudo bash temp-admin.sh --lang zh invite --sudo
# 或在当前 shell 里设一次:
export LINUX_TEMP_ADMIN_LANG=zh
```

## 它解决什么问题

临时给别人开 SSH 权限,最容易翻车的是:

- 直接把 root 密码给出去;
- 临时账号开完忘了删,长期留着;
- 公钥留在 `authorized_keys` 里没人清;
- 不记得自己之前开过哪些临时号;
- 用完没收回 sudo。

这个脚本把整套流程标准化:**创建 → 输出邀请包 → 登记 → 查看 → 撤销 → 到期自动删**。

它**不会**:保存私钥;生成或输出任何账号/Sudo 密码;修改 SSH 服务配置;改防火墙;开放任何入站端口。

## 完整流程

### 1. 下载

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
```

### 2. 创建邀请

```bash
sudo bash temp-admin.sh invite --sudo
```

交互模式会先让你确认信息(用户名、Host、有效期、是否 sudo、是否到期自动删),确认后输出邀请包。

### 3. 你会拿到这样一份邀请包（已脱敏）

下面只是格式示例,**不能用于登录**。真实私钥只在脚本运行时随机生成、并在终端显示一次。

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
注意：NOPASSWD sudo 等于完整 root 权限——该账号可提权为 root，并可能留下 root 拥有的进程、cron、systemd 单元或 SUID 文件等持久化。撤销只删除此账号本身，不会自动清理它以 root 身份创建的东西。

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

### 4. 把这份邀请包私聊发给协作者

对方拿到后只需两步,**无需安装任何东西、也不用懂这个工具**:

- 复制「保存私钥命令」那一段,在自己电脑上粘贴运行 → 得到私钥文件;
- 复制「SSH 登录命令」运行 → 登录成功。

> ⚠️ 邀请包含一次性私钥,**只通过可信私聊发送**,不要发群里、工单或公开页面。

### 5. 用完撤销（或等它到期自动删）

```bash
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3d4e5
```

默认 24 小时后会自动删除用户、家目录和密钥;但**用完立即手动撤销最稳妥**,别只依赖到期兜底。

## 常用操作

查看状态(登记的临时用户、过期时间、自动删除 timer):

```bash
sudo bash temp-admin.sh status
sudo bash temp-admin.sh status --user xxvcc-a1b2c3d4e5
```

撤销/删除(从列表选编号,或直接指定用户名):

```bash
sudo bash temp-admin.sh revoke
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3d4e5
```

查看账号过期与自动删除任务:

```bash
sudo bash temp-admin.sh expiry-status
# 加 --compact 顺带清理登记表里指向已不存在用户的失效条目（只改登记表，不动任何账号）
sudo bash temp-admin.sh expiry-status --compact
```

> 撤销未登记/陌生账号有额外限制(防误删),见[安全说明](#安全说明)。

## 常见用法

指定有效期(小时):

```bash
sudo bash temp-admin.sh invite --sudo --hours 12
```

不授予 sudo(创建为普通账号):

```bash
sudo bash temp-admin.sh invite --no-sudo
```

指定用户名前缀 / Host / 端口(前缀仅允许小写字母、数字、下划线、连字符,最长 20 字符):

```bash
sudo bash temp-admin.sh invite --prefix ops --sudo
sudo bash temp-admin.sh invite --host 203.0.113.10 --port 22 --sudo
```

只设账号过期、不创建自动删除任务:

```bash
sudo bash temp-admin.sh invite --sudo --no-auto-revoke
```

**自动化 / 非交互**(在 CI 或脚本里用)。非交互必须指定 `--host`;`--sudo --yes` 必须重复确认用户名;stdout 不是终端时还要显式允许输出私钥:

```bash
sudo bash temp-admin.sh invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 --port 22 --hours 24 \
  --sudo --install-deps --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

## 参考

### 支持的系统

- **主要支持**:Debian / Ubuntu、宝塔常见 Linux 环境、RHEL / Rocky / AlmaLinux / Fedora
- **尽力支持**:Alpine、Arch Linux

### 依赖

脚本会自动检测;缺失时可交互安装(需输入 `YES` 或传 `--install-deps`),支持 `apt-get` / `dnf` / `yum` / `apk` / `pacman`。需要的工具:

- `bash`、`ssh-keygen`、`useradd` 或 `adduser`、`userdel` 或 `deluser`、`usermod`、`chage`、`flock`
- 能计算未来日期的 `date`(GNU coreutils)或 `python3`
- `at` / `atq` / `atrm`:仅在 systemd 自动撤销不可用时,作备用自动删除
- `sudo`:仅在选择授予 sudo 时需要

### 关于“过期”和“自动删除”

默认有效期 24 小时。脚本会同时做两件事:

1. 用 `chage -E` 设置账号过期日期(按天,主要用于阻止后续登录,**不会删用户**);
2. 优先写持久 systemd `.service` + `.timer`(`OnCalendar` 绝对 UTC 时间 + `Persistent=true`),到点调用 `revoke` 删除用户、家目录、SSH key、sudoers 和登记记录;systemd 不可用或失败时尽量用 `at`(并尝试启用 `atd`);两者都不行才降级为只设账号过期,并在邀请包里提示需要手动撤销。

- 精确到小时的自动删除依赖 systemd timer 或备用 `at` 任务;`chage` 只是按天兜底。
- 交互模式不传 `--host` 时,会先问是否自动探测公网 IP——先尝试本地网卡/云厂商 metadata,失败才依次访问 `https://api.ipify.org`、`https://ifconfig.me/ip`、`https://icanhazip.com`,成败都有明确提示;`--yes` 模式不会静默外联,必须显式传 `--host`。排查可临时设 `LINUX_TEMP_ADMIN_DEBUG_IP=1`(诊断日志不会输出私钥)。
- `--host` 只接受普通域名、IPv4 或 IPv6;不要带端口(用 `--port` 单独指定),邀请包中的 SSH 命令会自动为 IPv6 加方括号。

### 写入的文件

```text
/usr/local/sbin/linux-temp-admin                              # 稳定撤销命令
/var/lib/linux-temp-admin/users.tsv                           # 本地登记表
/etc/systemd/system/linux-temp-admin-revoke-USER.service      # 含 NoNewPrivileges/PrivateTmp 轻量限制
/etc/systemd/system/linux-temp-admin-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER                          # 仅在启用免密 sudo 时
/home/USER/.ssh/authorized_keys
# 以及在 systemd 不可用时,at 队列中的备用自动删除任务
```

为防止一个被改过或降级的副本静默覆盖共享的 `/usr/local/sbin/linux-temp-admin`(会影响其他在册用户的撤销任务),当已安装版本与当前脚本不同时,脚本会**复用现有命令而不覆盖**并打印提示;确需替换时,运行前设置 `LINUX_TEMP_ADMIN_REINSTALL=1`。

## 安全说明

- 私钥只在创建时显示一次,服务器不保存;账号密码默认锁定,不输出任何账号/Sudo 密码。
- **NOPASSWD sudo 基本等同 root**,只给可信对象;撤销只删除该账号本身,不会清理它以 root 身份留下的进程、cron、systemd 单元或 SUID 文件。
- 删除用户会一并删除家目录和 SSH key;如果系统删除命令失败,脚本会停下并提示手动检查,不会假装撤销成功。
- **防误删**:`revoke` 默认只删除脚本登记过的用户;删除未登记但**本工具创建**(家目录 GECOS 带 `linux-temp-admin` 标记)的账号需显式 `--force`,非交互还需 `--confirm-force USER`。
- 即使使用 `--force`,也会拒绝删除 root、常见系统账号、UID 0、低 UID 系统账号,以及**任何非本工具创建(无标记)且未登记**的真实账号——这类账号请改用系统的 `userdel`。
- 创建过程中出错会尽量回滚(取消自动撤销、删 sudoers/登记记录、删除刚创建的用户);中途 Ctrl-C 也会触发回滚。
- 登记表、sudoers、systemd unit、撤销命令和用户 SSH key 文件会做符号链接/普通文件安全检查,拒绝覆盖不安全的目标。
- 不要把真实邀请包提交到 GitHub、Notion、工单或群聊;用完请立即 `revoke`,不要只依赖到期兜底。
- stdout 不是 TTY 时默认拒绝输出私钥,只有确认输出通道安全时才用 `--allow-non-tty-private-key-output`。

## 开发与许可证

本地校验:

```bash
bash -n temp-admin.sh
shellcheck -S warning temp-admin.sh
```

仓库已包含 GitHub Actions 工作流,会在 push 和 pull request 时自动运行 Bash 语法检查与 ShellCheck。

许可证:MIT,详见 [LICENSE](LICENSE)。
