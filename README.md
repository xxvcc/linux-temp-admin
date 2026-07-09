# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 一条命令，给协作者开一个**有时限、用完自动删**的临时 SSH 管理员账号。工具输出一份可私聊转发的邀请包；服务器只保存公钥，不保存私钥。

**linux-temp-admin** 适合临时给可信的协作者、运维或自动化助手开一个 SSH 管理入口——不发 root 密码、不留长期账号、到期自动回收。

它是一个**单静态二进制**：零运行时依赖，glibc/musl 通吃（含 Alpine/BusyBox），密钥生成、下载、日期计算、文件锁、进程清理全部原生实现，并支持 **ed25519 签名校验的自升级**。

中文 | [English](README.en.md)

---

## 目录

- [30 秒上手](#30-秒上手)
- [语言](#语言)
- [安装、升级与诊断](#安装升级与诊断)
- [它解决什么问题](#它解决什么问题)
- [完整流程](#完整流程)
- [常用操作](#常用操作)
- [常见用法](#常见用法)
- [参考](#参考)
- [安全说明](#安全说明)
- [开发与许可证](#开发与许可证)

## 30 秒上手

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
sudo linux-temp-admin invite --sudo
```

就这样。工具会：

1. 随机生成一对 SSH 密钥，创建一个临时用户（如 `xxvcc-a1b2c3d4e5`）；
2. 在终端输出**一份邀请包**——私聊发给对方即可，对方照着里面两条命令就能登录，**不需要懂任何细节**；
3. 默认 **24 小时后自动删除**这个用户、家目录和密钥。

> 不带子命令直接 `sudo linux-temp-admin` 会进入交互菜单。界面中英双语，见下方[语言](#语言)。

## 语言

界面语言按以下顺序确定：`--lang zh|en` > 环境变量 `LINUX_TEMP_ADMIN_LANG` > 系统 locale（`LC_ALL`，其次 `LANG`）> **默认中文**。

英文环境（`en_*` locale）会自动用英文；否则用 `--lang en` 或设环境变量：

```bash
sudo linux-temp-admin --lang en invite --sudo
# 或在当前 shell 里设一次：
export LINUX_TEMP_ADMIN_LANG=en
```

## 安装、升级与诊断

推荐用安装脚本：它按架构（amd64 / arm64）下载最新发布的二进制，**校验 SHA-256** 后再装到 `/usr/local/sbin/linux-temp-admin`。

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
linux-temp-admin doctor
```

如果你手上已经有二进制，也可以让它把自己安装成稳定命令：`sudo ./linux-temp-admin install`。

常用维护命令：

```bash
sudo linux-temp-admin doctor            # 检查依赖、sudoers.d、包管理器、init 系统、SSH 端口
sudo linux-temp-admin upgrade           # 从 GitHub 下载并验签后升级稳定命令
sudo linux-temp-admin upgrade --yes     # 非交互确认
sudo linux-temp-admin uninstall         # 卸载稳定命令

sudo ./linux-temp-admin install --force # 用手头这个二进制强制覆盖已装的稳定命令
```

`upgrade` 会下载二进制和分离签名，用**内嵌的 ed25519 公钥验签通过后**才安装（fail-closed，验签不过就中止）；只接受 HTTPS 地址（重定向也必须是 HTTPS），下载上限 64 MiB，且只有版本更新时才覆盖。需要修复或回退到自定义地址时用 `--force --url URL`。发布与签名流程见 [docs/releasing.md](docs/releasing.md)。

`install` 和 `upgrade` 是两件不同的事。`install` 是**放置**：把你手上已有的二进制放到位。`upgrade` 是**更新**：从 GitHub 取回新的二进制，验签后替换。

`install` 复制的是**当前正在运行的那个二进制**，所以只在你运行的是别处的副本时才有意义，比如 `sudo ./linux-temp-admin install`——前面的 `./` 是关键。它不联网、不验签，因为没有引入任何新信任：那些字节你此刻已经在以 root 执行了。这也使它成为离线机器和自建二进制唯一的安装途径（`upgrade` 只接受 HTTPS 且必须带发布签名，自己编译的二进制签不出来）。

如果你运行的就是已安装的 `/usr/local/sbin/linux-temp-admin`，它会发现字节完全相同、什么都不做，并明确告诉你「已是稳定命令，无需安装」（加不加 `--force` 都一样）。正因如此，交互菜单里**没有** `install` 项——能看到菜单就说明已经有二进制在以 root 运行。菜单里的更新入口只有一个：验签升级。

当目标路径上已有一个**内容不同**的二进制时，`install` 会拒绝覆盖，必须显式 `--force`——避免一个被改过或降级的副本静默替换掉共享的 `/usr/local/sbin/linux-temp-admin`，影响其他在册用户的自动撤销任务。`uninstall` 同理，在仍有登记用户时默认拒绝卸载。

日常更新请用 `upgrade`（会验签），而不是 `install --force`。

**操作审计日志**：每次特权操作（创建/删除账号、install/upgrade/uninstall）以 JSON 行追加写入 root 属主的 `/var/log/linux-temp-admin/audit.log`，记录时间、操作者（`SUDO_USER`）、动作、目标与结果。

## 它解决什么问题

临时给别人开 SSH 权限，最容易翻车的是：

- 直接把 root 密码给出去；
- 临时账号开完忘了删，长期留着；
- 公钥留在 `authorized_keys` 里没人清；
- 不记得自己之前开过哪些临时号；
- 用完没收回 sudo。

这个工具把整套流程标准化：**创建 → 输出邀请包 → 登记 → 查看 → 撤销 → 到期自动删**。

它**不会**：保存私钥；生成或输出任何账号/Sudo 密码；修改 SSH 服务配置；改防火墙；开放任何入站端口。

## 完整流程

### 1. 安装

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
```

### 2. 创建邀请

```bash
sudo linux-temp-admin invite --sudo
```

交互模式会先让你确认信息（用户名、Host、有效期、是否 sudo、是否到期自动删），确认后输出邀请包。

### 3. 你会拿到这样一份邀请包（已脱敏）

下面只是格式示例，**不能用于登录**。真实私钥只在运行时随机生成、并在终端显示一次。

```text
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3d4e5
Expires: 2026-07-09 01:00:00 CST
Sudo: yes
Login: SSH key only
Password login: locked
Auto revoke: yes
Auto revoke unit: linux-temp-admin-v2-revoke-xxvcc-a1b2c3d4e5

SSH 登录命令:
ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10

保存私钥命令:
cat > './xxvcc-a1b2c3d4e5.key' <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: 运行时生成的一次性私钥]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 './xxvcc-a1b2c3d4e5.key'

撤销命令:
sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5

Sudo 提示: 已启用 NOPASSWD sudo，等同完整 root，可能留下 root 拥有的持久化；撤销只删除此账号本身。

安全提醒: 私钥只显示这一次、服务器不保存；仅通过可信私聊发送；用完立即撤销。

----- END LINUX TEMP ADMIN INVITE -----
```

> 邀请包里的字段名和命令块保持英文/固定格式，方便原样复制转发；中文只出现在说明行上。

### 4. 把这份邀请包私聊发给协作者

对方拿到后只需两步，**无需安装任何东西、也不用懂这个工具**：

- 复制「保存私钥命令」那一段，在自己电脑上粘贴运行 → 得到私钥文件；
- 复制「SSH 登录命令」运行 → 登录成功。

> ⚠️ 邀请包含一次性私钥，**只通过可信私聊发送**，不要发群里、工单或公开页面。

### 5. 用完撤销（或等它到期自动删）

```bash
sudo linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

默认 24 小时后会自动删除用户、家目录和密钥；但**用完立即手动撤销最稳妥**，别只依赖到期兜底。

## 常用操作

查看状态（登记的临时用户、过期时间、自动删除 timer）：

```bash
sudo linux-temp-admin status
sudo linux-temp-admin status --user xxvcc-a1b2c3d4e5
```

撤销/删除（从列表选编号，或直接指定用户名）：

```bash
sudo linux-temp-admin revoke
sudo linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

查看账号过期与自动删除任务：

```bash
sudo linux-temp-admin cleanup-expired
# 加 --compact 顺带清理登记表里指向已不存在用户的失效条目（只改登记表，不动任何账号）
sudo linux-temp-admin cleanup-expired --compact
```

> `cleanup-expired` **只查看**到期/自动删除状态，不会主动删除任何用户；删除请用 `revoke`。撤销未登记/陌生账号有额外限制（防误删），见[安全说明](#安全说明)。

## 常见用法

指定有效期（小时，1 到 8760）：

```bash
sudo linux-temp-admin invite --sudo --hours 12
```

不授予 sudo（创建为普通账号）：

```bash
sudo linux-temp-admin invite --no-sudo
```

指定用户名前缀 / Host / 端口（前缀仅允许小写字母、数字、下划线、连字符，最长 20 字符）：

```bash
sudo linux-temp-admin invite --prefix ops --sudo
sudo linux-temp-admin invite --host 203.0.113.10 --port 22 --sudo
```

只设账号过期、不创建自动删除任务：

```bash
sudo linux-temp-admin invite --sudo --no-auto-revoke
```

**自动化 / 非交互**（在 CI 或脚本里用）。非交互必须指定 `--host`；`--sudo --yes` 必须重复确认用户名；stdout 不是终端时还要显式允许输出私钥：

```bash
sudo linux-temp-admin invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 --port 22 --hours 24 \
  --sudo --install-deps --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

## 参考

### 支持的系统

- **主要支持**：Debian / Ubuntu、宝塔常见 Linux 环境、RHEL / Rocky / AlmaLinux / Fedora
- **尽力支持**：Alpine、Arch Linux

### 依赖

二进制本身零运行时依赖。它只调用系统自带的**账号管理工具**；这些工具缺失时可交互安装（需确认或传 `--install-deps`），支持 `apt-get` / `dnf` / `yum` / `apk` / `pacman`：

- `useradd` 或 `adduser`、`userdel` 或 `deluser`、`usermod`、`chage`
- `sudo`：仅在选择授予 sudo 时需要

`doctor` 会逐项检查上面这些工具，外加包管理器、init 系统、`/etc/sudoers.d` 的安全性和探测到的 SSH 端口。

`at` / `atd` 是 systemd 不可用时自动删除的备用后端。它**不在依赖检查里，也不会被自动安装**：两者都不可用时，自动删除会降级为只设账号过期，并在邀请包里提示需要手动撤销。

### 关于"过期"和"自动删除"

默认有效期 24 小时。工具会同时做两件事：

1. 用 `chage -E` 设置账号过期日期（按天，主要用于阻止后续登录，**不会删用户**）；
2. 优先写持久 systemd `.service` + `.timer`（`OnCalendar` 绝对 UTC 时间 + `Persistent=true`，服务单元带 `NoNewPrivileges` 等轻量限制），到点调用 `revoke` 删除用户、家目录、SSH key、sudoers 和登记记录；systemd 不可用或失败时尽量用 `at`（并尝试启用 `atd`）；两者都不行才降级为只设账号过期，并在邀请包里提示需要手动撤销。

- 精确到小时的自动删除依赖 systemd timer 或备用 `at` 任务；`chage` 只是按天兜底。
- 自动删除任务的 `ExecStart` 调用的是**已安装的稳定命令**，所以选择自动删除时，工具会先确保 `/usr/local/sbin/linux-temp-admin` 存在。
- 交互模式不传 `--host` 时，会**静默**探测云厂商 metadata 和本地网卡（这两者都不出本机/本链路），探到的地址作为默认值填进提示符，回车即接受、也可直接改写。只有在本机探不到公网 IP 时，才会**询问**是否访问 `https://api.ipify.org`、`https://ifconfig.me/ip`、`https://icanhazip.com`——这一步会把你的服务器地址暴露给第三方，所以必须显式同意。`--yes` 模式永远不会外联，必须显式传 `--host`。
- `--host` 只接受普通域名、IPv4 或 IPv6；不要带端口（用 `--port` 单独指定），邀请包中的 SSH 命令会自动为 IPv6 加方括号。

### 写入的文件

```text
/usr/local/sbin/linux-temp-admin                             # 稳定撤销命令
/var/lib/linux-temp-admin/v2/registry.tsv                    # 本地登记表（root:root 0600，目录 0700）
/var/log/linux-temp-admin/audit.log                          # 操作审计日志（root:root 0600，目录 0700）
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.service  # 含 NoNewPrivileges 等轻量限制
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER                         # 仅在启用免密 sudo 时
/home/USER/.ssh/authorized_keys
# 以及在 systemd 不可用时，at 队列中的备用自动删除任务
```

## 安全说明

- 私钥只在创建时显示一次，服务器不保存；账号密码默认锁定，不输出任何账号/Sudo 密码。
- **NOPASSWD sudo 基本等同 root**，只给可信对象；撤销只删除该账号本身，不会清理它以 root 身份留下的进程、cron、systemd 单元或 SUID 文件。
- 删除用户会一并删除家目录和 SSH key；如果系统删除命令失败，工具会停下并提示手动检查，不会假装撤销成功。
- **防误删**：`revoke` 默认只删除本工具登记过的用户；删除未登记但**本工具创建**（GECOS 带 `linux-temp-admin` 标记）的账号需显式 `--force`，非交互还需 `--confirm-force USER`。
- 即使使用 `--force`，也会拒绝删除 root、常见系统账号、UID 0、低 UID 系统账号，以及**任何非本工具创建（无标记）且未登记**的真实账号——这类账号请改用系统的 `userdel`。
- 创建过程中出错会尽量回滚（取消自动撤销、删 sudoers/登记记录、删除刚创建的用户）。
- 登记表、sudoers、systemd unit、撤销命令和用户 SSH key 文件会做符号链接/普通文件安全检查，拒绝覆盖不安全的目标。
- 升级只接受 HTTPS 并强制 ed25519 验签，验签失败即中止，不会安装未签名或签名不符的二进制。
- 不要把真实邀请包提交到 GitHub、Notion、工单或群聊；用完请立即 `revoke`，不要只依赖到期兜底。
- stdout 不是 TTY 时默认拒绝输出私钥，只有确认输出通道安全时才用 `--allow-non-tty-private-key-output`。

## 开发与许可证

贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)；安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。版本变化见 [CHANGELOG.md](CHANGELOG.md)。

本地校验（需要 Go 1.25+）：

```bash
go build ./...
go vet -printf.funcs=printf,errorf,warnf ./...
test -z "$(gofmt -l .)"
go test -race ./...
```

仓库已包含 GitHub Actions 工作流，会在 push 和 pull request 时自动运行构建、vet、gofmt、测试，以及对 `scripts/` 的 ShellCheck。

许可证：MIT，详见 [LICENSE](LICENSE)。
