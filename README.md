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
- [它解决什么问题](#它解决什么问题)
- [语言](#语言)
- [安装、升级与诊断](#安装升级与诊断)
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

> 不带子命令直接 `sudo linux-temp-admin` 会进入交互菜单。菜单只在进入时和你按回车时显示，所以每次操作的结果都留在提示符上方，不会被菜单顶走。界面中英双语，见下方[语言](#语言)。

## 它解决什么问题

临时给别人开 SSH 权限，最容易翻车的是：

- 直接把 root 密码给出去；
- 临时账号开完忘了删，长期留着；
- 公钥留在 `authorized_keys` 里没人清；
- 不记得自己之前开过哪些临时号；
- 用完没收回 sudo。

这个工具把整套流程标准化：**创建 → 输出邀请包 → 登记 → 查看 → 撤销 → 到期自动删**。

它**不会**：保存私钥；生成或输出任何账号/Sudo 密码；修改 SSH 服务配置；改防火墙；开放任何入站端口。

## 语言

**默认中文，与服务器的 locale 无关。** 第一次在终端里运行时，工具会先问一次语言，记住之后就不再问：

```text
Language / 语言:
  1) 中文 (默认)
  2) English
选择 / select [1-2]:
```

选择保存在 `/var/lib/linux-temp-admin/v2/prefs`。想改随时进交互菜单选「切换语言 / Switch language」（这一项的标签是双语的，选错语言也找得到）。

优先级：`--lang zh|en` > 环境变量 `LINUX_TEMP_ADMIN_LANG` > 记住的选择 > 首次交互时的提问 > **中文**。

**系统 locale（`LANG`/`LC_ALL`）不再参与判断**——服务器装的是什么语言，跟拿着邀请的人说什么语言没多大关系。所以一台 `LANG=en_US.UTF-8` 的机器也默认中文，除非你选了英文。

```bash
sudo linux-temp-admin --lang en invite --sudo     # 只影响这一次
sudo -E linux-temp-admin invite --sudo            # 配合 LINUX_TEMP_ADMIN_LANG=en；注意 -E，sudo 默认会清掉环境变量
```

非交互运行（脚本、CI、到期自动撤销的定时器）问不了，所以用记住的选择，没有就用中文；`--lang`/环境变量始终可覆盖。

## 安装、升级与诊断

推荐用安装脚本：它必须以 root 运行，按架构（amd64 / arm64）下载最新发布的二进制，**校验 SHA-256 并用脚本内嵌的发布公钥验证 ed25519 签名**后再装到 `/usr/local/sbin/linux-temp-admin`——验签失败即中止（openssl 不可用时默认拒装，除非设置 `LTA_ALLOW_UNVERIFIED=1`）。下载只允许 HTTPS（含重定向），单个响应上限 64 MiB；需使用 curl，或同时支持 `--https-only` 与 `--max-filesize` 的 wget。

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
linux-temp-admin doctor
```

常用维护命令：

```bash
sudo linux-temp-admin doctor            # 检查依赖、sudoers.d、包管理器、init 系统、SSH 端口
sudo linux-temp-admin upgrade           # 从 GitHub 验签升级已安装的命令
sudo linux-temp-admin upgrade --yes     # 非交互确认
sudo linux-temp-admin uninstall         # 卸载：账号、授权、自动删除任务、状态与命令
sudo ./linux-temp-admin install         # 把手头这个二进制装到位（注意前面的 ./）
```

- **升级 `upgrade`**：从 GitHub 取回新二进制，用内嵌 ed25519 公钥验签通过才安装（fail-closed，验签不过就中止）；只接受 HTTPS、下载上限 64 MiB、仅版本更新时才覆盖。重定向后的实际拨号地址不能是私网或保留地址（含文档、基准测试、NAT64、6to4 等范围）。需要修复或指定自定义来源时用 `--force --url URL`（其签名为 `URL.sig`）。**日常更新用它。**
- **安装 `install`**：把你**手头已有**的二进制放到位（不联网、不验签），用于离线机器或自建二进制。目标已存在且内容不同时需显式 `--force`。它通过 `/proc/self/exe` 复制当前正在执行的二进制 inode，启动路径随后被替换也不会改变 root 实际安装的内容；因此只在你运行别处副本时才有意义（如 `sudo ./linux-temp-admin install`，前面的 `./` 是关键）。自动删除任务执行安装路径，因此邀请前会拒绝不安全、不可读取版本的已安装命令；开发版会安装当前运行文件的精确字节。

## 完整流程

### 1. 安装

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
```

### 2. 创建邀请

```bash
sudo linux-temp-admin invite --sudo
```

交互模式很短：探测到公网 IP 就直接用（`--host` 可改域名/其他地址）、默认授予 sudo（这是个建管理员的工具，`--no-sudo` 可建普通账号）、问是否到期自动删除；**选了自动删除才问有效期**。最后列出摘要让你确认，再输出邀请包。

### 3. 你会拿到这样一份邀请包（已脱敏）

下面只是格式示例，**不能用于登录**。真实私钥只在运行时随机生成、并在终端显示一次。

```text
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3d4e5
Expires: 2030-01-02 12:00:00 CST
Sudo: yes
Login: SSH key only (verified against the effective sshd config)
Password login: locked
Auto revoke: yes
Auto revoke unit: linux-temp-admin-v2-revoke-xxvcc-a1b2c3d4e5
Sshd exception: none

保存私钥命令:
cat > './xxvcc-a1b2c3d4e5.key' <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: 运行时生成的一次性私钥]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 './xxvcc-a1b2c3d4e5.key'

安全提醒: 私钥只显示这一次、服务器不保存；仅通过可信私聊发送；用完立即撤销。

----- END LINUX TEMP ADMIN INVITE -----
```

> 邀请包里的字段名和命令块保持英文/固定格式，方便原样复制转发；中文只出现在说明行上。

`Login:` 那行是**检查结果，不是口号**：创建任何东西之前，工具会读一遍 `sshd -T -C user=<新账号>`（sshd 的有效配置，已展开 `Include`、`Match` 和发行版加密策略），确认这个账号真的能用公钥登录，才敢这么写。读不到就如实标 `UNVERIFIED`。

### 4. 把这份邀请包私聊发给协作者

对方拿到后只需两步，**无需安装任何东西、也不用懂这个工具**：

- 复制「保存私钥命令」那一段，在自己电脑上粘贴运行 → 得到私钥文件；
- 用头部的 Host / Port / User 拼出登录命令即可，例如：
  `ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10`。

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

清理失效登记与孤儿授权：

```bash
sudo linux-temp-admin cleanup-expired --compact
```

**卸载 `uninstall`**：移除本工具在这台机器上留下的一切——临时账号（连同家目录）、它们的 sudo 授权与 sshd 例外、自动删除任务、状态目录（含 v1 遗留），最后才是命令本身。

```bash
sudo linux-temp-admin uninstall                      # 交互：先列清单，再输 YES
sudo linux-temp-admin uninstall --yes --remove-users # 非交互：有账号时必须显式加 --remove-users
sudo linux-temp-admin uninstall --yes --purge-audit  # 连审计日志一起删
```

- **审计日志默认保留**在 `/var/log/linux-temp-admin/audit.log`。它记录的是谁开过、谁删过 root 级账号；卸载顺手抹掉这份记录，正是入侵者会做的事。要删得显式 `--purge-audit`。
- **只要有一个账号删不掉，命令和状态目录都不会被删**，卸载中止并点名那个账号。留着一个带 sudo 的账号、却删掉唯一能管理它的命令，比不卸载更糟：它的自动删除任务执行的就是这个命令。
- **不能只删命令、留下账号**。`--force` 不再绕过这一点（它现在只保留原意：目标不是安全的 root 属主普通文件时仍强删）。
- **从临时账号自己运行卸载会被拒绝**——它会在删到自己时把自己的会话一起收走，留下拆到一半的机器。请用 root 或别的管理员身份运行。

`--compact` 会清掉：登记表里指向已不存在账号的失效条目，以及那些账号遗留的 **sudo 授权、sshd 例外和自动删除任务**（孤儿授权最危险——用户名一旦被复用就会重新生效）。它按「是否本工具当前托管的活账号」判定孤儿，所以一个被真实账号复用了名字的残留授权也会被发现。`doctor` 发现孤儿时提示的就是这条命令。

> `cleanup-expired` **从不删除账号**：删账号用 `revoke`，看列表用 `status`。撤销未登记/陌生账号有额外限制（防误删），见[安全说明](#安全说明)。

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

不自动删除——创建**永久账号**（不设到期、不删除，需手动 `revoke`）：

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

### 服务器不接受公钥登录时

有些服务器把公钥登录关掉了（`PubkeyAuthentication no`），或者把 `authorized_keys` 改到了集中路径、开了 `AllowUsers` 白名单、要求多因素认证。这时候写进 `~/.ssh/authorized_keys` 的公钥 sshd 根本不看，邀请再漂亮也登不进去。

**工具会在创建任何东西之前发现这一点并拒绝**（此时账号还没建，零残留），并告诉你到底卡在哪一条。你有两个选择：

**① 只为这一个账号开一条口子**（推荐）：

```bash
sudo linux-temp-admin invite --sudo --fix-sshd
```

它会写一个独立的 drop-in，内容只有一个 `Match User` 块：

```text
# /etc/ssh/sshd_config.d/10-linux-temp-admin-xxvcc-a1b2c3d4e5.conf
Match User xxvcc-a1b2c3d4e5
    PubkeyAuthentication yes
```

- **全局策略一个字节都不动**：其他所有账号的登录策略原封不动，该关的还是关着。
- 写入后先 `sshd -t` 校验语法，再用 `sshd -T -C user=<账号>` **证明确实生效**，最后才 `reload`（**reload 不是 restart**，现有会话不受影响）。任何一步不过，就删掉文件、不 reload、中止创建。
- `revoke`（含到期自动删除）会**删掉这个文件并 reload sshd**。所谓"还原"就是删掉我们自己写的文件——不需要备份，因此**不可能覆盖你后来对 sshd 做的任何改动**。

交互式运行会先问你一句；`--yes` 非交互模式下**不会**弹问，必须显式写 `--fix-sshd`——脚本不该在无人值守时悄悄改远程机器的 sshd。

**② 改用密码登录**（不碰 sshd）：

```bash
sudo linux-temp-admin invite --sudo --password-login
```

先验证 sshd 真的接受密码登录（否则拒绝），然后生成一个 24 位随机密码，只打印一次。**这是本工具最弱的一种授权**：密码在账号整个生命周期里都能被全网爆破，而且必须明文交付。能用 `--fix-sshd` 就别用它。

**工具不会为你做的事**：它**永远不会**修改 sshd 的全局配置，也**永远不会**绕过 `DenyUsers` / `DenyGroups` 这类显式拒绝规则——"不在白名单里"是你没表过态的默认值，而"明确拒绝"是你的决定。

想提前知道自己的服务器行不行，直接跑：

```bash
sudo linux-temp-admin doctor
```

## 参考

### 支持的系统

- **主要支持**：Debian / Ubuntu、宝塔常见 Linux 环境、RHEL / Rocky / AlmaLinux / Fedora
- **尽力支持**：Alpine、Arch Linux

### 依赖

二进制本身零运行时依赖。它只调用系统自带的**账号管理工具**；这些工具缺失时可交互安装（需确认或传 `--install-deps`），支持 `apt-get` / `dnf` / `yum` / `apk` / `pacman`：

- `id`、`useradd` 或 `adduser`、`userdel` 或 `deluser`、`usermod`、`chage`
- `sudo`：仅在选择授予 sudo 时需要

`doctor` 会显示**运行中的版本与已安装命令的版本**（两者不一致会提示——自动删除任务执行的是已安装的那份），逐项检查上面这些工具，外加包管理器、init 系统、`/etc/sudoers.d` 的安全性、探测到的 SSH 端口，并**预演一个新建临时账号能否通过公钥登录**（sshd 会拒绝时给出 `invite --fix-sshd` 提示）。它还会报告**孤儿的 sudo 授权、sshd 例外和自动删除任务**（账号已不存在却残留），以及设置了自动删除却已无对应任务的账号——都指向 `cleanup-expired --compact` 或 `revoke` 处理。

`at` / `atd` 是 systemd 不可用时自动删除的备用后端，**不在依赖检查里，也不会被自动安装**。

### 关于"过期"和"自动删除"

默认有效期 24 小时，且**默认开启自动删除**。开启自动删除时，工具会写入精确到点的自动删除任务（优先持久化 systemd timer，`at` 兜底），同时用 `chage -E` 设置按天粒度的兜底锁定。该兜底绝不会早于邀请中显示的截止时间，但最多可能晚约 24 小时；真正的精确截止机制是自动删除任务。如果两个调度后端都无法创建任务，整个邀请会回滚，不会留下“仅设置账号过期”的账号。自动删除任务调用的是已安装命令，因此工具会先确保 `/usr/local/sbin/linux-temp-admin` 存在。任务同时绑定创建时的 UID、随机 128 位世代标识和登记行；任一不匹配（包括登记表丢失或账号被重建）都会安全跳过删除。systemd 撤销失败会限速重试；`at` 和旧版一次性任务失败后需人工处理，`doctor` 会报告登记账号缺失自动删除任务的情况。

**不开启自动删除 = 永久账号**:不设任何到期、也不会被删除,只能手动 `revoke`。此时 `--hours` 被忽略。

关于 Host 的两点用户须知：

- 交互模式不传 `--host` 时，会**静默**探测云厂商 metadata 和本地网卡（这两者都不出本机/本链路），探到的地址作为默认值填进提示符，回车即接受、也可直接改写。只有在本机探不到公网 IP 时，才会**询问**是否访问 `https://api.ipify.org`、`https://ifconfig.me/ip`、`https://icanhazip.com`——这一步会把你的服务器地址暴露给第三方，所以必须显式同意。`--yes` 模式永远不会外联，必须显式传 `--host`。
- `--host` 只接受普通域名、IPv4 或 IPv6；不要带端口（用 `--port` 单独指定），邀请包中的 SSH 命令会自动为 IPv6 加方括号。自动探测只接受可路由公网地址，会排除私网、链路本地、文档、基准测试、CGNAT 等保留范围；显式域名或地址仍由操作者决定。

### 写入的文件

```text
/usr/local/sbin/linux-temp-admin                             # 稳定撤销命令
/var/lib/linux-temp-admin/v2/registry.tsv                    # 本地登记表（root:root 0600，目录 0700）
/var/lib/linux-temp-admin/v2/prefs                           # 记住的界面语言（root:root 0600）
/var/log/linux-temp-admin/audit.log                          # 操作审计日志（root:root 0600，目录 0700）
/run/linux-temp-admin.lock                                   # 全局账号/安装生命周期锁
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.service  # 含 NoNewPrivileges 等轻量限制
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER                         # 仅在启用免密 sudo 时
/etc/ssh/sshd_config.d/10-linux-temp-admin-USER.conf         # 仅在 --fix-sshd 时；只含一个 Match User 块，revoke 时删除
/home/USER/.ssh/authorized_keys
# 以及在 systemd 不可用时，at 队列中的备用自动删除任务
```

## 安全说明

- 私钥只在创建时显示一次，服务器不保存；账号密码默认锁定，不输出任何账号/Sudo 密码。
- 邀请里的 `Login:` 是**验证过的结论**：创建前会读 `sshd -T -C user=<新账号>` 确认这个账号真能登进去；读不到配置，或发现 `Address`、`Host`、`LocalAddress`、`LocalPort` 等依赖连接属性的 `Match` 条件时会标 `UNVERIFIED`，绝不凭空断言。
- **绝不修改 sshd 全局配置**。`--fix-sshd` 只写一个独立的、仅含 `Match User` 块的 drop-in（其他账号的策略一个字节不动），写入前 `sshd -t` 校验、写入后 `sshd -T` 证明生效、只 `reload` 不 `restart`。任一步失败都会触发清理，邀请事务还会独立重试；删除或恢复失败会作为回滚错误明确报告。`revoke` 会删掉该文件。**绝不绕过 `DenyUsers`/`DenyGroups` 这类显式拒绝规则。**
- `--password-login` 是最弱的授权方式（密码可被全网爆破、必须明文交付），只在显式要求时启用，且会先验证 sshd 确实接受密码登录。
- **NOPASSWD sudo 基本等同 root**，只给可信对象；撤销只删除该账号本身，不会清理它以 root 身份留下的进程、cron、systemd 单元或 SUID 文件。
- 删除用户会一并删除家目录和 SSH key；SSH 家目录必须严格属于目标 UID，绝不会把 root/UID 0 的目录当作目标家目录操作。如果系统删除命令失败，工具会停下并提示手动检查，不会假装撤销成功。
- **防误删**：`revoke` 默认只接受登记目标，且登记行和匹配 UID 仍不足以证明身份；当前账号还必须保留本工具写入的精确 GECOS 标记。UID、标记或自动任务世代不匹配时拒绝/跳过删除。删除未登记但带精确标记的账号需显式 `--force`，非交互还需 `--confirm-force USER`。
- 即使使用 `--force`，也会拒绝删除 root、常见系统账号、UID 0、低 UID 系统账号，以及**任何非本工具创建（无精确标记）**的真实账号——这类账号请改用系统的 `userdel`。
- 创建过程中任一步失败都会尝试完整回滚自动撤销、sudoers、sshd 例外、登记记录和新建账号；任何回滚失败都会明确报告并返回非零，不会把部分成功伪装成成功。
- invite、revoke、cleanup、install、upgrade、uninstall 共用一把位于可删除状态目录之外的 root 生命周期锁，账号、任务、授权、登记和二进制变更不会相互穿插。创建前同时检查本地 passwd 与 NSS，避免本地邀请覆盖 LDAP/SSSD 同名身份。
- 撤销时若 sudoers 或 sshd 例外无法完全移除，会保留账号和登记并尝试禁用登录，避免残留的按用户名授权在账号复用后重新生效；清理、登记或调度错误同样返回非零。
- 登记表会严格校验 schema、字段、UID 和世代标识；损坏或不可读时，`status`、`doctor`、清理、撤销和卸载都会 fail closed，而不是把“读不到”当成“没有账号”。
- 升级只接受 HTTPS 并强制 ed25519 验签，验签失败即中止，不会安装未签名或签名不符的二进制。
- 每次特权操作（建/删账号、install/upgrade/uninstall）会以 JSON 行追加写入 root 属主的 `/var/log/linux-temp-admin/audit.log`（记录时间、操作者 `SUDO_USER`、动作、目标、结果）。
- stdout 不是 TTY 时默认拒绝输出私钥，只有确认输出通道安全时才用 `--allow-non-tty-private-key-output`。
- 不要把真实邀请包提交到 GitHub、Notion、工单或群聊；用完请立即 `revoke`，不要只依赖到期兜底。

## 开发与许可证

- 贡献流程与本地校验：[CONTRIBUTING.md](CONTRIBUTING.md)
- 安全问题请按 [SECURITY.md](SECURITY.md) 私下报告；版本变化见 [CHANGELOG.md](CHANGELOG.md)。

许可证：MIT，详见 [LICENSE](LICENSE)。
