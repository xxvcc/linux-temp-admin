# 安装、升级与下载验证

中文 | [English](installing.en.md)

本文面向安装和维护 `linux-temp-admin` 的服务器管理员。日常创建、查看和撤销账号见[管理员指南](operator-guide.md)，安全保证与威胁边界见[安全模型](security-model.md)。

## 支持范围

- Linux 5.3 或更高版本；
- amd64 或 arm64；
- 主要支持 Debian、Ubuntu、RHEL、Rocky、AlmaLinux、Fedora 和常见宝塔环境；
- Alpine 和 Arch Linux 为尽力支持；
- 安装需要 root 权限、curl、OpenSSL 3、sha256sum 和 timeout；
- GitHub CDN 回退还需要 `getent` 或 `nslookup`，用于验证并固定每个重定向目标的公网地址。

二进制本身不依赖动态库或语言运行时。账号生命周期仍会使用系统的 `id`、`useradd`、`userdel`、`groupdel`、`usermod` 和 `chage`；密码登录还需要 `chpasswd`，授予 sudo 时还需要 `sudo` 和用于写入前策略校验的 `visudo`。`groupdel` 用于清理 `userdel` 可能留下、且已由登记中的 `SequentialID` 证明 GID 的受管同名私有组；它因此属于基础依赖，即使目标发行版上的 `userdel` 通常会自行删除该组。程序不回退到发行版 `adduser`/`deluser` 或任意 BusyBox 账号 applet：这些实现的参数、配置及编译期 shadow/group 语义不能仅凭命令名证明与 shadow 工具链等价。缺失依赖可在交互确认后通过 apt、dnf、yum 或 apk 安装；账号 helper 分别由 Debian 系的 `passwd`、RPM 系的 `shadow-utils` 或 Alpine/Arch 的 `shadow` 包提供。使用 apt 时，程序会依次尝试更新索引和安装软件包；即使旧缓存让安装完成，索引更新失败仍会作为错误返回并保留诊断。

### 传统系统邮箱目录兼容边界

账号创建与撤销会检查 `/var/mail` 和 `/var/spool/mail` 的实际元数据，而不是只按发行版名称放行。FHS 没有规定这些目录的属主和模式；以下是本次核验到的常见布局，不代表其他自定义布局自动受支持：

| 发行版/系列 | 实际邮箱目录 | 另一路径 | 已核验属主与模式 |
| --- | --- | --- | --- |
| Debian 12/13、Ubuntu 22.04/24.04 | `/var/mail` | `/var/spool/mail -> ../mail` | `root:mail 2775` |
| RHEL、Rocky、Alma、Oracle Linux、Fedora、CentOS、Amazon Linux 系 | `/var/spool/mail` | `/var/mail -> spool/mail` | `root:mail 0775` |
| Alpine | `/var/mail` | 依具体安装而定 | `root:root 0755` |
| Arch Linux 当前 `filesystem` 包 | `/var/spool/mail` | `/var/mail -> spool/mail` | `root:root 1777` |

产品策略只接受 root-owned 的真实系统邮箱目录；目录可以属于 `mail` 组并带 setgid，world-writable 时则必须有 sticky bit，同时任何 setuid 都会拒绝。因此现场可见的 `root:mail 3777` 和 Arch 的 `root:root 1777` 均兼容，而无 sticky 的 `0777`/`2777`、`mail:mail` 等非 root 属主及逃出上述两个路径的符号链接会在 `useradd` 前失败关闭。邮件投递服务和获准写入该目录的本地身份属于信任边界。

这里的兼容性只针对 `/var/mail/<用户名>` 或 `/var/spool/mail/<用户名>` 的传统单文件 mbox；程序不会把 Maildir 或宝塔 `/www/vmail` 当作系统邮箱目录遍历。完整撤销仍会按独立的 Home 安全规则清理本工具管理的整个 Home。

Arch Linux 不允许安全的部分升级，而 `pacman -Syu` 会升级整个系统，因此本工具不会在创建账号时自动运行 pacman。请根据提示由管理员先完成完整升级和依赖安装。

## 便利安装

在支持 `pipefail` 的 shell 中运行：

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/linux-temp-admin/install.sh | /usr/bin/sudo /bin/sh
```

安装完成后执行：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

便利入口通过 HTTPS 从官方镜像取得脚本并立即交给 root shell。`pipefail` 会让 curl 的 DNS、TLS、HTTP 或传输失败成为整个管道的失败；它**不认证脚本本身，也不能阻止已经收到的部分脚本开始执行**。第一次 curl 尚未取得安装器时，安装器还没有运行，因此无法自行回退 GitHub。

安装器启动后，二进制下载进入另一条严格验证链：SHA-256、detached ed25519 签名、架构和候选版本全部通过后，才会原子安装到 `/usr/local/sbin/linux-temp-admin`。不存在未验签或只有校验和的降级路径。

## 官方镜像与 GitHub 回退

程序内置的首选发布源是：

```text
https://dl.ll.cd/linux-temp-admin
```

安装或升级 `latest` 时：

1. 从镜像读取规范 `latest.json`，锁定一个精确 tag；只有索引本身发生传输故障才查询 GitHub Latest；
2. 从该镜像版本目录下载 `SHA256SUMS`、当前架构二进制和签名；
3. 三个文件作为同一套来源验证，不会与 GitHub 文件混用；
4. 只有传输故障才丢弃整套镜像文件，并从同一 GitHub tag 重新下载；
5. 校验和、签名、manifest 语义或候选版本失败都会立即停止。

传输故障包括 DNS、TLS、超时、HTTP、空响应、超限响应和不完整下载。镜像重定向、非规范 manifest、SHA-256 不匹配、ed25519 验签失败和版本不匹配不是传输故障，不能通过切换来源掩盖。

官方镜像文件必须直接返回，不允许重定向。GitHub Release CDN 可以使用经过公网地址验证的 HTTPS 重定向。所有下载都有连接/总超时、大小硬限制和有界重试。

## 高保证首次安装

便利入口在执行前信任镜像 HTTPS 和稳定安装脚本的部署。需要在 root 执行前认证脚本时，应同时固定：

- 已审计的 40 位 commit；
- 通过独立认证渠道取得的安装脚本 SHA-256；
- 精确的 `vX.Y.Z` 发行标签。

唯一规范、受动态故障测试保护的命令位于[维护者发版文档的 Host install and upgrade 章节](releasing.md#host-install-and-upgrade)。该流程先进入清理过的 root shell，再创建 root 独占的有界临时文件，验证独立哈希后才执行，并强制安装精确版本。

不要从网页内容或同一下载链路同时取得脚本和“预期哈希”；那不能提供独立认证。发布 tag、commit、脚本哈希和版本应来自发行审计记录及另一个可信渠道。

## 日常升级

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade --yes
```

升级器遵循与安装器相同的镜像优先、完整来源和 fail-closed 规则。默认只在版本更新时替换；明确需要同版重装、降级或修复不可读目标时才使用 `--force`。

自定义公开来源：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade --url https://downloads.example.com/linux-temp-admin
```

含凭据、token 或签名 query 的 URL 不应出现在 argv、shell 历史或日志中。把二进制 URL 放入 root 所有、`0600` 的绝对路径文件；可选第二行单独写签名 URL：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade --url-file /root/lta-upgrade-url
```

显式 `--url` 或 `--url-file` 只使用操作者选择的来源，失败时不会静默切换到官方镜像或 GitHub。该路径下载选定的二进制及其 detached ed25519 签名，并使用内置 keyring 验证，但不下载 `SHA256SUMS`。

## 安装本地二进制

```bash
/usr/bin/sudo ./linux-temp-admin install
```

`install` 把当前正在运行的二进制放到标准路径，不联网，也不额外验签，适用于离线机器或自行构建的文件。它通过 `/proc/self/exe` 复制当前 inode；只有在已经独立信任该二进制时才能使用。目标内容不同时需要显式 `--force`。

## 诊断安装问题

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin version
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

先区分错误类型：

- DNS、TLS、超时、HTTP 或不完整下载：传输故障，可以按既定策略重试或回退；
- checksum、signature、manifest、version 或架构错误：完整性故障，立即停止，不要强制绕过；
- OpenSSL 版本、系统工具、pidfd 或 sshd 条件不满足：主机环境问题，按 `doctor` 的具体结果处理。

卸载和受管账号处理见[管理员指南](operator-guide.md#卸载)。
