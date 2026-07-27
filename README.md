# linux-temp-admin

<p align="center">
  <img alt="Linux amd64 and arm64" src="https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian Ubuntu and RHEL compatible" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu%20%7C%20RHEL-compatible-A81D33?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 一条命令，为可信协作者创建一个有时限、用完自动删除的临时 SSH 管理员账号。

**linux-temp-admin** 不需要分享 root 密码，也不会在服务器保存邀请私钥。它会创建临时账号、输出可私聊转发的邀请包，并在到期时自动撤销账号、SSH key 和 sudo 授权。

程序是一个支持 glibc 和 musl 的静态二进制，适用于 amd64 和 arm64 Linux。账号、SSH 和定时任务操作仍会调用系统已有的标准管理工具。

中文 | [English](README.en.md)

## 30 秒上手

在支持 `pipefail` 的 shell 中运行：

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/linux-temp-admin/install.sh | /usr/bin/sudo /bin/sh &&
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

工具随后会：

1. 创建一个随机命名的临时账号；
2. 生成一次性 SSH key，并在终端显示邀请包；
3. 默认授予免密 sudo，并在 24 小时后自动删除账号；
4. 在创建前检查当前 sshd 配置：明确阻止登录就拒绝，无法完整判断则如实标记 `UNVERIFIED`。

快速入口从官方镜像取得安装脚本并交给 root shell。`set -o pipefail` 会传播 curl 失败，因此安装失败后不会继续创建邀请；它**不认证脚本本身，也不能阻止已经收到的部分脚本开始执行**。安装器启动后，下载的二进制仍会经过 SHA-256 和 ed25519 签名验证。需要在执行前认证安装脚本时，请使用[高保证首次安装流程](docs/installing.md#高保证首次安装)。

## 使用条件

- Linux 5.3 或更高版本，amd64 或 arm64；
- 主要支持 Debian、Ubuntu、RHEL、Rocky、AlmaLinux、Fedora 和常见宝塔环境；
- Alpine 和 Arch Linux 为尽力支持；
- 当前用户能够通过 `/usr/bin/sudo` 取得 root 权限；
- 安装器需要 curl、OpenSSL 3、sha256sum 和 timeout。

安装后建议先运行：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

`doctor` 会检查依赖、内核能力、包管理器、sudoers、init 系统、SSH 端口和公钥登录条件。

## 创建和交付邀请

快速入口已经创建了第一个邀请。以后可以单独运行：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

交互流程会显示账号、Host、端口、有效期、sudo 状态和登录验证结果，并输出一次性的私钥保存命令。服务器只保存公钥，私钥不会落盘。

把完整邀请包通过可信私聊发给协作者。对方保存私钥后，使用邀请头部的 Host、Port 和 User 登录，例如：

```bash
ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10
```

邀请包中的真实私钥只显示一次，不要发送到群聊、工单、Notion 或公开页面。

## 查看和撤销

```bash
# 查看全部临时账号
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status

# 从列表选择并撤销
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke

# 直接撤销指定账号
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

默认会在 24 小时后自动删除账号、家目录、SSH key、sudo 授权和本工具创建的 sshd 例外。即使启用了自动删除，用完后也应立即手动撤销。

## 常用命令

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin              # 交互菜单
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status       # 查看账号状态
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor       # 检查当前主机
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade      # 验签升级
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall    # 卸载并处理受管账号
```

界面默认中文。第一次交互运行时可以选择中文或 English，之后可在菜单中切换；单次运行也可以加 `--lang zh` 或 `--lang en`。

## 常见场景

指定 12 小时有效期：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --hours 12
```

创建不带 sudo 的普通账号：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --no-sudo
```

指定 Host、端口或用户名前缀：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --host admin.example.com --port 2222 --prefix ops --sudo
```

服务器禁止公钥登录时，只为新账号创建独立 sshd 例外：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --fix-sshd
```

该操作不会修改 sshd 全局策略，并会在撤销账号时删除对应例外。自动化调用、密码登录、永久账号和完整故障处理见[管理员指南](docs/operator-guide.md)。

## 安全要点

- `--sudo` 授予的是 NOPASSWD sudo，基本等同完整 root 权限，只能发给可信对象；
- 临时管理员取得 root 后可以自行建立其他持久化，本工具无法在撤销时自动清理这些外部改动；
- 邀请私钥只显示一次，应通过可信私聊交付，并在使用结束后立即撤销；
- 官方镜像 `https://dl.ll.cd/linux-temp-admin` 是默认下载源，只有传输故障才会从 GitHub 重新下载完整套件；已经取得有效镜像索引时仍固定同一版本，校验和、签名或版本失败会立即停止；
- stdout 不是终端时默认拒绝输出私钥，脚本化使用必须显式确认输出通道安全；
- 不要手工修改 `/var/lib/linux-temp-admin` 中的登记数据。

详细保证、威胁边界和故障处理见[安全模型](docs/security-model.md)。安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告。

## 文档

- [安装、升级与下载验证](docs/installing.md)
- [管理员指南](docs/operator-guide.md)
- [安全模型](docs/security-model.md)
- [版本变化](CHANGELOG.md)
- [贡献指南](CONTRIBUTING.md)
- [维护者发版流程](docs/releasing.md)

许可证：MIT，详见 [LICENSE](LICENSE)。
