# linux-temp-admin

一次性 Linux 临时管理员邀请脚本。

适合你临时给可信协作者 / 运维助手开一个 SSH 账号：脚本会随机生成 SSH 密钥对、创建临时用户、可选授予 sudo 权限，并输出一份可直接转发的连接邀请包。用完一条命令撤销账号。

> 默认用户名前缀：`xxvcc`，生成格式类似 `xxvcc-a1b2c3`。

## 安全提醒

这个脚本会创建 SSH 登录入口。如果选择授予 sudo 权限，该临时用户基本可以获得 root 权限。

请遵守：

- 只在可信服务器上运行。
- 私钥和 sudo 密码只通过可信私聊发送。
- 不要把邀请包发到群里、公开仓库、Notion 或工单系统。
- 用完立即撤销用户。
- 建议先下载脚本看一眼，再运行；不要盲目 `curl | bash`。

## 支持系统

第一版目标支持：

- Debian
- Ubuntu
- 宝塔常见 Linux 环境
- CentOS / Rocky Linux / AlmaLinux（使用 `wheel` 组）

脚本会在创建邀请前检测这些依赖：

- `bash`
- `ssh-keygen`
- `useradd` 或 `adduser`
- `chpasswd`
- `usermod`
- `chage`（用于账号过期，推荐）
- `sudo`（仅当你选择授予 sudo 权限时检测）

如果缺少依赖，脚本会询问是否自动安装。支持的包管理器：

- `apt-get`
- `dnf`
- `yum`
- `apk`
- `pacman`

也可以直接自动安装：

```bash
sudo bash temp-admin.sh invite --sudo --install-deps
```

或者禁止自动安装，缺依赖就退出：

```bash
sudo bash temp-admin.sh invite --sudo --no-install-deps
```

## 安装 / 下载

推荐：

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
sudo bash temp-admin.sh
```

或者：

```bash
curl -fsSLO https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
sudo bash temp-admin.sh
```

## 交互式使用

```bash
sudo bash temp-admin.sh
```

菜单：

```text
1) 创建一次性临时管理员邀请
2) 撤销/删除临时用户
3) 查看用户状态
4) 查看账号过期/自动删除状态
5) 退出
```

## 创建一次性临时管理员

交互式：

```bash
sudo bash temp-admin.sh invite
```

半自动示例：

```bash
sudo bash temp-admin.sh invite --prefix xxvcc --hours 24 --sudo
```

不授予 sudo：

```bash
sudo bash temp-admin.sh invite --prefix xxvcc --hours 24 --no-sudo
```

指定服务器地址和端口，仅影响输出的邀请包：

```bash
sudo bash temp-admin.sh invite --host 152.53.171.151 --port 22 --sudo
```

## 输出邀请包示例（已脱敏）

下面只是格式示例，**不可用于登录**。真实私钥和 sudo 密码只会在脚本运行时随机生成，并在终端里显示一次。

```text
====== 一次性临时管理员连接信息 ======

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3
Expires: 2026-05-17 01:00:00 CST
Sudo: yes
Passwordless sudo: no

SSH 登录命令：
ssh -i ./xxvcc-a1b2c3.key -p 22 xxvcc-a1b2c3@203.0.113.10

保存私钥命令：
cat > xxvcc-a1b2c3.key <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: 这里是真实运行时生成的一次性私钥]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 xxvcc-a1b2c3.key

Sudo 密码：
[REDACTED: 这里是真实运行时生成的一次性 sudo 密码]

撤销命令：
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3
```

安全提醒：

- README 里的示例是脱敏占位内容，不能登录任何服务器。
- 真实邀请包只能通过可信私聊发送给协作者。
- 不要把真实邀请包提交到 GitHub、Notion、工单或群聊。

## 撤销临时用户

脚本创建用户时会登记到：

```text
/var/lib/linux-temp-admin/users.tsv
```

登记内容只包括：用户名、创建时间、过期时间、是否 sudo、Host、端口、公钥指纹。  
不会记录私钥，也不会记录 sudo 密码。

交互式删除时可以从列表选择：

```bash
sudo bash temp-admin.sh revoke
```

示例交互：

```text
已登记的临时用户：
 1) xxvcc-a1b2c3
 2) xxvcc-d4e5f6
也可以直接输入用户名。
请选择要删除的编号/用户名: 1

将强制下线并删除用户 xxvcc-a1b2c3 及其家目录。
请输入完整用户名 xxvcc-a1b2c3 以确认删除:
```

也可以直接指定用户名：

```bash
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3
```

这会：

- 强制结束该用户进程；
- 删除该用户；
- 删除家目录；
- 删除该脚本创建的免密 sudoers 文件（如果存在）。

## 查看状态

查看指定用户：

```bash
bash temp-admin.sh status --user xxvcc-a1b2c3
```

列出默认前缀用户：

```bash
bash temp-admin.sh status
```

## 查看账号过期 / 自动删除状态

```bash
sudo bash temp-admin.sh cleanup-expired
```

说明：脚本创建账号时会用 `chage -E` 设置账号过期日期，同时默认尝试使用 `systemd-run` 创建一次性自动删除任务。

- 账号过期：通常阻止后续登录，但不会删除用户和家目录。
- 自动删除：到期后调用 `revoke`，会删除用户、家目录、SSH key、sudoers 文件和登记记录。
- 如果系统没有 `systemd-run`，脚本会降级为只设置账号过期，并提示你手动删除。

这个命令只查看状态，不主动删除，避免误删。确认后也可以手动执行：

```bash
sudo bash temp-admin.sh revoke --user USER
```

## 命令速查

```bash
# 创建邀请
sudo bash temp-admin.sh invite --sudo

# 创建 12 小时有效邀请
sudo bash temp-admin.sh invite --hours 12 --sudo

# 指定用户名前缀
sudo bash temp-admin.sh invite --prefix xxvcc --sudo

# 删除用户
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3

# 查看用户状态
bash temp-admin.sh status --user xxvcc-a1b2c3
```

## 关于“过期”和“自动删除”

默认有效期是 24 小时。脚本会尽量同时做两件事：

1. 通过 `chage -E` 设置 Linux 账号过期日期；
2. 通过 `systemd-run --on-active=<hours>h` 创建一次性自动删除任务。

需要注意：

- `chage -E` 通常是按“日期”过期，不是精确到分钟/小时的定时删除。
- 过期表示账号后续通常不能登录。
- 过期不等于删除，用户记录和家目录仍然存在。
- 自动删除任务会调用 `revoke`，删除用户、家目录、SSH key 和 sudoers 文件。
- 如果自动删除任务创建失败，请手动清理：

```bash
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3
```

## 设计原则

- 每次随机生成新的 SSH 密钥对。
- 创建时登记临时用户名，删除时可编号选择。
- 服务器只保存公钥，不保存私钥。
- 私钥只在创建成功后输出一次。
- 不把私钥、sudo 密码写入日志。
- 默认用户名前缀 `xxvcc`。
- 默认有效期 24 小时。
- 默认尝试创建自动删除任务；没有 systemd-run 时降级为账号过期。
- 删除用户时默认删除家目录和 SSH key。
- 创建前检测依赖；缺少依赖时可交互安装。
- 高风险操作要求输入 `YES` 确认。
- 不自动修改 `sshd_config`。
- 不自动改防火墙。
- 不自动开放端口。

## License

MIT
