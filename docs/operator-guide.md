# 管理员指南

中文 | [English](operator-guide.en.md)

本文说明 `linux-temp-admin` 的日常账号管理。安装与升级见[安装指南](installing.md)，安全保证见[安全模型](security-model.md)。

## 交互菜单与语言

不带子命令运行会进入交互菜单：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin
```

菜单只在进入时和按回车后重新显示，上一项操作结果会留在屏幕上。第一次交互运行会询问中文或 English，并把选择保存到 `/var/lib/linux-temp-admin/v2/prefs`。以后可在菜单中选择“切换语言 / Switch language”。

语言优先级为：`--lang zh|en`、`LINUX_TEMP_ADMIN_LANG`、已保存选择、首次交互提示、中文。系统的 `LANG` 和 `LC_ALL` 不决定界面语言。

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin --lang en status
```

非交互任务无法询问语言，会使用已保存选择，没有则使用中文。通过 sudo 调用时优先显式传 `--lang`，不要为一个语言变量宽泛保留调用者环境。

## 创建邀请

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

交互模式会：

1. 选择用户名，默认使用随机后缀；
2. 探测或询问邀请中的 Host 和 SSH 端口；
3. 默认授予 sudo，也可以选择普通账号；
4. 询问是否自动删除，启用时再询问有效期；
5. 显示完整摘要并确认；
6. 创建账号、授权和撤销任务，最后才输出邀请私钥。

创建任何内容前，工具会用 sshd 的有效配置预演新账号能否登录。明确阻止登录时会直接拒绝，无法完整判断时会在邀请中标记 `UNVERIFIED`，不会伪造已验证结论。

### Host 探测

不传 `--host` 时，交互模式先读取云 metadata 和本地网卡，这些探测不会离开本机或本链路。只有找不到公网地址时，才会询问是否访问公网 IP 服务；这会向第三方暴露服务器出口地址，必须显式同意。

`--yes` 模式永远不会主动访问公网 IP 服务，必须显式提供 `--host`。Host 只接受普通域名、IPv4 或 IPv6；端口使用单独的 `--port`。

### 常用变体

```bash
# 12 小时、带 sudo
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --hours 12

# 普通账号
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --no-sudo

# 指定用户名、前缀、Host 或端口
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --user ops-a1b2c3d4e5 --sudo
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --prefix ops --sudo
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --host admin.example.com --port 2222 --sudo

# 永久账号：不设到期，也不会自动删除
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --no-auto-revoke
```

关闭自动删除后，账号只能通过 `revoke` 手动删除，`--hours` 会被忽略。

## 交付邀请

邀请包包含 Host、Port、User、截止时间、sudo 状态、登录验证结果和一次性私钥保存命令。服务器只保存公钥；私钥只在成功创建后显示一次。

通过可信私聊转发完整邀请包。协作者保存私钥后，使用头部字段组合 SSH 命令：

```bash
ssh -i ./USER.key -p PORT USER@HOST
```

邀请字段和命令块使用固定英文格式，便于原样转发。不要把真实邀请放入群聊、工单、知识库或公开页面。

## 自动化与非交互运行

非交互创建必须明确 Host。授予 sudo 时必须重复确认用户名；stdout 不是终端时，还必须确认输出通道允许承载私钥：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 --port 22 --hours 24 \
  --sudo --install-deps --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

无人值守模式不会隐式安装依赖或修改 sshd；需要时必须显式传 `--install-deps` 或 `--fix-sshd`。日志系统、CI 输出和管道下游都应按私钥处理。

## 查看状态

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status --user xxvcc-a1b2c3d4e5
```

状态会显示账号身份、UID、有效期、自动删除任务和异常登记。`doctor` 还会报告孤儿 sudoers、sshd 例外、撤销任务和缺失调度器。

## 撤销账号

```bash
# 从列表选择
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke

# 指定账号
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

撤销会删除账号、家目录、公钥、sudoers、账号专属 sshd 例外和自动删除任务。任一按用户名授权无法安全删除时，工具会保留并禁用账号、返回非零，避免用户名被复用后重新取得残留权限。

删除未登记账号需要显式 `--force`，并有额外用户名确认。root、UID 0、低 UID 系统账号及没有本工具精确标记的真实账号始终不会被当作受管账号删除。

## 清理异常状态

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
```

`cleanup-expired` 只清理失效登记及孤儿 sudoers、sshd 例外和撤销任务，**不会删除账号**。删除账号使用 `revoke`，查看列表使用 `status`。

## 公钥登录被禁用

如果 sshd 关闭公钥登录、改变 `authorized_keys` 路径或使用 AllowUsers 白名单，工具会在创建前发现并拒绝。

推荐只为新账号创建独立例外：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --fix-sshd
```

该选项只写账号作用域的 sshd drop-in，不修改全局配置。文件会经过 `sshd -t` 和 `sshd -T -C user=...` 验证，然后只 reload、不 restart。任一步失败都会删除文件并中止；`revoke` 会删除例外并再次 reload。显式 `DenyUsers` 或 `DenyGroups` 永远不会被绕过。

无法使用公钥时也可明确选择密码：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --password-login
```

工具会先验证 sshd 接受密码，再生成只显示一次的随机密码。这是较弱的授权方式，密码在有效期内可以被网络暴力尝试，应优先使用公钥。

## 到期与自动删除

默认有效期为 24 小时并启用自动删除。优先使用持久化 systemd timer，systemd 不可用时使用已有的 `at`/`atd`；`at` 不会被自动安装。两个后端都无法创建任务时，整个邀请回滚。

`chage -E` 仅提供按天粒度的兜底锁定，可能晚于邀请显示时间；精确截止由撤销任务实现。撤销任务绑定创建时的 UID、随机世代标识和登记记录，账号被删除重建或身份不匹配时会拒绝误删。

## 卸载

```bash
# 交互式：先显示完整清单，再输入 YES
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall

# 非交互式；存在受管账号时必须明确允许删除
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users

# 删除受管账号并同时删除默认保留的审计日志
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users --purge-audit
```

卸载先删除受管账号及其授权、例外和任务，再删除状态与程序。任何账号删不掉时都会中止，不会留下带 sudo 的账号却删除管理命令。从临时账号自己的会话运行卸载会被拒绝。

审计日志默认保留在 `/var/log/linux-temp-admin/audit.log`。生命周期锁和卸载标记也会保留，用于阻止已经排队的旧进程在卸载后重建状态；显式重新安装会处理卸载标记。

## 写入位置

```text
/usr/local/sbin/linux-temp-admin
/var/lib/linux-temp-admin/v2/registry.tsv
/var/lib/linux-temp-admin/v2/prefs
/var/log/linux-temp-admin/audit.log
/run/linux-temp-admin.lock
/run/linux-temp-admin.lock.uninstalled
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.service
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER
/etc/ssh/sshd_config.d/10-linux-temp-admin-USER.conf
/home/USER/.ssh/authorized_keys
```

在 systemd 不可用时，还可能创建 `at` 队列任务。sshd 文件只在显式使用 `--fix-sshd` 时存在，sudoers 文件只在授予 sudo 时存在。
