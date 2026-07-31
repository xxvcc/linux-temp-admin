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
6. 创建账号和授权；启用自动撤销时创建任务，最后才输出邀请凭据。

创建任何内容前，工具会用 sshd 的有效配置检查计划凭据是否兼容。未解决的配置检查阻碍会拒绝创建，无法完整判断时会在邀请中标记 `UNVERIFIED`。显示“已对照 sshd 有效配置验证”只代表这项配置检查完整通过，不是对网络、防火墙、PAM、SELinux 或运行中 sshd 状态的端到端登录证明；交付前仍应沿实际连接路径测试邀请。

### Host 探测

不传 `--host` 时，交互模式先请求固定数字地址的云 metadata 端点并检查本地网卡。网卡检查不会发送流量；metadata 使用明文 HTTP，请求不使用 DNS、重定向或环境代理，但可能经过本地或云厂商网络，其返回值未经认证。程序只把探测值作为默认值，操作员必须确认或改写；尤其在密码登录模式下，应先通过云控制台、DNS 或其他独立渠道核对 Host，避免受邀者把密码提交给错误的 SSH 主机。只有找不到公网地址时，才会询问是否访问公网 IP 服务；这会向第三方暴露服务器出口地址，必须显式同意，返回值同样需要确认。

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

账号数据库项自 `useradd` 起就使用过去日期过期并锁定密码，不会复制 `/etc/skel`。程序核对完整身份并确认新 UID 没有残留进程后，仍会让 Home 保持不存在，再清理同名 crontab、复用 UID 的 `at`/`batch` 任务和 daemon 可能已读取的到期任务。检测到 cron/at 命令或仍运行的 daemon 时，这个无凭据、保持过期的 pending 账号会继续占用身份并等待 65 秒；进程清单无法可靠读取时也会保守等待。只有清场和复查通过后才创建权限 `0700` 的空 Home；密码/公钥、授权、登记和自动撤销任务全部完成后账号才被激活。有效期从清场完成后开始，因此等待不会缩短 `--hours` 请求的访问时长。

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

状态会显示账号身份、UID、有效期、自动删除任务和异常登记。`doctor` 还会报告孤儿 sudoers、sshd 例外，以及孤儿、缺失或无效的已登记撤销任务；它不会在没有待调度账号时单独证明 systemd 或 `at` 后端可用。

## 撤销账号

```bash
# 从列表选择
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke

# 指定账号
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

对于仍可用完整身份核对的账号，撤销会先禁用登录，删除并复核个人 crontab 和目标 UID 的 `at`/`batch` 任务，等待 65 秒的 daemon drain 后重复任务/进程清理，再删除账号、确定的 `/home/<用户名>` 家目录、UID 匹配的常规 mail spool、公钥、sudoers、账号专属 sshd 例外和自动删除任务；账号若已在程序外消失，只清理仍可安全识别的登记、按用户名授权和任务。只有 Home 是真实目录、属于登记账号的 UID/GID 且不包含挂载边界时才会递归清理；mail spool 也必须是受信系统邮件目录中的非链接普通文件，并在账号确认消失后复扫一次。Home 清理使用目录描述符，不接受链接形式的 Home 根；内部链接只删除链接本身而不跟随目标。遍历会在文件系统调用之间检查 100,000 个条目、128 层和两分钟的协作式预算，因此单次阻塞的文件系统调用不能被该期限中断。cron/at 和进程结果是重复快照，不是原子冻结。任一安全条件、资源上限、任务/进程盘点或按用户名授权无法确认时，都会尝试禁用账号，保留仍存在的账号和登记并返回非零，避免用户名复用后继承旧数据、任务或权限。

删除 `at` 作业前会重新读取作业正文并再次核对 UID 或精确撤销命令，避免已复用的作业 ID 指向无关任务；`at` 没有原子的比较删除接口，因此重新读取到 `atrm` 之间仍存在本机 root 信任边界内的极短窗口。

兼容旧版自动任务时，不带 UID/世代参数的 `revoke --yes` 若恰好与同名 `invite` 并发，无法证明旧删除意图在创建结束后仍指向同一账号。此时命令会明确警告、本次不删除任何账号并以成功状态跳过，避免 systemd 把旧任务重试到新世代；人工执行的同形非交互命令也遵循这一规则。并发操作完成后必须运行 `doctor`，并针对当前账号重新执行 `revoke`。

`doctor` 报告为 `legacy-unverified` 的账号来自旧版固定身份标记，无法排除同名/同 UID 重用。人工核查后，只能在交互终端运行 `revoke --user <名> --force` 并输入完整用户名确认。旧版 timer 使用的 `--yes --force --confirm-force` 以及其他非交互调用都不会获得这类账号的删除授权；`doctor` 会把仍存在的旧任务报告为孤儿任务，`cleanup-expired --compact` 会取消任务但保留活账号及登记供人工处理。

通过全部删除前检查后，程序会在调用 `userdel` 前持久化删除恢复见证。若账号删除、删除后的 mail spool 复扫或任务清理中断，`status` 和 `doctor` 会显示删除恢复状态，同名 `invite` 会拒绝覆盖该见证，`cleanup-expired --compact` 也不会删除见证。账号已经不存在或仍精确匹配登记世代时，运行 `revoke --user <名>` 可继续恢复；这两种状态下仍保留可识别的自动任务，但只有 systemd 任务会按重启策略自动重试，`at` 和旧的一次性任务需要人工重试。旧版、未登记或 pending 回滚只保留 UID 见证，若账号仍存在，必须人工核查后在交互终端运行 `revoke --user <名> --force` 并输入完整用户名，任何非交互调用都会被拒绝；这类活账号的旧自动任务会被当作孤儿任务取消，登记见证则保留供人工恢复。

删除未登记账号需要显式 `--force`，并有额外用户名确认；它不会绕过保留名称、UID 0 或未登记/旧身份低 UID 账号的保护。若某些系统把本工具新建的账号分配到低 UID，只有当前登记 UID、随机世代和精确 GECOS 标记完整绑定时才能正常撤销。没有本工具精确标记的真实账号始终不会被当作受管账号删除。

## 清理异常状态

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
```

`cleanup-expired` 只清理失效登记及孤儿 sudoers、sshd 例外和撤销任务，**不会删除账号**。删除账号使用 `revoke`，查看列表使用 `status`。

## 公钥登录被禁用

如果 sshd 关闭公钥登录、改变 `authorized_keys` 路径或使用 AllowUsers 白名单，工具会在创建前报告；未解决的阻碍会拒绝创建。

推荐只为新账号创建独立例外：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --fix-sshd
```

该选项只写账号作用域的 sshd drop-in，不修改全局配置。文件会经过 `sshd -t` 语法检查，再用 `sshd -T -C user=...` 检查有效配置；能找到运行中的 sshd 时只请求 reload、不 restart。若没有可通知的运行中 daemon，文件会保留供 socket 激活或下次启动读取，但邀请显示 `UNVERIFIED`。其他授权失败会尝试删除文件并中止；删除或恢复 reload 失败会返回非零并保留恢复见证。成功 `revoke` 会删除例外并再次请求 reload。显式 `DenyUsers` 或 `DenyGroups` 永远不会被绕过。

无法使用公钥时也可明确选择密码：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --password-login
```

工具只会在 sshd 有效配置检查未发现密码凭据阻碍或无法判断的规则后，才生成只显示一次的随机密码。这仍不是端到端登录测试。这是较弱的授权方式，密码在有效期内可以被网络暴力尝试，应优先使用公钥。

## 到期与自动撤销

默认有效期为 24 小时并安排自动撤销。优先使用持久化 systemd timer；systemd 不可用，或排程失败且相关 timer 已安全回滚时，才使用已有的 `at`/`atd`，`at` 不会被自动安装。任一后端都无法成功创建任务时，邀请会进入失败关闭回滚；若账号、授权或任务清理无法确认，工具会返回非零，并在必要时保留已禁用账号和登记见证供人工恢复，而不会把不完整清理报告为成功。

有效期在新 UID 的延迟任务清场和 65 秒 daemon drain 完成后只计算一次，并向上取整到整分钟：安全等待不会缩短请求时长，取整最多多不到一分钟。显示、systemd 和 `at` 共用这一绝对目标，其中 `at` 按 UTC 绝对分钟排程，不会因夏令时变化提前执行。`chage -E` 仅提供可能更晚的按天粒度兜底锁定。调度器忙碌、主机停机和重试都可能让实际删除延后；不再需要时应立即手动撤销。撤销任务绑定创建时的 UID、随机世代标识和登记记录，账号被删除重建或身份不匹配时会拒绝误删。

## 卸载

```bash
# 交互式：先扫描并显示卸载清单，再输入 YES
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall

# 非交互式；存在受管账号时必须明确允许删除
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users

# 删除受管账号并同时删除默认保留的审计日志
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users --purge-audit
```

卸载先对清单中的账号执行与普通 `revoke` 相同的身份核验和清理；只有确认账号、授权、例外和任务全部消失后才删除状态和程序。账号清理阶段的任一项无法确认都会中止卸载并保留管理命令与状态。从临时账号自己的会话运行卸载会被拒绝。

审计日志默认保留在 `/var/log/linux-temp-admin/audit.log`。生命周期锁和卸载标记也会保留；当前版本的进程在取得锁后会检查该标记并拒绝重建状态。已经载入且早于这项协议的旧版二进制可能不会检查它，因此该标记不保证约束每个历史排队进程；显式重新安装会处理卸载标记。

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
