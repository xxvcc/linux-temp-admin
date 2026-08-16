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

不传 `--host` 时，交互模式先请求固定数字地址的云 metadata 端点并检查本地网卡。这两个端点是 `http://169.254.169.254/latest/meta-data/public-ipv4` 和 `http://100.100.100.200/latest/meta-data/eipv4`，在确认创建之前就会被请求。前者是链路本地地址；后者属于 `100.64.0.0/10` 共享地址空间，**不保证止于本机链路**，在非云主机上这是两次可能离开本机的请求。网卡检查不会发送流量；metadata 使用明文 HTTP，请求不使用 DNS、重定向或环境代理，但可能经过本地或云厂商网络，其返回值未经认证。程序只把探测值作为默认值，操作员必须确认或改写；尤其在密码登录模式下，应先通过云控制台、DNS 或其他独立渠道核对 Host，避免受邀者把密码提交给错误的 SSH 主机。只有找不到公网地址时，才会询问是否访问公网 IP 服务；这会向第三方暴露服务器出口地址，必须显式同意，返回值同样需要确认。

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

关闭自动删除后，账号只能通过 `linux-temp-admin revoke` 手动删除，`--hours` 会被忽略。

账号数据库项自 `useradd` 起就使用过去日期过期并锁定密码，不会复制 `/etc/skel`。程序先在 root-only 高水位文件中永久烧掉一个 UID/GID，再用 `useradd` 把账号和私有组固定到同一号码；默认随机用户名具有长随机后缀，因此正常菜单创建不会复用本工具曾释放的数值身份。以 `<32hex>` 表示 32 位小写十六进制世代，当前版本让 GECOS 前四个子字段初始为空，并在第五个 trailing/other 字段写入紧凑世代见证：完成态为 `,,,,lta-m=<32hex>`，pending 创建态为 `,,,,lta-p=<32hex>`。旧版二进制在首字段看不到旧格式标记，因而对这种新账号失败关闭。Home 保持不存在时会执行两轮进程终止与同名 crontab、目标 UID `at`/`batch` 任务清理，不再前台等待 65 秒。显式 `--user` 仍可能复用历史名称和 daemon 已缓存的同名任务，所以该特殊路径会说明原因并同步等待一个轮询周期。邀请创建期间始终复核 `useradd` 后捕获的完整 passwd 快照；只有清场、完整快照和无残留进程复查通过后才创建权限 `0700` 的空 Home。密码/公钥、授权、登记和自动撤销任务全部完成后账号才被激活。有效期从清场完成后开始，因此显式用户名的安全等待不会缩短 `--hours` 请求的访问时长。

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

状态会显示账号身份、UID、有效期、自动删除任务、身份隔离截止时间和异常登记。v2.9.3 及更早版本创建、仍只有 GECOS 首字段世代见证的账号会显示 `generation-bound-first-field-compat`；`doctor` 会提示尽快撤销并用当前版本重新邀请。`doctor` 还会报告孤儿 sudoers、sshd 例外，以及孤儿、缺失或无效的到期撤销/隔离终删任务；它不会在没有待调度账号时单独证明 systemd 或 `at` 后端可用。

## 撤销账号

```bash
# 从列表选择
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke

# 指定账号
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

对于仍可核对稳定身份的账号，正常 systemd 撤销会先删除并确认 sudoers/sshd 授权、禁用登录、执行两轮个人 crontab、目标 UID `at`/`batch` 和进程清理，再建立持久化身份隔离并立即返回。当前格式要求登记用户名、UID/GID、确定的 Home 和第五字段 `lta-m=` 世代见证持续一致；受支持的标准账号工具没有供普通用户改写第五字段的入口，因此 full-name、room、工作/家庭电话或非空 shell 的自助修改及并发循环不会拖住撤销。稳定字段或第五字段见证变化会失败关闭。本机 root 能直接改写账号数据库或程序状态，仍属于信任边界。此后列表显示“已撤权，隔离待删”；passwd 项继续占用用户名和 UID/GID 至少 65 秒（向上取整到整分钟后不到 125 秒），期间已过期、密码锁定且没有本工具管理的 sudo/sshd 入口。后台 timer 到期后再次复查，再删除账号、确定的 `/home/<用户名>` 家目录、UID 匹配的常规 mail spool、公钥和任务。主机关机跨过截止时间时，持久化 timer 会在启动后补跑。systemd 不可用时，撤销仍在前台同步等待 65 秒并完成终删；卸载也必须同步终删，避免先移除后台任务需要的命令。账号若已在程序外消失，只清理仍可安全识别的登记、按用户名授权和任务，以及已有删除恢复见证授权的窄范围 mail spool。只有 Home 是真实目录、属于登记账号的 UID/GID 且不包含挂载边界时才会递归清理。Home 清理使用目录描述符，不接受链接形式的 Home 根；内部链接只删除链接本身而不跟随目标。遍历会在文件系统调用之间检查 100,000 个条目、128 层和两分钟的协作式预算，因此单次阻塞的文件系统调用不能被该期限中断。cron/at 和进程结果是重复快照，不是原子冻结。任一安全条件、资源上限、任务/进程盘点或按用户名授权无法确认时，都会尝试禁用账号，保留仍存在的账号和登记并返回非零，避免用户名复用后继承旧数据、任务或权限。

邮件专用清理只处理 `/var/mail/<用户名>` 或 `/var/spool/mail/<用户名>` 的传统单文件 mbox。存在的系统邮箱目录必须由 root 所有、不得带 setuid；world-writable 时必须带 sticky bit，所以 `root:mail 3777` 和 Arch Linux 的 `root:root 1777` 可用，而无 sticky 的 `0777`/`2777`、`mail:mail` 等非 root 属主都会失败关闭。目标 mailbox 还必须是 UID 匹配的非链接普通文件。`invite` 会在 `useradd` 前检查系统邮箱目录，并在 UID 已确定后重新检查；前置失败不会留下账号，helper 后的失败则会尝试回滚，无法确认时保留过期锁定、无凭据的账号和登记供恢复。专用逻辑不搜索或遍历 Maildir，也不触碰宝塔 `/www/vmail`；若 Maildir 位于本工具管理的 Home 内，完整撤销仍会按 Home 规则删除整个 Home。

删除 `at` 作业前会重新读取作业正文并再次核对 UID 或精确撤销命令，避免已复用的作业 ID 指向无关任务；`at` 没有原子的比较删除接口，因此重新读取到 `atrm` 之间仍存在本机 root 信任边界内的极短窗口。

兼容旧版自动任务时，不带 UID/世代参数的 `linux-temp-admin revoke --yes` 若恰好与同名 `invite` 并发，无法证明旧删除意图在创建结束后仍指向同一账号。此时命令会明确警告、本次不删除任何账号并以成功状态跳过，避免 systemd 把旧任务重试到新世代；人工执行的同形非交互命令也遵循这一规则。并发操作完成后必须运行 `linux-temp-admin doctor`，并针对当前账号重新执行 `linux-temp-admin revoke`。

`linux-temp-admin doctor` 报告为 `legacy-unverified` 的账号来自旧版固定身份标记，无法排除同名/同 UID 重用。人工核查后，只能在交互终端运行 `linux-temp-admin revoke --user <名> --force` 并输入完整用户名确认。若旧 v2 登记仍只有 9 列、没有记录 UID，这条人工恢复路径仅在当前账号保留精确固定标记且 UID 不低于 1000 时可用；程序会在清权前正式迁移登记到 v5、创建 `identity-sequence`，并重新核对登记语义与完整 passwd 快照。迁移或复核失败不会清理授权、禁用或删除账号。旧版 timer 使用的 `--yes --force --confirm-force` 以及其他非交互调用都不会获得这类账号的删除授权；若旧 timer 的 UID/世代与未绑定登记精确匹配，它只会先移除本工具的 sudoers/sshd 授权，再取消旧到期任务，全程不读取 passwd 删除策略、不禁用或删除账号，也不改登记。任一授权移除失败都不会主动取消任务，systemd 会按策略重试，已触发的 `at` 和旧一次性任务仍需人工处理；取消任务失败也返回非零，账号和登记始终保留供人工恢复。低 UID、UID 0、保留名称和标记不匹配仍受保护。`linux-temp-admin doctor` 会把仍存在的旧任务报告为孤儿任务，`linux-temp-admin cleanup-expired --compact` 也可取消任务而保留活账号及登记供人工处理。

v2.9.3 及更早版本创建的世代账号只有 GECOS 首字段中的旧完整标记。它尚未被改写时，`status` 显示 `generation-bound-first-field-compat`，普通及自动撤销仍可按登记 UID/世代和完整旧快照执行；撤销期间每次 passwd 复读都必须与开始时的完整快照逐字节一致，`doctor` 会提示尽快撤销并用当前版本重新邀请。`status`/`doctor` 都不会隐式改写旧账号；旧首字段见证若已经丢失且没有第五字段见证，账号会保持 protected，必须人工核查处理，不能用同名/同 UID 猜测恢复，也不能从登记内容自动重建见证。

从 v2.9.1 等旧版升级后，若 `status`/`doctor` 显示仍活着的 pending 创建登记，应先人工确认它确实来自失败的邀请。菜单选择该行会自动进入与直接运行 `linux-temp-admin revoke --user <名> --force` 相同的恢复门，并仍要求交互终端输入完整用户名；程序还会核对随机 pending 世代、GECOS、登记 UID（0 或当前 UID）、受管 Home、非 root UID/GID 和非空 shell。systemd 可用时，验证通过的 pending 身份也会立即撤权并保留精确世代进入后台隔离；同步回退才会把它转换为 UID-only 删除恢复见证。`--yes`、自动撤销、卸载批量、管道输入或任何身份不匹配都拒绝首次授权这类恢复。

删除授权、身份及删除前的任务/进程静默检查通过后，程序会在受控的 mail/Home 清理和 `userdel` 前持久化删除恢复见证；Home 清理后、`userdel` 前仍会再次复核任务、进程和稳定身份（用户名、UID/GID、Home、第五字段世代见证；旧单标记账号则复核完整快照）。若账号删除、删除后的 mail spool 复扫或任务清理中断，`status` 和 `doctor` 会显示删除恢复状态，同名 `invite` 会拒绝覆盖该见证，`cleanup-expired --compact` 也不会删除见证。账号已经不存在或仍精确匹配登记世代时，运行 `linux-temp-admin revoke --user <名>` 可继续恢复；账号缺失时，每轮窄范围邮件清扫前后都会复核本地 passwd 与 NSS 均无同名身份。上述两种状态下仍保留可识别的自动任务，但只有 systemd 任务会按重启策略自动重试，`at` 和旧的一次性任务需要人工重试。旧版、未登记或 pending 回滚只保留 UID 见证，若账号仍存在，必须人工核查后在交互终端运行 `linux-temp-admin revoke --user <名> --force` 并输入完整用户名，任何非交互调用都会被拒绝；这类活账号的旧自动任务会被当作孤儿任务取消，登记见证则保留供人工恢复。

删除未登记账号需要显式 `--force`，并有额外用户名确认；它不会绕过保留名称、UID 0 或未登记/旧身份低 UID 账号的保护。若某些系统把本工具新建的账号分配到低 UID，只有登记用户名、当前 UID/GID、确定的 Home、随机世代和兼容格式的精确 GECOS 见证完整绑定时才能正常撤销。没有本工具精确见证的真实账号始终不会被当作受管账号删除。

## 清理异常状态

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
```

`linux-temp-admin cleanup-expired` 只清理失效登记及孤儿 sudoers、sshd 例外和撤销任务，**不会删除账号**。删除账号使用 `linux-temp-admin revoke`，查看列表使用 `linux-temp-admin status`。

### 恢复缺失的身份序列

若 `linux-temp-admin doctor` 明确报告“有效 v5 登记表缺少 `identity-sequence`”，邀请和登记变更会失败关闭。只有这一种“对象确实不存在”的状态允许使用专用恢复命令；文件已存在但内容损坏、权限或属主不安全、是符号链接，或高水位低于登记 UID 时，命令绝不会覆盖它。此时应从可信备份恢复，或保留现场后人工调查，不能删除或手工改写文件来绕过检查。

恢复值 `N` 必须从可信历史独立确定为本工具**曾经预留过的最高 UID/GID**，包括后来已经删除的账号及在创建失败时已经烧掉的号码。当前 passwd/group 和仍存登记只能给出下限，不能证明历史最高值；不要猜测，也不要只把当前表中的最大 UID 当作完整历史。确认依据后，在真实交互终端运行：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin recover-identity-sequence --highest N
```

命令会显示登记最高值、本机当前分配范围与观测下限，并拒绝低于这些观测值的输入；达到或超过当前分配上限时会警告后续邀请将耗尽。继续时必须逐字输入命令给出的 `RECOVER IDENTITY-SEQUENCE HIGHEST=N`。确认后程序才取得全局生命周期锁，重新读取登记和本机 UID/GID 状态，拒绝确认期间发生的变化，并以 no-replace 方式创建 root:root、`0600` 的序列文件。成功输出的 `safe-after` 是一次至少 65 秒的身份隔离窗口；在它过去前，下一次自动用户名邀请不会跳过同步任务清场。成功和锁内失败都会以 `registry.identity-sequence.recover` 写入审计日志。恢复后再次运行 `linux-temp-admin doctor`，确认完整性错误已经消失。

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

默认随机用户名在即时任务清场后只计算一次有效期，不再经历 65 秒前台等待；显式 `--user` 则在名称复用防护完成后计算，因此安全等待不会缩短请求时长。目标向上取整到整分钟，最多多不到一分钟。显示、systemd 和 `at` 共用这一绝对目标，其中 `at` 按 UTC 绝对分钟排程，不会因夏令时变化提前执行。`chage -E` 仅提供可能更晚的按天粒度兜底锁定。调度器忙碌、主机停机和重试都可能让实际删除延后；不再需要时应立即手动撤销。撤销任务绑定创建时的用户名、UID/GID、确定的 Home、随机世代、GECOS 见证和登记记录；当前格式允许普通用户字段变化，但稳定身份不匹配或账号被删除重建时会拒绝误删。

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

清单里“依据”一列写着 `passwd-marker-block-only` 的活账号，只由 passwd GECOS 里的生命周期标记指认：没有登记行，也没有本工具的 sudo 授权、sshd 例外或自动删除任务。这类账号既不会被自动删除，默认也会中止卸载——它可能是登记行丢失的永久账号，但同样可能是**任何本机普通用户**用 `chfn` 给自己写上的同一串文字。人工确认它不是本工具创建的账号后，可以清除标记（`usermod -c '' <名>`），或用 `--ignore-foreign-markers` 明确跳过：

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --ignore-foreign-markers
```

该开关只对“仅有 passwd 标记”这一种形态生效，被跳过的账号会逐个打印出来。只要该用户名还带着本工具的任何一件授权、例外、任务或登记行，它就仍然照常中止卸载——跳过它们从不删除账号，只是不再让它们挡住卸载。

审计日志默认保留在 `/var/log/linux-temp-admin/audit.log`。生命周期锁和卸载标记也会保留；当前版本的进程在取得锁后会检查该标记并拒绝重建状态。已经载入且早于这项协议的旧版二进制可能不会检查它，因此该标记不保证约束每个历史排队进程；显式重新安装会处理卸载标记。

## 写入位置

```text
/usr/local/sbin/linux-temp-admin
/var/lib/linux-temp-admin/v2/registry.tsv
/var/lib/linux-temp-admin/v2/identity-sequence
/var/lib/linux-temp-admin/v2/prefs
/var/log/linux-temp-admin/audit.log
/run/linux-temp-admin.lock
/run/linux-temp-admin.lock.uninstalled
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.service
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.timer
/etc/systemd/system/linux-temp-admin-v2-quarantine-USER.service
/etc/systemd/system/linux-temp-admin-v2-quarantine-USER.timer
/etc/sudoers.d/linux-temp-admin-USER
/etc/ssh/sshd_config.d/10-linux-temp-admin-USER.conf
/home/USER/.ssh/authorized_keys
```

在 systemd 不可用时，还可能创建 `at` 队列任务。sshd 文件只在显式使用 `--fix-sshd` 时存在，sudoers 文件只在授予 sudo 时存在。
