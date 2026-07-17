# Changelog

All notable changes to this project are documented here.

## v2.5.1 - The recorded UID decides in both directions

- **An account whose UID contradicts the one recorded at creation is no longer
  deleted.** The registry pins a `(name, uid)` pair when it makes an account, and
  the code calls that pair its "only immutable proof" precisely because the GECOS
  marker beside it can be rewritten by the account itself. When the proof
  *matched*, it was honoured. When it *contradicted*, the check fell through and
  asked the forgeable marker instead — so an account carrying a UID this tool never
  issued was still deleted, on the say-so of the weaker witness.

  A contradicting UID is not a missing witness; it is a disproof. Whatever the
  account is now, it is provably not the one created under that name — a
  hand-recreated account that reused the name, or one that rewrote its own passwd
  entry. The recorded UID is now decisive both ways, and only a row that recorded
  no UID at all (rows written before the UID was recorded) still falls back to the
  marker, because those accounts must stay revocable.

- **This had teeth past deleting the wrong account.** `revoke` aims its SIGKILL
  sweep at the UID standing in passwd, so an account whose UID no longer matched
  had that sweep pointed wherever its UID now pointed — at a real user's processes
  where the two collide. The protection gate runs before that sweep, so refusing is
  what keeps it aimed at an account the tool can prove it created. Note the reach
  here is not privilege escalation: changing a UID needs `usermod`, i.e. root, so a
  `--no-sudo` invitee cannot do it and a `--sudo` one is root-equivalent already.
  It is a tool that could be made to point its own gun somewhere it never should.

- **`UIDTampered`'s report can now actually fire.** It exists to tell the operator
  "created as %d, now %d — inspect this by hand", and it lived inside the branch
  something else had already refused: on the one path where the tamper *was* the
  whole story, it never spoke. A refused account still loses its sudo grant and its
  sshd exception first, as it always has — that ordering is deliberate — so it is
  defanged and left for inspection rather than deleted on a false identification.

- The test table already stated this rule ("recorded uid does NOT match -> not the
  account we made -> protected") but only ever exercised it on accounts whose
  marker was absent anyway, so the one case that decides it — marker intact, UID
  contradicting — went untested and returned "deletable". Both halves are pinned
  now, and both fail against v2.5.0.

  Patch, not minor: this is a defect fix. The CLI contract is unchanged; the one
  behaviour that changes is a refusal replacing a deletion the tool could not
  justify.

## v2.5.0 - The temp users are one screen

- **Menu items 2, 3 and 4 are one entry: 「管理临时用户（查看 / 撤销 / 清理）」.**
  They were three ways into one list. Revoke opened by printing a bare column of
  names to pick from; the list itself was the entry beside it; and cleanup acted
  on rows of that same list. Now the table is the screen, and the two things
  anyone does with it are answers to one prompt:

  ```text
  [信息] 已登记的临时用户：
  ┌───┬──────────────┬──────┬──────┬──────────┬──────────────────────┬─────────────┬──────┐
  │ # │ 用户         │ 状态 │ SUDO │ 自动删除 │ 到期                 │ 主机        │ 端口 │
  ├───┼──────────────┼──────┼──────┼──────────┼──────────────────────┼─────────────┼──────┤
  │ 1 │ xxvcc-a1b2c3 │ 在册 │ 是   │ 是       │ 2026-07-18 17:00 CST │ 203.0.113.5 │ 22   │
  │ 2 │ xxvcc-d4e5f6 │ 缺失 │ 是   │ 是       │ 2026-07-16 09:00 CST │ 203.0.113.5 │ 22   │
  └───┴──────────────┴──────┴──────┴──────────┴──────────────────────┴─────────────┴──────┘
  输入编号或用户名撤销 · c 清理失效登记与孤儿授权 · 回车返回:
  ```

  Looking is the default — a bare Enter leaves, having changed nothing.

- **`revoke` picks from the table too**, instead of a bare list of names. Choosing
  what to delete used to mean reading names with none of the facts next to them:
  which account was expiring within the hour anyway, which carried sudo, which was
  already gone. Same rows, same numbering, in both places.

- **v2.4.0 argued the opposite of this, and was wrong on the facts.** It kept
  `revoke` a separate entry because "making delete a mode inside a viewer is a
  footgun" — but deleting a real account does not happen on a keystroke: revoke
  makes you type the account's full name, and a mistyped one is refused. A number
  that opens a confirmation is not a misclick. It also treated cleanup as a
  different subject from the list, when what `--compact` prunes is *precisely* the
  rows the table marks 缺失 — a registry row whose account is gone. Two tests now
  pin that equivalence from both sides: cleanup takes every missing row, and
  spares every row whose account exists.

- **What a number does depends on the row, and the difference is stated rather
  than smoothed over.** A 在册 row is a real account: revoke deletes it, behind the
  full-name confirmation. A 缺失 row has no account left to lose — only a registry
  row and any grant it left behind — so picking it sweeps those with no prompt,
  exactly as `c` sweeps every missing row without asking. Demanding a name for one
  of them and not for all of them would be ceremony, not safety. An earlier draft
  of this entry claimed the confirmation covered every row; a review caught that,
  and the behaviour is now pinned by its own test instead of being folklore.

- The renumbering is the cost, and it lands on operators who just learned v2.4.0's
  numbers: the menu goes from 9 entries to 7, and everything below 2 shifts up.
  Nothing scriptable moved — `status`, `revoke`, `cleanup-expired --compact` are
  unchanged as subcommands, and the menu has never been an interface a script can
  drive.

- **The gates this rests on are now actually tested.** The full-name confirmation
  — the whole safety argument above — was executed by no test in this repo: delete
  the block from `revoke` and the entire suite, `e2e` included, still passed. It is
  reachable only with a real account (a fake registry row takes revoke's
  "already gone" branch first), so the new tests create one, and one of them
  reproduces that mutation as a failure. The same went for the table's numbering:
  the old test asserted `recs[n-1]` and never read the screen, so inverting the
  rendered `#` column alone left every test green while the display told the
  operator to type the number of a different account. The new test reads the number
  off the rendered table and feeds it back in.

- `doctor` keeps its own orphan check. Orphaned grants are found by globbing
  `/etc/sudoers.d` and `/etc/ssh/sshd_config.d`, not by reading the registry, so a
  grant whose registry row is gone appears in doctor but in no table — which is
  exactly the case doctor exists to catch.

  Minor, not patch: the menu's entries changed meaning and position. That should
  not arrive as a patch.

## v2.4.0 - One list, one table

- **The registered temp users are shown as a table**, and the two commands that
  printed that list now share one renderer. `cleanup-expired` used to print its
  own strictly-poorer copy — `user`, `exists`, `expires`, `auto`, every one of
  them already a column of `status` under a different name (its `exists` is
  status's `active`/`missing`). Two views of the same rows, free to drift apart.

  ```text
  ┌──────────────┬──────┬──────┬──────────┬──────────────────────┬─────────────┬──────┐
  │ 用户         │ 状态 │ SUDO │ 自动删除 │ 到期                 │ 主机        │ 端口 │
  ├──────────────┼──────┼──────┼──────────┼──────────────────────┼─────────────┼──────┤
  │ xxvcc-a1b2c3 │ 在册 │ 是   │ 是       │ 2026-07-18 17:00 CST │ 203.0.113.5 │ 22   │
  └──────────────┴──────┴──────┴──────────┴──────────────────────┴─────────────┴──────┘
  ```

  The auto-revoke unit is deliberately not a column: 40-odd characters,
  mechanically derived from the username, and it would double the table's width to
  restate what the reader already knows. `status --user <name>` still prints it.

- **The menu's two entries become one view and one action.** "查看用户状态" and
  "查看账号过期/自动删除状态" showed the same rows; the second now does the thing
  only it can do:

  | | before | after |
  |---|---|---|
  | 3 | 查看用户状态 | **查看临时用户** — the table |
  | 4 | 查看账号过期/自动删除状态 | **清理失效登记与孤儿授权** — `--compact` |

  Item 4 is `doctor`'s remediation partner, which is what doctor already tells
  operators to run when it finds an orphaned grant. The old name promised a
  deletion the command opened by disclaiming ("this only shows expiry status; it
  does not delete users"); the banner now says what it is rather than what it is
  not. **`cleanup-expired` and `--compact` still work as subcommands — no script
  breaks.** `revoke` stays its own entry: making "delete" a mode inside a viewer is
  the footgun the language entry was moved to avoid.

- New `internal/table`, ~60 lines, **no new dependency** (the module graph stays
  `x/crypto`, `x/term`, `x/sys`). `fmt` cannot align this: `%-8s` pads by rune
  count while a terminal draws CJK two columns wide, so a Chinese cell overruns its
  column — untidy in key=value output, but it visibly breaks a box-drawn table's
  vertical rules. `table.Width` measures display columns, and a test pins every
  rendered line to exactly its top border's width with mixed zh/en rows. The width
  function covers the CJK ranges only, which is provably enough here (the cells are
  this tool's own zh/en labels plus fields `validate` constrains to ASCII); that
  scope is documented at `Width`, pointing at `x/text/width` for anyone who later
  feeds it arbitrary text.

  Minor, not patch: `status`'s output format changed and menu item 4 now *acts*
  where it used to *look*. Upgrading should not spring either of those on someone
  who asked for a patch.

## v2.3.0 - You pick the language, not the server

- **The language is Chinese by default, whatever the server's locale says, and the
  tool asks you once instead of guessing.** The host locale (`LANG`/`LC_ALL`) used
  to sit above the default in the precedence chain, so a plain
  `LANG=en_US.UTF-8` server — the overwhelming majority — silently overrode this
  project's own primary language, and an operator who wanted Chinese had to
  discover `--lang`. What language a box was installed in says little about the
  language of the person holding the invite, so the locale is no longer consulted
  at all.

  Instead, the first interactive run asks:

  ```text
  Language / 语言:
    1) 中文 (默认)
    2) English
  选择 / select [1-2]:
  ```

  The answer is remembered in `/var/lib/linux-temp-admin/v2/prefs` (root:root
  0600) and never asked again. A new interactive-menu entry, labelled
  bilingually as "切换语言 / Switch language" so it is findable even by someone
  who picked the language they cannot read, changes it later. It is appended
  rather than slotted in beside the other settings-ish entries: every existing
  digit keeps its meaning, and the only shifted key — Exit, 8 to 9 — now lands on
  the harmless language switcher instead of "uninstall the stable command".

  Precedence is now `--lang` > `LINUX_TEMP_ADMIN_LANG` > the remembered choice >
  the question > Chinese. The question is skipped wherever asking would be wrong —
  no terminal (a script, CI, the cron-fired auto-revoke) or a `--yes` run that
  said not to prompt — and those fall back to the remembered choice or Chinese.

  Note the consequence: a non-interactive run on an English server now prints
  Chinese unless `--lang`/`LINUX_TEMP_ADMIN_LANG` says otherwise. That is the
  intended trade for not letting the box's locale outrank the operator.

  This is a minor release, not a patch, deliberately: `upgrade` from 2.2.x brings
  a changed default, a question that was never asked before, and one more menu
  entry. A patch number would have promised none of that was in the box.

## v2.2.6 - Revoke actually revokes

A three-round adversarial security audit of the whole tool. The cryptographic
supply chain (signature-verified upgrade/install), the symlink/TOCTOU-hardened
write layer, the never-delete-a-real-account guarantee, and secret handling all
held up. Everything it did find was in the revoke path, and this release fixes it.

- **An invitee could make its own account permanently unrevocable.** The
  protection gate decided from `/etc/passwd` fields the account itself can rewrite:
  erase the managed GECOS marker (with the granted sudo, or plain `chfn` where
  `CHFN_RESTRICT` permits) and the tool concluded "not mine" and refused to delete
  it — forever. Worse, an invitee with NOPASSWD sudo could `usermod -o -u 0` itself
  into a permanently-root, permanently-protected account. And because the gate ran
  *before* the cleanup, the refusal left the NOPASSWD sudoers drop-in, the sshd
  `Match` exception, and the auto-revoke timer live with nothing left to remove
  them.

  The registry now records each account's UID at creation — fixed before the
  invitee ever had access, and unlike GECOS it cannot be rewritten retroactively —
  and that (name, uid) pair is what proves an account is the tool's. It stays
  reuse-proof, because a recreated account under the same name draws a fresh UID.
  A registry row written before this field still parses (the field is appended;
  the parser's minimum stays at nine), so accounts already on deployed hosts remain
  revocable, and a row written now still parses under an older build. The privilege
  grants are now stripped *before* the gate can refuse, so an account that survives
  never survives still holding sudo and an sshd exception. An account that rewrote
  its own UID is reported as tampered rather than silently refused.

- **A reconnect loop defeated revoke — and revoke destroyed its own fallback
  first.** The account stayed SSH-reachable throughout: nothing locked it, so a
  login landing in the window between the kill and the delete made `userdel` (which
  lacked `-f`) exit 8, and revoke returned failure *after* having already cancelled
  the auto-revoke timer. No sudo needed — a plain reconnect loop left the account
  alive indefinitely with nothing coming for it. Revoke now shuts the door first
  (`chage -E` to a past date, which is what stops a *key* login — locking the
  password alone would not — plus `usermod -L`), deletes with `-f`, and cancels the
  auto-revoke task only once the account is provably gone: a failed delete leaves
  the fallback armed to retry.

- **Orphaned NOPASSWD sudo grants were invisible.** `sshdconf` could enumerate its
  orphans; `sudoers` could not, so `cleanup-expired --compact` pruned the registry
  row and the sshd file while leaving `/etc/sudoers.d/linux-temp-admin-<user>` on
  disk — re-arming full root the moment that username was reused — and `doctor`
  only checked that the *directory* looked safe, never what was in it. Both now
  enumerate, report, and remove sudo orphans the same way they already did for sshd.

- Hardening from the same audit: `TerminateProcesses` re-scans after each SIGKILL
  (bounded) instead of one snapshot, so an actively-forking process cannot outlive
  the sweep; an invite that writes an sshd exception refreshes the installed
  command even without `--auto-revoke`, so an older binary cannot revoke the account
  and orphan the exception; sshd Allow/Deny patterns are matched with sshd's own
  semantics (only `*` and `?` are special — Go's `path.Match` honours `[...]`
  classes that sshd treats literally, which could print "verified" for a login sshd
  refuses); the silent metadata probe no longer queries a DNS-named endpoint, which
  broke the "never leaves this host or its link" promise and let a DNS spoofer seed
  the invite's Host; and the interactive menu no longer spins on a non-TTY stream of
  invalid input.

## v2.2.5 - The invite stops promising a login it never checked

- **`invite` now verifies that the account can actually log in — before it creates
  anything.** The tool wrote the public key to `~/.ssh/authorized_keys` and printed
  `Login: SSH key only` as a hardcoded literal, without ever asking sshd whether it
  would accept that key. On a host with `PubkeyAuthentication no`, an
  `AuthorizedKeysFile` pointing somewhere else, an `AllowUsers`/`AllowGroups`
  whitelist, an `AuthenticationMethods` demanding a second factor (which the
  tool's own `usermod -L` makes unsatisfiable), or a crypto policy without
  `ssh-ed25519`, the invite was printed anyway — reporting success, handing over a
  one-time private key, and locking the password, for an account with no usable way
  in. The irony was that `sysinfo` already ran `sshd -T` and threw away every line
  but `port`. It now reads sshd's effective configuration for the account
  (`sshd -T -C user=<name>`, which resolves `Include`, `Match`, and distro crypto
  policy) and refuses up front, naming the directive that blocks it. Nothing has
  been created at that point, so a refusal leaves the host untouched. The invite's
  `Login:` line is now a computed verdict and says `UNVERIFIED` when the config
  could not be read, instead of asserting a login method nobody checked.
- **`--fix-sshd` opens a door for one account, and only that account.** It writes a
  separate drop-in (`/etc/ssh/sshd_config.d/10-linux-temp-admin-<user>.conf`)
  holding nothing but a `Match User` block that lifts exactly the blockers found.
  sshd's global configuration is never edited, so every other account keeps the
  operator's baseline byte for byte — and "restoring" is deleting our own file, so
  there is no backup to go stale and clobber a later change. The grant is
  syntax-checked with `sshd -t`, *proved* effective with `sshd -T -C user=`, and
  only then reloaded (`reload`, never `restart`: live sessions survive). Any failure
  removes the file and refuses the invite. `revoke` — including the auto-revoke
  timer — deletes the drop-in and reloads sshd. An interactive run asks first; a
  `--yes` run refuses unless `--fix-sshd` was passed explicitly, so a script can
  never quietly rewrite a remote host's sshd configuration. An explicit
  `DenyUsers`/`DenyGroups` rule is never bypassed: not being on an allow list is a
  default nobody spoke about, an explicit deny is a decision.
- **`--password-login` is the opt-in fallback for hosts you would rather not
  touch.** It verifies that sshd really accepts passwords (refusing otherwise),
  issues a 24-character password from `crypto/rand` shown once, and hands it to
  `chpasswd` on stdin so it never appears in the process table. The invite says
  `Login: password` truthfully and warns that this is the weakest grant the tool
  issues.
- **A doomed invite is refused before the operator is asked anything.** The sshd
  preflight only reads, so it now runs before the Host is resolved and before the
  sudo and auto-delete questions — not after them. On a host whose sshd explicitly
  denies the account (a rule the tool will never bypass), the refusal is immediate
  and silent: no questions, and no asking an external echo service for this server's
  public IP, which resolving the Host can otherwise do. Phoning home on behalf of an
  invite that was always going to be refused is precisely the disclosure this tool
  promises not to make. Values passed explicitly on the command line (`--host`,
  `--port`) are still validated first — a bad flag is a usage error, and a malformed
  command should never reach a question at all.

- **The interactive flow no longer dead-ends a menu-driven operator on a
  locked-down host.** When a key login cannot be made to work — an unfixable deny, or
  the operator declines the per-account sshd exception — and sshd would accept a
  password, the interactive run now offers one (defaulting to No, behind the same
  "weakest grant this tool issues" warning). Previously the only route to a working
  invite there was `--password-login`, a flag the menu cannot reach, so a menu-only
  operator was stranded.

- **The interactive flow asks for the account lifetime.** A menu-driven run never
  touches `--hours`, so it was always fixed at 24h; it now prompts `Lifetime in hours
  [24]` when the flag was not given. The prompt is gated on a real TTY — an
  unbounded non-terminal stdin of invalid lines would otherwise spin the re-ask loop
  forever — so a piped run keeps the default rather than hanging.

- **Missing dependencies are named in the confirmation summary and installed only
  after YES.** The read-only dependency check moved ahead of the summary, which now
  lists the packages it would install; the install itself still waits until after the
  confirmation. The consent is the single YES rather than a separate install prompt.

- **The confirmation prompt now states the login method — and its price.** The sshd
  preflight running early also means the summary can carry a `login=` line naming the
  method and, when sshd has to be touched, the exact drop-in file that will appear on
  the host:

  ```text
  即将创建一次性临时账号：
    user=xxvcc-a1b2c3 host=203.0.113.10 port=22 hours=24 sudo=yes auto-delete=yes
    login=ssh 密钥；将为该账号写入 sshd 例外（全局策略不变）：/etc/ssh/sshd_config.d/10-linux-temp-admin-xxvcc-a1b2c3.conf
  确认创建请输入 YES:
  ```

  Previously the operator typed YES and was only then asked whether sshd could be
  modified — agreeing to the account before seeing what it would cost the host. And
  when the post-creation re-check against the account's real groups finds that sshd
  accepts the login as it is, the promised exception is not written and the invite
  says so, rather than quietly skipping a file the summary had named.

- **No path in a root-run tool may panic, and none may hang.** The sshd probe is
  reached through a guard that reports an unwired collaborator instead of
  dereferencing it, and the `<InstallPath> version` probe — which executes a binary
  at an operator-controlled path, as root, after the account already exists — is
  bounded by a timeout. A binary that never returned would otherwise leave the invite
  suspended with the account created and nothing printed.

- **Host detection now finds IPv6, not only IPv4.** Detection was v4-only: the
  local-interface scan skipped anything `To4()` returned nil for, and the
  external-echo filter rejected every address with a colon — so on a v6-only host
  detection always came up empty and the operator had to type the address by hand.
  Two of the three legs now try IPv6 as well: the interface scan accepts a
  global-unicast v6 (via a new `validate.PublicIPv6` gate that excludes loopback,
  link-local, unique-local `fc00::/7`, and the `2001:db8::/32` documentation range),
  and the external echo services accept a v6 reply. IPv4 is still preferred on a
  dual-stack box as the more universally reachable choice, and a detected v6 flows
  through the same `[addr]` bracketing the invite already applied to a hand-entered
  one.

  Cloud metadata is deliberately *not* consulted for IPv6: unlike a public IPv4
  (often NAT'd and visible only through metadata), a global v6 sits on the interface
  itself, so the interface scan already covers it — and the three clouds expose no v6
  at a fixed leaf (AWS/Alibaba under `network/interfaces/macs/<mac>/ipv6s`, Tencent
  under `.../local-ipv6s`, each needing a per-provider two-hop lookup that buys
  nothing here).

- **`doctor` reports whether sshd would accept a key login** for a freshly created
  temporary account, so the answer is available before an invite is needed, and
  names any sshd exception that outlived its account. `cleanup-expired --compact`
  removes those orphans.

  Safety properties worth stating, because they are what make the sshd write
  defensible at all:

  - **Every reload is gated on `sshd -t` — on the way out as well as in.** A reload
    re-execs sshd against whatever is on disk. If an operator left a typo in
    sshd_config this afternoon and never reloaded, the running daemon is still
    happily serving its old in-memory config; an ungated reload fired at 3am by the
    auto-revoke timer would be the thing that finally takes SSH off the machine. A
    missed reload is recoverable; a dead sshd on a remote box is not.
  - **The SIGHUP fallback confirms the pid is really sshd** before signalling it.
    SIGHUP's default action is to terminate, pid files go stale, and pids are
    recycled — so signalling a number on faith is not a no-op that might miss, it is
    a root-privileged kill aimed at whatever inherited it.
  - **"Nothing to reload" is not reported as success.** If no init system took the
    reload and no live sshd could be signalled, the drop-in stays (a socket-activated
    sshd reads it on the next connection) but the invite says UNVERIFIED rather than
    claiming a running daemon adopted a file it never saw.
  - **A narrowed crypto policy is preserved.** Lifting a `PubkeyAcceptedAlgorithms`
    restriction re-states the operator's effective list and appends `ssh-ed25519`,
    rather than writing `+ssh-ed25519` — OpenSSH's `+` appends to its *compiled-in
    default* set, so on precisely the FIPS/crypto-policy hosts where this can fire it
    would have handed the account sshd's entire default algorithm list. The directive
    is written back under the name that host's own sshd used for it (it was renamed
    in 8.5).
  - **An address-qualified `AllowUsers user@host` rule yields no verdict, not a pass.**
    The tool cannot know which IP the invitee will connect from, so it reports the
    login as UNVERIFIED instead of claiming a proof — and does not "fix" it either,
    since writing `AllowUsers <account>` would quietly cancel the operator's network
    restriction. Deny rules fail closed for the same reason, in the other direction.
  - **The login is re-checked against the account's real groups** once it exists.
    The preflight has to predict them (it runs before the account does), and
    `useradd` only gives an account a group of its own name where `USERGROUPS_ENAB`
    is on — so a host that drops new accounts into a shared group plus a
    `DenyGroups users` rule would otherwise have been stamped "verified" on a login
    sshd refuses.
  - **The auto-revoke timer is kept able to clean up after this invite.** It executes
    whatever binary sits at `InstallPath`, and an older one would delete the account
    and its registry row while leaving the sshd exception behind forever — so an
    older installed binary is now upgraded to this one.
  - **`--fix-sshd` is not defeated by a network-scoped `AllowUsers`.** An
    address-qualified rule such as `AllowUsers *@10.0.0.0/8` ("SSH only from the VPN")
    cannot be evaluated without knowing the invitee's address, so it is treated as a
    reason to print UNVERIFIED — never as a blocker to "repair" (which would silently
    cancel the network restriction) and never as something that fails the drop-in's
    proof-of-effect (the drop-in still makes the key work; that is what the proof
    checks). A bare `AllowUsers <account>` alongside it still counts as an
    unconditional pass.
  - **An address- or host-scoped `Match` block downgrades the invite to UNVERIFIED.**
    `sshd -T -C user=X` cannot evaluate `Match Address`/`Match Host` — the invitee's
    source address is unknown — so a host that, say, denies the account from the
    public internet would otherwise read as "verified" from a no-address probe. The
    tool now detects the presence of such a block (in the main config and the drop-in
    directory) and says UNVERIFIED rather than overclaiming. A block hidden in a
    deeply nested Include this scan does not reach falls back to the prior behaviour;
    it is never made worse.
  - **A revoke that cannot safely reload no longer tells the operator to hand-delete a
    file that is already gone.** When `Remove()` deletes the exception but skips the
    reload because the host's sshd config is invalid, the message now states exactly
    that, instead of a "removal failed; delete it by hand" that named a vanished path
    and buried the real problem.

  Two residual trade-offs, stated rather than hidden: an init-system `reload` command
  that exits 0 is trusted as success even though a SysV `service` script could in
  principle no-op on a host whose sshd is not running (a socket-activated sshd reads
  the new config on the next connection regardless, so this is not a false promise for
  that case); and when the binary already installed at `InstallPath` is an OLDER
  version, an `invite --auto-revoke` upgrades it in place (printing an INFO line) so
  the timer can clean up — which replaces a deliberately-placed older wrapper at that
  tool-owned path.

## v2.2.4 - Signature-verified bootstrap install

- **`install.sh` now verifies an ed25519 signature at first install.** The
  bootstrap installer previously trusted the release with only a same-origin
  SHA-256 checksum (trust-on-first-use). It now also verifies a detached ed25519
  signature against the release public key embedded in the script — the same
  offline key `upgrade` uses — failing closed on any mismatch, so a tampered or
  maliciously re-published binary is rejected even if the release host is
  compromised. When openssl (>= 3.0, for `pkeyutl -rawin`) is unavailable the
  install fails closed unless `LTA_ALLOW_UNVERIFIED=1` opts into checksum-only
  trust; the wget path probes for `--https-only` so BusyBox-only hosts still
  install. The Go binary is unchanged from v2.2.3.
- **Docs.** The security policy drops the removed v1 (bash) support line, and the
  README is reorganized as a focused user manual.

## v2.2.3 - invite refuses names revoke would protect

- **`invite` no longer creates an account the tool could never revoke.** A
  username in a reserved namespace — an explicit `--user root` / `--user
  systemd-*`, or any name generated from `--prefix systemd` — passed creation but
  is refused by the revoke path, which protects `systemd-*` and well-known system
  names. The account (optionally with NOPASSWD sudo) could be created but never
  deleted: not by a manual `revoke`, nor by its own auto-revoke timer, which
  failed silently at fire time while the invite reported success and scheduled it.
  Creation now shares a single `IsReservedName` predicate with revoke and refuses
  these names up front — the prefix is checked on the name-generation path (an
  explicit `--user` leaves the prefix unused), and the final username is checked
  authoritatively so an explicit `--user` cannot slip a reserved name through.

## v2.2.2 - The menu stops scrolling your results away

- **The interactive menu no longer redraws after every action.** It is drawn on
  entry, and again whenever you press Enter on an empty line. Previously each
  action's output was immediately buried under eight lines of menu, so you had to
  scroll back to read it — worst of all for `invite`, whose bundle carries the
  one-time private key. Now the result is the last thing on screen, directly above
  a one-line prompt (`请选择 [1-8]（回车显示菜单）` / `select [1-8] (Enter shows
  the menu)`), and results are framed with blank lines that do not depend on the
  terminal echoing your Enter, so piped and scripted runs read the same.
- A blank line at the prompt now redraws the menu instead of reporting an invalid
  choice.

## v2.2.1 - install tells the truth; the menu drops it

- **`install` no longer claims a write it did not make.** Running `install` from
  the already-installed binary finds the target byte-identical and does nothing —
  that short-circuit precedes the `--force` check — yet it printed "installed the
  stable command" and appended a matching `install ok` line to the audit log. It
  now reports "already the stable command; nothing to install" and audits nothing.
  `Manager.Install` returns whether it wrote, mirroring `Upgrade`'s `("", nil)`.
- **The interactive menu drops `install`.** Reaching the menu means a binary is
  already running as root, so `install` there was either the no-op above or a
  one-time bootstrap better done as `sudo ./linux-temp-admin install`. That made
  it look like a duplicate of `upgrade`, which its old label ("Install/update the
  current binary...") reinforced. `upgrade` is now the menu's single,
  signature-verified update path; the prompt range follows the table, so entries
  renumber and the menu is now `[1-8]`.

  `install` remains a subcommand: it is the only way to place a binary you already
  hold — an air-gapped host, or a self-built binary that carries no release
  signature (`upgrade` is HTTPS-only and fails closed without one). And
  `Manager.Install` stays what both `upgrade` and auto-revoke's
  `ensureStableInstalled` are built on.

## v2.2.0 - Full Chinese UI; v1 removed

- **Chinese is now the default UI language.** Precedence is unchanged (`--lang` >
  `LINUX_TEMP_ADMIN_LANG` > `LC_ALL`/`LANG` > fallback), but the fallback is now
  Chinese instead of English. Most servers run with no `LANG` set, so the Chinese
  UI of this Chinese-first project was almost never reached. An `en*` flag, env
  var, or locale still selects English; a locale in some third language (say
  `de_DE`) now gets Chinese where it previously got English.
- **Interactive menu is now fully localized.** Menu entries 1–8 previously printed
  bare English subcommand names in both languages, so `--lang zh` (or a `zh_*`
  locale) produced a Chinese title and heading over an English menu body. Each
  entry now carries a translated description, and label and dispatch live in one
  table so a reordered entry can no longer run the wrong command.
- **Host detection no longer interrogates before it looks.** `invite` without
  `--host` used to ask "detect public IP? [y/N]" before doing anything, so the
  common case cost an extra keystroke and defaulted to No. Cloud metadata and
  local interfaces — neither of which leaves the host or its link — are now
  probed silently, and what they find prefills the host prompt (Enter accepts,
  or type over it). The external echo services (`api.ipify.org` and friends)
  still require an explicit yes, because that step discloses the server to a
  third party. `--yes` mode is unchanged: it never reaches out and still
  requires `--host`.
- Restored the `TerminateProcesses` uid guard test that was lost with the v1
  unit-test suite: `kill` is now indirected so a test can prove a non-positive
  uid signals nothing, without signalling every root process when the guard
  regresses.
- **v1 (bash) tool removed.** `temp-admin.sh`, its unit tests, and its ShellCheck
  workflow are deleted, along with the `internal/legacy` detector and the leftover
  v1 artifact warnings `doctor` used to print. The ShellCheck workflow now lints
  `scripts/` instead. Both READMEs are rewritten to document the Go tool directly
  rather than carrying the v1 manual below a deprecation banner.
  - Upgrading from v1 is no longer assisted: drain v1 accounts with a v1 checkout
    (git tag `v1.2.3`) before removing its registry at
    `/var/lib/linux-temp-admin/users.tsv` and its
    `linux-temp-admin-revoke-*` systemd units. This tool never touched them; it
    only reported them.

## v2.1.0 - Operation audit log; v1 deprecation

- **Operation audit log (new).** Every privileged mutating operation — account
  create/delete, and install / uninstall / upgrade — is appended as a JSON line to
  a root-owned, append-only `/var/log/linux-temp-admin/audit.log` (0600), recording
  the timestamp, actor (the invoking user under sudo, plus the effective uid),
  action, target, result, and key parameters. Writes are best-effort and never
  block or fail the operation itself. (An on-host log is tamperable by root;
  forward it to a remote collector for tamper-evidence.)
- **v1 (bash) tool deprecated.** `temp-admin.sh` is no longer maintained and now
  prints a deprecation notice at startup pointing to the v2 Go tool (suppress with
  `LTA_SUPPRESS_DEPRECATION=1`). It still runs; no further features or fixes.

## v2.0.2 - Audit follow-up hardening

Low-severity hardening from the follow-up audit:

- **upgrade: reject redirects to private/reserved addresses.** An `upgrade` HTTPS
  redirect is refused if it resolves to a loopback / private / link-local / CGNAT
  address, so a compromised release host cannot use the root-run fetch as an SSRF
  pivot (e.g. to cloud metadata). The initial, operator-supplied `--url` is
  unaffected, so a deliberate internal mirror still works.
- **auto-revoke: stop orphaning systemd `.service` files.** `revoke` now precisely
  detects whether it is the firing auto-revoke service for a unit (via the process
  cgroup) rather than treating any systemd scope as such, so a manual `revoke` run
  from a systemd-managed shell no longer leaves an orphaned `.service` behind.
- **SSH port hint: consistent selection.** With multiple `Port` directives in
  `sshd_config`, the config fallback now reports the first (matching `sshd -T`)
  instead of the last.

## v2.0.1 - Security & correctness audit fixes

Follow-up hardening from a multi-pass security audit of the v2 rewrite. No new
features and no command/flag changes; existing behavior is unchanged except for the
`revoke` protection fix noted below.

- **revoke: never delete a real account via a stale registry entry.** A UID>=1000
  account is now protected unless it carries the tool's managed GECOS marker — a
  per-account, reuse-proof signal — instead of trusting a name-keyed registry entry
  that can outlive a deleted temp account and be inherited by a later real user of
  the same name. The managed check is now an exact GECOS-field match, not a
  substring, matching its documented guarantee.
- **invite: a failed sudo grant can no longer leave a NOPASSWD drop-in behind.** The
  drop-in is removed on any grant/verification failure, and a removal failure is
  reported rather than silently swallowed.
- **upgrade: version comparison is numeric-aware for prereleases** (`rc10` > `rc9`),
  closing an anti-rollback gap where a signed older prerelease could pass the
  "not newer" gate and a genuine prerelease upgrade could be skipped.
- **public-IP auto-detection rejects private/reserved addresses** on the external
  echo path too (previously only the cloud-metadata path filtered them).
- Fail-closed hardening: refuse the SSH-key write when the home directory's owner
  cannot be determined; refuse to replace an installed binary that cannot be read
  back unless `--force` is given.

## v2.0.0 - Go rewrite

Full rewrite of the tool in Go, shipped as a single static binary. The bash tool
remains as the `v1.x` maintenance line; the two can coexist.

- Same commands and behavior as v1.2.3 (invite / revoke / status / cleanup-expired
  / doctor / install / upgrade / uninstall / menu, bilingual zh/en, `--lang`).
- Native implementations replace the external tools the bash version shelled out
  to: ed25519 keygen (no `ssh-keygen`), HTTP with context timeouts (no
  `curl`/`wget`), Go `time` (no `date`), `/etc/passwd` parsing (no `getent`),
  atomic fd-based writes (no `install`), `syscall.Flock` (no `flock`), and a
  `/proc` scan (no `pkill`) — eliminating whole classes of shell/`set -e`/BusyBox
  portability bugs. Only the account tools (`useradd`/`usermod`/`chage`/`userdel`
  or BusyBox `adduser`/`deluser`), `systemctl`/`at`, and `visudo`/`sudo` are still
  invoked, via argv (no shell).
- **Signature-verified self-upgrade**: `upgrade` downloads over HTTPS and verifies
  a detached ed25519 signature against an embedded release key before installing,
  failing closed — the authenticated upgrade the bash tool never had.
- The one-time private key stays in memory and is printed once (never written to
  disk). TOCTOU-safe atomic root writes (fd-based owner/mode, `O_NOFOLLOW`,
  rename-not-follow). flock-guarded registry with atomic rewrite.
- Clean break from v1 state: separate registry directory
  (`/var/lib/linux-temp-admin/v2/`) and systemd unit namespace; `doctor` detects
  and reports leftover v1 artifacts without touching them.
- Tested: per-package unit tests, a 119-input differential parity harness vs the
  bash validators, root integration tests (symlink-attack, concurrent-flock,
  real invite→revoke lifecycle, signature accept/reject), all under `-race`;
  static amd64/arm64 cross-builds. Reviewed by a multi-agent parity/security audit.
- Release/signing: `docs/releasing.md`, `scripts/release.sh`, `scripts/install.sh`.

## v1.2.3 - 2026-07-07

- Fixed the `wget` upgrade download and public-IP autodetection failing on BusyBox/musl (Alpine): the GNU-only `--timeout`/`--tries`/`--dns-timeout`/`--connect-timeout` options are now probed, and on BusyBox wget the fetch is bounded with `timeout(1)` instead (BusyBox `-T` segfaults on some builds).
- Made the `/proc` kill fallback and the `getent`->/etc/passwd helpers errexit-safe, so an empty `/proc` status read (process vanished mid-scan) or a non-zero `getent` can no longer abort a revoke/rollback or `status` under `set -e`.
- Added `install(1)` to the dependency check, `doctor`, and the package map (coreutils), so a BusyBox build without the `install` applet is reported and auto-installable instead of failing cryptically mid-invite.
- Made the BusyBox `wget` path fail fast when it cannot be time-bounded (no `--timeout` support and no `timeout(1)`) instead of running an unbounded fetch that could hang for minutes on a stalled connect.
- Aligned the future-date capability probe with the compound `date` expression actually used for expiry, so a `date` that supports simple but not compound offsets can no longer report OK and then fail mid-invite.
- Hardened the `/proc` kill fallback to no-op for an empty or root (0) UID, and tightened the `at`-job cleanup to match the exact queued revoke command rather than a loose substring.
- Reworked account expiry to a timezone-aware date (first midnight after `now + hours`) that is never set before the requested window on any creation time, replacing the day-rounding that could lock a `--no-auto-revoke` account early (or, on scheduling failure, keep it loginable ~1 day too long).
- Made `cancel_auto_revoke` clean up both the systemd units and any matching `at` job, so reusing a username can no longer leave a stale auto-delete task that later removes a freshly created account.
- Cancelled the pre-created auto-delete task when the registry write fails, so a partly-created account is not left with a task that could never delete an unregistered user.
- Made `cleanup-expired --compact` prune under a single held lock (re-checking existence inside it) so a concurrent invite cannot lose its fresh registry entry.
- Documented `--lang`, `version`, `upgrade --force/--url`, and `expiry-status --compact` in `help`/usage; aligned `valid_installed_version` with the 3-component version comparator; matched real-or-effective UID in the pkill fallback; and hardened the getent fallback against duplicate rows.

## v1.2.2 - 2026-07-07

- Fixed `upgrade` silently refusing to replace an existing older install (reported `installed=none` and no-op'd): `installed_revoke_version` shadowed the caller's variable, so the version comparison never saw the installed version.
- Added a `getent`->/etc/passwd fallback so `invite`/`status`/`revoke` work on musl/BusyBox systems (Alpine) where `getent` is absent, instead of failing mid-creation and rolling back.
- Added a `/proc`-scanning fallback for forcing off a user's sessions when `pkill` is unavailable (BusyBox/Alpine), so revoke no longer deletes an account while leaving its processes running.
- Hardened the managed-account check to require the full GECOS tag rather than a bare substring.
- Avoided running `sshd -T` twice per `doctor` (a bilingual message double-evaluated the port probe).
- Fixed the auto-delete unit name being corrupted by the "stable command installed" banner, which had let stdout from the install step leak into the recorded systemd/at unit and broke later revoke cleanup and status lookups.
- Tightened `--no-auto-revoke` account expiry: the extra day-granular safety buffer is now added only when an auto-delete timer will remove the account first, so expiry-only accounts no longer stay loginable up to a day past the requested window.
- Bounded `wget` upgrade downloads to the configured size limit during transfer instead of only after writing the whole file.
- Blocked HTTP-downgrade redirects on the `wget` upgrade fallback (`--max-redirect=0` where supported), matching curl's HTTPS-only redirect policy.
- Added unit coverage for install stdout cleanliness, buffered vs. unbuffered expiry dates, and the wget redirect guard.

## v1.2.1 - 2026-07-07

- Hardened upgrade downloads with a 1 MiB size limit and cleanup of failed or oversized downloads.
- Made critical write paths explicitly check copy, append, chmod, and rename failures instead of relying on `errexit`.
- Ensured interactive-menu invite/install/upgrade failure paths abort cleanly and preserve rollback behavior.
- Corrected invite/revoke/uninstall status reporting when registry cleanup or file removal fails.
- Added unit coverage for failed upgrade downloads, oversized downloads, and registry append failures.

## v1.2.0 - 2026-07-07

- Added `doctor`, `install`, `upgrade`, and `uninstall` commands.
- Added interactive menu entries for system diagnosis, installation, upgrade, and uninstall.
- Hardened upgrade/install behavior with HTTPS-only downloads, version parsing, Bash syntax validation, and root-owned path checks.
- Added project governance files: `SECURITY.md`, `CONTRIBUTING.md`, GitHub issue templates, and a pull request template.
- Expanded unit tests for upgrade URL validation, version comparison, help output, and command argument errors.
- Updated Chinese and English README maintenance documentation.

## v1.1.2 - 2026-07-07

- Hardened NOPASSWD sudo handling by validating the effective sudo policy and cleaning up on failure.
- Required safely root-owned files/directories before executing or writing managed root paths.
- Rejected invalid `--lang` values instead of silently ignoring them.
- Excluded additional non-public IPv4 documentation ranges from auto-detection.
- Added unit tests and CI coverage for Bash syntax, ShellCheck, and function-level checks.
- Ignored local runtime/test fixture directories via `.gitignore`.

## v1.1.1

- Prompted for UI language on interactive operational subcommands.
- Preserved non-interactive behavior for `--yes`, CI, and piped runs.

## v1.1.0

- Merged Chinese and English behavior into a single bilingual script.

## v1.0.0

- Hardened the temporary admin workflow after security review.
- Added registry, revoke, auto-expiry, rollback, and safety checks for managed system files.
