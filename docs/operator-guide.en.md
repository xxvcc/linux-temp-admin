# Operator Guide

[中文](operator-guide.md) | English

This guide covers routine account management with `linux-temp-admin`. See the [installation guide](installing.en.md) for installation and upgrades, and the [security model](security-model.en.md) for detailed guarantees.

## Interactive menu and language

Run without a subcommand to enter the interactive menu:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin
```

The menu is shown on entry and again after you press Enter, leaving the previous operation's result visible. The first interactive run asks for Chinese or English and stores the choice in `/var/lib/linux-temp-admin/v2/prefs`. The menu can switch languages later.

Language precedence is `--lang zh|en`, `LINUX_TEMP_ADMIN_LANG`, the saved choice, the first-run prompt, then Chinese. System `LANG` and `LC_ALL` do not select the interface language.

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin --lang en status
```

Non-interactive tasks cannot prompt and use the saved choice, or Chinese if no choice exists. Prefer an explicit `--lang` through sudo instead of broadly preserving the caller's environment.

## Create an invite

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

The interactive flow:

1. chooses a username, using a random suffix by default;
2. detects or asks for the invite host and SSH port;
3. grants sudo by default, with an option for a regular account;
4. asks whether to auto-delete and then asks the lifetime only when enabled;
5. shows the complete summary for confirmation;
6. creates the account and grants, creates a task when automatic revocation is enabled, and only then prints the invite credential.

Before creating anything, the tool checks whether the planned credential is compatible with the effective sshd configuration. An unresolved blocker reported by the check refuses creation, and incomplete knowledge is reported as `UNVERIFIED`. "Verified against the effective sshd config" means only that this configuration check completed without a known blocker or unevaluated rule; it is not end-to-end proof of the network, firewall, PAM, SELinux, or running sshd state. Test the invite through the intended connection path before delivery.

### Host detection

Without `--host`, interactive mode first queries fixed-address cloud metadata endpoints and inspects local interfaces. Those endpoints are `http://169.254.169.254/latest/meta-data/public-ipv4` and `http://100.100.100.200/latest/meta-data/eipv4`, and both are requested before the create confirmation. The first is link-local; the second is in the `100.64.0.0/10` shared address space and is **not guaranteed to stop at the local link**, so on a non-cloud host these are two requests that may leave the machine. Interface inspection sends no traffic; metadata uses plaintext HTTP and avoids DNS, redirects, and environment proxies, but it may traverse the local or cloud-provider network and its response is unauthenticated. The detected value is only a default that the operator must confirm or replace. Especially for password login, verify the Host first through the cloud console, DNS, or another independent channel so the invitee is not directed to submit the password to the wrong SSH server. Only when no public address is found does the tool ask permission to query a public IP service, which exposes the server's egress address to that third party; that result also requires confirmation.

`--yes` mode never queries a public IP service and requires an explicit `--host`. The host accepts a plain domain, IPv4, or IPv6 value; pass the port separately with `--port`.

### Common variants

```bash
# 12 hours with sudo
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --hours 12

# Regular account
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --no-sudo

# Explicit username, prefix, host, or port
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --user ops-a1b2c3d4e5 --sudo
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --prefix ops --sudo
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --host admin.example.com --port 2222 --sudo

# Permanent account: no expiry and no automatic removal
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --no-auto-revoke
```

With automatic removal disabled, only `revoke` deletes the account and `--hours` is ignored.

The account-database entry is past-date expired and password-locked from `useradd`, and `/etc/skel` is not copied. Before that helper runs, the tool permanently burns a UID/GID in a root-only high-water file, then pins the account and private group to that same number. A default generated username has a long random suffix, so normal menu creation does not reuse a numeric identity previously released by this tool. With `<32hex>` denoting the 32 lowercase hexadecimal generation characters, the current version starts with the first four GECOS subfields empty and writes a compact generation witness in the fifth trailing/other field: `,,,,lta-m=<32hex>` when complete and `,,,,lta-p=<32hex>` while pending. An older binary sees no old-format marker in the first field and therefore fails closed on such a new account. While Home remains absent, two process-termination passes clear the same-name crontab and target-UID `at`/`batch` jobs without a 65-second foreground wait. An explicit `--user` may still reuse a historical name and a daemon-cached name-keyed job, so that exceptional path explains why it waits one polling cycle synchronously. The invite transaction keeps comparing the complete passwd snapshot captured after `useradd`; an empty mode-`0700` Home is created only after cleanup, exact-snapshot checks, and residual-process checks pass. The account is activated only after its password/key, grants, registry state, and automatic revoke task are complete. The requested lifetime starts after cleanup, so an explicit-name safety wait does not shorten the access requested by `--hours`.

## Deliver the invite

The bundle contains Host, Port, User, expiry, sudo state, login verdict, and a command that saves the one-time private key. Only the public key is stored on the server; the private key is printed once after successful creation.

Forward the complete bundle through trusted private chat. After saving the key, the collaborator forms the SSH command from the header fields:

```bash
ssh -i ./USER.key -p PORT USER@HOST
```

Invite fields and command blocks use a fixed English format so the bundle can be forwarded verbatim. Never put a real invite in a group chat, ticket, knowledge base, or public page.

## Automation and non-interactive use

A non-interactive invite requires an explicit host. Granting sudo must repeat the username, and non-terminal stdout must explicitly acknowledge that the output channel can carry a private key:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 --port 22 --hours 24 \
  --sudo --install-deps --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

Unattended mode never installs dependencies or changes sshd implicitly; pass `--install-deps` or `--fix-sshd` explicitly. Treat logs, CI output, and downstream pipelines as private-key channels.

## Inspect status

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status --user xxvcc-a1b2c3d4e5
```

Status reports account identity, UID, expiry, auto-delete task, identity-quarantine deadline, and registry anomalies. An account created by v2.9.3 or earlier that still has only a first-field GECOS generation witness is shown as `generation-bound-first-field-compat`; `doctor` recommends revoking it promptly and issuing a new invite with the current version. `doctor` also reports orphaned sudoers files and sshd exceptions, plus orphaned, missing, or invalid expiry-revoke and quarantine-finalizer tasks; with no account awaiting a schedule, it does not independently prove that the systemd or `at` backend is available.

## Revoke an account

```bash
# Choose from a list
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke

# Name one account
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

When the stable identity can still be checked, normal systemd revoke first removes and confirms sudoers/sshd grants, disables login, and performs two personal-crontab, target-UID `at`/`batch`, and process cleanup passes. It then establishes persistent identity quarantine and returns immediately. The current format requires the registered name, UID/GID, deterministic Home, and fifth-field `lta-m=` generation witness to remain exact. Supported standard account tools give ordinary users no path to rewrite that fifth field, so self-service full-name, room, work/home phone, or nonempty-shell changes, including a concurrent loop, do not hold revoke open. A stable-field or fifth-field-witness change fails closed. A local root that can directly rewrite the account database or program state remains inside the trust boundary. The list shows “access revoked; quarantined”; the passwd entry holds the name and UID/GID for at least 65 seconds (less than 125 seconds after minute rounding) while remaining expired, password-locked, and without a tool-managed sudo/sshd entry. At the deadline, a background timer repeats the checks and then removes the account, deterministic `/home/<username>` directory, UID-matched conventional mail spool, public key, and tasks. A persistent timer catches up after the host was down across the deadline. Without systemd, revoke still waits 65 seconds in the foreground and completes final deletion synchronously. Uninstall also finalizes synchronously so it cannot remove the command still needed by a background task. If the account disappeared outside the tool, revoke cleans only the registry, name-scoped grants, and tasks that remain safely identifiable, plus the narrow mail-spool cleanup authorized by an existing deletion-recovery witness. Recursive Home cleanup proceeds only for a real directory owned by the registered account's UID/GID with no mount boundary underneath. Home cleanup uses directory descriptors and rejects a symlink at the Home root; an internal symlink is unlinked without following its target. Traversal checks cooperative budgets of 100,000 entries, 128 levels, and two minutes between filesystem calls, so the deadline cannot interrupt one blocked filesystem call. Cron/at and process results are repeated snapshots, not an atomic freeze. If a safety condition, resource limit, job/process inventory, or name-scoped grant cannot be confirmed, revoke attempts to disable the account, retains any surviving account and the registry witness, and returns nonzero so username reuse cannot inherit old data, deferred work, or privilege.

Mail-specific cleanup handles only a traditional single-file mbox at `/var/mail/<username>` or `/var/spool/mail/<username>`. An existing mail spool must be root-owned and have no setuid bit; a world-writable spool must have sticky protection. Thus `root:mail 3777` and Arch Linux's `root:root 1777` work, while mode `0777`/`2777` without sticky and a non-root owner such as `mail:mail` fail closed. The target mailbox must also be a non-symlink regular file owned by the captured UID. `invite` checks the spool before `useradd` and again after the UID is known. A preflight failure leaves no account; a post-helper failure attempts rollback and retains an expired, locked, credential-less account plus its registry witness when cleanup cannot be confirmed. This specialized path neither searches nor traverses Maildir and never touches aaPanel's `/www/vmail`; a Maildir inside a tool-managed Home is still removed with the whole Home under the normal complete-revocation rules.

Before deleting an `at` job, the tool rereads its body and rechecks the UID or exact revoke command so a reused job ID cannot authorize deletion of an unrelated task. `at` has no atomic compare-and-delete interface, so a very short local-root trust-boundary interval remains between that read and `atrm`.

For compatibility with old automatic tasks, a `revoke --yes` command without UID/generation arguments cannot prove that its old deletion intent still names the same account if it collides with a concurrent same-name `invite`. The command warns explicitly, deletes no account, and exits successfully so systemd cannot retry the old task against the new generation; a manually issued non-interactive command of the same shape follows the same rule. After the concurrent operation finishes, run `doctor` and invoke `revoke` again against the current account.

An account reported by `doctor` as `legacy-unverified` carries an old fixed identity marker, so same-name/same-UID reuse cannot be excluded. After manual inspection, it can be recovered only by running `revoke --user <name> --force` in an interactive terminal and typing the complete username. If the old v2 registry row still has only nine fields and therefore no recorded UID, this manual path is available only while the current account retains the exact fixed marker and has UID 1000 or greater. Before stripping a grant, disabling login, or deleting anything, the command formally migrates the registry to v5, creates `identity-sequence`, and rechecks both the semantic registry record and complete passwd snapshot; a migration or recheck failure leaves those account states untouched. The historical timer's `--yes --force --confirm-force` arguments and every other non-interactive invocation are denied deletion authority for this account class; low or root UIDs, reserved names, and marker mismatches remain protected. `doctor` reports any surviving old task as orphaned, and `cleanup-expired --compact` cancels that task while retaining the live account and registry row for manual handling.

A generation-bound account created by v2.9.3 or earlier has only the old full marker in its first GECOS field. While it remains unchanged, `status` reports `generation-bound-first-field-compat` and ordinary or automatic revoke can still use the recorded UID/generation plus the complete old snapshot. Every passwd reread during revoke must be byte-for-byte equal to the snapshot captured at its start, and `doctor` advises revoking the account promptly and issuing a new invite with the current version. `status` and `doctor` never rewrite an old account implicitly. If its first-field witness is already gone and it has no fifth-field witness, the account stays protected for operator inspection and manual handling. Same-name/same-UID guesses cannot recover it, and the tool never reconstructs the missing witness from registry contents.

After upgrading from v2.9.1 or another older release, manually verify any live pending creation row shown by `status` or `doctor` really came from a failed invite. Selecting that row in the menu automatically enters the same recovery gate as `revoke --user <name> --force`, and an interactive terminal must still type the full username. The tool also checks the random pending generation, GECOS, recorded UID (zero or the current UID), managed Home, non-root UID/GID, and nonempty shell. With systemd, a proved pending identity is immediately stripped of access and retains its exact generation in background quarantine. Only the synchronous fallback weakens it to a UID-only deletion-recovery witness. `--yes`, automatic revoke, uninstall bulk removal, piped input, and every identity mismatch refuse the initial recovery authorization.

After deletion authorization, identity checks, and the pre-artifact job/process quiescence pass succeed, the tool persists a deletion-recovery witness before controlled mail/Home cleanup and `userdel`; after Home cleanup it checks jobs, processes, and stable identity again immediately before `userdel` (name, UID/GID, Home, and fifth-field generation witness, or the complete snapshot for an old single-marker account). If account deletion, the post-deletion mail-spool sweep, or task cleanup is interrupted, `status` and `doctor` show the recovery state, a same-name `invite` refuses to overwrite the witness, and `cleanup-expired --compact` does not discard the witness. When the account is absent or still exactly matches the recorded generation, run `revoke --user <name>` to resume. For an absent account, every narrow mail sweep confirms before and after that neither the local passwd database nor NSS contains the name. An identifiable automatic task is retained in either state, but only a systemd job retries automatically under its restart policy; `at` and legacy one-shot jobs require a manual retry. Legacy, unregistered, and pending-rollback paths retain only a UID witness. If that account is still live, inspect it and run `revoke --user <name> --force` in an interactive terminal, then type the complete username; every non-interactive invocation is refused. The old automatic task for such a live account is treated as orphaned and cancelled, while the registry witness remains for manual recovery.

Deleting an unregistered account requires explicit `--force` and an additional username confirmation; it does not override protection for reserved names, UID 0, or unregistered/legacy-identity low-UID accounts. If a system assigns a new tool-created account a low UID, it remains normally revocable only while the registered name, current UID/GID, deterministic Home, random generation, and exact compatible GECOS witness are fully bound. A real account without the tool's exact witness is never treated as managed.

## Clean anomalous state

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
```

`cleanup-expired` removes stale registry rows and orphaned sudoers files, sshd exceptions, and revoke tasks. It **never deletes an account**. Use `revoke` to delete an account and `status` to list them.

## Public-key login is disabled

If sshd disables public-key login, changes the `authorized_keys` path, or uses an AllowUsers list, the tool reports it before creation; an unresolved blocker refuses the invite.

The preferred repair is an exception scoped only to the new account:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --fix-sshd
```

This option writes an account-scoped sshd drop-in without changing global policy. It checks syntax with `sshd -t`, then checks the effective configuration with `sshd -T -C user=...`. When a running sshd can be reached, it requests a reload and never a restart. If no running daemon can be notified, the file remains for socket activation or the next start, but the invite says `UNVERIFIED`. Other grant failures attempt to remove the file and abort; a failed removal or restorative reload returns nonzero and retains recovery evidence. A successful `revoke` removes the exception and requests another reload. Explicit `DenyUsers` and `DenyGroups` rules are never bypassed.

When public keys cannot be used, password login can be selected explicitly:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --password-login
```

The tool creates a random password shown once only after the effective sshd configuration check finds neither a password-credential blocker nor an unevaluated rule. This is still not an end-to-end login test. Passwords are the weaker grant because they can be attacked over the network throughout their lifetime; prefer public keys.

## Expiry and automatic revocation

The default lifetime is 24 hours with automatic revocation scheduled. A persistent systemd timer is preferred; an existing `at`/`atd` service is used only when systemd is unavailable or its failed scheduling attempt was safely rolled back. `at` is never installed automatically. If neither backend can schedule revocation successfully, the invite enters fail-closed rollback. If account, grant, or task cleanup cannot be confirmed, the command returns nonzero and, when necessary, retains a disabled account and registry witness for manual recovery instead of reporting an incomplete cleanup as success.

A default random-name invite computes its lifetime once after immediate job cleanup and no longer has a 65-second foreground wait. An explicit `--user` computes it after the name-reuse defense, so that safety wait does not shorten the requested duration. The target is rounded upward to a whole minute, adding less than one minute. Display, systemd, and `at` share that absolute target; `at` uses an absolute UTC minute so daylight-saving changes cannot make it run early. `chage -E` provides only a possibly later, day-granularity lock fallback. Scheduler load, host downtime, and retries can delay actual removal; revoke access manually as soon as it is no longer needed. The task binds the original name, UID/GID, deterministic Home, random generation token, GECOS witness, and registry record. The current format permits ordinary user-field changes but refuses deletion after a stable-identity mismatch or account removal and recreation.

## Uninstall

```bash
# Interactive: scan and show the uninstall inventory, then type YES
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall

# Non-interactive; managed accounts require explicit removal authorization
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users

# Remove managed accounts and also delete the audit log retained by default
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users --purge-audit
```

Uninstall first applies the same identity checks and cleanup as a normal `revoke` to each account in the inventory. It deletes state and the program only after confirming that every account, grant, exception, and task is gone. Any item that cannot be confirmed during account cleanup aborts the uninstall and keeps the management command and state. Running uninstall from the temporary account's own session is refused.

A live account whose NAMED BY column reads `passwd-marker-block-only` is named only by the lifecycle marker in its passwd GECOS field: no registry row, and none of this tool's sudo grants, sshd exceptions, or auto-delete tasks. Such an account is never deleted automatically, and by default it also aborts the uninstall — it may be a permanent account whose registry row was lost, but it may equally be **any local user** who wrote the same text onto their own account with `chfn`. Once you have confirmed it is not an account this tool created, clear the marker (`usermod -c '' <name>`) or skip it explicitly:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --ignore-foreign-markers
```

The switch applies only to that one shape, and every skipped account is printed by name. As soon as the username also carries any grant, exception, task, or registry row of this tool's, it blocks the uninstall as before. Skipping never deletes an account; it only stops it from blocking.

The audit log remains at `/var/log/linux-temp-admin/audit.log` by default. The lifecycle lock and uninstall marker also remain; current binaries check the marker after taking the lock and refuse to recreate state. A previously loaded binary from before this protocol may not check it, so the marker does not guarantee control over every historically queued process. An explicit reinstall handles the marker.

## Written paths

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

An `at` queue entry may also exist when systemd is unavailable. The sshd file exists only after explicit `--fix-sshd`, and the sudoers file exists only for a sudo-enabled account.
