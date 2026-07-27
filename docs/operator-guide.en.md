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
6. creates the account, grants, and revoke task before printing the invite credential.

Before creating anything, the tool evaluates the effective sshd configuration to rehearse whether the new account can log in. A definite blocker refuses creation; incomplete knowledge is reported as `UNVERIFIED` rather than presented as a verified result.

### Host detection

Without `--host`, interactive mode first checks cloud metadata and local interfaces; these checks do not leave the host or local link. Only when no public address is found does it ask permission to query a public IP service, which exposes the server's egress address to that third party.

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

Status reports account identity, UID, expiry, auto-delete task, and registry anomalies. `doctor` also reports orphaned sudoers files, sshd exceptions, revoke tasks, and missing schedulers.

## Revoke an account

```bash
# Choose from a list
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke

# Name one account
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

Revoke removes the account, home directory, public key, sudoers grant, account-scoped sshd exception, and automatic task. If a name-scoped grant cannot be removed safely, the tool retains and disables the account and returns nonzero so username reuse cannot reactivate a leftover grant.

Deleting an unregistered account requires explicit `--force` and an additional username confirmation. Root, UID 0, low-UID system accounts, and real accounts without the tool's exact marker are never treated as managed accounts.

## Clean anomalous state

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
```

`cleanup-expired` removes stale registry rows and orphaned sudoers files, sshd exceptions, and revoke tasks. It **never deletes an account**. Use `revoke` to delete an account and `status` to list them.

## Public-key login is disabled

If sshd disables public-key login, changes the `authorized_keys` path, or uses an AllowUsers list, the tool detects the problem before creation and refuses the invite.

The preferred repair is an exception scoped only to the new account:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --fix-sshd
```

This option writes an account-scoped sshd drop-in without changing global policy. It validates the file with `sshd -t` and `sshd -T -C user=...`, then reloads rather than restarts sshd. Any failure removes the file and aborts; `revoke` removes the exception and reloads again. Explicit `DenyUsers` and `DenyGroups` rules are never bypassed.

When public keys cannot be used, password login can be selected explicitly:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --password-login
```

The tool first verifies that sshd accepts passwords, then creates a random password shown once. This is the weaker grant because the password can be attacked over the network throughout its lifetime; prefer public keys.

## Expiry and automatic removal

The default lifetime is 24 hours with automatic removal enabled. A persistent systemd timer is preferred; an existing `at`/`atd` service is the fallback when systemd is unavailable. `at` is never installed automatically. If neither backend can schedule removal, the entire invite rolls back.

`chage -E` provides only a day-granularity lock fallback and can be later than the displayed expiry; the revoke task enforces the exact deadline. The task binds the original UID, random generation token, and registry record, refusing to delete an account that has been removed and recreated or no longer matches.

## Uninstall

```bash
# Interactive: show the complete inventory, then type YES
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall

# Non-interactive; managed accounts require explicit removal authorization
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users

# Remove managed accounts and also delete the audit log retained by default
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users --purge-audit
```

Uninstall removes managed accounts and their grants, exceptions, and tasks before deleting state and the program. A failure to delete any account aborts the uninstall instead of leaving a sudo-capable account without its management command. Running uninstall from the temporary account's own session is refused.

The audit log remains at `/var/log/linux-temp-admin/audit.log` by default. The lifecycle lock and uninstall marker also remain to prevent already queued old processes from recreating state; an explicit reinstall handles the marker.

## Written paths

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

An `at` queue entry may also exist when systemd is unavailable. The sshd file exists only after explicit `--fix-sshd`, and the sudoers file exists only for a sudo-enabled account.
