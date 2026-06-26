# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> One command to grant a collaborator a **time-limited, auto-deleting** temporary SSH admin account. The script prints an invite bundle you forward over private chat; the server stores only the public key, never the private key.

**linux-temp-admin** is for temporarily giving a trusted collaborator, ops engineer, or automation agent an SSH admin entry point — without sharing the root password, without leaving long-lived accounts, and with automatic cleanup on expiry.

[中文](README.md) | English

## Contents

- [Quick start (30 seconds)](#quick-start-30-seconds)
- [Language](#language)
- [What it solves](#what-it-solves)
- [Full walkthrough](#full-walkthrough)
- [Everyday commands](#everyday-commands)
- [Common usage](#common-usage)
- [Reference](#reference)
- [Security notes](#security-notes)
- [Development & license](#development--license)

## Quick start (30 seconds)

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
sudo bash temp-admin.sh invite --sudo
```

That's it. The script will:

1. Generate a fresh SSH key pair and create a temporary user (e.g. `xxvcc-a1b2c3d4e5`);
2. Print an **invite bundle** in the terminal — forward it to your collaborator, who follows the two commands inside it to log in, **with no need to understand any of the details**;
3. **Auto-delete** the user, home directory, and key after **24 hours** by default.

> Running `sudo bash temp-admin.sh` with no subcommand opens an interactive menu.

## Language

The script ships English and Chinese in a single file. The UI language is resolved in this order: `--lang zh|en` > the `LINUX_TEMP_ADMIN_LANG` env var > an interactive language prompt (shown once when you open the menu **or run any operational subcommand**, as long as you're on a terminal and haven't locked the language via the two options above) > the caller's locale > **English (default)**. To use Chinese:

> Piped runs (`curl ... | sudo bash`), non-terminal environments such as CI, and non-interactive `--yes`/`-y` runs never show the prompt — they fall back to locale/default; pass `--lang zh` or set the env var to force Chinese there. `help`/`version` are never prompted.

```bash
sudo bash temp-admin.sh --lang zh invite --sudo
# or, once per shell:
export LINUX_TEMP_ADMIN_LANG=zh
```

## What it solves

The usual ways temporary SSH access goes wrong:

- Handing out the root password;
- Leaving temporary accounts around long after they're needed;
- Forgetting public keys left in `authorized_keys`;
- Losing track of which temporary users you created;
- Not revoking sudo after use.

This script standardizes the whole flow: **create → print invite bundle → register → inspect → revoke → auto-delete on expiry**.

It will **not**: store the private key; generate or print any account/sudo password; modify SSH service config; touch the firewall; or open any inbound port.

## Full walkthrough

### 1. Download

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
```

### 2. Create an invite

```bash
sudo bash temp-admin.sh invite --sudo
```

In interactive mode it confirms the details (username, host, validity, sudo, auto-delete) and then prints the invite bundle.

### 3. You get an invite bundle like this (redacted)

This is only a format example and **cannot be used to log in**. Real private keys are generated at runtime and shown once in the terminal.

```text
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3d4e5
Expires: 2026-05-17 01:00:00 CST
Sudo: yes
Login: SSH key only
Password login: locked
Auto revoke: yes
Auto revoke unit: linux-temp-admin-revoke-xxvcc-a1b2c3d4e5

SSH login command:
ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10

Save private key command:
cat > './xxvcc-a1b2c3d4e5.key' <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: one-time private key generated at runtime]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 './xxvcc-a1b2c3d4e5.key'

Sudo note:
NOPASSWD sudo is enabled. This account can log in only with the SSH key; account password is locked.
Note: NOPASSWD sudo is equivalent to full root — this account can escalate to root and may leave behind root-owned processes, cron jobs, systemd units, or SUID files. Revoking only deletes this account itself; it does not clean up anything it created as root.

Revoke command:
sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5

Security notes:
- The private key is shown only once and is not stored on the server.
- Account password is locked; no account/sudo password is printed.
- Send only via trusted private chat; never post in groups or public pages.
- Run the revoke command immediately after use.
- The server stores only the public key; deleting the user invalidates this key immediately.

----- END LINUX TEMP ADMIN INVITE -----
```

### 4. Forward the bundle to your collaborator over private chat

They only need two steps, **with nothing to install and no knowledge of this tool**:

- Copy the "Save private key command" block and run it on their machine → they get the key file;
- Copy the "SSH login command" and run it → logged in.

> ⚠️ The bundle contains a one-time private key. **Send it only over trusted private chat** — never in group chats, tickets, or public pages.

### 5. Revoke when done (or let it auto-delete on expiry)

```bash
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3d4e5
```

It auto-deletes the user, home directory, and key after 24 hours by default — but **revoking manually right after use is safest**; don't rely on expiry alone.

## Everyday commands

Show status (registered temp users, expiry, auto-delete timers):

```bash
sudo bash temp-admin.sh status
sudo bash temp-admin.sh status --user xxvcc-a1b2c3d4e5
```

Revoke/delete (pick from the list, or name the user directly):

```bash
sudo bash temp-admin.sh revoke
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3d4e5
```

Inspect account expiry and auto-delete tasks:

```bash
sudo bash temp-admin.sh expiry-status
# Add --compact to also prune registry entries pointing to users that no longer exist (registry only, no account is touched)
sudo bash temp-admin.sh expiry-status --compact
```

> Deleting unregistered/foreign accounts has extra guards (anti-mistake); see [Security notes](#security-notes).

## Common usage

Set the validity (hours):

```bash
sudo bash temp-admin.sh invite --sudo --hours 12
```

Without sudo (create a normal account):

```bash
sudo bash temp-admin.sh invite --no-sudo
```

Set the username prefix / host / port (prefix allows lowercase letters, digits, underscore, hyphen; max 20 chars):

```bash
sudo bash temp-admin.sh invite --prefix ops --sudo
sudo bash temp-admin.sh invite --host 203.0.113.10 --port 22 --sudo
```

Set account expiry only, without creating an auto-delete task:

```bash
sudo bash temp-admin.sh invite --sudo --no-auto-revoke
```

**Automation / non-interactive** (in CI or scripts). Non-interactive mode requires `--host`; `--sudo --yes` requires repeating the username for confirmation; when stdout is not a terminal you must also explicitly allow printing the private key:

```bash
sudo bash temp-admin.sh invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 --port 22 --hours 24 \
  --sudo --install-deps --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

## Reference

### Supported systems

- **Primary**: Debian / Ubuntu, common BT-panel Linux environments, RHEL / Rocky / AlmaLinux / Fedora
- **Best effort**: Alpine, Arch Linux

### Dependencies

The script detects them automatically; if missing, it can install them interactively (type `YES` or pass `--install-deps`) via `apt-get` / `dnf` / `yum` / `apk` / `pacman`. Tools used:

- `bash`, `ssh-keygen`, `useradd` or `adduser`, `userdel` or `deluser`, `usermod`, `chage`, `flock`
- a `date` that can compute a future date (GNU coreutils) or `python3`
- `at` / `atq` / `atrm`: only as a fallback auto-delete when systemd is unavailable
- `sudo`: only when granting sudo

### Expiry vs auto-delete

Default validity is 24 hours. The script does two things at once:

1. set the account expiry date with `chage -E` (date-granularity; mainly blocks future login, **does not delete the user**);
2. write a persistent systemd `.service` + `.timer` first (`OnCalendar` as an absolute UTC time + `Persistent=true`) that calls `revoke` at the deadline to delete the user, home directory, SSH key, sudoers file, and registry entry; if systemd is unavailable or fails, try `at` (and attempt to enable `atd`); only if neither works does it fall back to account expiry only and show a manual-revoke warning in the bundle.

- Hour-precise deletion depends on the systemd timer or the `at` fallback; `chage` is only a date-granularity backstop.
- In interactive mode without `--host`, the script first asks whether to auto-detect the public IP — trying local interfaces/cloud metadata first, then `https://api.ipify.org`, `https://ifconfig.me/ip`, `https://icanhazip.com`, reporting success or failure clearly. `--yes` mode never does this silently and requires an explicit `--host`. To troubleshoot, set `LINUX_TEMP_ADMIN_DEBUG_IP=1` (diagnostics never print the private key).
- `--host` accepts only a plain domain, IPv4, or IPv6 address; do not include a port (use `--port`). The SSH command brackets IPv6 addresses automatically.

### Files written

```text
/usr/local/sbin/linux-temp-admin                              # stable revoke command
/var/lib/linux-temp-admin/users.tsv                           # local registry
/etc/systemd/system/linux-temp-admin-revoke-USER.service      # with lightweight NoNewPrivileges/PrivateTmp hardening
/etc/systemd/system/linux-temp-admin-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER                          # only when passwordless sudo is enabled
/home/USER/.ssh/authorized_keys
# plus a fallback auto-delete job in the at queue when systemd is unavailable
```

To avoid a modified or downgraded copy silently overwriting the shared `/usr/local/sbin/linux-temp-admin` (which would redirect other registered users' revoke tasks), when the installed version differs from the current script the tool **reuses the existing command instead of overwriting** and prints a notice; set `LINUX_TEMP_ADMIN_REINSTALL=1` to force a replacement.

## Security notes

- The private key is shown only once and is not stored on the server; the account password is locked by default and no account/sudo password is printed.
- **NOPASSWD sudo is effectively root** — grant it only to trusted parties; revoking deletes only the account itself, not any root-owned processes, cron jobs, systemd units, or SUID files it left behind.
- Revoking deletes the home directory and SSH key; if the system delete command fails, the script stops and asks you to check manually instead of reporting a false success.
- **Anti-mistake guard**: `revoke` only deletes users registered by the script; deleting an unregistered account **created by this tool** (its home GECOS carries the `linux-temp-admin` tag) requires `--force`, and non-interactive runs also require `--confirm-force USER`.
- Even with `--force`, the script refuses to delete root, common system accounts, UID 0, low-UID system accounts, and any real account **not created by this tool (no tag) and not registered** — use the system's `userdel` for those.
- If creation fails mid-way, the script tries to roll back (cancel auto-revoke, remove the sudoers/registry entries, delete the just-created user); Ctrl-C mid-invite also triggers rollback.
- The registry, sudoers, systemd units, revoke command, and user SSH key files undergo symlink / regular-file safety checks and refuse to overwrite unsafe targets.
- Never commit real invite bundles to GitHub, Notion, tickets, or group chats; revoke immediately after use rather than relying on expiry.
- When stdout is not a TTY the script refuses to print the private key unless `--allow-non-tty-private-key-output` is passed.

## Development & license

Local checks:

```bash
bash -n temp-admin.sh
shellcheck -S warning temp-admin.sh
```

The repo includes a GitHub Actions workflow that runs Bash syntax checks and ShellCheck on push and pull request.

License: MIT, see [LICENSE](LICENSE).
