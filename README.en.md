# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> A one-time Linux temporary admin invite script: generate a fresh SSH key, create a temporary user, optionally grant NOPASSWD sudo, and auto-delete the user on expiry by default.

**linux-temp-admin** is useful when you need to temporarily grant SSH access to a trusted collaborator, operator, or automation assistant. It prints a private invite bundle that you can send through a trusted private chat. The server stores only the public key, never the private key.

**Languages / 语言**: [中文](README.md) | English

## Quick install

Download first, then run, so you can inspect the script:

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin-en.sh
chmod +x temp-admin-en.sh
sudo bash temp-admin-en.sh
```

Chinese script / 中文脚本:

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
sudo bash temp-admin.sh
```

Create a one-time sudo invite directly:

```bash
sudo bash temp-admin.sh invite --sudo
```

---

## Why use it?

Temporary SSH access often goes wrong because people:

- share a root password;
- keep temporary accounts around forever;
- forget public keys in `authorized_keys`;
- lose track of which temporary users were created;
- forget to revoke sudo access after the job is done.

This script standardizes the workflow: create, print invite bundle, register, inspect, revoke, and auto-delete on expiry.

## Features

- **Generates a fresh SSH key pair every time**.
- **Default username prefix is `xxvcc`**, e.g. `xxvcc-a1b2c3`.
- **Optional NOPASSWD sudo / wheel access**.
- **Default validity is 24 hours**.
- **Auto-delete on expiry by default** using persistent systemd `.service/.timer` units.
- **Key-only login**: account password is locked by default, and no account/sudo password is printed.
- **Deletes the home directory and SSH key when revoked**.
- **Deletion guard**: by default, `revoke` only deletes registered users or users matching the default prefix; other users require explicit `--force`.
- **Rollback on failed creation**: if creation fails mid-way, the script tries to remove the temporary user it just created.
- **Keeps a local registry of temporary users** so you can select by number when revoking.
- **Detects missing dependencies** and can install them interactively.
- **Separate Chinese and English scripts**: `temp-admin.sh` is the default Chinese script, and `temp-admin-en.sh` is the English script.
- **Does not modify sshd_config, firewall rules, or open ports**.

## How it works

```text
Run script
  ↓
Generate SSH private key + public key
  ↓
Create a temporary user, e.g. xxvcc-a1b2c3
  ↓
Write /home/USER/.ssh/authorized_keys
  ↓
Optionally add the user to sudo/wheel
  ↓
Register it in /var/lib/linux-temp-admin/users.tsv
  ↓
Schedule auto-revoke with a persistent systemd timer by default
  ↓
Print a one-time invite bundle
```

The script does **not**:

- store private keys;
- generate, print, write, or log account/sudo passwords;
- modify SSH daemon configuration;
- modify firewall rules;
- open inbound ports.

## Supported systems

### Primary support

- Debian / Ubuntu
- Common BT/Baota Linux environments
- RHEL / Rocky / AlmaLinux / Fedora

### Best effort

- Alpine
- Arch Linux

### Required tools

The script checks for:

- `bash`
- `ssh-keygen`
- `useradd` or `adduser`
- `usermod`
- `chage`
- `sudo` when sudo access is requested

It can install missing dependencies with:

- `apt-get`
- `dnf`
- `yum`
- `apk`
- `pacman`

## Quick start

### 1. Download

```bash
wget https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/temp-admin.sh
chmod +x temp-admin.sh
```

### 2. Create an invite

```bash
sudo bash temp-admin.sh invite --sudo
```

Set a custom validity period:

```bash
sudo bash temp-admin.sh invite --sudo --hours 12
```

Set a custom username prefix (lowercase letters, digits, underscore, and hyphen only; max 20 chars):

```bash
sudo bash temp-admin.sh invite --prefix ops --sudo
```

Set the Host and SSH port shown in the invite output:

```bash
sudo bash temp-admin.sh invite --host 203.0.113.10 --port 22 --sudo
```

### 3. Send the invite bundle privately

The script prints an SSH login command, one-time private key, and revoke command. Account password is locked by default, and no account/sudo password is printed. Send it only via a trusted private chat. Never paste it into groups or public pages.

Use the Chinese script with:

```bash
sudo bash temp-admin.sh invite --sudo
```

## Non-interactive examples

Auto-install dependencies and create a sudo invite:

```bash
sudo bash temp-admin.sh invite \
  --host 203.0.113.10 \
  --port 22 \
  --hours 24 \
  --sudo \
  --install-deps \
  --yes
```

Disable auto-delete and keep only account expiry:

```bash
sudo bash temp-admin.sh invite --sudo --no-auto-revoke
```

Create a normal non-sudo user:

```bash
sudo bash temp-admin.sh invite --no-sudo
```

## Redacted invite output example

This is only a format example and **cannot be used to log in**. Real private keys are generated at runtime and shown once in the terminal. Account password is locked by default, and no account/sudo password is printed.

```text
====== One-time Temporary Admin Invite / 一次性临时管理员连接信息 ======

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3
Expires: 2026-05-17 01:00:00 CST
Sudo: yes
Password login: locked
Auto revoke: yes
Auto revoke unit: linux-temp-admin-revoke-xxvcc-a1b2c3

SSH login command / SSH 登录命令：
ssh -i ./xxvcc-a1b2c3.key -p 22 xxvcc-a1b2c3@203.0.113.10

Save private key command / 保存私钥命令：
cat > xxvcc-a1b2c3.key <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: one-time private key generated at runtime]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 xxvcc-a1b2c3.key

Revoke command / 撤销命令：
sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3
```

## Daily operations

Show status:

```bash
sudo bash temp-admin.sh status
```

Select and delete a user from the registry:

```bash
sudo bash temp-admin.sh revoke
```

Delete a specific user:

```bash
sudo bash temp-admin-en.sh revoke --user xxvcc-a1b2c3
```

By default, `revoke` only deletes users registered by the script or users matching the default `xxvcc-*` prefix. To delete another user, explicitly pass `--force`:

```bash
sudo bash temp-admin-en.sh revoke --user USER --force
```

Show account expiry and auto-delete timers:

```bash
sudo bash temp-admin-en.sh expiry-status
# Backward-compatible alias: sudo bash temp-admin-en.sh cleanup-expired
```

## Expiry vs auto-delete

Default validity is 24 hours. The script tries to do two things:

1. set account expiry with `chage -E`;
2. write `/etc/systemd/system/linux-temp-admin-revoke-USER.service` and `.timer`, using `OnCalendar` + `Persistent=true` for persistent auto-delete.

Important details:

- `chage -E` is usually date-based, not minute/hour-precise; precise `--hours` auto-revoke depends on the systemd timer.
- Account expiry usually blocks future login but does not delete the user or home directory.
- Auto-delete calls `revoke`, which deletes the user, home directory, SSH key, sudoers file, and registry entry.
- If `systemctl` is unavailable or the revoke time cannot be calculated, the script falls back to account expiry only and asks you to revoke manually.
- If `--host` is not provided, the script tries to call `https://api.ipify.org` to detect the public IP for invite display only; pass `--host` explicitly if you do not want this external lookup.

## Files written

The script may write:

```text
/usr/local/sbin/linux-temp-admin
/var/lib/linux-temp-admin/users.tsv
/etc/systemd/system/linux-temp-admin-revoke-USER.service
/etc/systemd/system/linux-temp-admin-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER       # only when passwordless sudo is enabled
/home/USER/.ssh/authorized_keys
```

Auto-delete is managed by persistent systemd timers. Inspect them with:

```bash
systemctl list-timers --all | grep linux-temp-admin
```

## Security notes

- The private key is shown only once and is not stored on the server.
- Account password is locked by default, and no account/sudo password is printed.
- README examples are redacted placeholders and cannot log into any server.
- Revoking a user deletes its home directory and SSH key.
- Deletion guard: `revoke` only deletes registered/default-prefix users unless `--force` is explicitly used.
- If account creation fails mid-way, the script tries to roll back and remove the just-created temporary user.
- sudo access is effectively root access; grant it only to trusted parties.
- Never commit real invite bundles to GitHub, Notion, tickets, or group chats.
- Revoke immediately after use; do not rely only on expiry.
- Without `--host`, the script queries `api.ipify.org` for the public IP; pass `--host` manually if you want to avoid external requests.

## Validation

```bash
bash -n temp-admin.sh temp-admin-en.sh
```

If ShellCheck is installed:

```bash
shellcheck temp-admin.sh
```

## License

MIT. See [LICENSE](LICENSE).
