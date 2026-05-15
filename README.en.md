# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> A one-time Linux temporary admin invite script: generate a fresh SSH key, create a temporary user, optionally grant sudo, and auto-delete the user on expiry by default.

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
- **Optional sudo / wheel access**.
- **Default validity is 24 hours**.
- **Auto-delete on expiry by default** using `systemd-run` transient timers.
- **Deletes the home directory and SSH key when revoked**.
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
Schedule auto-revoke with systemd-run by default
  ↓
Print a one-time invite bundle
```

The script does **not**:

- store private keys;
- log sudo passwords;
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
- `chpasswd`
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

Set the Host and SSH port shown in the invite output:

```bash
sudo bash temp-admin.sh invite --host 203.0.113.10 --port 22 --sudo
```

### 3. Send the invite bundle privately

The script prints an SSH login command, one-time private key, sudo password, and revoke command. Send it only via a trusted private chat. Never paste it into groups or public pages.

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

This is only a format example and **cannot be used to log in**. Real private keys and sudo passwords are generated at runtime and shown once in the terminal.

```text
====== One-time Temporary Admin Invite / 一次性临时管理员连接信息 ======

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3
Expires: 2026-05-17 01:00:00 CST
Sudo: yes
Passwordless sudo: no
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

Sudo password / Sudo 密码：
[REDACTED: one-time sudo password generated at runtime]

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
sudo bash temp-admin.sh revoke --user xxvcc-a1b2c3
```

Show account expiry and auto-delete timers:

```bash
sudo bash temp-admin.sh cleanup-expired
```

## Expiry vs auto-delete

Default validity is 24 hours. The script tries to do two things:

1. set account expiry with `chage -E`;
2. create a one-shot auto-delete task with `systemd-run --on-active=<hours>h`.

Important details:

- `chage -E` is usually date-based, not minute-precise.
- Account expiry usually blocks future login but does not delete the user or home directory.
- Auto-delete calls `revoke`, which deletes the user, home directory, SSH key, sudoers file, and registry entry.
- If `systemd-run` is unavailable, the script falls back to account expiry only and asks you to revoke manually.

## Files written

The script may write:

```text
/usr/local/sbin/linux-temp-admin
/var/lib/linux-temp-admin/users.tsv
/etc/sudoers.d/linux-temp-admin-USER       # only when passwordless sudo is enabled
/home/USER/.ssh/authorized_keys
```

Auto-delete is managed by systemd transient units. Inspect them with:

```bash
systemctl list-timers --all | grep linux-temp-admin
```

## Security notes

- The private key is shown only once and is not stored on the server.
- README examples are redacted placeholders and cannot log into any server.
- Revoking a user deletes its home directory and SSH key.
- sudo access is effectively root access; grant it only to trusted parties.
- Never commit real invite bundles to GitHub, Notion, tickets, or group chats.
- Revoke immediately after use; do not rely only on expiry.

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
