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
sudo bash temp-admin-en.sh invite --sudo
```

For non-interactive sudo invites, repeat the full username and explicitly allow private-key output if stdout is not a TTY:

```bash
sudo bash temp-admin-en.sh invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 \
  --sudo \
  --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
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
- **Default username prefix is `xxvcc`**, e.g. `xxvcc-a1b2c3d4e5`.
- **Optional NOPASSWD sudo / wheel access**.
- **Default validity is 24 hours**.
- **Auto-delete on expiry by default** using persistent systemd `.service/.timer` units first, with an `at` fallback when systemd scheduling is unavailable.
- **Key-only login**: account password is locked by default, and no account/sudo password is printed.
- **Deletes the home directory and SSH key when revoked**.
- **Deletion guard**: by default, `revoke` only deletes users registered by the script; unregistered users require explicit `--force`, and non-interactive deletion also requires `--confirm-force USER`; protected/system users are always refused.
- **Rollback on failed creation**: if creation fails mid-way, the script tries to cancel auto-revoke tasks and remove the temporary user it just created.
- **Safer writes for critical files**: registry, sudoers, systemd units, installed revoke command, and `authorized_keys` refuse unsafe symlinks/non-regular files and use atomic writes where practical.
- **Keeps a local registry of temporary users** so you can select by number when revoking.
- **Detects missing dependencies** and can install them interactively; auto-install requires typing `YES` or passing `--install-deps`.
- **Non-TTY private-key output guard**: refuses to print the private key when stdout is not a terminal unless `--allow-non-tty-private-key-output` is passed.
- **Non-interactive sudo confirmation**: `--sudo --yes` requires `--confirm-sudo USER`.
- **Separate Chinese and English scripts**: `temp-admin.sh` is the default Chinese script, and `temp-admin-en.sh` is the English script.
- **Does not modify sshd_config, firewall rules, or open ports**.

## How it works

```text
Run script
  ↓
Generate SSH private key + public key
  ↓
Create a temporary user, e.g. xxvcc-a1b2c3d4e5
  ↓
Write /home/USER/.ssh/authorized_keys
  ↓
Optionally add the user to sudo/wheel
  ↓
Register it in /var/lib/linux-temp-admin/users.tsv
  ↓
Schedule auto-revoke with a persistent systemd timer by default; use at fallback when systemd scheduling fails
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
- `userdel` or `deluser`
- `usermod`
- `chage`
- `flock`
- `at` / `atq` / `atrm` only for fallback auto-delete when systemd scheduling is unavailable
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
sudo bash temp-admin-en.sh invite --sudo
```

Set a custom validity period:

```bash
sudo bash temp-admin-en.sh invite --sudo --hours 12
```

Set a custom username prefix (lowercase letters, digits, underscore, and hyphen only; max 20 chars):

```bash
sudo bash temp-admin-en.sh invite --prefix ops --sudo
```

Set the Host and SSH port shown in the invite output:

```bash
sudo bash temp-admin-en.sh invite --host 203.0.113.10 --port 22 --sudo
```

### 3. Send the invite bundle privately

The script prints an SSH login command, one-time private key, and revoke command. Account password is locked by default, and no account/sudo password is printed. Send it only via a trusted private chat. Never paste it into groups or public pages.

Use the Chinese script with:

```bash
sudo bash temp-admin.sh invite --sudo
```

## Non-interactive examples

Auto-install dependencies and create a sudo invite. Non-interactive mode must pass `--host`; `--sudo --yes` must repeat the username, and non-TTY stdout must explicitly allow private-key output:

```bash
sudo bash temp-admin-en.sh invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 \
  --port 22 \
  --hours 24 \
  --sudo \
  --install-deps \
  --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

Disable auto-delete and keep only account expiry:

```bash
sudo bash temp-admin-en.sh invite --sudo --no-auto-revoke
```

Create a normal non-sudo user:

```bash
sudo bash temp-admin-en.sh invite --no-sudo
```

## Redacted invite output example

This is only a format example and **cannot be used to log in**. Real private keys are generated at runtime and shown once in the terminal. Account password is locked by default, and no account/sudo password is printed.

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

## Daily operations

Show status:

```bash
sudo bash temp-admin-en.sh status
```

Select and delete a user from the registry:

```bash
sudo bash temp-admin-en.sh revoke
```

Delete a specific user:

```bash
sudo bash temp-admin-en.sh revoke --user xxvcc-a1b2c3d4e5
```

By default, `revoke` only deletes users registered by the script. To delete an unregistered user, explicitly pass `--force`; if you also use `--yes` non-interactively, repeat the full username:

```bash
sudo bash temp-admin-en.sh revoke --user USER --force
sudo bash temp-admin-en.sh revoke --user USER --force --yes --confirm-force USER
```

Show account expiry and auto-delete timers:

```bash
sudo bash temp-admin-en.sh expiry-status
# Backward-compatible alias: sudo bash temp-admin-en.sh cleanup-expired
```

## Expiry vs auto-delete

Default validity is 24 hours. The script tries to do two things:

1. set account expiry with `chage -E`;
2. write `/etc/systemd/system/linux-temp-admin-revoke-USER.service` and `.timer`, using `OnCalendar` + `Persistent=true` for persistent auto-delete first; if systemd scheduling is unavailable or fails, try an `at` fallback job.

Important details:

- `chage -E` is usually date-based, not minute/hour-precise; precise `--hours` auto-revoke depends on the systemd timer or fallback `at` job.
- Account expiry usually blocks future login but does not delete the user or home directory.
- Auto-delete calls `revoke`, which deletes the user, home directory, SSH key, sudoers file, and registry entry.
- If `systemctl` is unavailable or systemd timer creation fails, the script tries an `at` fallback job; only if `at` is unavailable too does it fall back to account expiry only and shows a manual-revoke warning in the invite bundle.
- If account expiry cannot be set (missing `chage` or `chage` failure), the script stops creation and rolls back the just-created user.
- In interactive mode, if `--host` is not provided, the script asks before automatic detection. It first tries local public interface addresses and common cloud metadata endpoints; only if that fails does it try `https://api.ipify.org`, `https://ifconfig.me/ip`, and `https://icanhazip.com`, and it clearly reports success or failure. In `--yes` non-interactive mode it will not perform this external lookup and requires explicit `--host`.
- To troubleshoot public-IP detection failures, temporarily set `LINUX_TEMP_ADMIN_DEBUG_IP=1`; the script prints per-metadata/external-service failure reasons or invalid responses.
- `--host` accepts only a plain domain, IPv4, or IPv6 address; do not include a port, use `--port` separately. The invite bundle automatically brackets IPv6 addresses in the SSH command.

## Files written

The script may write:

```text
/usr/local/sbin/linux-temp-admin
/var/lib/linux-temp-admin/users.tsv
/etc/systemd/system/linux-temp-admin-revoke-USER.service  # includes lightweight NoNewPrivileges/PrivateTmp hardening
/etc/systemd/system/linux-temp-admin-revoke-USER.timer
fallback job in the at queue                    # only when systemd timer is unavailable and at is available
/etc/sudoers.d/linux-temp-admin-USER       # only when passwordless sudo is enabled
/home/USER/.ssh/authorized_keys
```

Auto-delete is managed by persistent systemd timers first. The status command also shows `/usr/local/sbin/linux-temp-admin` install version and permissions. Inspect timers and fallback `at` jobs with:

```bash
systemctl list-timers --all | grep linux-temp-admin
atq
```

## Security notes

- The private key is shown only once and is not stored on the server.
- Account password is locked by default, and no account/sudo password is printed.
- README examples are redacted placeholders and cannot log into any server.
- Revoking a user deletes its home directory and SSH key; if the system delete command fails, the script stops and asks you to check manually instead of reporting a false success.
- Deletion guard: `revoke` only deletes registered users unless `--force` is explicitly used; non-interactive deletion of unregistered users also requires `--confirm-force USER`.
- Even with `--force`, the script refuses to delete root, common system accounts, UID 0, or low-UID system accounts.
- If the local registry is lost/corrupted, revoking those users also requires explicit `--force`; non-interactive deletion also requires `--confirm-force USER`.
- If account creation fails mid-way, the script tries to cancel auto-revoke tasks, roll back sudoers/registry state, and remove the just-created temporary user.
- The registry, sudoers, systemd units, `/usr/local/sbin/linux-temp-admin`, and user SSH key files perform basic path-safety checks and refuse to overwrite unsafe symlinks or non-regular files.
- sudo access is effectively root access; grant it only to trusted parties.
- Never commit real invite bundles to GitHub, Notion, tickets, or group chats.
- Revoke immediately after use; do not rely only on expiry.
- In interactive mode, missing `--host` asks before automatic public-IP detection; the script first tries local/cloud metadata, then external public-IP services if needed, and clearly reports success or failure. `--yes` mode requires explicit `--host`.
- Set `LINUX_TEMP_ADMIN_DEBUG_IP=1` to troubleshoot public-IP detection; diagnostics never print the private key.
- When stdout is not a TTY, the script refuses to print the one-time private key unless `--allow-non-tty-private-key-output` is passed.
- `--sudo --yes` requires `--confirm-sudo USER` to avoid accidentally granting sudo non-interactively.

## Validation

```bash
bash -n temp-admin.sh temp-admin-en.sh
shellcheck -S warning temp-admin.sh temp-admin-en.sh
```

The repository includes a GitHub Actions workflow that runs Bash syntax checks and ShellCheck on push and pull request.

## License

MIT. See [LICENSE](LICENSE).
