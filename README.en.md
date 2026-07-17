# linux-temp-admin

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-supported-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> One command to grant a collaborator a **time-limited, auto-deleting** temporary SSH admin account. The tool prints an invite bundle you forward over private chat; the server stores only the public key, never the private key.

**linux-temp-admin** is for temporarily giving a trusted collaborator, ops engineer, or automation agent an SSH admin entry point — without sharing the root password, without leaving long-lived accounts, and with automatic cleanup on expiry.

It ships as a **single static binary**: zero runtime dependencies, glibc/musl alike (including Alpine/BusyBox). Key generation, downloads, date arithmetic, file locking, and process cleanup are all native, and it supports an **ed25519-signature-verified self-upgrade**.

[中文](README.md) | English

---

## Contents

- [Quick start (30 seconds)](#quick-start-30-seconds)
- [What it solves](#what-it-solves)
- [Language](#language)
- [Install, upgrade, and doctor](#install-upgrade-and-doctor)
- [Full walkthrough](#full-walkthrough)
- [Everyday commands](#everyday-commands)
- [Common usage](#common-usage)
- [Reference](#reference)
- [Security notes](#security-notes)
- [Development & license](#development--license)

## Quick start (30 seconds)

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
sudo linux-temp-admin invite --sudo
```

That's it. The tool will:

1. Generate a fresh SSH key pair and create a temporary user (e.g. `xxvcc-a1b2c3d4e5`);
2. Print **an invite bundle** — forward it over private chat, and the recipient logs in by running the two commands inside it, **without needing to understand any of this**;
3. Delete that user, its home directory, and its key **automatically after 24 hours** by default.

> Running `sudo linux-temp-admin` with no subcommand opens an interactive menu. The menu is drawn on entry and whenever you press Enter, so each action's result stays on screen above the prompt instead of being scrolled away. The UI is bilingual; see [Language](#language).

## What it solves

Granting someone temporary SSH access usually goes wrong in these ways:

- handing out the root password;
- creating a temporary account and forgetting to delete it;
- leaving a public key in `authorized_keys` that nobody cleans up;
- losing track of which temporary accounts you have opened;
- never taking back sudo.

This tool standardizes the whole flow: **create → print invite bundle → register → inspect → revoke → auto-delete on expiry**.

It does **not**: store the private key; generate or print any account/sudo password; modify the SSH server configuration; touch the firewall; or open any inbound port.

## Language

**Chinese by default, whatever the server's locale says.** The first time you run it at a terminal it asks once, then remembers:

```text
Language / 语言:
  1) 中文 (默认)
  2) English
选择 / select [1-2]:
```

The choice is saved in `/var/lib/linux-temp-admin/v2/prefs`. Change it any time from the interactive menu under "Switch language / 切换语言" (that entry is labelled in both languages, so it is findable even if you picked the one you cannot read).

Precedence: `--lang zh|en` > the `LINUX_TEMP_ADMIN_LANG` environment variable > the remembered choice > the question on first interactive use > **Chinese**.

**The system locale (`LANG`/`LC_ALL`) is deliberately not consulted.** What language a server was installed in says little about the language of the person holding the invite. So a box with `LANG=en_US.UTF-8` still defaults to Chinese until you choose English.

```bash
sudo linux-temp-admin --lang en invite --sudo     # this run only
sudo -E linux-temp-admin invite --sudo            # with LINUX_TEMP_ADMIN_LANG=en; note -E, sudo scrubs the environment by default
```

A non-interactive run (a script, CI, the auto-revoke timer) has nobody to ask, so it uses the remembered choice or falls back to Chinese; `--lang` and the environment variable always override.

## Install, upgrade, and doctor

The install script is the recommended path: it downloads the latest released binary for your architecture (amd64 / arm64), **verifies its SHA-256 and a detached ed25519 signature against the release key embedded in the script**, and installs it to `/usr/local/sbin/linux-temp-admin` — failing closed on any mismatch (and, when openssl is unavailable, refusing to install unless `LTA_ALLOW_UNVERIFIED=1` is set).

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
linux-temp-admin doctor
```

Everyday maintenance:

```bash
sudo linux-temp-admin doctor            # check dependencies, sudoers.d, package manager, init system, SSH port
sudo linux-temp-admin upgrade           # download, verify the signature, and upgrade the stable command
sudo linux-temp-admin upgrade --yes     # non-interactive confirmation
sudo linux-temp-admin uninstall         # remove the stable command
sudo ./linux-temp-admin install         # install the binary in hand as the stable command (note the leading ./)
```

- **`upgrade`** fetches a new binary from GitHub and installs it only **after the embedded ed25519 public key verifies it** (fail-closed); HTTPS only, capped at 64 MiB, overwrites only when the version is newer. To repair or pin a custom source, use `--force --url URL` (its signature is `URL.sig`). **Use this for routine updates.**
- **`install`** places a binary you **already have** (no network, no signature check) — for an air-gapped host or a self-built binary. It copies the binary that is *currently running*, so it is only meaningful when you run a copy from elsewhere (`sudo ./linux-temp-admin install`, where the leading `./` is the point). It refuses to overwrite a *different* binary without `--force`; `uninstall` refuses by default while registered users still exist.

## Full walkthrough

### 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
```

### 2. Create an invite

```bash
sudo linux-temp-admin invite --sudo
```

Interactive mode asks you to confirm the details (username, host, lifetime, sudo, auto-delete) before printing the bundle.

### 3. You get an invite bundle like this (redacted)

The following is a format sample only and **cannot be used to log in**. The real private key is generated at run time and shown once, in your terminal.

```text
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3d4e5
Expires: 2026-07-09 01:00:00 CST
Sudo: yes
Login: SSH key only (verified against the effective sshd config)
Password login: locked
Auto revoke: yes
Auto revoke unit: linux-temp-admin-v2-revoke-xxvcc-a1b2c3d4e5
Sshd exception: none

SSH login command:
ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10

Save private key command:
cat > './xxvcc-a1b2c3d4e5.key' <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: one-time private key generated at run time]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 './xxvcc-a1b2c3d4e5.key'

Revoke command:
sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5

Sudo note: NOPASSWD sudo is enabled (equivalent to full root); it may leave root-owned persistence. Revoking only deletes this account itself.

Security notes: the private key is shown only once and not stored on the server; send only via trusted private chat; revoke immediately after use.

----- END LINUX TEMP ADMIN INVITE -----
```

> The bundle's field names and command blocks stay in English and keep a fixed format so it can be forwarded verbatim; only the caption lines are localized.

The `Login:` line is **a verdict, not a slogan**. Before anything is created, the tool reads `sshd -T -C user=<new account>` — sshd's effective configuration, with `Include`, `Match`, and the distro's crypto policy already resolved — and only claims a key login if that account really could log in. If the config cannot be read, the line says `UNVERIFIED` instead of guessing.

### 4. Forward the bundle to your collaborator over private chat

They only need two steps, **without installing anything or understanding this tool**:

- copy the "Save private key command" block, paste and run it locally → they get the key file;
- copy the "SSH login command" and run it → they are in.

> ⚠️ The bundle contains a one-time private key. **Send it only over trusted private chat** — never in a group, a ticket, or a public page.

### 5. Revoke when done (or let it auto-delete on expiry)

```bash
sudo linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

The user, home directory, and key are deleted automatically after 24 hours by default, but **revoking manually as soon as you are done is safest** — do not rely on expiry alone.

## Everyday commands

Show status (registered temporary users, expiry, auto-delete timer):

```bash
sudo linux-temp-admin status
sudo linux-temp-admin status --user xxvcc-a1b2c3d4e5
```

Revoke/delete (pick a number from the list, or name the user):

```bash
sudo linux-temp-admin revoke
sudo linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

Clean up stale registry rows and orphaned grants:

```bash
sudo linux-temp-admin cleanup-expired --compact
```

`--compact` removes registry entries naming accounts that no longer exist, and the **sudo grants and sshd exceptions those accounts left behind** (an orphaned grant is the dangerous one — it re-arms the moment its username is reused). This is the command `doctor` points you at when it finds one.

> `cleanup-expired` **never deletes an account**: use `revoke` for that, and `status` to see the list. Revoking unregistered or unknown accounts has extra guards — see [Security notes](#security-notes).

## Common usage

Set the lifetime in hours (1 to 8760):

```bash
sudo linux-temp-admin invite --sudo --hours 12
```

No sudo (create a plain account):

```bash
sudo linux-temp-admin invite --no-sudo
```

Set the username prefix / host / port (the prefix allows lowercase letters, digits, underscores, and hyphens, up to 20 characters):

```bash
sudo linux-temp-admin invite --prefix ops --sudo
sudo linux-temp-admin invite --host 203.0.113.10 --port 22 --sudo
```

Set account expiry only, without an auto-delete task:

```bash
sudo linux-temp-admin invite --sudo --no-auto-revoke
```

**Automation / non-interactive** (CI or scripts). Non-interactive runs must pass `--host`; `--sudo --yes` must re-confirm the username; and when stdout is not a terminal you must explicitly allow printing the private key:

```bash
sudo linux-temp-admin invite \
  --user xxvcc-a1b2c3d4e5 \
  --host 203.0.113.10 --port 22 --hours 24 \
  --sudo --install-deps --yes \
  --confirm-sudo xxvcc-a1b2c3d4e5 \
  --allow-non-tty-private-key-output
```

### When the server does not accept public-key logins

Some servers have key logins switched off (`PubkeyAuthentication no`), or redirect `authorized_keys` to a central path, or run an `AllowUsers` whitelist, or demand a second factor. On such a host sshd never reads the key written to `~/.ssh/authorized_keys`, and no invite — however pretty — can log in.

**The tool now finds this out before it creates anything, and refuses** (the account does not exist yet, so nothing is left behind), naming the directive that blocks it. You have two ways forward.

**1. Open a door for this one account** (recommended):

```bash
sudo linux-temp-admin invite --sudo --fix-sshd
```

It writes a drop-in of its own, containing nothing but a `Match User` block:

```text
# /etc/ssh/sshd_config.d/10-linux-temp-admin-xxvcc-a1b2c3d4e5.conf
Match User xxvcc-a1b2c3d4e5
    PubkeyAuthentication yes
```

- **The global policy is not edited at all.** Every other account keeps your baseline, byte for byte.
- The file is syntax-checked with `sshd -t`, then **proved effective** with `sshd -T -C user=<account>`, and only then is sshd asked to `reload` (**reload, never restart**: live sessions survive). If any step fails, the file is removed, sshd is not reloaded, and the invite is refused.
- `revoke` (including the auto-delete timer) **deletes that file and reloads sshd**. "Restoring" is deleting our own file — there is no backup to keep, so the tool can never clobber a change you made to sshd in the meantime.

An interactive run asks first. A `--yes` run never asks and never modifies sshd implicitly: it refuses unless `--fix-sshd` said so out loud, because a script must not quietly rewrite a remote host's sshd configuration while nobody is watching.

**2. Fall back to a password** (leaves sshd alone):

```bash
sudo linux-temp-admin invite --sudo --password-login
```

It first verifies that sshd really does accept passwords (and refuses otherwise), then issues a 24-character random password, shown once. **This is the weakest grant the tool issues**: the password is brute-forceable from anywhere for the account's whole lifetime and must be delivered in the clear. Prefer `--fix-sshd`.

**What the tool will never do**: edit sshd's global configuration, or bypass an explicit `DenyUsers`/`DenyGroups` rule. Not being on an allow list is a default you never spoke about; an explicit deny is a decision you made.

To find out where your server stands before you need an invite:

```bash
sudo linux-temp-admin doctor
```

## Reference

### Supported systems

- **Primary**: Debian / Ubuntu, common aaPanel Linux environments, RHEL / Rocky / AlmaLinux / Fedora
- **Best effort**: Alpine, Arch Linux

### Dependencies

The binary itself has no runtime dependencies. It only calls the system's **account-management tools**; when those are missing it can install them interactively (confirm, or pass `--install-deps`) via `apt-get` / `dnf` / `yum` / `apk` / `pacman`:

- `useradd` or `adduser`, `userdel` or `deluser`, `usermod`, `chage`
- `sudo`: only needed when granting sudo

`doctor` checks each of the tools above, plus the package manager, the init system, the safety of `/etc/sudoers.d`, and the detected SSH port.

`at` / `atd` is the auto-delete fallback backend for hosts without systemd. It is **not part of the dependency check and is never auto-installed**.

### Expiry vs auto-delete

The default lifetime is 24 hours. The tool both sets a day-granularity account expiry with `chage -E` (to block further logins — it **does not delete the user**) and writes an auto-delete task that actually removes the user at the deadline: a persistent systemd timer preferred, `at` as fallback, degrading to expiry-only (with a "revoke manually" note in the bundle) if neither is available. The auto-delete task invokes the installed stable command, so choosing auto-delete makes the tool ensure `/usr/local/sbin/linux-temp-admin` exists first.

Two host notes:

- In interactive mode without `--host`, cloud metadata and local interfaces are probed **silently** (neither leaves this host or its link), and whatever they find becomes the default in the host prompt — press Enter to accept it, or type over it. Only when no public IP is found locally does it **ask** before querying `https://api.ipify.org`, `https://ifconfig.me/ip`, and `https://icanhazip.com`: that step discloses your server's address to a third party, so it needs an explicit yes. `--yes` mode never reaches out at all; it requires an explicit `--host`.
- `--host` accepts a plain domain, IPv4, or IPv6 only; do not append a port (use `--port`). The SSH command in the bundle brackets IPv6 addresses automatically.

### Files written

```text
/usr/local/sbin/linux-temp-admin                             # stable revoke command
/var/lib/linux-temp-admin/v2/registry.tsv                    # local registry (root:root 0600, dir 0700)
/var/lib/linux-temp-admin/v2/prefs                           # the remembered UI language (root:root 0600)
/var/log/linux-temp-admin/audit.log                          # operation audit log (root:root 0600, dir 0700)
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.service  # with NoNewPrivileges and similar light confinement
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER                         # only when NOPASSWD sudo is enabled
/home/USER/.ssh/authorized_keys
# plus a fallback auto-delete job in the at queue when systemd is unavailable
```

## Security notes

- The private key is shown once at creation and never stored on the server; the account password is locked by default, and no account/sudo password is ever printed.
- The invite's `Login:` line is **a verified conclusion**: before creating anything, the tool reads `sshd -T -C user=<new account>` to confirm the account really can log in, and says `UNVERIFIED` when it cannot read the config. It never asserts a login method it did not check.
- **sshd's global configuration is never edited.** `--fix-sshd` writes a separate drop-in holding a single `Match User` block (no other account's policy changes by one byte); it is syntax-checked with `sshd -t`, proved effective with `sshd -T`, reloaded (never restarted), removed on any failure, and deleted by `revoke`. **An explicit `DenyUsers`/`DenyGroups` rule is never bypassed.**
- `--password-login` is the weakest grant available (brute-forceable from anywhere, delivered in the clear). It is opt-in only, and refuses unless sshd is verified to accept passwords.
- **NOPASSWD sudo is essentially root.** Grant it only to trusted parties. Revoking deletes the account itself; it does not clean up processes, cron jobs, systemd units, or SUID files that account left behind as root.
- Deleting a user also deletes the home directory and SSH key. If the system's delete command fails, the tool stops and tells you to check manually rather than pretending the revoke succeeded.
- **Guard against accidental deletion**: `revoke` only deletes users this tool registered. Deleting an unregistered account that **this tool created** (its GECOS carries the `linux-temp-admin` marker) requires an explicit `--force`, plus `--confirm-force USER` when non-interactive.
- Even with `--force`, it refuses to delete root, well-known system accounts, UID 0, low-UID system accounts, and **any real account that this tool did not create (no marker) and did not register** — use the system's `userdel` for those.
- A failure partway through creation rolls back what it can (cancel auto-revoke, remove the sudoers drop-in and registry entry, delete the just-created user).
- Upgrades are HTTPS-only and ed25519-signature-enforced; a verification failure aborts, so an unsigned or mis-signed binary is never installed.
- Every privileged action (account create/delete, install/upgrade/uninstall) is appended as a JSON line to the root-owned `/var/log/linux-temp-admin/audit.log` (time, actor `SUDO_USER`, action, target, result).
- When stdout is not a TTY, printing the private key is refused by default; pass `--allow-non-tty-private-key-output` only when the output channel is known to be safe.

## Development & license

- Contributing & local checks: [CONTRIBUTING.md](CONTRIBUTING.md)
- Report security issues privately per [SECURITY.md](SECURITY.md); version history in [CHANGELOG.md](CHANGELOG.md).

License: MIT, see [LICENSE](LICENSE).
