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
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh <<'LTA_BOOTSTRAP' &&
set -eu
umask 077
fail() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 || fail "cannot disable core dumps"
[ -d /tmp ] && [ ! -L /tmp ] || fail "/tmp is not a real directory"
tmp_meta=$(stat -Lc '%u %a' -- /tmp) || fail "cannot inspect /tmp"
case "$tmp_meta" in
  "0 1"[0-7][0-7][0-7]) ;;
  *) fail "/tmp must be root-owned, sticky, and free of special bits other than sticky" ;;
esac

if ! FSIZE_BLOCK_BYTES=$(
  ulimit -f 1 || exit 1
  awk '$1 == "Max" && $2 == "file" && $3 == "size" { print $4; found=1 }
       END { if (!found) exit 1 }' /proc/self/limits
); then
  fail "cannot determine the shell file-size limit unit"
fi
case "$FSIZE_BLOCK_BYTES" in
  512 | 1024) ;;
  *) fail "unsupported shell file-size limit unit" ;;
esac
INSTALLER_MAX_BYTES=1048576
INSTALLER_BLOCKS=$(( (INSTALLER_MAX_BYTES + FSIZE_BLOCK_BYTES - 1) / FSIZE_BLOCK_BYTES ))
installer=$(mktemp /tmp/.lta-bootstrap.XXXXXXXXXX) || fail "cannot create root-owned installer file"
cleanup() { rm -f -- "$installer"; }
trap cleanup 0
trap 'exit 1' HUP INT TERM
installer_downloaded=0
for installer_url in \
  https://dl.ll.cd/linux-temp-admin/install.sh \
  https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh
do
  installer_download_rc=0
  (
    ulimit -f "$INSTALLER_BLOCKS" || exit 1
    exec timeout -k 5 70 curl -q --fail --silent --show-error --location --max-redirs 0 \
      --connect-timeout 10 --max-time 60 --max-filesize "$INSTALLER_MAX_BYTES" \
      --proto '=https' --proto-redir '=https' \
      --output "$installer" "$installer_url"
  ) || installer_download_rc=$?
  if [ "$installer_url" = https://dl.ll.cd/linux-temp-admin/install.sh ] && \
     [ "$installer_download_rc" -eq 47 ]; then
    fail "official mirror installer redirected; refusing source-policy fallback"
  fi
  if [ "$installer_download_rc" -eq 0 ]; then
    installer_size=$(wc -c < "$installer") || fail "cannot measure installer"
    case "$installer_size" in
      '' | *[!0-9]*) fail "invalid installer size" ;;
    esac
    if [ "$installer_size" -gt 0 ] && [ "$installer_size" -le "$INSTALLER_MAX_BYTES" ]; then
      installer_downloaded=1
      break
    fi
  fi
done
[ "$installer_downloaded" -eq 1 ] || fail "installer download failed or exceeded its limit"
/bin/sh "$installer"
LTA_BOOTSTRAP
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

That's it. The tool will:

1. Generate a fresh SSH key pair and create a temporary user (e.g. `xxvcc-a1b2c3d4e5`);
2. Print **an invite bundle** — forward it over private chat, and the recipient logs in by running the two commands inside it, **without needing to understand any of this**;
3. Delete that user, its home directory, and its key **automatically after 24 hours** by default.

> Running `/usr/bin/sudo /usr/local/sbin/linux-temp-admin` with no subcommand opens an interactive menu. The menu is drawn on entry and whenever you press Enter, so each action's result stays on screen above the prompt instead of being scrolled away. The UI is bilingual; see [Language](#language).

## What it solves

Granting someone temporary SSH access usually goes wrong in these ways:

- handing out the root password;
- creating a temporary account and forgetting to delete it;
- leaving a public key in `authorized_keys` that nobody cleans up;
- losing track of which temporary accounts you have opened;
- never taking back sudo.

This tool standardizes the whole flow: **create → print invite bundle → register → inspect → revoke → auto-delete on expiry**.

The default public-key flow does **not** store the private key, generate an account password, or modify sshd configuration. Only an explicit `--password-login` generates and prints an account password once, and only an explicit `--fix-sshd` writes an account-scoped sshd drop-in. The tool never sets a sudo password, touches the firewall, or opens an inbound port.

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
/usr/bin/sudo /usr/local/sbin/linux-temp-admin --lang en invite --sudo  # this run only
```

A non-interactive run (a script, CI, the auto-revoke timer) has nobody to ask, so it uses the remembered choice or falls back to Chinese; `--lang` and the environment variable always override. Across sudo, prefer an explicit `--lang` instead of broadly preserving the caller's environment for one language variable.

## Install, upgrade, and doctor

The install script is the recommended path: it must run as root and requires curl, OpenSSL 3, sha256sum, and timeout. GitHub CDN fallback also requires either `getent` or `nslookup` so the script can validate and pin a public address before requesting each redirect hop. It downloads the latest released binary for your architecture (amd64 / arm64), **verifies its SHA-256 and detached ed25519 signature against the release keyring embedded in the script**, and installs it to `/usr/local/sbin/linux-temp-admin`. There is no unsigned downgrade path. Downloads and redirects are HTTPS-only, every transfer has a kernel-enforced file-size ceiling and bounded retries, and the verified candidate is probed under time/output limits in an unpredictable file inside a root-safe destination directory before the atomic replacement. For rollback resistance on a first install, add `LTA_RELEASE=vX.Y.Z` to the root-environment assignments on the `/usr/bin/sudo /usr/bin/env -i` command above; the script downloads that exact tag and requires the candidate to report the matching version.

The compiled-in official release source is `https://dl.ll.cd/linux-temp-admin`. A `latest` install or upgrade reads the mirror index and pins its exact version; an explicitly pinned release goes directly to that tag. It then fetches `SHA256SUMS`, the current-architecture binary, and its signature from one source; mirror and GitHub files are never mixed. Only a **transport failure** such as DNS, TLS, timeout, HTTP, empty/oversized response, or an incomplete download discards that whole set and falls back to GitHub. When a valid mirror index was obtained, the GitHub fallback remains pinned to the same tag. Official mirror URLs must directly return the canonical single-line index, lowercase newline-terminated `SHA256SUMS`, and a raw 64-byte signature; redirects, mirror-index semantics, checksum, ed25519 signature, and candidate-version failures abort immediately without fallback. The GitHub fallback may still follow public HTTPS redirects required by the Release CDN.

The convenience bootstrap tries the official mirror first and uses raw GitHub only if the installer transfer fails or returns an empty/oversized response; a mirror redirect aborts immediately. It trusts the TLS of the source ultimately used, plus either the mirror's stable-file deployment or GitHub's current `main`. A high-assurance first install should also pin an audited commit, verify the installer hash through an independent channel, and execute a root-owned copy; see the complete procedure in the [release guide](docs/releasing.md#host-install-and-upgrade).

Run the [root-owned bootstrap in Quick start](#quick-start-30-seconds); it never hands `sudo` a temporary file that the invoking user can replace. Diagnose the completed installation separately:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

Everyday maintenance:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor            # check dependencies, sudoers.d, package manager, init system, SSH port
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade           # prefer the official mirror; redownload from GitHub after transport failure
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade --yes     # non-interactive confirmation
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall         # uninstall: accounts, grants, auto-delete tasks, state, command
/usr/bin/sudo ./linux-temp-admin install         # put the binary in hand into place (note the leading ./)
```

- **`upgrade`** fetches a complete same-version `SHA256SUMS`, binary, and signature set from the official mirror by default, and redownloads the whole set from GitHub only if transport fails; files are never assembled across sources. A manifest-semantic, checksum, ed25519-signature, or candidate-version failure is fail-closed and never triggers fallback. Downloads are HTTPS-only, capped at 64 MiB, use bounded retries for transport failures and 408/425/429/5xx, and overwrite only when the version is newer. The address actually dialed after a redirect cannot be private or reserved (including documentation, benchmarking, NAT64, and 6to4 ranges), and candidate-version probing has time and output limits. Explicit `--url URL` and `--url-file /absolute/path` use only that custom source; no failure silently switches to the official mirror or GitHub. Use `--url URL` for a public custom source (its signature is `URL.sig`). Add `--force` only for an intentional same-version reinstall or downgrade, or to repair a target whose current version cannot be read. A URL containing credentials or signed query parameters must instead be stored in an absolute, root-owned `0600` file and passed with `--url-file`, keeping the secret out of shell history, sudo logs, and `/proc` command lines. The file's first line is the binary URL; an optional second line is an independent signature URL (each may retain its own presigned query). Only the one-line form derives `.sig` from the first line. The GitHub-specific cache bypass is applied only to official Release URLs and never rewrites a custom signed URL. **Use this for routine updates.**
- **`install`** places a binary you **already have** (no network, no signature check) — for an air-gapped host or a self-built binary. It copies the binary inode that is *currently running* through `/proc/self/exe`, so replacing the launch pathname cannot change what root installs. It is only meaningful when you run a copy from elsewhere (`/usr/bin/sudo ./linux-temp-admin install`, where the leading `./` is the point). It refuses to overwrite a *different* binary without `--force`. Even byte-identical content is a no-op only when the target is root:root, exactly `0755`, has no special bits, and its parent is safe; otherwise metadata is atomically repaired. Because auto-delete jobs execute the installed path, an invite refuses an unsafe installed command or one whose version cannot be read; development builds install the exact bytes currently running.

## Full walkthrough

### 1. Install

Use the [root-owned bootstrap above](#quick-start-30-seconds). For a high-assurance first install, use the [commit- and hash-pinned procedure in the release guide](docs/releasing.md#host-install-and-upgrade).

### 2. Create an invite

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

Interactive mode is short: a locally-detected public IP is used without asking (`--host` overrides for a domain or another address); sudo is granted by default (this is an admin tool — `--no-sudo` makes a plain account); it asks whether to auto-delete on expiry, and **only asks the lifetime when auto-delete is on**. It then shows a summary to confirm before printing the bundle.

### 3. You get an invite bundle like this (redacted)

The following is a format sample only and **cannot be used to log in**. The real private key is generated at run time and shown once, in your terminal.

```text
----- BEGIN LINUX TEMP ADMIN INVITE -----

Host: 203.0.113.10
Port: 22
User: xxvcc-a1b2c3d4e5
Expires: 2030-01-02 12:00:00 CST
Sudo: yes
Login: SSH key only (verified against the effective sshd config)
Password login: disabled
Auto revoke: yes
Auto revoke unit: linux-temp-admin-v2-revoke-xxvcc-a1b2c3d4e5
Sshd exception: none

Save private key command:
cat > './xxvcc-a1b2c3d4e5.key' <<'EOF_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED: one-time private key generated at run time]
-----END OPENSSH PRIVATE KEY-----
EOF_KEY
chmod 600 './xxvcc-a1b2c3d4e5.key'

Security notes: the private key is shown only once and not stored on the server; send only via trusted private chat; revoke immediately after use.

----- END LINUX TEMP ADMIN INVITE -----
```

> The bundle's field names and command blocks stay in English and keep a fixed format so it can be forwarded verbatim; only the caption lines are localized.

The `Login:` line is **a verdict, not a slogan**. Before anything is created, the tool reads `sshd -T -C user=<new account>` — sshd's effective configuration, with `Include`, `Match`, and the distro's crypto policy already resolved — and only claims a key login if that account really could log in. If the config cannot be read, the line says `UNVERIFIED` instead of guessing.

### 4. Forward the bundle to your collaborator over private chat

They only need two steps, **without installing anything or understanding this tool**:

- copy the "Save private key command" block, paste and run it locally → they get the key file;
- build the login command from the header's Host / Port / User, e.g.
  `ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10`.

> ⚠️ The bundle contains a one-time private key. **Send it only over trusted private chat** — never in a group, a ticket, or a public page.

### 5. Revoke when done (or let it auto-delete on expiry)

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

The user, home directory, and key are deleted automatically after 24 hours by default, but **revoking manually as soon as you are done is safest** — do not rely on expiry alone.

## Everyday commands

Show status (registered temporary users, expiry, auto-delete timer):

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status --user xxvcc-a1b2c3d4e5
```

Revoke/delete (pick a number from the list, or name the user):

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

Clean up stale registry rows and orphaned grants:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
```

**`uninstall`** removes the temporary accounts (with their home directories), their sudo grants and sshd exceptions, their auto-delete tasks, the state directory (v1's leftovers included), and — last — the command itself. The lifecycle lock and uninstall marker deliberately remain so queued old processes cannot recreate state after teardown; the audit log is also retained by default.

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall                      # interactive: shows an inventory, then asks for YES
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --remove-users # non-interactive: --remove-users is required when accounts exist
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall --yes --purge-audit  # remove the audit log too
```

- **The audit log is kept by default** at `/var/log/linux-temp-admin/audit.log`. It records who opened and closed root-capable accounts; erasing it on the way out is what covering your tracks looks like. `--purge-audit` removes it. The logger stops at 64 MiB instead of consuming the filesystem indefinitely; archive or rotate the file when that limit is reached.
- **If any account cannot be removed, neither the command nor the state directory is**, and the uninstall stops and names it. Leaving a sudo-capable account behind while deleting the only thing that manages it is worse than not uninstalling: its auto-delete task invokes that very command.
- **Uninstalling the command and keeping the accounts is not an option.** `--force` no longer bypasses this; it keeps only its original meaning (remove a target that is not a safe root-owned regular file).
- **Running it from a temporary account is refused** — the teardown would reap that account's own session partway through and leave the box half dismantled. Run it as root or another administrator.

`--compact` removes registry entries naming accounts that no longer exist, and the **sudo grants, sshd exceptions, and auto-delete tasks those accounts left behind** (an orphaned grant is the dangerous one — it re-arms the moment its username is reused). It decides "orphan" by whether the name is a live account this tool still manages, so a leftover grant whose name a real account reused is caught too. This is the command `doctor` points you at when it finds one.

> `cleanup-expired` **never deletes an account**: use `revoke` for that, and `status` to see the list. Revoking unregistered or unknown accounts has extra guards — see [Security notes](#security-notes).

## Common usage

Set the lifetime in hours (1 to 8760):

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --hours 12
```

No sudo (create a plain account):

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --no-sudo
```

Set the username prefix / host / port (the prefix allows lowercase letters, digits, underscores, and hyphens, up to 20 characters):

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --prefix ops --sudo
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --host 203.0.113.10 --port 22 --sudo
```

Create a permanent account (no expiry, no auto-delete — revoke by hand):

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --no-auto-revoke
```

**Automation / non-interactive** (CI or scripts). Non-interactive runs must pass `--host`; `--sudo --yes` must re-confirm the username; and when stdout is not a terminal you must explicitly allow printing the private key:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite \
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
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --fix-sshd
```

It writes a dedicated drop-in containing an account-scoped `Match User` block, followed by `Match all` to restore global scope so later files expanded by the same Include glob are not accidentally captured:

```text
# /etc/ssh/sshd_config.d/10-linux-temp-admin-xxvcc-a1b2c3d4e5.conf
Match User xxvcc-a1b2c3d4e5
    PubkeyAuthentication yes
Match all
```

- **The global policy is not edited at all.** Every other account keeps your baseline, byte for byte.
- The file is syntax-checked with `sshd -t`, then **proved effective** with `sshd -T -C user=<account>`, and only then is sshd asked to `reload` (**reload, never restart**: live sessions survive). If any step fails, the file is removed, sshd is not reloaded, and the invite is refused.
- `revoke` (including the auto-delete timer) **deletes that file and reloads sshd**. "Restoring" is deleting our own file — there is no backup to keep, so the tool can never clobber a change you made to sshd in the meantime.

An interactive run asks first. A `--yes` run never asks and never modifies sshd implicitly: it refuses unless `--fix-sshd` said so out loud, because a script must not quietly rewrite a remote host's sshd configuration while nobody is watching.

**2. Fall back to a password** (leaves sshd alone):

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --password-login
```

It first verifies that sshd really does accept passwords (and refuses otherwise), then issues a 24-character random password, shown once. **This is the weakest grant the tool issues**: the password is brute-forceable from anywhere for the account's whole lifetime and must be delivered in the clear. Prefer `--fix-sshd`.

**What the tool will never do**: edit sshd's global configuration, or bypass an explicit `DenyUsers`/`DenyGroups` rule. Not being on an allow list is a default you never spoke about; an explicit deny is a decision you made.

To find out where your server stands before you need an invite:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

## Reference

### Supported systems

- **Primary**: Debian / Ubuntu, common aaPanel Linux environments, RHEL / Rocky / AlmaLinux / Fedora
- **Best effort**: Alpine, Arch Linux
- **Kernel requirement**: Linux 5.3 or newer, with `pidfd_open` and `pidfd_send_signal` allowed by the seccomp/container policy. This is required to avoid signalling an unrelated process after PID reuse; `doctor` probes the live environment and `invite` refuses to create an account when the capability is unavailable.

### Dependencies

The binary itself has no runtime dependencies. It only calls the system's **account-management tools**; when those are missing it can install them interactively (confirm, or pass `--install-deps`) via `apt-get` / `dnf` / `yum` / `apk`:

- `id`, `useradd` or `adduser`, `userdel` or `deluser`, `usermod`, `chage`
- `sudo`: only needed when granting sudo

Arch's `pacman` does not support partial upgrades, while the safe `pacman -Syu` upgrades the whole system. This tool therefore never runs pacman automatically while creating an account. Run the prompted `pacman -Syu --needed ...` deliberately first, then retry the invite.

`doctor` shows **the running version and the installed command's version** (flagging a mismatch — the auto-delete task runs the installed one), checks each of the tools above and the pidfd capability, plus the package manager, the init system, the safety of `/etc/sudoers.d`, and the detected SSH port, and **rehearses whether a freshly created temporary account could log in by public key** (pointing you at `invite --fix-sshd` when sshd would refuse). It also reports **orphaned sudo grants, sshd exceptions, and auto-delete tasks** (the account is absent or its identity is unverified while the artifact remains), and accounts set to auto-delete with no task left to do it — pointing you at `cleanup-expired --compact` or `revoke`.

`at` / `atd` is the auto-delete fallback backend for hosts without systemd. It is **not part of the dependency check and is never auto-installed**.

### Expiry vs auto-delete

The default lifetime is 24 hours, and **auto-delete is on by default**. With auto-delete on, the tool writes an exact-time auto-delete task (a persistent systemd timer preferred, `at` as fallback) and sets a day-granularity `chage -E` backstop. The backstop is deliberately never earlier than the displayed deadline and may lock up to roughly 24 hours later; the scheduled revoke is the exact deadline mechanism. If neither backend can create that task, the whole invite is rolled back instead of leaving an expiry-only account. The task invokes the installed command, so the tool ensures `/usr/local/sbin/linux-temp-admin` exists first. Each task is bound to the creation UID, a random 128-bit generation token, and the matching registry row; any mismatch (including a lost row or a recreated account) safely skips deletion. Failed systemd revokes retry with rate limiting; `at` and legacy one-shot failures need manual attention, and `doctor` reports registered accounts whose auto-delete task is missing.

**Auto-delete off = a permanent account**: no expiry is set and it is never deleted — revoke it by hand. `--hours` is ignored in that case.

Two host notes:

- In interactive mode without `--host`, cloud metadata and local interfaces are probed **silently** (neither leaves this host or its link), and whatever they find becomes the default in the host prompt — press Enter to accept it, or type over it. Only when no public IP is found locally does it **ask** before querying `https://api.ipify.org`, `https://ifconfig.me/ip`, and `https://icanhazip.com`: that step discloses your server's address to a third party, so it needs an explicit yes. `--yes` mode never reaches out at all; it requires an explicit `--host`.
- `--host` accepts a plain domain, IPv4, or IPv6 only; do not append a port (use `--port`). The SSH command in the bundle brackets IPv6 addresses automatically. Auto-detection accepts only routable public addresses and excludes private, link-local, documentation, benchmarking, CGNAT, and other reserved ranges; an explicit domain or address remains the operator's choice.

### Files written

```text
/usr/local/sbin/linux-temp-admin                             # stable revoke command
/var/lib/linux-temp-admin/v2/registry.tsv                    # local registry (root:root 0600, dir 0700)
/var/lib/linux-temp-admin/v2/prefs                           # the remembered UI language (root:root 0600)
/var/log/linux-temp-admin/audit.log                          # operation audit log (root:root 0600, dir 0700)
/run/linux-temp-admin.lock                                   # global account/install lifecycle lock
/run/linux-temp-admin.lock.uninstalled                       # completed-uninstall marker; cleared by an explicit install
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.service  # with NoNewPrivileges and similar light confinement
/etc/systemd/system/linux-temp-admin-v2-revoke-USER.timer
/etc/sudoers.d/linux-temp-admin-USER                         # only when NOPASSWD sudo is enabled
/etc/ssh/sshd_config.d/10-linux-temp-admin-USER.conf         # only with --fix-sshd; account block plus Match all reset, removed by revoke
/home/USER/.ssh/authorized_keys
# plus a fallback auto-delete job in the at queue when systemd is unavailable
```

## Security notes

- The private key is shown once at creation and never stored on the server. Key accounts use an unmatchable shadow value that disables password authentication without triggering Alpine/OpenSSH's whole-account lock check. Only explicit `--password-login` generates and prints an account password once; the tool never generates a sudo password.
- The invite's `Login:` line is **a verified conclusion**: before creating anything, the tool reads `sshd -T -C user=<new account>` to confirm the account really can log in, and says `UNVERIFIED` when it cannot read the config or finds connection-scoped `Match` criteria such as `Address`, `Host`, `LocalAddress`, or `LocalPort`. It never asserts a login method it did not check.
- **sshd's global configuration is never edited.** `--fix-sshd` writes a separate drop-in whose `Match User` block contains only directives needed to lift detected blockers, followed by `Match all` to reset the Include stream's scope; other accounts keep their effective policy. It is syntax-checked with `sshd -t`, proved effective with `sshd -T`, and reloaded (never restarted). Any failure triggers cleanup plus an independent retry by the invite transaction; an inability to remove or restore is surfaced as a rollback failure. `revoke` deletes the drop-in. **An explicit `DenyUsers`/`DenyGroups` rule is never bypassed.**
- `--password-login` is the weakest grant available (brute-forceable from anywhere, delivered in the clear). It is opt-in only, and refuses unless sshd is verified to accept passwords.
- **NOPASSWD sudo is essentially root.** Grant it only to trusted parties. Revoking deletes the account itself; it does not clean up processes, cron jobs, systemd units, or SUID files that account left behind as root.
- Deleting a user also deletes the home directory and SSH key. An SSH home must belong exactly to the target UID and can never be a root/UID-0 directory. If the system's delete command fails, the tool stops and tells you to check manually rather than pretending the revoke succeeded.
- **Guard against accidental deletion**: every new invite, including a permanent account with auto-delete disabled, gets an independent random generation embedded in both its exact GECOS marker and registry row. `revoke` normally requires the UID, generation, and marker all to match; any mismatch refuses or skips deletion. The generation is a readable account-incarnation binding, not a secret and not a defense against an attacker who already has root. Deleting an unregistered account with the exact marker requires explicit `--force`, plus `--confirm-force USER` when non-interactive.
- Fixed-GECOS accounts migrated from the v2 registry are reported as `managed=false identity=legacy-unverified`. A same-name, same-UID replacement can copy that old shared marker, so scheduled revocation, bulk cleanup, and uninstall never auto-delete these accounts. Inspect one manually, then invoke `revoke --user USER --force` directly and type the full username (non-interactive use also requires `--yes --confirm-force USER`).
- Even with `--force`, it refuses to delete root, well-known system accounts, UID 0, low-UID system accounts, and **any real account that this tool did not create (no exact marker)** — use the system's `userdel` for those.
- A failure at any creation step attempts a full rollback of the schedule, sudoers grant, sshd exception, registry row, and newly created account. Any rollback failure is reported and returns nonzero instead of presenting partial success as success.
- The **managed-state commits** of invite, revoke, cleanup, install, upgrade, and uninstall are serialized by one root-owned lifecycle lock outside removable state; account, schedule, grant, registry, and binary transitions cannot interleave. Human confirmation, dependency installation, and upgrade download/signature verification run outside the lock; after acquiring it, the command revalidates the account inventory or installed version before committing, so an interactive or network wait cannot delay an expired revoke. Usernames are checked through both the local passwd database and NSS before creation, so a local invite cannot shadow an LDAP/SSSD identity.
- If a sudoers grant or sshd exception cannot be fully removed during revoke, the account and registry row are retained and login is disabled when possible, preventing a surviving name-scoped grant from re-arming after username reuse. Cleanup, registry, and scheduler errors also return nonzero.
- The registry strictly validates its schema, fields, UID, and generation token. If it is corrupt or unreadable, `status`, `doctor`, cleanup, revoke, and uninstall fail closed instead of treating "unreadable" as "no accounts."
- Default upgrades use the official mirror as one complete preferred source and redownload the whole set from GitHub only after a transport failure; manifest-semantic, checksum, signature, or candidate-version failures abort. An explicit custom URL never switches to an official source.
- Every privileged action (account create/delete, install/upgrade/uninstall) is appended as a JSON line to the root-owned `/var/log/linux-temp-admin/audit.log` (time, actor `SUDO_USER`, action, target, result). A record is capped at 64 KiB and the log at 64 MiB; at the limit, the operation continues with a visible audit warning until the operator archives or rotates the file.
- When stdout is not a TTY, printing the private key is refused by default; pass `--allow-non-tty-private-key-output` only when the output channel is known to be safe.

## Development & license

- Contributing & local checks: [CONTRIBUTING.md](CONTRIBUTING.md)
- Report security issues privately per [SECURITY.md](SECURITY.md); version history in [CHANGELOG.md](CHANGELOG.md).

License: MIT, see [LICENSE](LICENSE).
