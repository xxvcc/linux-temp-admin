# Security Model

[中文](security-model.md) | English

`linux-temp-admin` creates SSH-accessible Linux accounts and can grant NOPASSWD sudo. This document describes its guarantees, explicit non-goals, and failure behavior. See [SECURITY.md](../SECURITY.md) to report a vulnerability.

## Trust and threat scope

The tool assumes these foundations remain trusted:

- the Linux kernel, local root, filesystem, and system account database;
- OpenSSH, sudo, systemd or `at`, and the system account-management commands;
- the download trust chain explicitly chosen during installation;
- the operator's private channel used to deliver an invite.

It focuses on preventing its own command injection, path traversal, symlink overwrite, TOCTOU, account mis-deletion, UID/PID reuse mistakes, incomplete rollback, stale name-scoped grants, and unverified upgrades.

An attacker who already has root can modify the program, kernel, account database, audit log, or registry. The tool cannot defend against root on the same host. It also does not repair vulnerabilities in the operating system, OpenSSH, sudo, or package manager.

## Invite credentials

- SSH keys are the default. The private key is printed once after successful creation and is not stored on the server;
- private-key or password output is refused when stdout is not a terminal unless `--allow-non-tty-private-key-output` explicitly acknowledges the channel;
- an invite bundle is itself a secret and must travel only through trusted private chat;
- `--password-login` generates a random password shown once, but that password can be attacked over the network throughout the account lifetime and is the weaker grant;
- key-based accounts use a shadow value that cannot match a valid password without triggering Alpine/OpenSSH's whole-account locked interpretation.

## What sudo means

`--sudo` writes an account-specific NOPASSWD sudoers grant and is effectively full root access. A trusted collaborator with root can create cron jobs, systemd units, SUID files, new accounts, or other persistence. Revoke removes only the account, grants, and tasks created and registered by this tool; it cannot infer and remove unrelated objects that collaborator created as root.

A "temporary account" limits the lifetime of the managed entry point. It is not a sandbox for root behavior. Never issue a sudo invite to an untrusted person.

## SSH login verdict

Before creation, the tool evaluates the effective configuration equivalent to `sshd -T -C user=<new account>`, including Include, Match, and distribution crypto policy. The invite claims a verified key login only when that can be proved; incomplete knowledge is reported as `UNVERIFIED`, and a definite blocker refuses creation.

`--fix-sshd` writes only an account-scoped drop-in and restores later configuration scope with `Match all`. It validates with `sshd -t` and an effective-configuration check, then reloads rather than restarts sshd. Any failure removes the file and rolls back. Explicit `DenyUsers` and `DenyGroups` rules are never bypassed.

## Account identity and deletion safety

Every new invite binds:

- the UID observed at creation;
- a random 128-bit generation token;
- an exact managed GECOS marker;
- the corresponding registry record.

Automatic revoke and ordinary `revoke` require these identity values to agree. If the account is deleted and recreated, the UID is reused, the marker changes, or the registry is corrupt, unattended deletion is refused rather than guessing that the same name is the same object.

Accounts migrated from the old fixed-marker registry are shown as `legacy-unverified` and are never automatically deleted by timers, bulk cleanup, or uninstall. They require manual inspection and a fully confirmed `revoke --force`.

Even with `--force`, root, UID 0, low-UID system accounts, and real accounts without the tool's exact marker are not deleted as managed accounts.

## Processes and PID reuse

Before revocation, processes belonging to the target UID are inspected and Linux pidfds bind signals to those exact process instances, avoiding a signal to an unrelated process after PID reuse. Linux 5.3 plus usable `pidfd_open` and `pidfd_send_signal` are required for safe revocation. `doctor` probes them, and `invite` refuses creation when they are unavailable.

## Transactions, locking, and rollback

Managed-state commits for invite, revoke, cleanup, install, upgrade, and uninstall share a root lifecycle lock so account, grant, registry, task, and binary changes do not interleave. Human confirmation, dependency installation, download, and signature verification are kept outside the lock where possible; state is revalidated after acquiring it.

Any invite failure attempts to roll back the task, sudoers file, sshd exception, registry row, and account. A rollback failure is reported explicitly with a nonzero status and is never presented as success.

If revoke cannot completely remove a name-scoped grant, it retains and attempts to disable the account so username reuse cannot reactivate the leftover privilege. Treat every rollback or revoke error as an unresolved security incident.

## Files and state

- registry, preferences, and audit directories require root ownership and strict permissions;
- the registry validates schema, fields, UID, generation, and size and fails closed when corrupt or unreadable;
- installation, upgrades, and state writes use same-directory temporary files, metadata checks, atomic replacement, and required fsync operations;
- an SSH home must belong to the target UID, and recursive removal refuses root/UID 0 homes and live mount boundaries;
- sudoers files, sshd exceptions, and automatic tasks use restricted project names and are removed only as verified managed objects.

Do not edit `/var/lib/linux-temp-admin/v2/registry.tsv` manually. An unreadable registry is never treated as an empty one.

## Expiry revocation

The exact deadline is enforced by a systemd timer or an existing `at` backend; `chage -E` is only a day-granularity lock fallback. Invite creation rolls back when neither scheduling backend is available.

The revoke task rechecks UID, generation token, GECOS marker, and registry row. An identity mismatch, missing registry, or recreated account is skipped safely for operator inspection. Failed systemd revokes use bounded retries; one-shot backend failures require `doctor` and manual action.

## Installation and upgrade trust boundary

Default binary installation and upgrades use the embedded ed25519 keyring to verify canonical `SHA256SUMS`, a detached signature, architecture, and version. The official mirror is the preferred complete source. After a valid mirror index, only a transport failure discards the complete set and redownloads it from the same GitHub tag; a transport failure obtaining the index queries GitHub Latest. Manifest-semantic, checksum, signature, and candidate-version failures stop immediately.

The README convenience command streams the official mirror's installer into a root shell. `pipefail` propagates curl failures, but it cannot authenticate the script before execution or retract partial bytes already delivered to the shell. Once running, the installer verifies the binary. When the first script itself must be authenticated, use the [commit-, independent-hash-, and exact-version-pinned procedure](installing.en.md#high-assurance-first-install).

A compromised mirror can replace the stable installer or manifest or deny service, threatening new convenience installs. It cannot forge an ed25519 binary accepted by an already installed client. The current v1 release private key was historically stored on a networked maintainer host, so it is not claimed to have been offline since generation; future rotation must use an overlap release to migrate the embedded keyring.

A valid signature alone does not provide absolute rollback protection for a first install: control over version routing can replay an older version that remains validly signed. Independently pin the exact version and audit record when rollback resistance is required.

## Audit log

Privileged operations append JSON lines to `/var/log/linux-temp-admin/audit.log`, recording time, caller, action, target, and result. The root-owned file and directory have per-record and total limits; at 64 MiB operations continue with a warning to archive or rotate the log.

This is a local trace, not a remote immutable log resistant to root. Uninstall retains it by default and removes it only with explicit `--purge-audit`.

## Conditions requiring operator action

- invite or revoke returns nonzero;
- `doctor` reports an orphaned grant, identity mismatch, or missing revoke task;
- registry corruption, permission drift, or an unsafe installation path;
- checksum, signature, manifest, or candidate-version failure;
- possible leakage of a private key, password, download credential, or invite bundle.

Do not ignore these conditions because another source worked or the account appears unable to log in. Preserve evidence, revoke related access, fix the cause, and rerun `doctor`.
