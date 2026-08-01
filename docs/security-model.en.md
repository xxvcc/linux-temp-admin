# Security Model

[中文](security-model.md) | English

`linux-temp-admin` creates SSH-accessible Linux accounts and can grant NOPASSWD sudo. This document describes its guarantees, explicit non-goals, and failure behavior. See [SECURITY.md](../SECURITY.md) to report a vulnerability.

## Trust and threat scope

The tool assumes these foundations remain trusted:

- the Linux kernel, local root, filesystem, and system account database;
- OpenSSH, sudo, systemd or `at`, and the system account-management commands;
- mail-delivery services and local identities that the administrator authorizes to modify entries in an accepted system mail spool;
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

`--sudo` writes an account-specific NOPASSWD sudoers grant and is effectively full root access. A trusted collaborator with root can create cron jobs, systemd units, SUID files, new accounts, or other persistence. Revoke removes the account, grants, and auto-revoke task managed by this tool; to prevent deferred work from crossing a username/UID reuse, it also removes the account's personal crontab and every `at`/`batch` job owned by that UID. It cannot infer and remove system-wide cron jobs, systemd units, SUID files, new accounts, or other unrelated objects that the collaborator created as root.

A "temporary account" limits the lifetime of the managed entry point. It is not a sandbox for root behavior. Never issue a sudo invite to an untrusted person.

## SSH login verdict

Before creation, the tool checks compatibility against the effective configuration equivalent to `sshd -T -C user=<new account>`, including Include, Match, and distribution crypto policy. The invite says "verified against the effective sshd config" only when the check finds neither a known blocker nor an unevaluated rule. Incomplete knowledge is reported as `UNVERIFIED`, and an unresolved blocker reported by the check refuses creation.

This verdict means only that the planned credential is compatible with the effective sshd configuration inspected by the tool. It is not an end-to-end SSH login test and does not prove the complete state of the network, firewall, PAM, SELinux, or the running sshd process. Test the invite through the intended connection path before delivery.

A future account has no NSS group membership before creation, so OpenSSH cannot reliably evaluate `Match Group` yet. Only when the check has no other known blocker and the future groups are its sole uncertainty does the tool create a pending account with no password or key credential, rerun the effective-configuration check against its real groups, and install a credential after that check passes. A known blocker still follows the normal refusal or explicitly authorized repair path; deferral cannot hide it. A `Match` that depends on connection attributes such as source address or destination port remains unevaluable: key invitations are explicitly marked `UNVERIFIED`, while password invitations fail closed.

`--fix-sshd` writes only an account-scoped drop-in and restores later configuration scope with `Match all`. It validates with `sshd -t` and an effective-configuration check. When a running sshd can be reached, it requests a reload and never a restart. If no running daemon can be notified, the file remains for socket activation or the next start, but the invite is marked `UNVERIFIED`. Other grant failures attempt to remove the file and roll back; a failed removal or restorative reload returns nonzero and retains recovery evidence under the incomplete-rollback rules below. Explicit `DenyUsers` and `DenyGroups` rules are never bypassed.

## Account identity and deletion safety

Every new invite binds:

- the matching UID/GID durably burned and explicitly selected before `useradd`;
- a random 128-bit generation token;
- an exact managed GECOS marker;
- the corresponding registry record.

Automatic revoke and ordinary `revoke` require these identity values to agree. If the account is deleted and recreated, the UID is reused, the marker changes, or the registry is corrupt, unattended deletion is refused rather than guessing that the same name is the same object.

A root-only high-water file beside the registry advances atomically before each `useradd`. Even if later creation or rollback fails, this tool never allocates that UID/GID again. A candidate is above every UID and GID in the ordinary local passwd/group range and is limited to the overlap of the `login.defs` UID and GID ranges. `useradd -U -u ID -K GID_MIN=ID -K GID_MAX=ID` pins the account and private group to the same number, and the complete passwd identity is checked afterward. Once a v5 registry exists, a missing or corrupt high-water file fails closed instead of being reconstructed from only the surviving accounts and risking reuse of a retired identity. This guarantee covers this tool, an intact state directory, and the local account databases. Non-enumerable external NSS, another local root explicitly assigning IDs, or manual state-directory deletion remain trust boundaries, so this is not a claim of absolute system-wide non-reuse.

The account-database entry is created with `useradd -M -e 1970-01-01 -p '!'`, so it is expired to a past date and password-locked from the moment it appears, and it does not copy `/etc/skel`, which may contain host-local authentication material. A default generated username has a long random suffix and is paired with a UID/GID this tool has never reused. While the account is still credential-less, Home-less, and expired, the tool performs two process-termination and cron/at cleanup passes without a 65-second wait. An explicit `--user` may reuse a historical name and a daemon-cached name-keyed job, so that path still clears, waits one complete polling cycle, and clears again. Only after the repeated checks and complete identity verification pass does the tool create an empty mode-`0700` Home through a pinned `/home` directory descriptor and assign its owner. The account stays past-date expired throughout preparation. A final `chage` writes the requested expiry or never-expire value and activates login only after the password or key, sshd/sudo policy, registry state, and automatic revoke task are complete.

The tool repeatedly rechecks the complete passwd snapshot at critical transaction stages; the GECOS identity-finalization and account-deletion paths also verify it after their name-scoped helpers return, detecting observable same-name replacement. These checks do not turn a helper into an atomic compare-and-swap; local root that can concurrently rewrite the account database remains inside the trust boundary. Account deletion invokes only `userdel --` without `-r/-f`, never a distro `deluser` that can read `/etc/deluser.conf` and re-enable recursive cleanup or an arbitrary BusyBox applet whose compile-time account-database semantics are unknown. Shadow-utils `-f` is also refused because it can delete a same-name group that another account still uses as its primary group.

Accounts migrated from the old fixed-marker registry are shown as `legacy-unverified` and are never automatically deleted by timers, bulk cleanup, or uninstall. The historical timer's `--yes --force --confirm-force` arguments do not authorize deleting such an account. A surviving legacy task is reported as orphaned and may be cancelled by `cleanup-expired --compact` without deleting the live account or registry row. After manual inspection, an operator must run `revoke --force` in an interactive terminal and type the complete username; non-interactive deletion is always refused.

A release before v2.9.2 could retain a live pending creation row after `useradd` succeeded and later preparation failed. That row alone grants no ordinary or unattended deletion authority. Only after manual inspection may an operator make it a recovery candidate by selecting it in the menu or running `revoke --user <name> --force` directly in an interactive terminal and typing the full username. The random registry generation must exactly match the pending GECOS marker, the recorded UID must be either the not-yet-written zero or the current UID, the Home must be the deterministic managed path, both UID and GID must be non-root, and the shell must be nonempty. With systemd, the exact pending generation enters persistent quarantine; only the synchronous fallback weakens it to a generation-less UID-only `DeletionStarted` witness before cleanup. `--yes`, automatic tasks, uninstall bulk removal, non-TTY input, and every incomplete or mismatched state always fail closed and retain the account and row.

Root, UID 0, and reserved names are never deleted. A low-UID account is revocable as tool-created only when its current registry UID, random generation, and exact GECOS marker are fully bound; an unregistered or legacy-identity low-UID account remains protected even with `--force`. A real account without the tool's exact marker is likewise never deleted as managed.

## Deferred jobs, processes, and identity reuse

A personal crontab and `at`/`batch` jobs do not reliably disappear when login is disabled, current processes are killed, or plain `userdel --` runs. Before a new account receives a password, public key, or sudo grant, and before an old account releases its username/UID, the tool removes and verifies the same-name personal crontab, inventories every job through `atq` and the generated `atrun uid=` header from `at -c`, and removes jobs for the target UID. Immediately before each `atrm`, it reads the same ID again and rebinds it to either the expected UID or the tool's exact revoke command; after a removal error it also distinguishes a surviving target from a disappeared target or reused ID. The tool recognizes its own automatic revoke job only when the `atrun` header says that root owns it. It probes that owner header within a 64 KiB limit, so an oversized job already identified as non-root does not block automatic-task inventory; only a root job is retained and read in full under the larger bounded limit. The external `at` interface has no atomic compare-and-delete operation, so a very short interval remains between that fresh read and `atrm`; local root able to replace a job in that interval is inside the trust boundary. A partial at-tool installation, corrupt or oversized queue output, an unparseable owner, or a surviving artifact fails closed.

Direct spool verification explicitly supports the cron directories `/var/spool/cron/crontabs`, `/var/spool/cron`, and `/var/spool/cron/tabs`, and the at directories `/var/spool/cron/atjobs`, `/var/spool/at`, and `/var/spool/atjobs`. Implementations using other layouts are outside this file-level verification. A new default random account uses a UID/GID this tool will not reuse, so its two immediate cleanup passes neither release the identity nor need to wait for a daemon poll. An explicitly reused username, the revoke fallback without persistent systemd, and uninstall finalization still synchronously hold the disabled identity for at least 65 seconds. An unreliable process inventory conservatively waits or retains the account rather than skipping the window.

Normal systemd revoke does not wait in the foreground. It first removes and confirms the sudo/sshd grants, disables login, and performs two process-termination and cron/at cleanup passes. It then creates a persistent quarantine timer in a separate namespace and atomically records its deadline and unit as deletion-recovery state. Only after the timer is enabled and the state is durable does the command report that access is revoked. The passwd entry continues to occupy the name, UID, and GID while the account is expired, locked, and has no managed privilege entry. The deadline rounds “now plus 65 seconds” upward to a whole minute, so quarantine lasts at least 65 and less than 125 seconds. At expiry, the service repeats identity, job, and process checks before cleaning Home/mail and invoking `userdel`. `Persistent=true` catches up after a host was down across the deadline. `doctor` reports a missing or modified finalizer separately, and compaction does not discard its registry witness.

Before revocation, every live thread in each thread group carrying the target UID is inspected; a group whose leader is already a zombie but whose worker still runs is not treated as empty. Linux pidfds bind signals to the inspected thread-group instance, avoiding a signal to an unrelated process after PID reuse, and thread credentials are checked again after the pidfd is opened. The UID is scanned again after every SIGKILL sweep, and account deletion proceeds only after two consecutive stable per-thread scans observe no live process. A TGID/TID disappearing before inspection resets that confirmation; an unreliable scan or exhausted bounded retries fails closed. Linux 5.3 plus usable `pidfd_open` and `pidfd_send_signal` are required for safe revocation. `doctor` probes them, and `invite` refuses creation when they are unavailable.

The `/proc`, pidfd, cron, and at checks are repeated bounded snapshots under the same lifecycle lock, not a kernel-atomic freeze. They substantially narrow the race window and retain the disabled account when observation is unreliable, but cannot exclude local root that changes account databases or schedulers outside that lock; local root remains inside the trust boundary. System-wide cron entries, systemd units, or other root persistence separately created by a sudo-enabled collaborator are also outside personal-job cleanup.

## Transactions, locking, and rollback

Managed-state commits for invite, revoke, cleanup, install, upgrade, and uninstall share a root lifecycle lock so account, grant, registry, task, and binary changes do not interleave. Human confirmation, dependency installation, download, and signature verification are kept outside the lock where possible; state is revalidated after acquiring it.

A same-name `invite` also owns the exclusive side of an account barrier, while current revokes use its shared side. If a compatibility `revoke --yes` command without UID/generation arguments finds that a same-name creation already owns the exclusive barrier, it deletes nothing and skips successfully so an old systemd job cannot retry against the new generation; a manually issued non-interactive command of the same shape is skipped too and must be followed by `doctor` and a fresh revoke after the concurrent operation. This is a safety-first migration boundary, not proof that the account was deleted. An old binary that was already loaded and began waiting on the global lock before the new barrier took effect cannot be fully reconstructed by the new process locks; invite also scans for the exact root-owned legacy revoke process and refuses username reuse, but system helpers and `/proc` observation still are not an atomic compare-and-swap, and local root remains inside the trust boundary.

Registry schema v5 records the monotonic-identity bit, quarantine deadline, and separate finalizer unit. Normal systemd revoke writes exact UID/generation-bound `DeletionStarted` quarantine state after immediate access removal. Traditional synchronous paths write their deletion witness before controlled mail/Home cleanup and `userdel`. Jobs, processes, and the complete identity are checked again after Home cleanup and before `userdel`. Exact-generation accounts retain their UID/generation binding. Legacy, unregistered, and synchronous pending-rollback paths retain only a UID witness, preserving mail-spool cleanup authority after an already-authorized deletion loses the account without turning an incomplete identity into unattended live-account deletion authority. Post-deletion recovery permits only owner-checked conventional mail-spool cleanup and never recursively removes the absent account's old Home path; each sweep also confirms both before and after that no same-name local or NSS identity exists. An ordinary record update, removal, or compaction cannot overwrite a recovery row, and same-name creation waits for recovery to finish. A live UID-only or generation-mismatched account allows only interactive `--force` manual recovery; its stale automatic task is cancelled so an unattended command with no authority to finish recovery does not retry forever.

An invite failure runs its rollback stack, cleaning the task, sudoers file, sshd exception, registry row, and any new account that can still be matched to the complete creation-time identity. If the half-created account identity, grant cleanup, or recursive Home cleanup cannot be confirmed, the tool retains the account and registry witness for manual recovery instead of guessing by username. Every incomplete rollback is reported explicitly with a nonzero status and is never presented as success.

If the UID selected for a new account already has residual processes, or a `/proc` scan cannot reach a reliable verdict, the tool retains a credential-less, past-date-expired, password-locked pending account without a Home to keep that UID occupied and preserves the registry witness for manual recovery. It does not delete the account and immediately expose the same UID to another allocation.

If revoke cannot completely remove a name-scoped grant, it retains and attempts to disable the account so username reuse cannot reactivate the leftover privilege. Treat every rollback or revoke error as an unresolved security incident.

## Files and state

- registry, preferences, and audit directories require root ownership and strict permissions;
- the registry validates schema, fields, UID, generation, quarantine state, and size. The monotonic UID/GID high-water file must also be root-owned, mode `0600`, well-formed, and present alongside a v5 registry; corruption or unreadable state fails closed;
- installation, upgrades, and state writes use same-directory temporary files, metadata checks, atomic replacement, and required fsync operations;
- a new account uses only the deterministic `/home/<username>` path when it did not already exist; `/home` must be root-managed and the created real directory must belong to the target non-root UID/GID. Revoke removes it while the complete account identity remains checkable. Recursive Home removal uses directory descriptors. A symlink at the Home root, an owner mismatch, or a live mount boundary is refused; an internal symlink is unlinked without following its target. Traversal checks cooperative budgets of 100,000 entries, 128 levels, and two minutes between filesystem calls, so the deadline cannot interrupt one blocked filesystem call;
- conventional mail cleanup checks only the traditional single-file mbox locations `/var/mail/<username>` and `/var/spool/mail/<username>`. Those two paths may alias each other, but their resolved target cannot escape the two accepted directories. An existing mail spool must be a real root-owned directory with no setuid bit; a world-writable spool must also have sticky protection. Common `root:mail 2775`/`0775`, the observed `root:mail 3777`, and Arch Linux's `root:root 1777` are therefore accepted. Mode `0777`/`2777` without sticky, any non-root owner including `mail:mail`, and every setuid directory fail closed. A target mailbox must be a non-symlink regular file owned by the captured UID, and its absence is checked again after the parent directory is fsynced;
- creation preflights the mail-spool directories before `useradd`, then reopens and revalidates them while the account is bound to its selected UID but remains expired, locked, credential-less, and without a Home. A preflight failure creates no account. If a root becomes unsafe after the helper runs, the transaction attempts rollback with the complete captured identity and retains a disabled account plus its registry witness when cleanup cannot be confirmed. Mail-specific cleanup neither searches nor traverses Maildir and never touches aaPanel's `/www/vmail`; a Maildir inside the managed Home is still removed with that Home under the preceding rules during complete-account revocation;
- sudoers files, sshd exceptions, and automatic tasks use restricted project names and are removed only as verified managed objects.

Do not edit `/var/lib/linux-temp-admin/v2/registry.tsv` manually. An unreadable registry is never treated as an empty one.

## Expiry revocation

A default random-name invite computes its requested lifetime after immediate deferred-job cleanup and no longer has a 65-second foreground wait. An explicit `--user` computes the lifetime after its synchronous name-reuse defense, so the safety wait does not shorten nominal access. The target is converted once into an absolute deadline rounded upward to a whole minute, adding less than one minute. Invite display, the `chage -E` backstop date, the systemd timer, and `at` are all derived from that target; `at` receives an absolute UTC minute so a daylight-saving transition cannot revoke access early. `chage -E` remains only a later, day-granularity lock fallback. `at` is attempted only when systemd is unavailable or its failed scheduling attempt was safely rolled back. Invite creation rolls back when neither backend can schedule successfully or the deadline has already arrived before scheduling. Scheduler load, host downtime, and revoke retries can delay actual removal, so access that is no longer needed should be revoked manually.

The revoke task rechecks UID, generation token, GECOS marker, and registry row. An identity mismatch, missing registry, or recreated account is skipped safely for operator inspection. Failed systemd revokes use bounded retries; one-shot backend failures require `doctor` and manual action.

## Installation and upgrade trust boundary

Default binary installation and upgrades use the embedded ed25519 keyring to verify canonical `SHA256SUMS`, a detached signature, architecture, and version. The official mirror is the preferred complete source. After a valid mirror index, only a transport failure discards the complete set and redownloads it from the same GitHub tag; a transport failure obtaining the index queries GitHub Latest. Manifest-semantic, checksum, signature, and candidate-version failures stop immediately.

The README convenience command streams the official mirror's installer into a root shell. `pipefail` propagates curl failures, but it cannot authenticate the script before execution or retract partial bytes already delivered to the shell. Once running, the installer verifies the binary. When the first script itself must be authenticated, use the [commit-, independent-hash-, and exact-version-pinned procedure](installing.en.md#high-assurance-first-install).

A compromised mirror can replace the stable installer or manifest or deny service, threatening new convenience installs. It cannot forge an ed25519 binary accepted by an already installed client. The current v1 release private key was historically stored on a networked maintainer host, so it is not claimed to have been offline since generation; future rotation must use an overlap release to migrate the embedded keyring.

A valid signature alone does not provide absolute rollback protection for a first install: control over version routing can replay an older version that remains validly signed. Independently pin the exact version and audit record when rollback resistance is required.

## Audit log

Privileged operations make a best-effort attempt to append JSON lines to `/var/log/linux-temp-admin/audit.log`, recording time, caller, action, target, and result. The root-owned file and directory have per-record and total limits. At 64 MiB, or after another write failure, the privileged operation continues with a warning and may have no audit record; the operator must archive, rotate, or repair the log. If a crash leaves an incomplete final line, the next writer truncates it back to the last complete JSON line before appending.

This is a local trace, not a remote immutable log resistant to root. Uninstall retains it by default and removes it only with explicit `--purge-audit`.

## Conditions requiring operator action

- invite or revoke returns nonzero;
- `doctor` reports an orphaned grant, identity mismatch, or missing revoke task;
- registry corruption, permission drift, or an unsafe installation path;
- checksum, signature, manifest, or candidate-version failure;
- possible leakage of a private key, password, download credential, or invite bundle.

Do not ignore these conditions because another source worked or the account appears unable to log in. Preserve evidence, revoke related access, fix the cause, and rerun `doctor`.
