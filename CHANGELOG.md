# Changelog

All notable changes to this project are documented here.

## v2.0.0 - Go rewrite

Full rewrite of the tool in Go, shipped as a single static binary. The bash tool
remains as the `v1.x` maintenance line; the two can coexist.

- Same commands and behavior as v1.2.3 (invite / revoke / status / cleanup-expired
  / doctor / install / upgrade / uninstall / menu, bilingual zh/en, `--lang`).
- Native implementations replace the external tools the bash version shelled out
  to: ed25519 keygen (no `ssh-keygen`), HTTP with context timeouts (no
  `curl`/`wget`), Go `time` (no `date`), `/etc/passwd` parsing (no `getent`),
  atomic fd-based writes (no `install`), `syscall.Flock` (no `flock`), and a
  `/proc` scan (no `pkill`) — eliminating whole classes of shell/`set -e`/BusyBox
  portability bugs. Only the account tools (`useradd`/`usermod`/`chage`/`userdel`
  or BusyBox `adduser`/`deluser`), `systemctl`/`at`, and `visudo`/`sudo` are still
  invoked, via argv (no shell).
- **Signature-verified self-upgrade**: `upgrade` downloads over HTTPS and verifies
  a detached ed25519 signature against an embedded release key before installing,
  failing closed — the authenticated upgrade the bash tool never had.
- The one-time private key stays in memory and is printed once (never written to
  disk). TOCTOU-safe atomic root writes (fd-based owner/mode, `O_NOFOLLOW`,
  rename-not-follow). flock-guarded registry with atomic rewrite.
- Clean break from v1 state: separate registry directory
  (`/var/lib/linux-temp-admin/v2/`) and systemd unit namespace; `doctor` detects
  and reports leftover v1 artifacts without touching them.
- Tested: per-package unit tests, a 119-input differential parity harness vs the
  bash validators, root integration tests (symlink-attack, concurrent-flock,
  real invite→revoke lifecycle, signature accept/reject), all under `-race`;
  static amd64/arm64 cross-builds. Reviewed by a multi-agent parity/security audit.
- Release/signing: `docs/releasing.md`, `scripts/release.sh`, `scripts/install.sh`.

## v1.2.3 - 2026-07-07

- Fixed the `wget` upgrade download and public-IP autodetection failing on BusyBox/musl (Alpine): the GNU-only `--timeout`/`--tries`/`--dns-timeout`/`--connect-timeout` options are now probed, and on BusyBox wget the fetch is bounded with `timeout(1)` instead (BusyBox `-T` segfaults on some builds).
- Made the `/proc` kill fallback and the `getent`->/etc/passwd helpers errexit-safe, so an empty `/proc` status read (process vanished mid-scan) or a non-zero `getent` can no longer abort a revoke/rollback or `status` under `set -e`.
- Added `install(1)` to the dependency check, `doctor`, and the package map (coreutils), so a BusyBox build without the `install` applet is reported and auto-installable instead of failing cryptically mid-invite.
- Made the BusyBox `wget` path fail fast when it cannot be time-bounded (no `--timeout` support and no `timeout(1)`) instead of running an unbounded fetch that could hang for minutes on a stalled connect.
- Aligned the future-date capability probe with the compound `date` expression actually used for expiry, so a `date` that supports simple but not compound offsets can no longer report OK and then fail mid-invite.
- Hardened the `/proc` kill fallback to no-op for an empty or root (0) UID, and tightened the `at`-job cleanup to match the exact queued revoke command rather than a loose substring.
- Reworked account expiry to a timezone-aware date (first midnight after `now + hours`) that is never set before the requested window on any creation time, replacing the day-rounding that could lock a `--no-auto-revoke` account early (or, on scheduling failure, keep it loginable ~1 day too long).
- Made `cancel_auto_revoke` clean up both the systemd units and any matching `at` job, so reusing a username can no longer leave a stale auto-delete task that later removes a freshly created account.
- Cancelled the pre-created auto-delete task when the registry write fails, so a partly-created account is not left with a task that could never delete an unregistered user.
- Made `cleanup-expired --compact` prune under a single held lock (re-checking existence inside it) so a concurrent invite cannot lose its fresh registry entry.
- Documented `--lang`, `version`, `upgrade --force/--url`, and `expiry-status --compact` in `help`/usage; aligned `valid_installed_version` with the 3-component version comparator; matched real-or-effective UID in the pkill fallback; and hardened the getent fallback against duplicate rows.

## v1.2.2 - 2026-07-07

- Fixed `upgrade` silently refusing to replace an existing older install (reported `installed=none` and no-op'd): `installed_revoke_version` shadowed the caller's variable, so the version comparison never saw the installed version.
- Added a `getent`->/etc/passwd fallback so `invite`/`status`/`revoke` work on musl/BusyBox systems (Alpine) where `getent` is absent, instead of failing mid-creation and rolling back.
- Added a `/proc`-scanning fallback for forcing off a user's sessions when `pkill` is unavailable (BusyBox/Alpine), so revoke no longer deletes an account while leaving its processes running.
- Hardened the managed-account check to require the full GECOS tag rather than a bare substring.
- Avoided running `sshd -T` twice per `doctor` (a bilingual message double-evaluated the port probe).
- Fixed the auto-delete unit name being corrupted by the "stable command installed" banner, which had let stdout from the install step leak into the recorded systemd/at unit and broke later revoke cleanup and status lookups.
- Tightened `--no-auto-revoke` account expiry: the extra day-granular safety buffer is now added only when an auto-delete timer will remove the account first, so expiry-only accounts no longer stay loginable up to a day past the requested window.
- Bounded `wget` upgrade downloads to the configured size limit during transfer instead of only after writing the whole file.
- Blocked HTTP-downgrade redirects on the `wget` upgrade fallback (`--max-redirect=0` where supported), matching curl's HTTPS-only redirect policy.
- Added unit coverage for install stdout cleanliness, buffered vs. unbuffered expiry dates, and the wget redirect guard.

## v1.2.1 - 2026-07-07

- Hardened upgrade downloads with a 1 MiB size limit and cleanup of failed or oversized downloads.
- Made critical write paths explicitly check copy, append, chmod, and rename failures instead of relying on `errexit`.
- Ensured interactive-menu invite/install/upgrade failure paths abort cleanly and preserve rollback behavior.
- Corrected invite/revoke/uninstall status reporting when registry cleanup or file removal fails.
- Added unit coverage for failed upgrade downloads, oversized downloads, and registry append failures.

## v1.2.0 - 2026-07-07

- Added `doctor`, `install`, `upgrade`, and `uninstall` commands.
- Added interactive menu entries for system diagnosis, installation, upgrade, and uninstall.
- Hardened upgrade/install behavior with HTTPS-only downloads, version parsing, Bash syntax validation, and root-owned path checks.
- Added project governance files: `SECURITY.md`, `CONTRIBUTING.md`, GitHub issue templates, and a pull request template.
- Expanded unit tests for upgrade URL validation, version comparison, help output, and command argument errors.
- Updated Chinese and English README maintenance documentation.

## v1.1.2 - 2026-07-07

- Hardened NOPASSWD sudo handling by validating the effective sudo policy and cleaning up on failure.
- Required safely root-owned files/directories before executing or writing managed root paths.
- Rejected invalid `--lang` values instead of silently ignoring them.
- Excluded additional non-public IPv4 documentation ranges from auto-detection.
- Added unit tests and CI coverage for Bash syntax, ShellCheck, and function-level checks.
- Ignored local runtime/test fixture directories via `.gitignore`.

## v1.1.1

- Prompted for UI language on interactive operational subcommands.
- Preserved non-interactive behavior for `--yes`, CI, and piped runs.

## v1.1.0

- Merged Chinese and English behavior into a single bilingual script.

## v1.0.0

- Hardened the temporary admin workflow after security review.
- Added registry, revoke, auto-expiry, rollback, and safety checks for managed system files.
