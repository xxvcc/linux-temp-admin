# Changelog

All notable changes to this project are documented here.

## v2.2.4 - Signature-verified bootstrap install

- **`install.sh` now verifies an ed25519 signature at first install.** The
  bootstrap installer previously trusted the release with only a same-origin
  SHA-256 checksum (trust-on-first-use). It now also verifies a detached ed25519
  signature against the release public key embedded in the script — the same
  offline key `upgrade` uses — failing closed on any mismatch, so a tampered or
  maliciously re-published binary is rejected even if the release host is
  compromised. When openssl (>= 3.0, for `pkeyutl -rawin`) is unavailable the
  install fails closed unless `LTA_ALLOW_UNVERIFIED=1` opts into checksum-only
  trust; the wget path probes for `--https-only` so BusyBox-only hosts still
  install. The Go binary is unchanged from v2.2.3.
- **Docs.** The security policy drops the removed v1 (bash) support line, and the
  README is reorganized as a focused user manual.

## v2.2.3 - invite refuses names revoke would protect

- **`invite` no longer creates an account the tool could never revoke.** A
  username in a reserved namespace — an explicit `--user root` / `--user
  systemd-*`, or any name generated from `--prefix systemd` — passed creation but
  is refused by the revoke path, which protects `systemd-*` and well-known system
  names. The account (optionally with NOPASSWD sudo) could be created but never
  deleted: not by a manual `revoke`, nor by its own auto-revoke timer, which
  failed silently at fire time while the invite reported success and scheduled it.
  Creation now shares a single `IsReservedName` predicate with revoke and refuses
  these names up front — the prefix is checked on the name-generation path (an
  explicit `--user` leaves the prefix unused), and the final username is checked
  authoritatively so an explicit `--user` cannot slip a reserved name through.

## v2.2.2 - The menu stops scrolling your results away

- **The interactive menu no longer redraws after every action.** It is drawn on
  entry, and again whenever you press Enter on an empty line. Previously each
  action's output was immediately buried under eight lines of menu, so you had to
  scroll back to read it — worst of all for `invite`, whose bundle carries the
  one-time private key. Now the result is the last thing on screen, directly above
  a one-line prompt (`请选择 [1-8]（回车显示菜单）` / `select [1-8] (Enter shows
  the menu)`), and results are framed with blank lines that do not depend on the
  terminal echoing your Enter, so piped and scripted runs read the same.
- A blank line at the prompt now redraws the menu instead of reporting an invalid
  choice.

## v2.2.1 - install tells the truth; the menu drops it

- **`install` no longer claims a write it did not make.** Running `install` from
  the already-installed binary finds the target byte-identical and does nothing —
  that short-circuit precedes the `--force` check — yet it printed "installed the
  stable command" and appended a matching `install ok` line to the audit log. It
  now reports "already the stable command; nothing to install" and audits nothing.
  `Manager.Install` returns whether it wrote, mirroring `Upgrade`'s `("", nil)`.
- **The interactive menu drops `install`.** Reaching the menu means a binary is
  already running as root, so `install` there was either the no-op above or a
  one-time bootstrap better done as `sudo ./linux-temp-admin install`. That made
  it look like a duplicate of `upgrade`, which its old label ("Install/update the
  current binary...") reinforced. `upgrade` is now the menu's single,
  signature-verified update path; the prompt range follows the table, so entries
  renumber and the menu is now `[1-8]`.

  `install` remains a subcommand: it is the only way to place a binary you already
  hold — an air-gapped host, or a self-built binary that carries no release
  signature (`upgrade` is HTTPS-only and fails closed without one). And
  `Manager.Install` stays what both `upgrade` and auto-revoke's
  `ensureStableInstalled` are built on.

## v2.2.0 - Full Chinese UI; v1 removed

- **Chinese is now the default UI language.** Precedence is unchanged (`--lang` >
  `LINUX_TEMP_ADMIN_LANG` > `LC_ALL`/`LANG` > fallback), but the fallback is now
  Chinese instead of English. Most servers run with no `LANG` set, so the Chinese
  UI of this Chinese-first project was almost never reached. An `en*` flag, env
  var, or locale still selects English; a locale in some third language (say
  `de_DE`) now gets Chinese where it previously got English.
- **Interactive menu is now fully localized.** Menu entries 1–8 previously printed
  bare English subcommand names in both languages, so `--lang zh` (or a `zh_*`
  locale) produced a Chinese title and heading over an English menu body. Each
  entry now carries a translated description, and label and dispatch live in one
  table so a reordered entry can no longer run the wrong command.
- **Host detection no longer interrogates before it looks.** `invite` without
  `--host` used to ask "detect public IP? [y/N]" before doing anything, so the
  common case cost an extra keystroke and defaulted to No. Cloud metadata and
  local interfaces — neither of which leaves the host or its link — are now
  probed silently, and what they find prefills the host prompt (Enter accepts,
  or type over it). The external echo services (`api.ipify.org` and friends)
  still require an explicit yes, because that step discloses the server to a
  third party. `--yes` mode is unchanged: it never reaches out and still
  requires `--host`.
- Restored the `TerminateProcesses` uid guard test that was lost with the v1
  unit-test suite: `kill` is now indirected so a test can prove a non-positive
  uid signals nothing, without signalling every root process when the guard
  regresses.
- **v1 (bash) tool removed.** `temp-admin.sh`, its unit tests, and its ShellCheck
  workflow are deleted, along with the `internal/legacy` detector and the leftover
  v1 artifact warnings `doctor` used to print. The ShellCheck workflow now lints
  `scripts/` instead. Both READMEs are rewritten to document the Go tool directly
  rather than carrying the v1 manual below a deprecation banner.
  - Upgrading from v1 is no longer assisted: drain v1 accounts with a v1 checkout
    (git tag `v1.2.3`) before removing its registry at
    `/var/lib/linux-temp-admin/users.tsv` and its
    `linux-temp-admin-revoke-*` systemd units. This tool never touched them; it
    only reported them.

## v2.1.0 - Operation audit log; v1 deprecation

- **Operation audit log (new).** Every privileged mutating operation — account
  create/delete, and install / uninstall / upgrade — is appended as a JSON line to
  a root-owned, append-only `/var/log/linux-temp-admin/audit.log` (0600), recording
  the timestamp, actor (the invoking user under sudo, plus the effective uid),
  action, target, result, and key parameters. Writes are best-effort and never
  block or fail the operation itself. (An on-host log is tamperable by root;
  forward it to a remote collector for tamper-evidence.)
- **v1 (bash) tool deprecated.** `temp-admin.sh` is no longer maintained and now
  prints a deprecation notice at startup pointing to the v2 Go tool (suppress with
  `LTA_SUPPRESS_DEPRECATION=1`). It still runs; no further features or fixes.

## v2.0.2 - Audit follow-up hardening

Low-severity hardening from the follow-up audit:

- **upgrade: reject redirects to private/reserved addresses.** An `upgrade` HTTPS
  redirect is refused if it resolves to a loopback / private / link-local / CGNAT
  address, so a compromised release host cannot use the root-run fetch as an SSRF
  pivot (e.g. to cloud metadata). The initial, operator-supplied `--url` is
  unaffected, so a deliberate internal mirror still works.
- **auto-revoke: stop orphaning systemd `.service` files.** `revoke` now precisely
  detects whether it is the firing auto-revoke service for a unit (via the process
  cgroup) rather than treating any systemd scope as such, so a manual `revoke` run
  from a systemd-managed shell no longer leaves an orphaned `.service` behind.
- **SSH port hint: consistent selection.** With multiple `Port` directives in
  `sshd_config`, the config fallback now reports the first (matching `sshd -T`)
  instead of the last.

## v2.0.1 - Security & correctness audit fixes

Follow-up hardening from a multi-pass security audit of the v2 rewrite. No new
features and no command/flag changes; existing behavior is unchanged except for the
`revoke` protection fix noted below.

- **revoke: never delete a real account via a stale registry entry.** A UID>=1000
  account is now protected unless it carries the tool's managed GECOS marker — a
  per-account, reuse-proof signal — instead of trusting a name-keyed registry entry
  that can outlive a deleted temp account and be inherited by a later real user of
  the same name. The managed check is now an exact GECOS-field match, not a
  substring, matching its documented guarantee.
- **invite: a failed sudo grant can no longer leave a NOPASSWD drop-in behind.** The
  drop-in is removed on any grant/verification failure, and a removal failure is
  reported rather than silently swallowed.
- **upgrade: version comparison is numeric-aware for prereleases** (`rc10` > `rc9`),
  closing an anti-rollback gap where a signed older prerelease could pass the
  "not newer" gate and a genuine prerelease upgrade could be skipped.
- **public-IP auto-detection rejects private/reserved addresses** on the external
  echo path too (previously only the cloud-metadata path filtered them).
- Fail-closed hardening: refuse the SSH-key write when the home directory's owner
  cannot be determined; refuse to replace an installed binary that cannot be read
  back unless `--force` is given.

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
