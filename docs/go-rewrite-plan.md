# linux-temp-admin — Go rewrite plan (v2.0)

Rewrite of the hardened bash tool (`temp-admin.sh`, currently v1.2.3) in Go.
Goal: keep full feature parity while eliminating the classes of bugs the bash
version keeps hitting (`set -e` subtleties, quoting/word-splitting, and the
GNU-vs-busybox portability of `date`/`wget`/`getent`/`install`/`pkill`), add the
two things it never had (signature-verified self-upgrade, real multi-distro
end-to-end tests), and preserve the "drop one artifact on any box" model.

## Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Distribution | **Signed static binaries + bash bootstrap.** Per-arch static binaries on GitHub Releases, each signed; a small auditable `curl \| bash` bootstrap fetches + verifies the right one. |
| 2 | Dependencies / CLI | **Near-zero deps + hand-written CLI.** stdlib + `x/sys/unix` + `x/crypto/ssh` only; subcommands dispatched with stdlib `flag`, full control over the bespoke UX (`--lang` anywhere, interactive menu, `--confirm-*`). |
| 3 | Scope | **Full parity with v1.2.3.** Includes `at` fallback, OpenRC/sysvinit, all five package managers, `doctor`, menu, zh/en. |
| 4 | Compatibility | **Clean break.** v2 uses its own fresh registry/unit-naming formats and does NOT take over bash-era deployments. A migration doc + a v2 "legacy-artifact detector" (warn, don't auto-adopt) covers already-deployed boxes. |

## Non-goals (v2.0)

- Not reimplementing the user database / PAM: creating & deleting users still
  shells out to `useradd`/`userdel`/`chage` (true in any language).
- No daemon, no database, no listening network surface.
- No automatic in-place takeover of v1 (bash) state — see Migration.

## Native vs shell-out boundary (where the rewrite pays off)

| Bash shells out to | Go does it natively with | Win |
|---|---|---|
| `ssh-keygen` | `crypto/ed25519` + `x/crypto/ssh` (keygen, OpenSSH marshal, fingerprint) | drop dependency |
| `curl`/`wget` (incl. `-T` segfault / unbounded hang) | `net/http` + `context` timeout + explicit redirect/TLS policy | fixes timeout/downgrade/size-cap at once |
| `date -d` (compound relative) | `time` | drop GNU/busybox divergence |
| `getent` | `os/user` (`osusergo`) + `/etc/passwd` fallback | drop dependency |
| `install` (atomic owner/mode) | `os.OpenFile(O_CREAT\|O_EXCL)` + `Fchown`/`Fchmod` + `rename` | drop dependency, tighter TOCTOU |
| `pkill` | read `/proc`, signal natively | drop dependency |
| `flock` | `x/sys/unix.Flock` on an fd | drop dependency |
| **Still shelled (no clean native path):** `useradd/usermod/userdel/deluser/adduser`, `chage`, `systemctl`, `at/atq/atrm`, `visudo`, `sudo -n -l`, `sshd -T` | `os/exec` with arg slices (no shell), stdout/stderr captured separately | no injection, explicit errors |

Dependency budget: `golang.org/x/sys/unix`, `golang.org/x/crypto/ssh`, stdlib
`crypto/ed25519` + `net/http`. Nothing else. `CGO_ENABLED=0` + `osusergo` build
tags → fully static, musl/glibc agnostic.

## Package layout

```
cmd/linux-temp-admin/main.go        thin entry: build info, dispatch
internal/
  cli/         subcommand dispatch, --lang extraction, interactive menu, confirm semantics
  i18n/        zh/en message catalog + language resolution (flag > env > locale > en)
  validate/    username / prefix / host(v4,v6,DNS) / port / hours / url / version (+ fuzz)
  fsutil/      atomic root-owned file/dir writes (replaces install/safe_write); O_NOFOLLOW, fd-based owner/mode
  registry/    v2 store + flock + symlink guards + atomic rewrite
  sshkey/      ed25519 keygen, OpenSSH serialize, fingerprint, TOCTOU-safe authorized_keys write
  sudoers/     write NOPASSWD, visudo validate, `sudo -n -l` recheck, remove
  user/        exists / create (useradd|adduser) / lock / expiry (chage) / delete / terminate procs / protection / passwd lookup
  schedule/    systemd unit (OnCalendar UTC) + at fallback + dual cancel; unit naming
  netdetect/   public-IP detection (cloud metadata + external services) with context timeouts
  selfmanage/  install / upgrade (SIGNED) / uninstall; version compare; atomic stable-binary replace
  sysinfo/     pkg-manager / SSH-port / init-system detection; doctor checks
  legacy/      detect v1(bash)-era artifacts and warn (see Migration)
```

File operations use fd/openat-family (`O_NOFOLLOW`, `Fchownat`) where possible —
closing TOCTOU windows more tightly than bash could.

## v2 data formats (fresh — clean break)

- **Registry**: `/var/lib/linux-temp-admin/v2/registry.tsv` (distinct dir from v1's
  `/var/lib/linux-temp-admin/users.tsv`, so both can exist during migration).
  0600, root-only, flock, symlink-guarded, atomic rewrite. First line a
  `# linux-temp-admin registry v2` header carrying a schema version so future
  format changes are detectable. Fields chosen freshly (no v1 byte-compat).
- **systemd units**: `linux-temp-admin-v2-revoke-<escaped-user>.{service,timer}` —
  distinct prefix so v2 never touches v1 units and vice versa.
- **at jobs**: identified by an embedded, version-tagged command marker.
- **stable binary**: still `/usr/local/sbin/linux-temp-admin` (v2 replaces v1 here
  on install); preflight refuses/​warns if a v1 registry with live accounts exists.

## Migration from v1 (bash) — clean break

v2 does not adopt v1 state. Instead:

1. **Doc**: "Draining v1" — run `temp-admin.sh status` to list active accounts,
   `temp-admin.sh revoke` each (or let them expire), `temp-admin.sh uninstall`,
   then install v2.
2. **`legacy` detector**: v2 `doctor` (and `install` preflight) scan for v1
   artifacts — the old registry, `linux-temp-admin-revoke-*` units (no `-v2-`),
   `/etc/sudoers.d/linux-temp-admin-*` for users not in the v2 registry — and
   **warn with exact cleanup commands**. Never auto-delete (that's the operator's
   call; auto-adopting foreign state is what we explicitly rejected).
3. **Optional `migrate` subcommand** (stretch): read v1 registry read-only and
   emit the exact v1 revoke commands to run — a convenience, not an auto-takeover.

## Testing strategy (the core reason for the rewrite)

1. **Unit / table tests** per package. Port the ~60 assertions from the existing
   `tests/unit.sh` directly as Go table tests (validators, version compare, date
   math, IP classification, registry parse, unit-name escaping) — a ready-made
   parity corpus.
2. **Golden parity tests** (P1): diff pure-function outputs against the bash
   version to lock 1:1 behavior where parity is required.
3. **End-to-end integration tests** (`//go:build integration`, run as root in
   containers): real `invite` → assert user exists, key `0600` owned by user,
   sudoers passes `visudo`, `chage` expiry date correct, systemd timer created;
   then `revoke` → assert everything cleaned. **CI matrix: Debian, Alpine
   (musl/busybox), Fedora.** This is what bash never had and what would have
   caught this session's regressions.
4. **Native fuzz** on host/username/url parsers.
5. **`-race`** on registry concurrency tests.
6. **Legacy-detector test**: a container pre-seeded with v1 artifacts → assert v2
   warns (and never modifies them).

## Phased roadmap

Each phase ships something buildable, tested, and reviewable. The bash tool stays
the shipping version until v2.0 is cut.

- **P0 — Scaffold.** `go.mod`, package skeleton, CI (build + `go vet` +
  staticcheck + test + cross-compile amd64/arm64 static), decisions recorded.
  *Deliverable:* green CI on an empty-but-structured tree.
- **P1 — Leaf packages.** `validate`, `i18n`, `version`, date math, IP
  classification, registry parse. Side-effect-free; ported tests + golden parity.
  *Deliverable:* these packages at 1:1 parity with bash, fully tested.
- **P2 — Security primitives.** `fsutil`, `registry`, `sshkey` (native crypto),
  `sudoers`. Root integration tests.
  *Deliverable:* can create a key + write authorized_keys + a valid sudoers file +
  a locked registry entry, verified as root.
- **P3 — System interaction.** `user`, `schedule` (systemd + at), `netdetect`,
  `sysinfo`/`doctor`, `legacy`.
- **P4 — CLI assembly.** all subcommands + interactive menu + i18n glue →
  feature parity with v1.2.3; per-command cross-check against bash behavior.
- **P5 — Self-upgrade + release.** `selfmanage` with **signed** payload
  verification; the auditable bash bootstrap; release pipeline (static amd64/arm64
  builds, sign, GitHub Release, checksums).
- **P6 — Cutover.** multi-agent parity/security audit (as in the bash hardening
  rounds) + integration matrix green + README (zh/en) → tag **v2.0.0**. Keep bash
  as a `v1.x` maintenance branch with a deprecation window.

## Definition of done (v2.0)

- Every v1.2.3 subcommand/flag reproduced (verified by per-command cross-check).
- Zero external dependency on `ssh-keygen`/`curl`/`wget`/`date`/`getent`/`install`/
  `pkill`/`flock` (all native); `useradd`/`chage`/`systemctl`/`at`/`visudo` shelled
  safely.
- Signed self-upgrade, fail-closed on bad signature.
- Integration suite green on Debian + Alpine + Fedora in CI.
- `-race` clean; fuzz corpus committed; staticcheck clean.
- Legacy-artifact detector + migration doc.

## Risks / watch-items

- **Static `os/user` + NSS**: pure-Go `os/user` (`osusergo`) does not consult NSS
  (LDAP/SSSD). Fine for local accounts (this tool's domain) with the `/etc/passwd`
  fallback — but note it explicitly and choose the build tag deliberately.
- **Lost "read-before-run-as-root" transparency** of a shipped binary: mitigate
  with reproducible builds, signatures, small auditable bootstrap, readable source.
- **The scheduled stable binary**: upgrade must atomically replace it without
  disrupting an auto-revoke run already in flight.
- **Scope creep**: parity is substantial; resist adding features during the port.
- **arch matrix**: amd64 + arm64 to start; add others on demand.

## Next step

With decisions locked, start **P0 (scaffold + CI)** and **P1 (leaf packages with
ported tests)**, so the geometry — "compiles, tests green, behavior matches bash"
— is visible early, then proceed phase by phase.
