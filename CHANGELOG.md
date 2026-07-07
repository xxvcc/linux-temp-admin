# Changelog

All notable changes to this project are documented here.

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
