# Contributing

Thanks for helping improve `linux-temp-admin`.

This project changes system users, sudoers files, SSH keys, and auto-revoke jobs. Keep changes small, auditable, and conservative.

## Before You Start

- Read `README.md` / `README.en.md` and `SECURITY.md`.
- Do not commit real invite bundles, private keys, hostnames, server IPs, `/etc/shadow` data, or `authorized_keys` from real systems.
- Prefer focused pull requests: one behavior change, hardening fix, or documentation improvement at a time.

## Local Checks

Run:

```bash
bash -n temp-admin.sh tests/unit.sh
shellcheck -S warning temp-admin.sh tests/unit.sh
bash tests/unit.sh
```

For changes that touch account creation, revoke, sudoers, systemd timers, or `at`, also test in a disposable VM/container. Do not test destructive paths on a machine with real users unless you fully understand the impact.

## Design Rules

- Keep the script dependency-light and portable across Debian/Ubuntu, RHEL-compatible systems, Alpine, and Arch where practical.
- Validate all user-controlled values before using them in paths, shell commands, systemd units, sudoers, or registry records.
- Prefer root-owned temporary files plus atomic rename for managed root files.
- Do not silently overwrite an existing stable command if doing so could break another registered user's auto-revoke task.
- Keep non-interactive automation explicit: dangerous actions need `--yes` plus a specific confirmation value when relevant.
- Update both Chinese and English README files when user-facing behavior changes.
- Add or update tests for validation, parsing, quoting, and safety boundary changes.

## Pull Request Checklist

- [ ] Bash syntax check passes.
- [ ] ShellCheck passes.
- [ ] Unit tests pass.
- [ ] README / CHANGELOG updated when behavior changes.
- [ ] Security-sensitive behavior was tested or clearly explained.
