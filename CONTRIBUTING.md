# Contributing

Thanks for helping improve `linux-temp-admin`.

This project changes system users, sudoers files, SSH keys, and auto-revoke jobs. Keep changes small, auditable, and conservative.

The repo holds two implementations that coexist: the **v2 Go** rewrite (`cmd/`, `internal/`, shipped as a signed static binary) and the **v1 bash** tool (`temp-admin.sh`, in `v1.x` maintenance). New work targets v2; the checks below cover both.

## Before You Start

- Read `README.md` / `README.en.md` and `SECURITY.md`.
- Do not commit real invite bundles, private keys (including the release signing key), hostnames, server IPs, `/etc/shadow` data, or `authorized_keys` from real systems.
- Prefer focused pull requests: one behavior change, hardening fix, or documentation improvement at a time.

## Local Checks

**Go (v2)** — requires Go 1.25+:

```bash
go build ./...
go vet -printf.funcs=printf,errorf,warnf ./...
test -z "$(gofmt -l .)"            # gofmt must be clean
go test -race ./...
sudo go test -race -tags integration ./...   # root integration tests (disposable host)
```

**Bash (v1.x):**

```bash
bash -n temp-admin.sh tests/unit.sh
shellcheck -S warning temp-admin.sh tests/unit.sh scripts/*.sh
bash tests/unit.sh
```

For changes that touch account creation, revoke, sudoers, systemd timers, or `at`, also test in a disposable VM/container. Do not test destructive paths on a machine with real users unless you fully understand the impact.

## Design Rules

- Keep both implementations dependency-light and portable across Debian/Ubuntu, RHEL-compatible systems, Alpine (musl/BusyBox), and Arch where practical. v2 depends only on the Go stdlib plus `golang.org/x/sys` and `golang.org/x/crypto`.
- Validate all user-controlled values before using them in paths, shell commands, systemd units, sudoers, or registry records. In Go, never build a shell command string — use `os/exec` with an argv slice.
- Prefer root-owned temporary files plus atomic rename for managed root files; set owner/mode on the file descriptor and never follow a symlink at the target.
- Do not silently overwrite an existing stable command if doing so could break another registered user's auto-revoke task.
- Keep non-interactive automation explicit: dangerous actions need `--yes` plus a specific confirmation value when relevant.
- Update both Chinese and English README files when user-facing behavior changes.
- Add or update tests for validation, parsing, quoting, and safety boundary changes.

## Pull Request Checklist

- [ ] Go: `build`, `vet` (with `-printf.funcs`), `gofmt`, and `test -race` pass; integration tests pass or are unaffected. (Bash changes: `bash -n`, ShellCheck, and `bash tests/unit.sh` pass.)
- [ ] README / CHANGELOG updated when behavior changes.
- [ ] Security-sensitive behavior was tested in a disposable environment or clearly explained.
