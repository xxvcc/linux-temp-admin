# Security Policy

`linux-temp-admin` creates SSH-accessible Linux users and can grant NOPASSWD sudo, so security reports are taken seriously.

## Supported Versions

| Version | Supported |
| --- | --- |
| 2.x (Go) | Yes |
| < 2.0 | No |

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting / security advisory flow for this repository when available. Include:

- affected version and commit;
- Linux distribution and init system;
- exact command line used;
- expected and actual behavior;
- whether root, sudoers, systemd, `at`, registry, or SSH key files are involved;
- minimal reproduction steps or a patch suggestion, if you have one.

If the report involves a real invite bundle, private key, username, host, or server address, redact it before sending.

## Security Scope

In scope:

- command injection, path traversal, symlink, TOCTOU, or unsafe overwrite issues;
- unsafe sudoers generation or privilege handling;
- account deletion or revoke safety bugs;
- private key leakage or unsafe non-interactive output behavior;
- auto-revoke reliability bugs that leave unexpected privileged access.

Out of scope:

- access granted intentionally to a trusted user;
- persistence created manually by a sudo-enabled temporary user after login;
- vulnerabilities in the underlying OS, OpenSSH, sudo, systemd, or package manager;
- social sharing mistakes after an invite bundle is copied outside the terminal.

## Operator Guidance

- Treat every invite bundle as a secret because it contains a one-time private key.
- Revoke access immediately after use; do not rely only on expiry.
- Grant `--sudo` only to users you trust with full root access.
- Keep `/usr/local/sbin/linux-temp-admin` root-owned and not group/world writable.
- v2: `upgrade` verifies an ed25519 signature against the embedded release key before installing (fails closed); the `install.sh` bootstrap verifies both the published SHA-256 checksum and a detached ed25519 signature (against the release key embedded in the script) over HTTPS, failing closed unless `LTA_ALLOW_UNVERIFIED=1` is set when openssl is unavailable. Report any way to bypass either check.
