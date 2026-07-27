# Security Policy

`linux-temp-admin` creates SSH-accessible Linux users and can grant NOPASSWD sudo, so security reports are taken seriously.

## Supported Versions

| Version | Supported |
| --- | --- |
| Latest 2.x release | Yes |
| Older 2.x releases | No |
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
- Treat revoke or rollback cleanup errors as unresolved incidents. The command returns nonzero and retains the account/registry when a name-scoped sudoers or sshd grant cannot be safely removed.
- The official installer is `https://dl.ll.cd/linux-temp-admin/install.sh`. Binary installation and upgrades verify the complete release set and detached ed25519 signature against the embedded keyring, with no unsigned or checksum-only fallback.
- The README convenience command streams the mirror's installer into a root shell and therefore trusts that first HTTPS/script path before binary verification begins. Use the [installation guide](docs/installing.en.md#high-assurance-first-install) when the script must be authenticated before execution.

The complete runtime guarantees, failure behavior, and residual risks are documented in the [security model](docs/security-model.en.md). Installation source selection and verification are documented in the [installation guide](docs/installing.en.md).
