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
- Keep `/usr/local/sbin/linux-temp-admin` a root-owned regular file, never a symlink, and not group/world writable. Invites refuse to schedule against a command that fails those checks or cannot report a valid version.
- Keep `/var/lib/linux-temp-admin/v2/registry.tsv` root-owned and unmodified. Registry corruption or read failure is handled fail-closed; unattended revokes additionally require the recorded UID and random generation token to match, and every live deletion still requires the exact managed GECOS marker.
- Treat revoke or rollback cleanup errors as unresolved incidents. The command returns nonzero and retains the account/registry when a name-scoped sudoers or sshd grant cannot be safely removed.
- The official installer is `https://dl.ll.cd/linux-temp-admin/install.sh`. Default install and `upgrade` operations prefer that official mirror and obtain the selected release's manifest/checksum data, binary, and detached ed25519 signature as a complete source set. They never combine mirror and GitHub files.
- GitHub is a fallback only for transport failures such as DNS, TLS, timeout, HTTP, empty/oversized-response, or incomplete-download failures. A valid mirror manifest pins fallback assets to the same tag. Manifest-semantic, checksum, signature, and candidate-version failures stop immediately without fallback.
- Official mirror URLs must return files directly without redirects. The mirror index is canonical single-line JSON, `SHA256SUMS` is lowercase NUL-free text ending in a newline, and detached signatures are exactly 64 raw bytes. A mirror redirect or noncanonical file is a source-policy failure and never triggers fallback; GitHub Release CDN redirects remain HTTPS-only and must resolve to public addresses.
- Explicit `upgrade --url` and `upgrade --url-file` requests use only the operator-selected source and never silently switch to the official mirror or GitHub.
- Both default paths fail closed. `upgrade` verifies the complete release set and detached ed25519 signature against the embedded keyring before installing; the `install.sh` bootstrap verifies the published SHA-256 checksum and detached signature, and requires OpenSSL 3 with no unsigned or checksum-only fallback. Report any way to bypass these checks or the source-selection rules above.
