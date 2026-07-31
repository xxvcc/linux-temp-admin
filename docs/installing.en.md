# Installation, Upgrades, and Download Verification

[中文](installing.md) | English

This guide is for administrators who install and maintain `linux-temp-admin`. See the [operator guide](operator-guide.en.md) for creating and revoking accounts, and the [security model](security-model.en.md) for guarantees and trust boundaries.

## Supported environment

- Linux 5.3 or newer;
- amd64 or arm64;
- primary support for Debian, Ubuntu, RHEL, Rocky, AlmaLinux, Fedora, and common aaPanel environments;
- best-effort support for Alpine and Arch Linux;
- root access plus curl, OpenSSL 3, sha256sum, and timeout for installation;
- `getent` or `nslookup` for GitHub CDN fallback, so every redirect target can be validated and pinned to a public address.

The binary has no dynamic-library or language-runtime dependency. Account lifecycle operations still use the system's `id`, `useradd`, `userdel`, `usermod`, and `chage`; password login additionally requires `chpasswd`, while granting sudo requires `sudo` and `visudo` for pre-commit policy validation. The tool does not fall back to a distro `adduser`/`deluser` or an arbitrary BusyBox account applet: command names alone cannot prove equivalent arguments, configuration, or compile-time shadow/group semantics. Missing tools can be installed through apt, dnf, yum, or apk after interactive confirmation.

Arch Linux has no safe partial-upgrade mode, while `pacman -Syu` upgrades the whole system. The tool therefore never runs pacman automatically while creating an account. Complete the prompted upgrade and dependency installation deliberately first.

## Convenience install

Run this in a shell that supports `pipefail`:

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/linux-temp-admin/install.sh | /usr/bin/sudo /bin/sh
```

After installation, run:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

The convenience command obtains the script from the official mirror over HTTPS and streams it directly to a root shell. `pipefail` propagates curl DNS, TLS, HTTP, and transfer failures to the whole pipeline; it **does not authenticate the script or stop an already received partial script from beginning execution**. Before the first curl has obtained the installer, the installer is not running and cannot provide its own GitHub fallback.

Once started, the installer applies a separate strict verification chain to the binary. SHA-256, the detached ed25519 signature, architecture, and candidate version must all pass before an atomic installation to `/usr/local/sbin/linux-temp-admin`. There is no unsigned or checksum-only fallback.

## Official mirror and GitHub fallback

The compiled-in preferred release source is:

```text
https://dl.ll.cd/linux-temp-admin
```

For a `latest` install or upgrade:

1. read the canonical mirror `latest.json` and pin one exact tag; only a transport failure while obtaining the index queries GitHub Latest;
2. download `SHA256SUMS`, the current-architecture binary, and its signature from that mirror version directory;
3. verify the three files as one source set without mixing in GitHub files;
4. only a transport failure discards the whole mirror set and redownloads it from the same GitHub tag;
5. checksum, signature, manifest-semantic, and candidate-version failures stop immediately.

Transport failures include DNS, TLS, timeout, HTTP, empty or oversized responses, and incomplete downloads. A mirror redirect, noncanonical manifest, SHA-256 mismatch, ed25519 verification failure, or version mismatch is not a transport failure and must not be hidden by changing sources.

Official mirror files must be returned directly without redirects. GitHub Release CDN redirects remain HTTPS-only and must resolve to validated public addresses. Every download has connect and total timeouts, hard size limits, and bounded retries.

## High-assurance first install

Before execution, the convenience path trusts the mirror HTTPS endpoint and stable-installer deployment. When the script must be authenticated before root executes it, independently pin all three of these values:

- the audited 40-hex commit;
- the install script SHA-256 obtained through a separately authenticated channel;
- the exact `vX.Y.Z` release tag.

The single canonical command, protected by dynamic failure tests, is in [Host install and upgrade in the maintainer release guide](releasing.md#host-install-and-upgrade). It first enters a sanitized root shell, creates a bounded root-owned temporary file, verifies the independent hash before execution, and forces the exact release.

Do not obtain both the script and its "expected hash" from the same web page or download path; that is not independent authentication. Obtain the tag, commit, script hash, and version from the release audit record and another trusted channel.

## Routine upgrade

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade --yes
```

The upgrader follows the same mirror-first, complete-source, fail-closed policy as the installer. By default it replaces only an older version. Use `--force` only for a deliberate same-version reinstall, downgrade, or repair of an unreadable target.

For a public custom source:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade --url https://downloads.example.com/linux-temp-admin
```

A URL containing credentials, tokens, or signed query values must not appear in argv, shell history, or logs. Put the binary URL in an absolute root-owned `0600` file; an optional second line can hold an independent signature URL:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade --url-file /root/lta-upgrade-url
```

Explicit `--url` and `--url-file` requests use only the operator-selected source and never silently switch to the official mirror or GitHub.

## Install a local binary

```bash
/usr/bin/sudo ./linux-temp-admin install
```

`install` places the currently running binary at the standard path without network access or an additional signature check. It is intended for offline hosts and self-built binaries, and copies the current inode through `/proc/self/exe`. Use it only after independently trusting that binary. A different existing target requires explicit `--force`.

## Diagnose installation failures

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin version
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

Classify the failure first:

- DNS, TLS, timeout, HTTP, or incomplete download: transport failure, eligible for the defined retry or fallback policy;
- checksum, signature, manifest, version, or architecture error: integrity failure, stop immediately and do not force a bypass;
- OpenSSL version, system tool, pidfd, or sshd condition: host-environment problem, follow the concrete `doctor` result.

See [Uninstall](operator-guide.en.md#uninstall) for teardown and managed-account handling.
