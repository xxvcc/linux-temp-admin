# linux-temp-admin

<p align="center">
  <img alt="Linux amd64 and arm64" src="https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian Ubuntu and RHEL compatible" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu%20%7C%20RHEL-compatible-A81D33?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> One command creates a time-limited SSH administrator account for a trusted collaborator and removes it automatically when it expires.

**linux-temp-admin** avoids sharing the root password and never stores the invite's private key on the server. It creates a temporary account, prints a bundle you can forward privately, and later removes the account, SSH key, and sudo grant.

The program is one static binary for amd64 and arm64 Linux, on both glibc and musl. Account, SSH, and scheduler operations still use the host's standard administration tools.

[中文](README.md) | English

## Quick start

Run this in a shell that supports `pipefail`:

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/linux-temp-admin/install.sh | /usr/bin/sudo /bin/sh &&
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

The tool then:

1. creates a temporary account with a random name;
2. generates a one-time SSH key and prints an invite bundle;
3. grants passwordless sudo by default and removes the account after 24 hours;
4. checks the effective sshd configuration before creation, refusing a definite blocker and reporting incomplete knowledge as `UNVERIFIED`.

The quick start obtains the installer from the official mirror and sends it to a root shell. `set -o pipefail` propagates curl failures, so a failed install does not continue to `invite`; it **does not authenticate the script or stop an already received partial script from beginning execution**. Once the installer is running, the downloaded binary is still verified with SHA-256 and an ed25519 signature. Use the [high-assurance first-install procedure](docs/installing.en.md#high-assurance-first-install) when the script must be authenticated before execution.

## Requirements

- Linux 5.3 or newer on amd64 or arm64;
- primary support for Debian, Ubuntu, RHEL, Rocky, AlmaLinux, Fedora, and common aaPanel environments;
- best-effort support for Alpine and Arch Linux;
- permission to obtain root through `/usr/bin/sudo`;
- curl, OpenSSL 3, sha256sum, and timeout for the installer.

After installation, run:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor
```

`doctor` checks dependencies, kernel capabilities, the package manager, sudoers, the init system, the SSH port, and public-key login conditions.

## Create and deliver an invite

The quick start already creates the first invite. Later invites can be created with:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo
```

The interactive flow shows the account, host, port, expiry, sudo state, and login verdict, followed by a command that saves the one-time private key. Only the public key is stored on the server.

Send the complete bundle through trusted private chat. After saving the key, the collaborator builds the SSH command from the bundle's Host, Port, and User fields, for example:

```bash
ssh -i ./xxvcc-a1b2c3d4e5.key -p 22 xxvcc-a1b2c3d4e5@203.0.113.10
```

The real private key is shown only once. Never put an invite bundle in a group chat, ticket, Notion page, or public site.

## Inspect and revoke

```bash
# Show all temporary accounts
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status

# Choose an account from a list and revoke it
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke

# Revoke one account directly
/usr/bin/sudo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1b2c3d4e5
```

By default, the account, home directory, SSH key, sudo grant, and any tool-created sshd exception are removed after 24 hours. Revoke access immediately when work is finished even when automatic removal is enabled.

## Everyday commands

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin              # Interactive menu
/usr/bin/sudo /usr/local/sbin/linux-temp-admin status       # Account status
/usr/bin/sudo /usr/local/sbin/linux-temp-admin doctor       # Inspect this host
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade      # Verified upgrade
/usr/bin/sudo /usr/local/sbin/linux-temp-admin cleanup-expired --compact
/usr/bin/sudo /usr/local/sbin/linux-temp-admin uninstall    # Remove managed accounts and the tool
```

The interface defaults to Chinese. The first interactive run offers Chinese or English, and the menu can switch languages later. Use `--lang zh` or `--lang en` for one invocation.

## Common scenarios

Use a 12-hour lifetime:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --hours 12
```

Create a regular account without sudo:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --no-sudo
```

Set the host, port, or username prefix:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --host admin.example.com --port 2222 --prefix ops --sudo
```

When public-key login is disabled, create an account-scoped sshd exception:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin invite --sudo --fix-sshd
```

This does not modify the global sshd policy, and the exception is removed with the account. See the [operator guide](docs/operator-guide.en.md) for automation, password login, permanent accounts, and complete troubleshooting.

## Security essentials

- `--sudo` grants NOPASSWD sudo, which is effectively full root access. Use it only for trusted people;
- a temporary administrator with root can create separate persistence that this tool cannot discover or remove during revoke;
- the invite's private key is shown once, must travel only through trusted private chat, and should be revoked as soon as work ends;
- the official mirror at `https://dl.ll.cd/linux-temp-admin` is the default source. Only transport failures redownload a complete set from GitHub; after a valid mirror index, fallback remains on the same release, while checksum, signature, or version failures stop immediately;
- private-key output is refused when stdout is not a terminal unless automation explicitly acknowledges the output channel;
- do not edit the registry under `/var/lib/linux-temp-admin` by hand.

See the [security model](docs/security-model.en.md) for detailed guarantees, trust boundaries, and failure handling. Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

## Documentation

- [Installation, upgrades, and download verification](docs/installing.en.md)
- [Operator guide](docs/operator-guide.en.md)
- [Security model](docs/security-model.en.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Maintainer release process](docs/releasing.md)

License: MIT. See [LICENSE](LICENSE).
