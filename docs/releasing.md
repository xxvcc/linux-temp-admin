# Releasing linux-temp-admin v2 (Go)

v2 ships signed static binaries. `upgrade` verifies an **ed25519 signature**
against a public key embedded in the binary, failing closed on any mismatch.

## Signing key

The release signing key is **already configured**: the public key is committed in
[`internal/selfmanage/release_pubkey.hex`](../internal/selfmanage/release_pubkey.hex),
and the private key is held offline by the maintainer (`~/.lta/signing.key`, mode
`0600`). `upgrade` verifies each release against it. If no key were embedded,
`upgrade` fails closed (signed upgrade disabled).

**Back up the private key** in ≥2 offline places and treat it like a root
credential: losing it means no future release will verify on existing installs
(they carry the old public key), and a leak lets anyone sign malicious updates.

To rotate, or set up on a fresh maintainer machine:

```sh
go run ./cmd/lta-release keygen ~/.lta/signing.key   # prints the PUBLIC key hex
```

Replace the hex line in `internal/selfmanage/release_pubkey.hex` with the printed
public key and commit. (Rotation only takes effect on installs that upgrade to a
build carrying the new key.)

## Cut a release

```sh
LTA_SIGN_KEY=~/.lta/signing.key scripts/release.sh 2.0.0
gh release create v2.0.0 dist/linux-temp-admin-linux-* dist/SHA256SUMS --title v2.0.0
```

`release.sh` builds static `linux/amd64` and `linux/arm64` binaries (version
stamped via `-ldflags -X`), signs each (`<binary>.sig`, raw 64-byte ed25519),
and writes `SHA256SUMS`.

## Install / upgrade on a host

- **Install** (bootstrap): downloads over HTTPS and verifies SHA-256 against the
  published `SHA256SUMS` before installing.

  ```sh
  curl -fsSL https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh | sudo sh
  ```

- **Upgrade** (signature-verified by the binary itself):

  ```sh
  sudo linux-temp-admin upgrade
  ```

  Downloads `linux-temp-admin-linux-<arch>` + `.sig`, verifies the ed25519
  signature with the embedded key, confirms the downloaded version is newer,
  then atomically replaces the installed binary. `--url URL` overrides the source
  (its signature is `URL.sig`); `--force` reinstalls regardless of version.

## Trust model

- **Bootstrap install**: TLS + SHA-256 checksum (both fetched over HTTPS).
- **Upgrades**: TLS + an ed25519 signature that only the offline private key can
  produce, verified in-process before anything is written.
