# Releasing linux-temp-admin v2 (Go)

v2 ships signed static binaries. `upgrade` verifies an **ed25519 signature**
against a public key embedded in the binary, failing closed on any mismatch.

## One-time: create the signing key

```sh
go run ./cmd/lta-release keygen ~/.lta/signing.key   # prints the PUBLIC key hex
```

- Keep `~/.lta/signing.key` **offline**; only the release step uses it.
- Paste the printed public-key hex onto its own line in
  [`internal/selfmanage/release_pubkey.hex`](../internal/selfmanage/release_pubkey.hex),
  then commit that change. Until a valid key is embedded, `upgrade` refuses
  (signed upgrade disabled) — this is intentional fail-closed behavior.

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
