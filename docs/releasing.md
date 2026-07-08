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

The build runs in CI; **signing stays offline** — the signing key never touches
GitHub Actions. Two steps:

**1. Tag → CI builds a draft.** Push a `v2+` tag. The `Release` workflow
([`.github/workflows/release.yml`](../.github/workflows/release.yml)) builds the
static `linux/amd64` + `linux/arm64` binaries (`-trimpath`, version stamped from
the tag), writes `SHA256SUMS`, and stages them in a **draft** GitHub Release.

```sh
git tag -a v2.0.1 -m "linux-temp-admin v2.0.1"
git push origin v2.0.1        # CI builds + stages the draft
```

**2. Sign offline → publish.** On the machine that holds the signing key, sign
the exact CI-built binaries and publish:

```sh
LTA_SIGN_KEY=~/.lta/signing.key scripts/sign-release.sh v2.0.1
```

[`sign-release.sh`](../scripts/sign-release.sh) downloads the draft's binaries,
verifies their checksums, signs each (`<binary>.sig`, raw 64-byte ed25519),
**verifies every signature against the embedded public key (fails closed)**,
refreshes `SHA256SUMS` to cover the `.sig` files, uploads them, and flips the
release from draft to published. It signs the bytes CI actually published, so
the signature is valid for the exact assets users download — no reproducible
build assumption required.

The release is public only after step 2, so users never see an unsigned release.

### Fully local fallback

If CI is unavailable, build, sign, and publish entirely locally in one shot:

```sh
LTA_SIGN_KEY=~/.lta/signing.key scripts/release.sh 2.0.1
gh release create v2.0.1 dist/linux-temp-admin-linux-* dist/SHA256SUMS --title v2.0.1
```

`release.sh` uses the same `-trimpath` static build as CI, so it reproduces the
same binaries; it signs each and writes `SHA256SUMS` (covering the sigs too).

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
- **Release provenance**: binaries are built in CI (auditable workflow logs,
  `-trimpath` reproducible) but signed offline — the signing key is never present
  in GitHub Actions, so a compromised CI cannot mint a binary that passes
  `upgrade`'s signature check.
