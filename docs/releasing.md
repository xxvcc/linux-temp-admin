# Releasing linux-temp-admin v2 (Go)

v2 ships signed static binaries. `upgrade` verifies an **ed25519 signature**
against a public key embedded in the binary, failing closed on any mismatch.
Building and running the release helpers requires Go 1.26.5 or newer.

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

`keygen` is create-only: it refuses an existing path and any symlink instead of
overwriting key material. Move the old file aside deliberately before a rotation.

Replace the hex line in `internal/selfmanage/release_pubkey.hex` with the printed
public key and commit. (Rotation only takes effect on installs that upgrade to a
build carrying the new key.)

## Cut a release

The build runs in CI; **signing stays offline** — the signing key never touches
GitHub Actions. Two steps:

**1. Tag → CI tests and builds a draft.** Push an exact semantic-version tag with major 2
or newer: `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-prerelease`. Four-component,
metadata-suffixed, malformed, and pre-v2 tags are rejected. The `Release` workflow
([`.github/workflows/release.yml`](../.github/workflows/release.yml)) builds the
first runs vet, ordinary race tests, root integration race tests, formatting,
shell syntax, and ShellCheck. Only after all gates pass does it build static
`linux/amd64` + `linux/arm64` binaries (`-trimpath`, version stamped from the
tag), write `SHA256SUMS`, and stage them in a **draft** GitHub Release with
generated final release notes. A rerun may refresh a draft, but refuses to
overwrite assets after publication.

```sh
git tag -a v2.0.1 -m "linux-temp-admin v2.0.1"
git push origin v2.0.1        # CI builds + stages the draft
```

**2. Sign offline → publish.** On the machine that holds the signing key, sign
the exact CI-built binaries and publish:

```sh
git fetch --tags origin
git switch --detach v2.0.1
LTA_SIGN_KEY=~/.lta/signing.key scripts/sign-release.sh v2.0.1
```

[`sign-release.sh`](../scripts/sign-release.sh) downloads the draft's binaries,
verifies their checksums, signs each (`<binary>.sig`, raw 64-byte ed25519),
**verifies every signature against the embedded public key (fails closed)**,
refreshes `SHA256SUMS` to cover the `.sig` files, uploads them, and flips the
release from draft to published. It signs the bytes CI actually published, so
the signature is valid for the exact assets users download — no reproducible
build assumption required. Before downloading anything it requires a clean
worktree at the tag, verifies the local tag object equals GitHub's tag object,
and refuses unless the release is still a draft. Prerelease tags remain marked
prerelease; only a stable tag becomes Latest.

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

- **Install** (bootstrap): downloads over HTTPS and verifies both SHA-256 against
  the published `SHA256SUMS` and a detached ed25519 signature against the release
  key embedded in `install.sh`, before installing. It fails closed on any
  mismatch; if openssl (>= 3.0) is unavailable it refuses to install unless
  `LTA_ALLOW_UNVERIFIED=1` is set (checksum-only fallback). The script must run as
  root, accepts HTTPS redirects only, caps each response at 64 MiB, and requires
  curl or wget with both `--https-only` and `--max-filesize` support.

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

- **Bootstrap install**: TLS + SHA-256 checksum + a detached ed25519 signature
  verified against the release key embedded in `install.sh` (fails closed; the
  same offline key as `upgrade`). All fetched over HTTPS.
- **Upgrades**: TLS + an ed25519 signature that only the offline private key can
  produce, verified in-process before anything is written.
- **Release provenance**: binaries are built in CI (auditable workflow logs,
  `-trimpath` reproducible) but signed offline — the signing key is never present
  in GitHub Actions, so a compromised CI cannot mint a binary that passes
  `upgrade`'s signature check.
