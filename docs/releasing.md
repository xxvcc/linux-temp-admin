# Releasing linux-temp-admin v2

Release binaries are reproducibly rebuilt and signed with ed25519. The release
private key is never present on a networked machine, candidate source is never
executed on the signing machine, and CI output is never signed merely because
its own checksum file matches.

## Maintainer model

This repository currently uses a single-maintainer release process. Pull
requests preserve an auditable diff and must pass every required status check
and resolve every discussion, but GitHub does not require approval from another
account, CODEOWNERS review, or approval of the last push. The
`release-staging` and `release-mirror` environments likewise have no required
reviewers; their branch/tag restrictions and disabled administrator bypass
remain enforced.

References below to independent caches, channels, machines, checks, or recorded
values describe technical separation, not a second human reviewer. This model
explicitly gives up human separation of duties: compromise of the sole
maintainer's GitHub authority can change protected source and workflows without
another person's approval. The required CI, OpenPGP-signed tag, offline ed25519
release signature, reproducible rebuild, immutable Release, restricted mirror
receiver, and public post-deployment verification remain mandatory. Keep the
GitHub credential, OpenPGP private key, and offline ed25519 key separately
protected; external review is useful but is not a release gate.

## One-time trusted tooling setup

On an audited source commit, before preparing any candidate release, record its
full 40-hex commit ID in the maintainer's release audit record, place a standalone
root-owned checkout at the path below, and build the small network-incapable
signer with the exact supported Go toolchain:

```bash
TRUSTED_SIGNER_SOURCE=/opt/lta-reviewed-source
TRUSTED_SIGNER_COMMIT='replace-with-the-independently-recorded-40-hex-audited-commit'
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  LC_ALL=C TRUSTED_SIGNER_SOURCE="$TRUSTED_SIGNER_SOURCE" \
  TRUSTED_SIGNER_COMMIT="$TRUSTED_SIGNER_COMMIT" \
  /bin/bash -p <<'LTA_TRUSTED_SIGNER'
set -Eeuo pipefail
umask 077
fail() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 || fail "cannot disable core dumps"
unset TAR_OPTIONS GZIP BZIP2 BZIP XZ_OPT

  : "${TRUSTED_SIGNER_SOURCE:?set the root-owned audited source directory}"
  : "${TRUSTED_SIGNER_COMMIT:?set the independently recorded audited commit}"
  [[ "$TRUSTED_SIGNER_SOURCE" == /* && "$TRUSTED_SIGNER_SOURCE" != *$'\n'* ]] \
    || fail "TRUSTED_SIGNER_SOURCE must be an absolute single-line path"
  [[ -d "$TRUSTED_SIGNER_SOURCE" && ! -L "$TRUSTED_SIGNER_SOURCE" ]] \
    || fail "trusted signer source is not a real directory"
  [[ "$(readlink -f -- "$TRUSTED_SIGNER_SOURCE")" == "$TRUSTED_SIGNER_SOURCE" ]] \
    || fail "trusted signer source must be canonical and contain no symlinked ancestor"
  [[ "$TRUSTED_SIGNER_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || fail "TRUSTED_SIGNER_COMMIT must be exactly 40 lowercase hex characters"

  check_safe_source_dir() {
    local source_dir=$1 source_dir_meta source_dir_uid source_dir_mode source_dir_extra parent_dir
    while :; do
      [[ -d "$source_dir" && ! -L "$source_dir" ]] \
        || fail "trusted signer source ancestor is not a real directory: $source_dir"
      source_dir_meta=$(stat -Lc '%u %a' -- "$source_dir") \
        || fail "cannot inspect trusted signer source ancestor: $source_dir"
      read -r source_dir_uid source_dir_mode source_dir_extra <<< "$source_dir_meta"
      [[ "$source_dir_meta" == "$source_dir_uid $source_dir_mode" &&
         "$source_dir_uid" == 0 && "$source_dir_mode" =~ ^[0-7]{3,4}$ &&
         -z "$source_dir_extra" ]] \
        || fail "trusted signer source ancestor has invalid metadata: $source_dir"
      (( (8#$source_dir_mode & 8#7022) == 0 )) \
        || fail "trusted signer source ancestor is writable by another user or has special bits: $source_dir"
      [[ "$source_dir" == / ]] && break
      parent_dir=$(dirname -- "$source_dir")
      [[ "$parent_dir" != "$source_dir" ]] || fail "cannot resolve trusted signer source ancestry"
      source_dir=$parent_dir
    done
  }
  check_safe_source_dir "$TRUSTED_SIGNER_SOURCE"
  [[ -d "$TRUSTED_SIGNER_SOURCE/.git" && ! -L "$TRUSTED_SIGNER_SOURCE/.git" ]] \
    || fail "trusted signer source must be a standalone Git checkout"
  for external_git_store in \
    "$TRUSTED_SIGNER_SOURCE/.git/commondir" \
    "$TRUSTED_SIGNER_SOURCE/.git/objects/info/alternates" \
    "$TRUSTED_SIGNER_SOURCE/.git/objects/info/http-alternates"; do
    [[ ! -e "$external_git_store" && ! -L "$external_git_store" ]] \
      || fail "trusted signer source uses an external Git object or metadata store: $external_git_store"
  done

  [[ -d /tmp && ! -L /tmp ]] || fail "/tmp is not a real directory"
  tmp_meta=$(stat -Lc '%u %a' -- /tmp) || fail "cannot inspect /tmp"
  [[ "$tmp_meta" =~ ^0\ 1[0-7]{3}$ ]] \
    || fail "/tmp must be root-owned, sticky, and free of other special bits"
  build_root=$(mktemp -d /tmp/lta-trusted-signer-build.XXXXXXXXXX)
  install_stage=
  cleanup() {
    timeout -k 5 120 rm -rf -- "$build_root" \
      || echo "warning: could not remove trusted build workspace" >&2
    [[ -z "$install_stage" ]] || timeout -k 5 60 rm -f -- "$install_stage" \
      || echo "warning: could not remove trusted install staging file" >&2
  }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM

  source_nodes="$build_root/source-nodes"
  if ! timeout -k 5 120 find "$TRUSTED_SIGNER_SOURCE" -print0 > "$source_nodes"; then
    fail "cannot enumerate the complete trusted signer source tree"
  fi
  while IFS= read -r -d '' source_node; do
    [[ ! -L "$source_node" && ( -d "$source_node" || -f "$source_node" ) ]] \
      || fail "trusted signer source contains a symlink or special file: $source_node"
    source_meta=$(stat -Lc '%u %a' -- "$source_node") \
      || fail "cannot inspect trusted signer source: $source_node"
    read -r source_uid source_mode source_extra <<< "$source_meta"
    [[ "$source_meta" == "$source_uid $source_mode" && "$source_uid" == 0 &&
       "$source_mode" =~ ^[0-7]{3,4}$ && -z "$source_extra" ]] \
      || fail "trusted signer source has invalid metadata: $source_node"
    (( (8#$source_mode & 8#7022) == 0 )) \
      || fail "trusted signer source is writable by another user or has special bits: $source_node"
  done < "$source_nodes"

  cd -- "$TRUSTED_SIGNER_SOURCE"
  PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  LC_ALL=C
  export PATH LC_ALL
  if ! trusted_go_version=$(env -i PATH="$PATH" LC_ALL=C HOME=/root GOROOT= GOENV=off \
       GOTOOLCHAIN=local GOFLAGS= GOWORK=off GOEXPERIMENT= GOFIPS140=off \
       GOTELEMETRY=off GOAUTH=off timeout -k 5 30 go version); then
    fail "cannot execute the trusted Go toolchain"
  fi
  [[ "$(awk '{print $3}' <<<"$trusted_go_version")" == go1.26.5 ]] \
    || fail "trusted Go toolchain is not exactly go1.26.5"
  signer_arch=$(env -i PATH="$PATH" LC_ALL=C HOME=/root GOROOT= GOENV=off \
    GOTOOLCHAIN=local GOFLAGS= GOWORK=off GOEXPERIMENT= GOFIPS140=off \
    GOTELEMETRY=off GOAUTH=off timeout -k 5 30 go env GOARCH) \
    || fail "cannot determine the trusted Go architecture"
  case "$signer_arch" in
    amd64) signer_tune=GOAMD64=v1 ;;
    arm64) signer_tune=GOARM64=v8.0 ;;
    *) echo "unsupported trusted-signer architecture: $signer_arch" >&2; exit 1 ;;
  esac
  git_env=(env -i PATH="$PATH" LC_ALL=C HOME=/root \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 \
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false \
    GIT_PAGER=cat GIT_OPTIONAL_LOCKS=0)
  git_options=(--git-dir="$TRUSTED_SIGNER_SOURCE/.git" --work-tree="$TRUSTED_SIGNER_SOURCE" \
    -c core.bare=false -c core.fsmonitor=false -c core.hooksPath=/dev/null \
    -c core.attributesFile=/dev/null -c core.pager=cat)

  if ! source_head=$("${git_env[@]}" timeout -k 5 60 git \
    "${git_options[@]}" \
    rev-parse --verify 'HEAD^{commit}'); then
    fail "cannot resolve trusted signer source HEAD"
  fi
  [[ "$source_head" == "$TRUSTED_SIGNER_COMMIT" ]] \
    || fail "trusted signer source HEAD is not the recorded audited commit"

  source_tree="$build_root/source-tree"
  "${git_env[@]}" timeout -k 5 60 git \
    "${git_options[@]}" \
    ls-tree -r -z "$TRUSTED_SIGNER_COMMIT" > "$source_tree" \
    || fail "cannot enumerate audited commit tree"
  while IFS= read -r -d '' tree_entry; do
    tree_mode=${tree_entry%% *}
    case "$tree_mode" in
      100644|100755) ;;
      120000|160000) fail "audited signer commit contains a symlink or submodule" ;;
      *) fail "audited signer commit contains unsupported mode $tree_mode" ;;
    esac
  done < "$source_tree"

  if ! signer_fsize_block_bytes=$(
    ulimit -f 1 || exit 1
    awk '$1 == "Max" && $2 == "file" && $3 == "size" { print $4; found=1 }
         END { if (!found) exit 1 }' /proc/self/limits
  ); then
    fail "cannot determine the trusted Bash file-size limit unit"
  fi
  case "$signer_fsize_block_bytes" in
    512|1024) ;;
    *) fail "unsupported trusted Bash file-size limit unit" ;;
  esac
  source_archive_max_bytes=134217728
  source_archive_blocks=$((
    (source_archive_max_bytes + signer_fsize_block_bytes - 1) / signer_fsize_block_bytes
  ))
  source_archive="$build_root/source.tar"
  if ! (
    ulimit -f "$source_archive_blocks" || exit 1
    exec "${git_env[@]}" timeout -k 5 120 git \
      "${git_options[@]}" \
      archive --format=tar --output="$source_archive" "$TRUSTED_SIGNER_COMMIT"
  ); then
    fail "cannot export the bounded audited signer source snapshot"
  fi
  source_snapshot="$build_root/source"
  mkdir -m 0700 "$source_snapshot"
  timeout -k 5 120 tar --extract --file="$source_archive" --directory="$source_snapshot" \
    --no-same-owner --no-same-permissions \
    || fail "cannot extract audited signer source snapshot"
  while IFS= read -r -d '' tree_entry; do
    tree_header=${tree_entry%%$'\t'*}
    tree_path=${tree_entry#*$'\t'}
    read -r tree_mode tree_type tree_object <<<"$tree_header"
    [[ "$tree_type" == blob && -f "$source_snapshot/$tree_path" && ! -L "$source_snapshot/$tree_path" ]] \
      || fail "exported signer source is missing a regular audited file: $tree_path"
    extracted_object=$("${git_env[@]}" timeout -k 5 60 git "${git_options[@]}" \
      hash-object --no-filters -- "$source_snapshot/$tree_path") \
      || fail "cannot hash exported signer source: $tree_path"
    [[ "$extracted_object" == "$tree_object" ]] \
      || fail "exported signer source differs from audited Git object: $tree_path"
  done < "$source_tree"
  cd -- "$source_snapshot"

  for build_id in a b; do
    mkdir -m 0700 "$build_root/$build_id" "$build_root/$build_id/gocache" \
      "$build_root/$build_id/gomodcache" "$build_root/$build_id/gopath" \
      "$build_root/$build_id/gotmp"
    env -i PATH="$PATH" LC_ALL=C HOME=/root GOROOT= GOENV=off GOTOOLCHAIN=local \
      GOFLAGS= GOWORK=off GO111MODULE=on GOEXPERIMENT= GOFIPS140=off \
      GOTELEMETRY=off GOAUTH=off GOVCS='*:off' GOPROXY=https://proxy.golang.org \
      GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GONOPROXY= GOINSECURE= \
      GOCACHE="$build_root/$build_id/gocache" \
      GOMODCACHE="$build_root/$build_id/gomodcache" \
      GOPATH="$build_root/$build_id/gopath" GOTMPDIR="$build_root/$build_id/gotmp" \
      CGO_ENABLED=0 GOOS=linux GOARCH="$signer_arch" "$signer_tune" \
      timeout -k 30 900 go build -mod=readonly -buildvcs=false -trimpath \
        -o "$build_root/$build_id/lta-release" ./cmd/lta-release
  done
  timeout -k 5 60 cmp "$build_root/a/lta-release" "$build_root/b/lta-release"
  [[ -d /opt && ! -L /opt && "$(readlink -f -- /opt)" == /opt ]] \
    || fail "/opt must be a canonical real directory"
  check_safe_source_dir /opt
  if [[ -e /opt/lta-release-tools || -L /opt/lta-release-tools ]]; then
    check_safe_source_dir /opt/lta-release-tools
  else
    timeout -k 5 60 install -d -o 0 -g 0 -m 0700 /opt/lta-release-tools
    check_safe_source_dir /opt/lta-release-tools
  fi
  [[ ( ! -e /opt/lta-release-tools/lta-release && ! -L /opt/lta-release-tools/lta-release ) \
     || ( -f /opt/lta-release-tools/lta-release && ! -L /opt/lta-release-tools/lta-release ) ]] \
    || fail "trusted signer destination is a symlink or special file"
  install_stage=$(mktemp /opt/lta-release-tools/.lta-release.XXXXXXXXXX)
  timeout -k 5 60 install -o 0 -g 0 -m 0755 "$build_root/a/lta-release" "$install_stage"
  timeout -k 5 60 cmp "$build_root/a/lta-release" "$install_stage"
  timeout -k 5 60 mv -Tf -- "$install_stage" /opt/lta-release-tools/lta-release
  timeout -k 5 60 cmp "$build_root/a/lta-release" /opt/lta-release-tools/lta-release
  timeout -k 5 60 sha256sum /opt/lta-release-tools/lta-release
LTA_TRUSTED_SIGNER
```

The preparation workstation must likewise have Go 1.26.5 installed as its
local toolchain. An automatically downloaded toolchain is not sufficient: the
version gate and every reproducible build use `GOENV=off GOTOOLCHAIN=local
GOFLAGS= GOWORK=off` so they cannot inspect one compiler and build with another
or inherit an unrelated workspace file. The trusted signer setup, CI, and
preparation all disable shared Go caches for release-critical builds, use fresh
private build/module caches, require the public Go module proxy and checksum
database, disable direct VCS fetching, and clear caller-controlled `GOROOT`,
experiment, FIPS, telemetry, and authentication settings. The signer is built
twice with independent caches and installed only after the outputs compare
byte-for-byte. Run the setup from a separately audited, canonical source tree
whose complete contents and ancestry are root-owned and not writable by another
account; the block verifies that boundary before Git or Go sees the tree. It also
enters a clean privileged Bash, disables caller Git configuration and replacement
objects, rejects shared object/metadata stores and submodules, requires `HEAD` to
equal the independently recorded commit, and validates `/tmp`. The actual builds
consume a bounded private `git archive` snapshot of that exact commit, then hash
every extracted file back to its Git blob before compiling. Worktree attributes,
filters, ignored files, and local Git configuration therefore cannot change the
build input. Two independent cache roots must produce identical signer bytes.

Copy audited versions of `prepare-release.sh` and `publish-release.sh` to the
online release workstation. Copy `offline-sign-release.sh` and `lta-release` to
the air-gapped signing machine. Record the signer SHA-256 separately on that
machine. Do not replace those trusted copies from a candidate tag; candidate
files are inputs, never release tooling.

The offline and publishing scripts pin the trusted signer/verifier through an
open `/proc` descriptor, then validate its owner and mode, hash it, and execute
that descriptor throughout the run. Replacing its pathname after the hash
therefore cannot change the executed inode. The trusted scripts use an absolute
Bash interpreter in privileged mode so exported shell functions and `BASH_ENV`
are ignored, replace the caller's `PATH` with root-controlled system locations,
and neutralize caller-controlled OpenSSL module configuration on the networked
phases. Execute the trusted scripts directly as shown below; invoking them as
`bash script.sh` is rejected because it bypasses the protected shebang. Keep
`/opt/lta-release-tools` root-owned and non-writable by other users; the
descriptor pin is defense in depth, not permission to use an attacker-writable
tool directory. The scripts independently reject a signer/verifier path with a
symlinked, foreign-owned, or group/world-writable ancestor. Preparation and
signing output paths must be new canonical paths whose existing parents are
protected by ownership and mode or by root-owned sticky-directory semantics;
the path is checked again immediately before creation. Network clients, local Git/GPG operations, removable-media
copies, compiler runs, and signer/verifier invocations all have hard timeouts.
Each trusted phase also disables core dumps before reading any release input;
the online phases also disable Git credential prompts and lazy object fetching,
GitHub CLI prompts/pagers, and GnuPG automatic key retrieval.

All three trusted phases create private snapshots below `/tmp`. They refuse to
run unless `/tmp` is a real, root-owned directory with exactly the sticky special
bit set. This prevents another local account that owns a nonstandard temporary
directory from
renaming a validated private snapshot out from under the ceremony. Repair the
host configuration before proceeding; do not patch the trusted script or move
release inputs into an untrusted temporary tree to bypass this gate. The online
scripts overwrite and export `GH_HOST=github.com`, clear inherited proxy, TLS,
and Git overrides, and use a new private GitHub CLI configuration directory.
Authentication must come from an explicit short-lived `GH_TOKEN`, so caller
configuration cannot redirect authenticated release operations to another host.
In the commands below the already-sanitized root shell reads that token silently
from `/dev/tty`, validates it, and only then exports it to the trusted script.
The token therefore appears in neither shell history nor the `sudo`/`env` command
line. It remains available only in the environment of the root release process
and the GitHub CLI children that require it.

Record the maintainer OpenPGP signing-key fingerprint through an independent
channel. Both online phases require that exact primary or signing-subkey
fingerprint from GnuPG's `VALIDSIG` status; a merely valid signature from another
key in the local keyring is rejected.

Before enabling release staging, configure these repository controls. They are
part of the release trust boundary and cannot be enforced by files inside the
repository:

1. Protect `main` with a ruleset that requires pull requests, required CI status
   checks, resolved conversations, and blocks force pushes and deletion. Set the
   required approval count to zero, and do not require CODEOWNERS review or
   approval of the last push. CODEOWNERS remains ownership metadata only. Do not
   permit ruleset bypass by ordinary release operations.
2. Protect `v*` tags with a ruleset that restricts creation, update, and deletion
   to the designated release maintainers. The pipeline additionally requires an
   annotated tag with a valid OpenPGP signature and independently pins its exact
   signing fingerprint.
3. Create an environment named `release-staging` with no required reviewers,
   disable administrator bypass, and restrict deployments to the protected
   `main` branch. A `workflow_run` receiver executes from the default branch even
   though it validates and stages the triggering `v*` tag.
4. Only after verifying those controls, set the repository Actions variable
   `LTA_RELEASE_ENVIRONMENT_CONFIGURED` to the exact value `true`. Missing or
   different values fail closed before the write-capable job can run. Remove the
   variable immediately if the environment or rulesets are weakened.
5. Keep the repository's default Actions token permission read-only and do not
   allow Actions to approve pull requests.

The staging workflow uses one fixed repository-wide concurrency group, so only
one draft writer runs at a time even when multiple tags are pushed. GitHub does
not provide an atomic compare-and-set operation spanning release enumeration and
the Latest pointer. The release coordinator must therefore also hold one
organization-wide publication lock for the entire preparation, offline signing,
and publication ceremony. Do not prepare or publish two tags concurrently from
different workstations or workflow runs.

The OpenPGP tag-signing key is separate from the offline ed25519 release key.
Before the first release under this process, generate or import a dedicated
maintainer OpenPGP key whose UID contains an email verified on the `xxvcc`
GitHub account. Upload only its armored public key to that account, protect the
private half, and record both the full primary fingerprint and the fingerprint
of the subkey that will actually sign tags. Prefer an offline primary key with a
hardware-backed signing subkey. Historical unsigned tags do not satisfy this
gate, and an OpenPGP key registered to another GitHub account is not a substitute.

## Offline ed25519 release key

The following command does not create an OpenPGP key. It creates the raw
ed25519 private key used to sign release binaries and must run only on the
air-gapped signing machine:

```bash
/opt/lta-release-tools/lta-release keygen /offline/keys/release-v1.key
```

The key creator/loader checks the complete directory ancestry by opening each
component relative to its already pinned parent descriptor with
`openat(O_DIRECTORY|O_NOFOLLOW)`, then opens the leaf with `openat(O_NOFOLLOW)`.
It refuses unsafe writable ancestors,
symlinks, non-regular files, another owner, special mode bits, and anything
other than mode `0600`. Back up the key in at least two offline places. A leak
permits forged root-level upgrades; losing it prevents unattended upgrades by
clients that trust only that key.

## Keyring

[`internal/selfmanage/release_pubkey.hex`](../internal/selfmanage/release_pubkey.hex)
is a keyring: every non-comment line is one complete 64-hex-character ed25519
public key. Malformed and duplicate entries disable upgrade fail-closed. The
installer contains the same keys as PEM blocks; a Go test parses both and
requires exact ordered equality.

After changing the keyring, generate the installer blocks with the fixed tool:

```bash
/opt/lta-release-tools/lta-release pem internal/selfmanage/release_pubkey.hex
go test ./internal/selfmanage
```

Paste the complete output between `LTA_RELEASE_KEYS_BEGIN` and
`LTA_RELEASE_KEYS_END` in `scripts/install.sh`. CI refuses a mismatch.

## Release sequence

### 1. Create an audited signed tag

The candidate commit must already be in `origin/main`. Use an OpenPGP-signed tag;
`prepare-release.sh` and `publish-release.sh` both verify its signature against
the independently pinned fingerprint and compare the local tag object with
GitHub.

```bash
TAG_SIGNING_FPR='<full-40-hex-OpenPGP-signing-subkey-fingerprint>'
git switch main
git pull --ff-only
RELEASE_COMMIT="$(git rev-parse --verify 'origin/main^{commit}')"
test "$(git rev-parse --verify 'HEAD^{commit}')" = "$RELEASE_COMMIT"
git -c user.name='XXV.CC' \
    -c user.email='github@xxv.cc' \
    -c user.signingkey="${TAG_SIGNING_FPR}!" \
    -c gpg.format=openpgp \
    -c gpg.program=/usr/bin/gpg \
    tag -s v2.8.0 "$RELEASE_COMMIT" -m 'linux-temp-admin v2.8.0'
git -c gpg.format=openpgp -c gpg.program=/usr/bin/gpg \
    verify-tag --raw v2.8.0
git push origin v2.8.0
```

Before pushing, the `VALIDSIG` record from `verify-tag --raw` must identify the
recorded signing-subkey fingerprint. After pushing, query the GitHub tag-object
API and require `verification.verified=true`, `verification.reason=valid`, and
an armored OpenPGP signature before continuing. Use that same fingerprint as
`LTA_EXPECTED_TAG_SIGNER_FINGERPRINT` during preparation and publication.

The `Release` workflow uses exactly Go 1.26.5. Its read-only `gate-build` job
runs vet, uncached race tests, root integration tests, formatting, shell checks,
the mirror receiver policy tests, a clean-worktree check, and
`govulncheck v1.6.0`, then builds static
amd64/arm64 binaries with fixed tuning, `GOWORK=off`, `-mod=readonly`, and
`-buildvcs=false`. The ordinary Go workflow uses the same pinned vulnerability
scanner version; a floating audit tool is not part of the release decision. A
separate `Stage Release Draft` `workflow_run`, whose definition comes from the
default branch rather than the candidate tag, receives only those artifacts and
uses its narrowly scoped write token to create a new unsigned draft. Candidate
tag workflows never receive a write token. The stage job requires GitHub to
recognize the annotated tag's OpenPGP signature; the online trusted phases still
pin and verify the exact signer fingerprint independently. Both workflows
enforce the clients' 64 MiB binary limit before staging. CI refuses to refresh any existing draft;
investigate and deliberately remove a bad draft before rerunning instead of
overwriting bytes that an offline ceremony may already have signed.

### 2. Online preparation, with no private key

Run the separately installed trusted preparation script. The source argument is
a repository containing the tag; the script disables local Git replacement
objects, checks the commit's ancestry against GitHub's `main` rather than a
caller-configured `origin`, rejects symlinks and submodules, and exports the
self-contained tree with `git archive`. Ignored/untracked files and candidate
scripts therefore cannot affect the build. It checks the successful Release
workflow and draft, rebuilds with exactly Go 1.26.5, `GOWORK=off`, and the CI
flags, then `cmp`s every CI binary byte-for-byte. Draft assets are fetched one
at a time through the authenticated Release Asset API after an advertised-size
preflight and under a kernel file-size limit. The source archive has its own size
limit, and Git/GPG, archive extraction, each GitHub operation, and each
architecture build are independently time-bounded. The prepared transfer
directory is assembled through bounded copies, and its final permission,
manifest-hash, and checksum verification operations are also time-bounded so a
stalled output medium cannot hold this trusted phase forever.

```bash
LTA_EXPECTED_TAG_SIGNER_FINGERPRINT='<independently recorded OpenPGP fingerprint>'
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  LTA_EXPECTED_TAG_SIGNER_FINGERPRINT="$LTA_EXPECTED_TAG_SIGNER_FINGERPRINT" \
  /bin/bash -p <<'LTA_PREPARE_RELEASE'
set -Eeuo pipefail
umask 077
fail() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 || fail "cannot disable core dumps"
if ! IFS= read -r -s -p 'Short-lived github.com release token: ' GH_TOKEN </dev/tty; then
  printf '\n' >/dev/tty || :
  fail "cannot read GH_TOKEN from the controlling terminal"
fi
printf '\n' >/dev/tty
[[ -n "$GH_TOKEN" && "$GH_TOKEN" != *[[:space:]]* ]] \
  || fail "GH_TOKEN must be one non-empty token without whitespace"
export GH_TOKEN
exec /opt/lta-release-tools/prepare-release.sh \
  v2.8.0 /srv/linux-temp-admin /srv/release-transfer/v2.8.0-prepared
LTA_PREPARE_RELEASE
```

Record the printed tag, commit, and prepared-manifest SHA-256 in a separate
authenticated release record. Transfer the prepared directory to removable
media as data. A compromised CI can choose its binary and checksum together,
but it cannot make those bytes equal the trusted rebuild unless the audited
source/toolchain or preparation workstation is also compromised.

### 3. Air-gapped signing

Disconnect networking and remove proxy/GitHub credentials. Invoke the trusted
offline script and fixed signer by their permanent paths, not paths copied from
the candidate or transfer media:

```bash
LTA_SIGN_KEY=/offline/keys/release-v1.key
LTA_TRUSTED_SIGNER=/opt/lta-release-tools/lta-release
LTA_TRUSTED_SIGNER_SHA256='<offline-recorded signer sha256>'
LTA_EXPECTED_TAG=v2.8.0
LTA_EXPECTED_COMMIT='<independently recorded 40-hex commit>'
LTA_EXPECTED_PREPARED_MANIFEST_SHA256='<independently recorded sha256>'
LTA_EXPECTED_RELEASE_SIGNER_PUBKEY='<independently recorded 64-hex OLD public key>'
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  LTA_SIGN_KEY="$LTA_SIGN_KEY" LTA_TRUSTED_SIGNER="$LTA_TRUSTED_SIGNER" \
  LTA_TRUSTED_SIGNER_SHA256="$LTA_TRUSTED_SIGNER_SHA256" \
  LTA_EXPECTED_TAG="$LTA_EXPECTED_TAG" LTA_EXPECTED_COMMIT="$LTA_EXPECTED_COMMIT" \
  LTA_EXPECTED_PREPARED_MANIFEST_SHA256="$LTA_EXPECTED_PREPARED_MANIFEST_SHA256" \
  LTA_EXPECTED_RELEASE_SIGNER_PUBKEY="$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" \
  /opt/lta-release-tools/offline-sign-release.sh \
  /media/in/v2.8.0-prepared /media/out/v2.8.0-signed
```

The script copies the removable input into a size-bounded private local snapshot
under a hard copy timeout, so a replaced special file or stalled medium cannot
hold the signing ceremony forever or fill the machine before validation. It
strictly validates the tag/version and complete keyring as well as every
manifest and recorded value there, proves the private key's public half exactly
equals the independently selected release signer and is in the candidate
keyring, and calls only the descriptor-pinned signer on that snapshot. Every
signer operation is independently time-bounded. Creation of the signed transfer
directory, every final copy, permission change, manifest hash, and checksum
verification is independently time-bounded as well.
The selected public key is recorded inside the signed-bundle manifest, and every
signature is verified against that exact key rather than any key in the rotation
keyring. It never calls Go, Git, GitHub, curl, or a candidate executable. Remove
the private-key media before transferring the signed directory back online.
Record the printed signed-bundle manifest SHA-256 through an independent
operator channel; do not carry that value only beside the signed directory.

### 4. Online publication, with no private key

Use the fixed signer as a verifier only:

```bash
LTA_TRUSTED_SIGNER=/opt/lta-release-tools/lta-release
LTA_TRUSTED_SIGNER_SHA256='<independently recorded signer sha256>'
LTA_EXPECTED_SIGNED_BUNDLE_MANIFEST_SHA256='<independently recorded signed-bundle manifest sha256>'
LTA_EXPECTED_TAG_SIGNER_FINGERPRINT='<independently recorded OpenPGP fingerprint>'
LTA_EXPECTED_RELEASE_SIGNER_PUBKEY='<the same independently recorded 64-hex key>'
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  LTA_TRUSTED_SIGNER="$LTA_TRUSTED_SIGNER" \
  LTA_TRUSTED_SIGNER_SHA256="$LTA_TRUSTED_SIGNER_SHA256" \
  LTA_EXPECTED_SIGNED_BUNDLE_MANIFEST_SHA256="$LTA_EXPECTED_SIGNED_BUNDLE_MANIFEST_SHA256" \
  LTA_EXPECTED_TAG_SIGNER_FINGERPRINT="$LTA_EXPECTED_TAG_SIGNER_FINGERPRINT" \
  LTA_EXPECTED_RELEASE_SIGNER_PUBKEY="$LTA_EXPECTED_RELEASE_SIGNER_PUBKEY" \
  /bin/bash -p <<'LTA_PUBLISH_RELEASE'
set -Eeuo pipefail
umask 077
fail() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 || fail "cannot disable core dumps"
if ! IFS= read -r -s -p 'Short-lived github.com release token: ' GH_TOKEN </dev/tty; then
  printf '\n' >/dev/tty || :
  fail "cannot read GH_TOKEN from the controlling terminal"
fi
printf '\n' >/dev/tty
[[ -n "$GH_TOKEN" && "$GH_TOKEN" != *[[:space:]]* ]] \
  || fail "GH_TOKEN must be one non-empty token without whitespace"
export GH_TOKEN
exec /opt/lta-release-tools/publish-release.sh \
  /srv/release-transfer/v2.8.0-signed /srv/linux-temp-admin
LTA_PUBLISH_RELEASE
```

The publisher first makes a size-bounded snapshot of the transferred directory
under a hard copy timeout and binds that private copy to the independently
recorded signed-bundle manifest hash, then verifies the manifest, pinned tag
signer, self-contained source tree, GitHub `main` ancestry, successful CI run,
keyring, checksums, and both
signatures. While the
release is still a draft it rejects any missing or extra assets, replaces all
expected assets with the exact signed bytes, checks the complete asset list
again, downloads the draft, compares every byte, and checks GitHub's SHA-256
digest for every asset immediately before publication. Stable versions must be
strictly newer than every published stable release, and the current Latest must
already equal that maximum and remain unchanged during preparation; prereleases
never become Latest. It publishes every release initially with `--latest=false`,
downloads and verifies the public versioned assets with bounded retries and hard
file limits, and only then promotes a stable tag to Latest. Before the first
remote mutation it preflights every command needed by the remaining publication
and verification path, including `curl` and `timeout`. A final enumeration
detects a concurrently published higher stable tag and restores Latest to the
exact highest stable release other than the current tag. If there is no other
stable release, it clears Latest and confirms the REST Latest route is exactly a
404; authentication or transport errors never count as that empty state. The
Latest route is then independently compared, checksummed, and
signature-verified for both architectures, followed by another highest-version
check. An EXIT trap performs the same exact restoration after
any error or signal following a possibly applied promotion. These checks narrow
the race window but cannot make the GitHub API transactional; the mandatory
global publication lock above remains the control that prevents two authorized
publishers from overlapping.

The publication command is deliberately resumable after the release has become
public. It accepts that state only when the tag, draft/prerelease flags, complete
asset-name set, sizes, GitHub SHA-256 digests, signed-bundle bytes, versioned
public downloads, checksums, and ed25519 signatures all still match exactly. It
does not clobber assets on a published release. This covers interruption after
publication, after Latest promotion, or during final CDN verification without
weakening the signed-bundle binding. If the release is already Latest when a
read-only resume begins, a later verification or transport failure leaves that
pre-existing state unchanged; automatic restoration is armed only before a
mutation attempted by the current run.

If public CDN verification fails after publication, treat the release as
incomplete: do not announce it. Diagnose transport separately from checksum or
signature failure. A `?download=1` retry is used only as a cache-bypass transport
attempt; it never bypasses cryptographic verification.

Keep the signed bundle and all independently recorded values. After correcting
a transient GitHub/CDN or local-tool problem, rerun the identical
`publish-release.sh` command and environment shown above. The script either
finishes the exact release or fails closed before changing a mismatched public
release. Never delete, replace, or manually clobber assets on an already
published release to make a retry pass.

If the script reports that automatic Latest restoration itself failed, keep the
release unannounced and retain the organization-wide publication lock. Restore
network/API access, rerun the same publisher first, and inspect its exact result.
For manual incident recovery only, use the following fail-closed procedure. It
uses decimal-string comparison rather than machine-sized arithmetic, rejects a
noncanonical published stable tag, excludes the failed `TAG`, and verifies the
exact resulting Latest state:

```bash
TAG=v2.8.0  # the failed release; verify this value before running
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  TAG="$TAG" /bin/bash -p <<'LTA_LATEST_RECOVERY'
set -Eeuo pipefail
umask 077
fail() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 || fail "cannot disable core dumps for Latest recovery"
if ! IFS= read -r -s -p 'Short-lived github.com release token: ' GH_TOKEN </dev/tty; then
  printf '\n' >/dev/tty || :
  fail "cannot read GH_TOKEN from the controlling terminal"
fi
printf '\n' >/dev/tty
[[ -n "$GH_TOKEN" && "$GH_TOKEN" != *[[:space:]]* ]] \
  || fail "GH_TOKEN must be one non-empty token without whitespace"
REPO=xxvcc/linux-temp-admin
[[ "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]

work="$(mktemp -d /root/.lta-latest-recovery.XXXXXX)"
GH_CONFIG_DIR="$work/gh-config"
mkdir -m 0700 -- "$GH_CONFIG_DIR"
GH_HOST=github.com
GH_PROMPT_DISABLED=1
GH_PAGER='cat'
export GH_TOKEN GH_CONFIG_DIR GH_HOST GH_PROMPT_DISABLED GH_PAGER
cleanup() {
  timeout -k 5 30 rm -rf -- "$work" \
    || echo "warning: could not remove private recovery workspace $work" >&2
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
gh_with_timeout() {
  timeout -k 5 300 gh "$@"
}

decimal_gt() {
  local left=$1 right=$2
  (( ${#left} > ${#right} )) && return 0
  (( ${#left} < ${#right} )) && return 1
  [[ "$left" > "$right" ]]
}
stable_gt() {
  local newer=$1 older=$2 nmajor nminor npatch omajor ominor opatch pair left right
  [[ "$newer" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
  nmajor=${BASH_REMATCH[1]}; nminor=${BASH_REMATCH[2]}; npatch=${BASH_REMATCH[3]}
  [[ "$older" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
  omajor=${BASH_REMATCH[1]}; ominor=${BASH_REMATCH[2]}; opatch=${BASH_REMATCH[3]}
  for pair in "$nmajor:$omajor" "$nminor:$ominor" "$npatch:$opatch"; do
    left=${pair%%:*}; right=${pair#*:}
    decimal_gt "$left" "$right" && return 0
    decimal_gt "$right" "$left" && return 1
  done
  return 1
}

release_tags="$(gh_with_timeout api --paginate "repos/${REPO}/releases?per_page=100" \
  --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name')"
fallback=
while IFS= read -r candidate; do
  [[ -n "$candidate" ]] || continue
  [[ "$candidate" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || { echo "noncanonical stable tag: $candidate" >&2; exit 1; }
  [[ "$candidate" != "$TAG" ]] || continue
  if [[ -z "$fallback" ]] || stable_gt "$candidate" "$fallback"; then
    fallback=$candidate
  fi
done <<<"$release_tags"

if [[ -n "$fallback" ]]; then
  gh_with_timeout release edit "$fallback" --repo "$REPO" --latest
  actual="$(gh_with_timeout release view --repo "$REPO" --json tagName --jq '.tagName')"
  [[ "$actual" == "$fallback" ]] \
    || { echo "Latest is $actual, expected $fallback" >&2; exit 1; }
else
  gh_with_timeout release edit "$TAG" --repo "$REPO" --latest=false
  response="$work/latest-response"
  set +e
  gh_with_timeout api --include "repos/${REPO}/releases/latest" >"$response" 2>&1
  latest_status=$?
  set -e
  if [[ "$latest_status" -eq 0 ]]; then
    echo "Latest still exists when no stable fallback should exist" >&2
    exit 1
  fi
  [[ "$latest_status" -eq 1 ]] \
    || { cat "$response" >&2; echo "Latest query failed with unexpected status $latest_status" >&2; exit 1; }
  [[ "$(grep -Ec '^HTTP/[0-9.]+ [0-9]{3}([[:space:]]|$)' "$response")" -eq 1 \
     && "$(grep -Ec '^HTTP/[0-9.]+ 404([[:space:]]|$)' "$response")" -eq 1 ]] \
    || { cat "$response" >&2; echo "Latest query did not return an exact 404" >&2; exit 1; }
fi
LTA_LATEST_RECOVERY
```

Any other tag, success response in the no-candidate case, authentication error,
or transport error means recovery is not complete. Do not announce either
release until the publisher completes its full verification successfully.
The sanitized root shell intentionally carries only the prompted token and explicit tag;
it does not inherit proxy, custom CA, GitHub configuration, or credential-helper
settings from the operator environment. Every GitHub CLI operation has a hard
timeout and uses a private, transient configuration directory.

### 5. Official mirror synchronization and announcement gate

Publishing the GitHub Release is not the end of the release. The
[`Mirror signed release`](../.github/workflows/mirror-release.yml) workflow must
finish before announcement. It accepts only an immutable public GitHub Release
with the exact five-asset release set, rechecks the checksum manifest and both
ed25519 signatures against the trusted keyring, verifies the released binaries,
and copies one complete release into
`https://dl.ll.cd/linux-temp-admin/vX.Y.Z/`. The version directory also receives
`install.sh` from the released signed tag. Every public versioned file is read
back and compared byte-for-byte before a stable pointer is changed. Only a tag
that is still GitHub Latest may replace the stable `install.sh`; `latest.json`
is written last, then a separate job performs a real root installation and a
same-version forced self-upgrade from the public mirror. That canary first
verifies the stable installer hash and fails if either client reports that it
used the GitHub fallback.

Create a protected GitHub Environment named `release-mirror` with no required
reviewers. Disable administrator bypass, and allow only protected `v*` tags plus
the protected default branch used for an explicit recovery dispatch. Enable
immutable Releases for the repository; synchronization fails closed when the
selected GitHub Release is mutable. Configure exactly these environment values:

- Actions variables: `MIRROR_HOST`, `MIRROR_PORT`, `MIRROR_USER`, and
  `LTA_RELEASE_MIRROR_ENVIRONMENT_CONFIGURED` with the exact value `true`;
- Actions secrets: a dedicated `MIRROR_SSH_KEY` and an independently pinned
  `MIRROR_KNOWN_HOSTS` entry.

Set the configuration gate only after independently verifying the Environment,
tag/default-branch rulesets, host-key pin, SSH receiver, document-root policy,
and public HTTPS configuration. Remove or change it immediately if any of those
controls is weakened. The workflow also requires its own definition to come
from the repository's default branch and refuses any other repository identity.

#### Mirror host layout

The production mirror uses the following exact layout. Treat a difference as
configuration drift and clear the Environment configuration gate until it has
been revalidated:

- `ltamirror` is a password-locked, non-sudo account. Its login shell exists
  only so sshd can execute the forced command; its sole authorized key cannot
  start an interactive command, PTY, user rc, agent/X11 session, or forwarding.
- [`scripts/mirror-receiver.py`](../scripts/mirror-receiver.py) is installed as
  `/usr/local/libexec/linux-temp-admin-mirror-receiver`, owned `root:root` and
  mode `0755`. `/usr/bin/rrsync` must also be a canonical, root-owned,
  non-writable executable.
- `/var/lib/linux-temp-admin-mirror` is owned `ltamirror:ltamirror`, mode
  `0700`, and contains the persistent `.deploy.lock` plus private transient
  transfer directories.
- `/www/wwwroot/dl.ll.cd/linux-temp-admin` is owned `ltamirror:www`, mode
  `0755`. Its parent directories remain root-owned and not group/world
  writable.
- [`deploy/nginx/linux-temp-admin.conf`](../deploy/nginx/linux-temp-admin.conf)
  is installed as
  `/www/server/panel/vhost/nginx/extension/dl.ll.cd/linux-temp-admin.conf`,
  owned `root:root` and mode `0644`. The `dl.ll.cd` virtual host includes that
  directory and permits only TLS 1.2 and TLS 1.3.

`/home/ltamirror/.ssh/authorized_keys` is owned `ltamirror:ltamirror`, mode
`0600`, and contains exactly the dedicated deployment public key with these
options:

```text
restrict,command="/usr/local/libexec/linux-temp-admin-mirror-receiver" ssh-ed25519 <dedicated-mirror-public-key>
```

The private half never belongs on the mirror host. OpenSSH `restrict` is part of
the boundary, but the forced receiver is what validates the command and content.
It permits only a canonical `vX.Y.Z/` or prerelease directory containing the
exact six expected files. Existing versioned bytes cannot be replaced or
deleted; a retry may only fill a missing file with bytes consistent with the
complete staged checksum set. It rejects reads, traversal, arbitrary rsync
modes, links, special files, and every other destination. Stable `install.sh`
must match a complete non-prerelease version, and canonical `latest.json` is
published last. The receiver refuses a stable downgrade or altered metadata for
the current version. The client-side `--ignore-existing` flag is not itself an
immutability boundary.

The Nginx include claims the complete `/linux-temp-admin/` namespace before the
virtual host's generic regular-expression locations. It serves only the two
stable files and the six versioned files, disables compression at the origin,
adds `no-transform` and HSTS, disables directory listing, and rejects HTTP write
methods. Versioned objects use
`Cache-Control: public, max-age=31536000, immutable, no-transform`; stable and
unknown routes use `no-store, no-cache, must-revalidate, no-transform`. The CDN
must preserve these policies and the downloaded representation bytes.

#### Maintenance and recovery

Before installing a receiver change, run its tests without creating bytecode,
then install it through a root-owned temporary file and atomic rename. An active
SSH session may continue using the old inode, so wait for it to finish before
declaring the rollout complete:

```bash
python3 -B -m unittest -v scripts/mirror_receiver_test.py
cmp scripts/mirror-receiver.py /usr/local/libexec/linux-temp-admin-mirror-receiver
```

The final `cmp` is a post-install drift check and must succeed. For an Nginx
change, preserve the prior root-owned include, install the audited repository
copy, run `nginx -t`, reload the `nginx` service only after the syntax check, and
repeat the public header, method, unknown-path, and byte-comparison probes. If
syntax, reload, or a public probe fails, restore the preserved include, retest,
reload, and keep the release gate closed.

Recovery is deliberately narrow:

1. If a transfer stopped before all six immutable files arrived, dispatch the
   mirror workflow again for the same immutable GitHub tag. The receiver checks
   every existing byte and fills only the missing files.
2. If `install.sh` changed but `latest.json` did not, rerun the current GitHub
   Latest tag. The workflow republishes the installer first and the manifest
   last; clients remain signature-verified during the interrupted state.
3. If any existing versioned byte differs, an extra path exists, a checksum or
   signature fails, or the public response is transformed, stop synchronization
   and announcement. Preserve the host and CDN evidence, disable or rotate the
   deployment credential, and investigate. Do not delete or overwrite the
   version directory as routine recovery.
4. A leftover `transfer-*` directory may be quarantined only after confirming
   that no `ltamirror` receiver or rsync process is active. `.deploy.lock` is
   persistent state and must not be treated as a stale transfer.
5. After total mirror loss, rebuild this empty layout, restore the audited
   receiver and Nginx include, rotate the deployment key, and dispatch each
   required immutable tag. Dispatch the current GitHub Latest tag after its
   version bytes are present so stable files are reconstructed last. Repeat all
   independent public checks before reopening the announcement gate.

An intentional emergency downgrade is not normal deployment-key recovery: the
receiver blocks it. It requires an explicitly authorized and recorded root-host
incident procedure, explicit client downgrade handling, and a fresh audit.

Do not announce a release until both mirror workflow jobs are green and an
independent network check has fetched `latest.json`, the selected version's
checksum manifest, binaries, and signatures from the public hostname, compared
them with the immutable GitHub assets, verified both architectures, and run a
real mirror bootstrap plus a routine self-upgrade canary. A mirror transport
failure may be repaired and the exact immutable tag resynchronized with
`workflow_dispatch`; a checksum, signature, tag, version, or manifest mismatch
is an integrity incident, not a reason to announce with GitHub-only instructions.

`scripts/sign-release.sh` and `scripts/release.sh` intentionally exit with an
error. The old online one-step signer and unchecked local fallback must not be
used.

## Planned key rotation

A single signature cannot be valid under two unrelated ed25519 keys. Rotation
therefore requires an overlap release and a migration window:

1. Generate NEW on the air-gapped machine; retain OLD.
2. Add both public keys to the candidate keyring, ordered `OLD`, then `NEW`, and
   add both installer PEM blocks. CI tests their equality.
3. Record OLD's complete 64-hex public key independently, set it as
   `LTA_EXPECTED_RELEASE_SIGNER_PUBKEY`, and publish a transition release
   containing both keys but signed with OLD. Every
   existing client can install it; the resulting binary trusts both keys.
4. Keep publishing with OLD during the announced migration window. Preserve a
   versioned transition release and explicit recovery instructions.
5. Switch both the private-key path and independently expected signer public key
   to NEW while keeping both public keys for another support window. Only after
   the supported fleet has crossed the transition may OLD be removed from new
   binaries and the installer.

A host offline for the whole migration window still trusts only OLD and cannot
authenticate a NEW-only latest release. It must install the preserved OLD-signed
transition release or use an independently verified manual bootstrap. This is a
cryptographic limitation, not something version comparison can solve.

If OLD is compromised, do not use it for a transition: an attacker can create an
indistinguishable transition too. Existing OLD-only clients require an
out-of-band trust recovery and should be treated as potentially compromised.

## Host install and upgrade

Bootstrap installation requires root, OpenSSL 3, sha256sum, timeout, and curl:

```bash
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh <<'LTA_BOOTSTRAP'
set -eu
umask 077
fail() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 || fail "cannot disable core dumps"
[ -d /tmp ] && [ ! -L /tmp ] || fail "/tmp is not a real directory"
tmp_meta=$(stat -Lc '%u %a' -- /tmp) || fail "cannot inspect /tmp"
case "$tmp_meta" in
  "0 1"[0-7][0-7][0-7]) ;;
  *) fail "/tmp must be root-owned, sticky, and free of other special bits" ;;
esac

if ! FSIZE_BLOCK_BYTES=$(
  ulimit -f 1 || exit 1
  awk '$1 == "Max" && $2 == "file" && $3 == "size" { print $4; found=1 }
       END { if (!found) exit 1 }' /proc/self/limits
); then
  fail "cannot determine the shell file-size limit unit"
fi
case "$FSIZE_BLOCK_BYTES" in
  512 | 1024) ;;
  *) fail "unsupported shell file-size limit unit" ;;
esac
INSTALLER_MAX_BYTES=1048576
INSTALLER_BLOCKS=$(( (INSTALLER_MAX_BYTES + FSIZE_BLOCK_BYTES - 1) / FSIZE_BLOCK_BYTES ))
installer=$(mktemp /tmp/.lta-bootstrap.XXXXXXXXXX) \
  || fail "cannot create root-owned installer file"
cleanup() { rm -f -- "$installer"; }
trap cleanup 0
trap 'exit 1' HUP INT TERM
installer_downloaded=0
for installer_url in \
  https://dl.ll.cd/linux-temp-admin/install.sh \
  https://raw.githubusercontent.com/xxvcc/linux-temp-admin/main/scripts/install.sh
do
  installer_download_rc=0
  (
    ulimit -f "$INSTALLER_BLOCKS" || exit 1
    exec timeout -k 5 70 curl -q --fail --silent --show-error --location --max-redirs 0 \
      --connect-timeout 10 --max-time 60 --max-filesize "$INSTALLER_MAX_BYTES" \
      --proto '=https' --proto-redir '=https' \
      --output "$installer" "$installer_url"
  ) || installer_download_rc=$?
  if [ "$installer_url" = https://dl.ll.cd/linux-temp-admin/install.sh ] && \
     [ "$installer_download_rc" -eq 47 ]; then
    fail "official mirror installer redirected; refusing source-policy fallback"
  fi
  if [ "$installer_download_rc" -eq 0 ]; then
    installer_size=$(wc -c < "$installer") || fail "cannot measure installer"
    case "$installer_size" in
      '' | *[!0-9]*) fail "invalid installer size" ;;
    esac
    if [ "$installer_size" -gt 0 ] && [ "$installer_size" -le "$INSTALLER_MAX_BYTES" ]; then
      installer_downloaded=1
      break
    fi
  fi
done
[ "$installer_downloaded" -eq 1 ] || fail "installer download failed or exceeded its limit"
/bin/sh "$installer"
LTA_BOOTSTRAP
```

That convenience bootstrap tries the official mirror first and uses raw GitHub
only after an installer transport, empty-response, or size-limit failure. An
official-mirror redirect is a source-policy failure and aborts instead. It
trusts the TLS and mutable script route of the source ultimately used. The
mirrored installer is copied from the released signed tag, but is not itself an
offline-ed25519-signed GitHub Release asset.
For a high-assurance first install, obtain all three values below through
the release audit/signing record and a separate authenticated channel, then run:

```bash
INSTALLER_COMMIT='replace-with-the-audited-40-hex-commit'
INSTALLER_SHA256='replace-with-the-independent-64-hex-script-hash'
LTA_RELEASE_TAG='v2.8.0'
/usr/bin/sudo /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  INSTALLER_COMMIT="$INSTALLER_COMMIT" INSTALLER_SHA256="$INSTALLER_SHA256" \
  LTA_RELEASE_TAG="$LTA_RELEASE_TAG" /bin/bash <<'LTA_BOOTSTRAP'
set -Eeuo pipefail
umask 077
fail() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 || fail "cannot disable core dumps"

  : "${INSTALLER_COMMIT:?set the audited 40-hex commit}"
  : "${INSTALLER_SHA256:?set the independently verified 64-hex script hash}"
  : "${LTA_RELEASE_TAG:?set the exact vX.Y.Z release tag}"
  [[ "$INSTALLER_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || fail "invalid INSTALLER_COMMIT"
  [[ "$INSTALLER_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "invalid INSTALLER_SHA256"
  [[ "$LTA_RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] \
    || fail "invalid LTA_RELEASE_TAG"

  if [[ ! -d /tmp || -L /tmp ]]; then
    fail "/tmp is not a real directory"
  fi
  if ! tmp_meta=$(stat -Lc '%u %a' -- /tmp); then
    fail "cannot inspect /tmp metadata"
  fi
  [[ "$tmp_meta" =~ ^0\ 1[0-7]{3}$ ]] \
    || fail "/tmp must be root-owned, sticky, and free of other special bits"

  if ! FSIZE_BLOCK_BYTES=$(
    ulimit -f 1 || exit 1
    awk '$1 == "Max" && $2 == "file" && $3 == "size" { print $4; found=1 }
         END { if (!found) exit 1 }' /proc/self/limits
  ); then
    fail "cannot determine the shell file-size limit unit"
  fi
  case "$FSIZE_BLOCK_BYTES" in
    512 | 1024) ;;
    *) fail "unsupported shell file-size limit unit" ;;
  esac
  INSTALLER_MAX_BYTES=1048576
  INSTALLER_BLOCKS=$(( (INSTALLER_MAX_BYTES + FSIZE_BLOCK_BYTES - 1) / FSIZE_BLOCK_BYTES ))
  installer=$(mktemp /tmp/.lta-bootstrap.XXXXXXXXXX) \
    || fail "cannot create root-owned installer file"
  cleanup() { rm -f -- "$installer"; }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM
  if ! (
    ulimit -f "$INSTALLER_BLOCKS" || exit 1
    exec timeout -k 5 70 curl -q --fail --silent --show-error --location \
      --connect-timeout 10 --max-time 60 --max-filesize "$INSTALLER_MAX_BYTES" \
      --proto '=https' --proto-redir '=https' \
      --output "$installer" \
      "https://raw.githubusercontent.com/xxvcc/linux-temp-admin/${INSTALLER_COMMIT}/scripts/install.sh"
  ); then
    fail "installer download failed or exceeded its limit"
  fi
  installer_size=$(wc -c < "$installer") || fail "cannot measure installer"
  [[ "$installer_size" =~ ^[0-9]+$ ]] \
    || fail "invalid installer size"
  (( installer_size > 0 && installer_size <= INSTALLER_MAX_BYTES )) \
    || fail "installer is empty or oversized"
  printf '%s  %s\n' "$INSTALLER_SHA256" "$installer" | sha256sum -c -
  /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    LTA_RELEASE="$LTA_RELEASE_TAG" /bin/sh "$installer"
LTA_BOOTSTRAP
```

Both downloads start only after a sanitized root shell is running. That root
process validates the pinned values, creates the unpredictable `0600` file in
an explicit trusted `/tmp`, downloads directly into it, checks its bounded size,
and (for the high-assurance flow) verifies the independent hash before execution.
No caller-owned inode is copied, opened, or executed by root. `/tmp` is accepted
only when it is a real root-owned directory with exactly the sticky special bit;
another unprivileged user then cannot replace or remove the root-owned file.
Root itself and the kernel/filesystem remain trusted. `/bin/sh` reads the file,
so a `noexec` mount does not prevent this procedure. The exact release selector
then prevents a release host from replaying a different still-valid signed version.

Each bootstrap download disables `.curlrc`, limits both the initial and redirected
protocols to HTTPS, and runs curl only after setting a kernel `RLIMIT_FSIZE`
calculated from the active shell's measured 512- or 1024-byte unit. It completes
successfully before any downloaded text is interpreted as shell code. The
installer has no unsigned/checksum-only fallback. It drops imported shell
functions before fixing a trusted root `PATH`, disables core dumps, neutralizes
caller-controlled OpenSSL configuration/provider paths, and gives each download
explicit connect/total timeouts plus a kernel `RLIMIT_FSIZE`, so chunked
responses and old curl versions cannot bypass the hard cap.

For `latest`, the installer first reads the official mirror's strict canonical
`latest.json` and pins its exact `vX.Y.Z` tag. It then downloads
`SHA256SUMS`, the selected architecture binary, and its detached signature as a
complete set from that version directory. A transport failure discards the
whole mirror set and downloads all three files again from the same GitHub tag;
only a transport failure while obtaining the mirror index itself uses GitHub
Latest. An explicit `LTA_RELEASE=vX.Y.Z` similarly tries that exact mirror
directory, then the same GitHub tag after transport failure. Manifest-semantic,
checksum, signature, and candidate-version failures stop immediately without
fallback, and files from the two sources are never combined. The GitHub path
uses bounded retries and adds `download=1` only on later GitHub attempts to
bypass a stuck Release CDN entry. Every official mirror URL must return its
file directly with status 200; a redirect is a source-policy failure and never
selects GitHub. `latest.json` must be the canonical single-line JSON emitted by
the workflow, `SHA256SUMS` must contain lowercase digests in NUL-free text that
ends with a newline, and detached signatures must be exactly 64 raw bytes.

After verification, the installer validates every destination ancestor as
root-owned and not group/world writable, creates an unpredictable `0600`
staging file beside the destination, probes the signed candidate under
time/output limits, verifies the staging copy again, and only then atomically
renames it into place. Passing `LTA_RELEASE_TAG=vX.Y.Z` through the validated
high-assurance bootstrap selects that exact release and requires the signed
candidate to report exactly `X.Y.Z`.

Routine self-upgrade is:

```bash
/usr/bin/sudo /usr/local/sbin/linux-temp-admin upgrade
```

The Go upgrader follows the same complete-source rule. It obtains the strict
mirror manifest, pins its exact tag, and downloads `SHA256SUMS`, the binary, and
signature from the official mirror. Only a transport failure selects GitHub;
after a valid manifest, the fallback redownloads the complete same-tag set.
Manifest-semantic, checksum, signature, and candidate-version failures stop
without fallback. Explicit `--url` and `--url-file` requests retain their
operator-selected binary/signature source and never silently switch to either
official source.

Every upgrader download accepts only HTTPS, rejects private/reserved redirect
targets at the actual dial point, and permits a private initial address only
for an explicit operator-selected custom URL. Official mirror requests do not
redirect; GitHub Release requests may follow public HTTPS redirects. Every
response is hard-limited and transport errors plus 408/425/429/5xx statuses are
boundedly retried. Structured
`download=1` cache bypass is limited to later official GitHub Release attempts
and never modifies a custom URL. The upgrader verifies checksums and the
detached signature against the embedded keyring, bounds the candidate version
process, compares versions, and atomically installs root:root `0755`. A
byte-identical existing target is a no-op only if its parent and all target
metadata are already safe; otherwise it is atomically repaired.

## Trust boundaries and residual risk

- The private key is protected from candidate code, CI, GitHub, and networked
  preparation/publication. The air-gapped OS, fixed signer binary, trusted
  offline script, and physical transfer procedure remain trusted.
- Reproducible comparison binds CI bytes to the audited tag under the fixed Go
  toolchain. The audited source, signed-tag identity, trusted preparation copy,
  Go distribution, and preparation workstation remain trusted.
- The convenience bootstrap obtains its script and embedded trust anchors over
  TLS from the official mirror. The mirror takes that installer from the signed
  Git tag, but the script is not currently an offline-ed25519-signed Release
  asset. High-assurance bootstrap therefore still uses an audited 40-hex commit
  in the raw GitHub URL and verifies the script hash through an independent
  channel before running it.
- A fresh bootstrap has no previously installed version state, so a release-host
  compromise can replay an older release that still has a valid offline
  signature. Pin an audited installer commit and pass `LTA_RELEASE=vX.Y.Z` when
  rollback resistance is required for first installation; the installer rejects
  a candidate whose reported version does not exactly match that tag.
- Publication is not transactionally coupled to public CDN verification. If the
  CDN remains unavailable after the bounded checks, the already-published
  release needs explicit operator remediation and must not be announced.
- GitHub publication and mirror synchronization are separate operations. The
  mirror host, TLS/CDN configuration, restricted deployment receiver, protected
  `release-mirror` environment, and announcement gate remain trusted operational
  controls; failure of the mirror workflow leaves the public GitHub Release
  unannounced rather than weakening client verification.
- GitHub has no atomic compare-and-set across "find the highest stable release"
  and "mark this release Latest". Repeated checks and automatic demotion detect
  observed conflicts, but cannot eliminate an operation that starts immediately
  after the last check. The protected environment and organization-wide
  single-publisher lock are mandatory operational controls.
- The single-maintainer model has no independent human approval boundary. A
  compromise of that maintainer's GitHub authority can merge source or workflow
  changes and request deployments. Offline release signing and client
  verification still prevent an account-only attacker from forging an accepted
  binary update, but the stable bootstrap script and release availability remain
  operational trust surfaces. Monitor them from a separate system and rotate
  affected credentials immediately after a suspected compromise.
