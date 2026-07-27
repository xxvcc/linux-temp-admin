#!/bin/bash -p
[[ $- == *p* ]] || { echo "execute sign-release.sh directly; privileged Bash mode is required" >&2; exit 2; }
set -Eeuo pipefail
echo "sign-release.sh is intentionally disabled: an online one-step signer exposes the long-term key." >&2
echo "Use trusted copies of prepare-release.sh, offline-sign-release.sh, and publish-release.sh; see docs/releasing.md." >&2
exit 2
