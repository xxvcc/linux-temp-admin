#!/bin/bash -p
[[ $- == *p* ]] || { echo "execute release.sh directly; privileged Bash mode is required" >&2; exit 2; }
set -Eeuo pipefail
echo "release.sh is intentionally disabled: the old local fallback bypassed provenance and prerelease gates." >&2
echo "Use prepare-release.sh, offline-sign-release.sh, and publish-release.sh; see docs/releasing.md." >&2
exit 2
