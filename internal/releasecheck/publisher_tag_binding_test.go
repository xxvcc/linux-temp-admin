package releasecheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GitHub clears a release's tag when an update omits tag_name. Model that
// mutation before returning the response: checking the response is too late
// once a newly published release has become immutable.
func TestPublisherPatchesPreserveEachBoundReleaseTag(t *testing.T) {
	publish := readReleaseFile(t, "../../scripts/publish-release.sh")
	start := strings.Index(publish, "initial_release_state() {")
	end := strings.Index(publish, "\nrequire_remote_tag_object() {")
	if start < 0 || end <= start {
		t.Fatal("could not isolate bound publisher mutation functions")
	}
	for _, tc := range []struct {
		name, initial, invoke, want string
	}{
		{
			name:    "publish candidate",
			initial: "v2.10.9 true false false 12345",
			invoke:  "publish_bound_release",
			want:    "v2.10.9 false false true 12345 false",
		},
		{
			name:    "restore mutable candidate to draft",
			initial: "v2.10.9 false false false 12345",
			invoke:  "secure_failed_publication_state",
			want:    "v2.10.9 true false false 12345 false",
		},
		{
			name:    "promote candidate to Latest",
			initial: "v2.10.9 false false true 12345",
			invoke:  "set_latest_by_release_id 12345 v2.10.9 true",
			want:    "v2.10.9 false false true 12345 true",
		},
		{
			name:    "restore previous Latest with its own tag",
			initial: "v2.10.8 false false true 12344",
			invoke:  "set_latest_by_release_id 12344 v2.10.8 true",
			want:    "v2.10.8 false false true 12344 true",
		},
		{
			name:    "clear candidate Latest",
			initial: "v2.10.9 false false true 12345",
			invoke:  "set_latest_by_release_id 12345 v2.10.9 false",
			want:    "v2.10.9 false false true 12345 false",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "patch-tag.sh")
			body := `#!/bin/bash
set -Eeuo pipefail
TAG=v2.10.9
REPO=mock/repo
EXPECTED_RELEASE_ID=12345
expected_prerelease=false
MAX_RELEASE_VERSION_BYTES=128
printf '%s\n' "$TEST_INITIAL" > "$TEST_STATE/release"
gh_with_timeout() {
  local tag draft prerelease immutable id endpoint field latest=unchanged
  read -r tag draft prerelease immutable id < "$TEST_STATE/release"
  if [[ "$1" == api && "$2" == "repos/${REPO}/releases/${id}" ]]; then
    cat "$TEST_STATE/release"
    return 0
  fi
  [[ "$1" == api && "$2" == --method && "$3" == PATCH ]] || return 90
  endpoint=$4
  [[ "$endpoint" == "repos/${REPO}/releases/${id}" ]] || return 91
  shift 4
  # Match the real API's omission behavior, not the desired caller behavior.
  tag=untagged-fixture
  while (( $# )); do
    case "$1" in
      -f|-F)
        field=$2
        case "$field" in
          tag_name=*) tag=${field#*=} ;;
          draft=true) draft=true; immutable=false ;;
          draft=false) draft=false; immutable=true ;;
          prerelease=*) prerelease=${field#*=} ;;
          make_latest=*) latest=${field#*=} ;;
          *) return 92 ;;
        esac
        shift 2
        ;;
      --jq) shift 2 ;;
      *) return 93 ;;
    esac
  done
  printf '%s %s %s %s %s\n' "$tag" "$draft" "$prerelease" "$immutable" "$id" > "$TEST_STATE/release"
  printf '%s %s %s %s %s %s\n' "$tag" "$draft" "$prerelease" "$immutable" "$id" "$latest" >> "$TEST_STATE/mutations"
  cat "$TEST_STATE/release"
}
` + publish[start:end] + "\n" + tc.invoke + "\n"
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", "-p", script)
			cmd.Env = append(os.Environ(), "TEST_STATE="+dir, "TEST_INITIAL="+tc.initial)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("bound release tag was lost during PATCH: %v\n%s", err, out)
			}
			mutations, err := os.ReadFile(filepath.Join(dir, "mutations"))
			if err != nil || string(mutations) != tc.want+"\n" {
				t.Fatalf("mutations = %q, %v; want exactly %q", mutations, err, tc.want+"\n")
			}
		})
	}
}
