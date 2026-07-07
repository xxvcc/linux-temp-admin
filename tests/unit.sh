#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT_DIR/temp-admin.sh"

# shellcheck source=../temp-admin.sh
source "$SCRIPT"

fail() {
  printf 'not ok - %s\n' "$*" >&2
  exit 1
}

assert_eq() {
  local actual="$1" expected="$2" label="$3"
  [[ "$actual" == "$expected" ]] || fail "$label: expected [$expected], got [$actual]"
}

assert_success() {
  local label="$1"
  shift
  "$@" || fail "$label: expected success"
}

assert_failure() {
  local label="$1"
  shift
  if "$@"; then
    fail "$label: expected failure"
  fi
}

assert_output_contains() {
  local output="$1" needle="$2" label="$3"
  [[ "$output" == *"$needle"* ]] || fail "$label: missing [$needle] in output"
}

assert_eq "$(bash "$SCRIPT" --version)" "$VERSION" "version command"
assert_eq "$(bash "$SCRIPT" --lang zh version)" "$VERSION" "version command with --lang"
help_output=$(bash "$SCRIPT" --lang en help)
assert_output_contains "$help_output" "bash temp-admin.sh doctor" "help includes doctor"
assert_output_contains "$help_output" "bash temp-admin.sh upgrade" "help includes upgrade"

source_output=$(bash -c 'source "$1"; declare -F valid_host >/dev/null' _ "$SCRIPT" 2>&1) \
  || fail "source guard failed: $source_output"
assert_eq "$source_output" "" "sourcing script should not execute main"

if output=$(bash "$SCRIPT" --lang fr help 2>&1); then
  fail "invalid --lang should fail"
fi
assert_output_contains "$output" "--lang only supports zh or en: fr" "invalid --lang"

if output=$(bash "$SCRIPT" help --lang 2>&1); then
  fail "missing --lang value should fail"
fi
assert_output_contains "$output" "--lang requires a value" "missing --lang value"

assert_success "valid username with prefix and random suffix" valid_username "xxvcc-a1b2c3"
assert_success "valid username starting underscore" valid_username "_ops1"
assert_failure "username cannot start with digit" valid_username "1ops"
assert_failure "username cannot contain dot" valid_username "ops.user"
assert_failure "username cannot end with dash" valid_username "ops-"
assert_failure "username cannot contain uppercase" valid_username "Ops"

assert_success "valid prefix" valid_prefix "ops-1"
assert_success "valid one-letter prefix" valid_prefix "o"
assert_failure "prefix cannot end with dash" valid_prefix "ops-"
assert_failure "prefix cannot end with underscore" valid_prefix "ops_"
assert_failure "prefix cannot contain uppercase" valid_prefix "Ops"

assert_success "valid DNS host" valid_host "server-1.example.com"
assert_success "valid IPv4 host" valid_host "203.0.113.10"
assert_success "valid IPv6 host" valid_host "2001:db8::1"
assert_success "valid IPv4-mapped IPv6 host" valid_host "::ffff:192.0.2.1"
assert_failure "host must not contain port" valid_host "example.com:22"
assert_failure "host must not contain spaces" valid_host "bad host"
assert_failure "host must reject shell metacharacters" valid_host "bad;touch"
assert_failure "IPv4 octet out of range" valid_host "999.1.1.1"
assert_failure "IPv4 leading zero" valid_host "010.0.0.1"
assert_failure "IPv6 triple colon" valid_host "2001:::1"
assert_failure "IPv6 too many groups" valid_host "1:2:3:4:5:6:7:8:9"
assert_failure "DNS label cannot start with dash" valid_host "-bad.example"
assert_failure "DNS label cannot end with dash" valid_host "bad-.example"
assert_failure "DNS host cannot start with dot" valid_host ".example"
assert_failure "DNS host cannot end with dot" valid_host "example."

assert_success "public IPv4" is_public_ipv4 "8.8.8.8"
assert_failure "private 10/8" is_public_ipv4 "10.0.0.1"
assert_failure "private 172.16/12" is_public_ipv4 "172.16.0.1"
assert_failure "private 192.168/16" is_public_ipv4 "192.168.1.1"
assert_failure "carrier-grade NAT" is_public_ipv4 "100.64.0.1"
assert_failure "link-local" is_public_ipv4 "169.254.1.1"
assert_failure "benchmark network" is_public_ipv4 "198.18.0.1"
assert_failure "documentation 192.0.2/24" is_public_ipv4 "192.0.2.1"
assert_failure "documentation 198.51.100/24" is_public_ipv4 "198.51.100.10"
assert_failure "documentation 203.0.113/24" is_public_ipv4 "203.0.113.10"
assert_failure "multicast" is_public_ipv4 "224.0.0.1"
assert_failure "invalid IPv4 leading zero" is_public_ipv4 "010.0.0.1"

assert_eq "$(ssh_host_for_command "example.com")" "example.com" "ssh host DNS"
assert_eq "$(ssh_host_for_command "2001:db8::1")" "[2001:db8::1]" "ssh host IPv6"
assert_eq "$(shell_quote_arg "a'b")" "'a'\''b'" "shell single-quote escaping"
assert_eq "$(systemd_quote_arg $'a"b\\c\nz')" '"a\"b\\c z"' "systemd argument escaping"
assert_success "valid installed version" valid_installed_version "1.2.3"
assert_success "valid installed prerelease version" valid_installed_version "1.2.3-rc1"
assert_failure "invalid installed version text" valid_installed_version "not-a-version"
assert_eq "$(extract_script_version "$SCRIPT")" "$VERSION" "extract script version"
assert_success "newer version compares greater" version_gt "1.2.0" "1.1.2"
assert_success "major version compares greater" version_gt "2.0.0" "1.9.9"
assert_success "final release compares greater than prerelease" version_gt "1.2.0" "1.2.0-rc1"
assert_failure "same version is not greater" version_gt "1.2.0" "1.2.0"
assert_failure "older version is not greater" version_gt "1.1.9" "1.2.0"
assert_failure "prerelease is not greater than final" version_gt "1.2.0-rc1" "1.2.0"
assert_success "default upgrade URL is valid" valid_upgrade_url "$DEFAULT_UPGRADE_URL"
assert_success "custom https upgrade URL is valid" valid_upgrade_url "https://example.com/temp-admin.sh"
assert_failure "upgrade URL must be https" valid_upgrade_url "http://example.com/temp-admin.sh"
assert_failure "upgrade URL rejects whitespace" valid_upgrade_url "https://example.com/a b.sh"
assert_failure "upgrade URL rejects shell metacharacters" valid_upgrade_url "https://example.com/a|b.sh"

download_tmp=$(mktemp -d)
download_dest="$download_tmp/temp-admin.sh"
if (
  command_exists() { [[ "$1" == "curl" ]]; }
  curl() {
    local out=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '%s' 'partial' > "$out"
    return 22
  }
  download_script_to_file "https://example.com/temp-admin.sh" "$download_dest"
) >/dev/null 2>&1; then
  rm -rf "$download_tmp"
  fail "download failure should fail"
fi
[[ ! -e "$download_dest" ]] || {
  rm -rf "$download_tmp"
  fail "download failure should remove partial file"
}
if (
  export MAX_UPGRADE_BYTES=4
  command_exists() { [[ "$1" == "curl" ]]; }
  curl() {
    local out=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '%s' '12345' > "$out"
  }
  download_script_to_file "https://example.com/temp-admin.sh" "$download_dest"
) >/dev/null 2>&1; then
  rm -rf "$download_tmp"
  fail "oversized download should fail"
fi
[[ ! -e "$download_dest" ]] || {
  rm -rf "$download_tmp"
  fail "oversized download should remove file"
}
rm -rf "$download_tmp"

if output=$(bash "$SCRIPT" --lang en doctor --bad 2>&1); then
  fail "unsupported doctor argument should fail"
fi
assert_output_contains "$output" "doctor: unsupported argument: --bad" "doctor unsupported argument"

if output=$(bash "$SCRIPT" --lang en install --bad 2>&1); then
  fail "unsupported install argument should fail"
fi
assert_output_contains "$output" "install: unsupported argument: --bad" "install unsupported argument"

if output=$(bash "$SCRIPT" --lang en uninstall --bad 2>&1); then
  fail "unsupported uninstall argument should fail"
fi
assert_output_contains "$output" "uninstall: unsupported argument: --bad" "uninstall unsupported argument"

if output=$(bash "$SCRIPT" --lang en upgrade --url http://example.com/temp-admin.sh --yes 2>&1); then
  fail "unsafe upgrade URL should fail"
fi
assert_output_contains "$output" "Upgrade URL is unsafe or invalid" "upgrade rejects unsafe URL"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  install_tmp=$(mktemp -d)
  existing_install="$install_tmp/linux-temp-admin"
  printf '%s\n' '#!/usr/bin/env bash' '[[ "${1:-}" == "version" ]] && echo "9.9.9"' > "$existing_install"
  chmod 700 "$existing_install"
  if (
    export INSTALL_PATH="$existing_install"
    command_exists() {
      [[ "$1" == "cmp" ]] && return 1
      command -v "$1" >/dev/null 2>&1
    }
    install_script_file_for_revoke "$SCRIPT" false false
  ) >/dev/null 2>&1; then
    rm -rf "$install_tmp"
    fail "install should refuse to overwrite without cmp and without force"
  fi
  assert_eq "$(bash "$existing_install" version)" "9.9.9" "cmp-missing install refusal keeps existing command"
  (
    export INSTALL_PATH="$existing_install"
    command_exists() {
      [[ "$1" == "cmp" ]] && return 1
      command -v "$1" >/dev/null 2>&1
    }
    install_script_file_for_revoke "$SCRIPT" false true
  ) >/dev/null 2>&1 || {
    rm -rf "$install_tmp"
    fail "auto install should reuse existing command when cmp is unavailable"
  }
  assert_eq "$(bash "$existing_install" version)" "9.9.9" "cmp-missing auto install keeps existing command"
  rm -rf "$install_tmp"

  registry_tmp=$(mktemp -d)
  if (
    export REGISTRY_DIR="$registry_tmp/registry"
    export REGISTRY_FILE="$REGISTRY_DIR/users.tsv"
    export REGISTRY_LOCK_FILE="$REGISTRY_DIR/users.lock"
    printf() {
      if [[ "${1:-}" == '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' ]]; then
        return 1
      fi
      builtin printf "$@"
    }
    registry_record_user "xxvcc-audit" "2099-01-01" "no" "no" "example.com" "22" "SHA256:test" "no" ""
  ) >/dev/null 2>&1; then
    rm -rf "$registry_tmp"
    fail "registry append failure should fail"
  fi
  rm -rf "$registry_tmp"
fi

fallback_unit=$(
  command_exists() { return 1; }
  auto_revoke_unit_name "bad/name"
)
assert_eq "$fallback_unit" "${MANAGED_TAG}-revoke-badname" "auto revoke unit fallback sanitizes"

printf 'ok - unit tests passed\n'
