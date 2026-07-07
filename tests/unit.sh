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
assert_failure "installed version rejects 2 components (version_gt cannot parse them)" valid_installed_version "1.2"
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

# The day-granular chage expiry must never lock before the requested window
# (accounts stay usable for at least --hours), yet stay within ~1 extra day.
if date -u -d "+1 day" +%F >/dev/null 2>&1; then
  for expiry_h in 1 6 12 24 8760; do
    expiry_date=$(expire_date_from_hours "$expiry_h")
    lock_epoch=$(date -u -d "$expiry_date 00:00:00" +%s)
    window_epoch=$(date -u -d "+${expiry_h} hours" +%s)
    [[ "$lock_epoch" -ge "$window_epoch" ]] \
      || fail "expiry for ${expiry_h}h ($expiry_date) locks before now+${expiry_h}h (premature)"
    [[ "$lock_epoch" -le $((window_epoch + 172800)) ]] \
      || fail "expiry for ${expiry_h}h ($expiry_date) is more than 2 days past the window"
  done
fi

# passwd_entry must resolve a local account without getent (musl/Alpine lack it).
passwd_entry_no_getent=$(
  command_exists() { [[ "$1" != "getent" ]] && command -v "$1" >/dev/null 2>&1; }
  passwd_entry "root"
)
assert_output_contains "$passwd_entry_no_getent" "root:" "passwd_entry falls back to /etc/passwd when getent is absent"

# passwd_db must not duplicate rows when getent prints output but exits non-zero.
passwd_db_root_count=$(
  command_exists() { [[ "$1" == "getent" ]] || command -v "$1" >/dev/null 2>&1; }
  getent() { printf 'root:x:0:0:root:/root:/bin/bash\n'; return 2; }
  passwd_db | grep -c '^root:'
)
assert_eq "$passwd_db_root_count" "1" "passwd_db does not duplicate rows on getent non-zero-with-output"

# account_is_managed must require the FULL tag, not the bare substring, so a
# self-set partial GECOS cannot pose as tool-managed.
managed_full=$(
  passwd_entry() { printf 'u:x:1000:1000:%s temporary admin,,,:/home/u:/bin/sh\n' "$MANAGED_TAG"; }
  account_is_managed u && echo yes || echo no
)
managed_bare=$(
  passwd_entry() { printf 'u:x:1000:1000:%s,,,:/home/u:/bin/sh\n' "$MANAGED_TAG"; }
  account_is_managed u && echo yes || echo no
)
assert_eq "$managed_full" "yes" "account_is_managed accepts the full managed GECOS tag"
assert_eq "$managed_bare" "no" "account_is_managed rejects a bare-tag GECOS substring"

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

# GNU wget: must use --timeout and forbid redirects (--max-redirect=0).
wget_probe_tmp=$(mktemp -d)
(
  export WGET_ARGS_FILE="$wget_probe_tmp/args"
  command_exists() { [[ "$1" == "wget" ]]; }
  wget() {
    if [[ "${1:-}" == "--help" ]]; then printf '  --timeout=SECS\n  --tries=N\n  --max-redirect=N\n'; return 0; fi
    printf '%s\n' "$*" > "$WGET_ARGS_FILE"
    printf 'ok'
  }
  download_script_to_file "https://example.com/x.sh" "$wget_probe_tmp/out"
) >/dev/null 2>&1
gnu_wget_args=$(cat "$wget_probe_tmp/args" 2>/dev/null)
assert_output_contains "$gnu_wget_args" "--max-redirect=0" "wget(GNU) forbids redirects when supported"
assert_output_contains "$gnu_wget_args" "--timeout=30" "wget(GNU) uses --timeout when supported"
rm -rf "$wget_probe_tmp"

# busybox wget: must NOT pass GNU-only long options and must NOT pass -T (it can
# segfault on some builds); when timeout(1) exists the fetch is wrapped in it.
wget_probe_tmp=$(mktemp -d)
(
  export WGET_ARGS_FILE="$wget_probe_tmp/args"
  command_exists() { case "$1" in curl) return 1 ;; *) return 0 ;; esac; }  # wget + timeout present
  timeout() { printf 'TIMEOUT %s\n' "$1" >> "$WGET_ARGS_FILE"; shift; "$@"; }
  wget() {
    if [[ "${1:-}" == "--help" ]]; then printf 'BusyBox wget: -c -q -O FILE\n'; return 1; fi
    printf 'WGET %s\n' "$*" >> "$WGET_ARGS_FILE"
    printf 'ok'
  }
  download_script_to_file "https://example.com/x.sh" "$wget_probe_tmp/out"
) >/dev/null 2>&1
busybox_args=$(cat "$wget_probe_tmp/args" 2>/dev/null)
[[ "$busybox_args" != *--max-redirect* ]] || { rm -rf "$wget_probe_tmp"; fail "wget(busybox) must not pass --max-redirect"; }
[[ "$busybox_args" != *--timeout* ]] || { rm -rf "$wget_probe_tmp"; fail "wget(busybox) must not pass --timeout"; }
[[ "$busybox_args" != *"-T "* ]] || { rm -rf "$wget_probe_tmp"; fail "wget(busybox) must not pass -T (segfaults on some builds)"; }
[[ "$busybox_args" == *"TIMEOUT 30"* ]] || { rm -rf "$wget_probe_tmp"; fail "wget(busybox) must wrap the fetch in timeout(1) when available"; }
rm -rf "$wget_probe_tmp"

# busybox wget with no timeout(1) available: must FAIL FAST (return non-zero and
# never run an unbounded fetch that would hang for minutes on a stalled connect).
wget_probe_tmp=$(mktemp -d)
notimeout_rc=0
(
  export WGET_ARGS_FILE="$wget_probe_tmp/args"
  command_exists() { case "$1" in wget) return 0 ;; *) return 1 ;; esac; }  # only wget: no timeout(1)
  wget() {
    if [[ "${1:-}" == "--help" ]]; then printf 'BusyBox wget\n'; return 1; fi
    printf 'RAN %s\n' "$*" >> "$WGET_ARGS_FILE"   # must NOT be reached
    printf 'ok'
  }
  download_script_to_file "https://example.com/x.sh" "$wget_probe_tmp/out"
) >/dev/null 2>&1 || notimeout_rc=$?
[[ "$notimeout_rc" -ne 0 ]] || { rm -rf "$wget_probe_tmp"; fail "download must fail fast when busybox wget has no timeout mechanism"; }
[[ ! -e "$wget_probe_tmp/args" ]] || { rm -rf "$wget_probe_tmp"; fail "download must not run an unbounded busybox wget (no timeout available)"; }
rm -rf "$wget_probe_tmp"

# Regression: the /proc kill fallback must not abort the caller under set -e when
# a status read yields no data (a process vanished mid-scan). Call the real
# function as a bare statement under set -e with a UID that matches nothing and a
# no-op signal (0), so it scans real /proc (with entries that come and go) but
# signals no one; it must return cleanly rather than errexit-abort.
signal_errexit_probe=$(
  set -Eeuo pipefail
  signal_uid_processes 0 999999999
  printf 'survived'
)
assert_eq "$signal_errexit_probe" "survived" "signal_uid_processes must not abort under set -e on empty status reads"

# Guard: signal_uid_processes must no-op for uid 0 or an empty uid (never
# mass-signal root or match a vanished process's empty uid). Use signal 0 so even
# a broken guard stays harmless.
signal_guard_zero=$( set -Eeuo pipefail; signal_uid_processes 0 0; printf 'ok' )
assert_eq "$signal_guard_zero" "ok" "signal_uid_processes no-ops for uid 0"
signal_guard_empty=$( set -Eeuo pipefail; signal_uid_processes 0 ''; printf 'ok' )
assert_eq "$signal_guard_empty" "ok" "signal_uid_processes no-ops for an empty uid"

# Regression: passwd_entry must not abort under set -e when getent exits non-zero
# with output (partly-failing NSS); it should still return that output.
passwd_entry_nonzero=$(
  set -Eeuo pipefail
  command_exists() { [[ "$1" == getent ]] || command -v "$1" >/dev/null 2>&1; }
  getent() { printf 'svc:x:1234:1234::/nonexistent:/usr/sbin/nologin\n'; return 2; }
  passwd_entry "svc"
  printf ' :done'
)
assert_output_contains "$passwd_entry_nonzero" "svc:" "passwd_entry returns getent output even when getent exits non-zero"
assert_output_contains "$passwd_entry_nonzero" ":done" "passwd_entry does not abort under set -e on non-zero getent"

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

  # Installing must not print to stdout: install_self_for_revoke runs inside
  # schedule_auto_revoke/schedule_at_revoke whose stdout becomes the recorded
  # auto-revoke unit name. A leaked "[OK] installed" banner would corrupt it and
  # break later timer/at-job cleanup and status lookups.
  install_stdout_tmp=$(mktemp -d)
  install_stdout=$(
    export INSTALL_PATH="$install_stdout_tmp/linux-temp-admin"
    install_script_file_for_revoke "$SCRIPT" false false 2>/dev/null
  )
  rm -rf "$install_stdout_tmp"
  assert_eq "$install_stdout" "" "install must not emit to stdout (would corrupt auto-revoke unit name)"

  # installed_revoke_version must populate the CALLER's variable even when the
  # caller names it 'installed_ver' (regression: a same-named internal local
  # shadowed it, so `upgrade` saw installed=none and silently no-op'd).
  irv_tmp=$(mktemp -d)
  (
    export INSTALL_PATH="$irv_tmp/linux-temp-admin"
    printf '%s\n' '#!/usr/bin/env bash' '[[ "$1" == version ]] && echo "1.2.0"' > "$INSTALL_PATH"
    chmod 700 "$INSTALL_PATH"
    installed_ver="SENTINEL"
    installed_revoke_version installed_ver || { echo "return-failed"; exit 3; }
    [[ "$installed_ver" == "1.2.0" ]] || { echo "not-populated:$installed_ver"; exit 4; }
  ) || fail "installed_revoke_version must populate a caller variable named installed_ver"
  rm -rf "$irv_tmp"

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
