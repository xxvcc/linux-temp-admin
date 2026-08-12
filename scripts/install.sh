#!/bin/sh
# Signed bootstrap installer for linux-temp-admin.
# Deployed /bin/sh implementations (Bash, dash, and BusyBox ash) support the
# non-POSIX ulimit -c/-f switches used for kernel-enforced output limits.
# shellcheck disable=SC3045
# Explicit non-POSIX Bash lets imported functions override even special builtins
# such as `set` and `unset`. POSIXLY_CORRECT is a Bash dynamic variable: this
# assignment changes command lookup before the first shadowable command runs.
case ${BASH_VERSION-} in
  ?*) POSIXLY_CORRECT=y ;;
esac
set -eu
# Some systems link /bin/sh to Bash, which imports exported functions before
# executing this file. Clear every command name we call before trusting PATH.
for imported_name in id uname mktemp stat sha256sum openssl timeout awk grep od wc cp chmod chown mv \
  dirname mkdir rm sleep sync curl getent nslookup command printf ulimit echo umask export unset set trap exit return break ':' '['; do
  unset -f "$imported_name" 2>/dev/null || :
done
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
OPENSSL_CONF=/dev/null
export PATH LC_ALL OPENSSL_CONF
unset OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES
umask 077
if ! ulimit -c 0 2>/dev/null; then
  echo "error: could not disable core dumps" >&2
  exit 1
fi

release="${LTA_RELEASE-latest}"
expected_version=""
release_tag=""
MIRROR_ROOT=https://dl.ll.cd/linux-temp-admin
GITHUB_RELEASE_ROOT=https://github.com/xxvcc/linux-temp-admin/releases
MANAGED_DEST=/usr/local/sbin/linux-temp-admin
DEST="${DEST:-$MANAGED_DEST}"
TMP_ROOT=/tmp
MAX_BINARY_BYTES=67108864
MAX_SUMS_BYTES=1048576
MAX_SIGNATURE_BYTES=256
MAX_MANIFEST_BYTES=1048576
MAX_PROBE_BYTES=256
MAX_RELEASE_VERSION_BYTES=128
MIRROR_FETCH_ATTEMPTS=2
MIRROR_FETCH_TIMEOUT_SECONDS=20
GITHUB_FETCH_ATTEMPTS=4
GITHUB_FETCH_TIMEOUT_SECONDS=90
CONNECT_TIMEOUT_SECONDS=10

fail() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run this installer as root"
case "$DEST" in
  //*) fail "DEST must not begin with //" ;;
  /*) ;;
  *) fail "DEST must be an absolute path" ;;
esac

for command_name in id uname mktemp stat sha256sum openssl timeout awk grep od wc cp chmod chown mv \
  dirname mkdir rm sleep curl; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done
if [ "$DEST" != "$MANAGED_DEST" ]; then
  command -v sync >/dev/null 2>&1 || fail "required command not found: sync"
fi

case "$release" in
  latest) ;;
  *)
    [ "${#release}" -le $((MAX_RELEASE_VERSION_BYTES + 1)) ] \
      || fail "LTA_RELEASE must not exceed 129 ASCII bytes"
    case "$release" in
      '' | *[!v0-9A-Za-z.+-]*) fail "LTA_RELEASE must be latest or an exact vX.Y.Z release tag" ;;
    esac
    printf '%s\n' "$release" \
      | grep -Eq '^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$' \
      || fail "LTA_RELEASE must be latest or an exact vX.Y.Z release tag"
    release_tag=$release
    expected_version=${release#v}
    ;;
esac

# Bash uses 1024-byte `ulimit -f` blocks normally but 512-byte blocks in POSIX
# or sh mode; dash and BusyBox ash also use 512. Probe in a command-substitution
# child so the temporary soft limit cannot affect the installer, then read the
# inherited kernel value from Linux procfs instead of guessing from shell names.
if ! FSIZE_BLOCK_BYTES=$(
  ulimit -f 1 || exit 1
  awk '$1 == "Max" && $2 == "file" && $3 == "size" { print $4; found=1 }
       END { if (!found) exit 1 }' /proc/self/limits
); then
  fail "could not determine the shell file-size limit unit"
fi
case "$FSIZE_BLOCK_BYTES" in
  512 | 1024) ;;
  *) fail "unsupported shell file-size limit unit" ;;
esac

if [ ! -d "$TMP_ROOT" ] || [ -L "$TMP_ROOT" ]; then
  fail "temporary root is not a real directory: $TMP_ROOT"
fi
if ! tmp_root_uid=$(stat -c %u -- "$TMP_ROOT"); then
  fail "cannot inspect temporary root owner: $TMP_ROOT"
fi
case "$tmp_root_uid" in
  '' | *[!0-9]*) fail "invalid temporary root owner: $TMP_ROOT" ;;
esac
[ "$tmp_root_uid" -eq 0 ] || fail "temporary root is not root-owned: $TMP_ROOT"
if ! tmp_root_mode=$(stat -c %A -- "$TMP_ROOT"); then
  fail "cannot inspect temporary root mode: $TMP_ROOT"
fi
case "$tmp_root_mode" in
  d?????????) ;;
  *) fail "invalid temporary root mode: $TMP_ROOT" ;;
esac
case "$tmp_root_mode" in
  ?????w????|????????w?)
    case "$tmp_root_mode" in
      ?????????t|?????????T) ;;
      *) fail "writable temporary root lacks the sticky bit: $TMP_ROOT" ;;
    esac
    ;;
esac

# LTA_RELEASE_KEYS_BEGIN -- every PEM block must match, in order, one complete
# non-comment line in internal/selfmanage/release_pubkey.hex. A Go test enforces
# this invariant, including during a multi-key rotation overlap.
RELEASE_PUBKEY_PEMS='
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAmCRx+wyfgvdhQ8idBF+KkxGA+Myifa1ShrsgAGFOrxw=
-----END PUBLIC KEY-----
'
# LTA_RELEASE_KEYS_END

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac
asset="linux-temp-admin-linux-${arch}"

tmp="$(mktemp -d "$TMP_ROOT/linux-temp-admin.XXXXXXXXXX")"
stage=""
cleanup() {
  if [ -n "$stage" ]; then
    rm -f -- "$stage"
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Keep this classifier aligned with validate.PublicIP. A GitHub redirect target
# is resolved before curl can request it, every answer must be public, and the
# selected answer is pinned with --resolve so DNS rebinding cannot change it.
validate_resolver_output() {
  resolver_mode=$1
  awk -v mode="$resolver_mode" '
    function public_v4_parts(a, b, c, d) {
      if (a == 0 || a == 10 || a == 127 || a >= 224) return 0
      if (a == 100 && b >= 64 && b <= 127) return 0
      if (a == 169 && b == 254) return 0
      if (a == 172 && b >= 16 && b <= 31) return 0
      if (a == 192 && b == 168) return 0
      if (a == 192 && b == 0 && (c == 0 || c == 2)) return 0
      if (a == 192 && b == 31 && c == 196) return 0
      if (a == 192 && b == 52 && c == 193) return 0
      if (a == 192 && b == 88 && c == 99) return 0
      if (a == 192 && b == 175 && c == 48) return 0
      if (a == 198 && (b == 18 || b == 19)) return 0
      if (a == 198 && b == 51 && c == 100) return 0
      if (a == 203 && b == 0 && c == 113) return 0
      return 1
    }
    function parse_v4(text, parts, count, i) {
      count=split(text, parts, ".")
      if (count != 4) return 0
      for (i=1; i<=4; i++) {
        if (parts[i] !~ /^[0-9]+$/ || parts[i] + 0 > 255 ||
            (length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0")) return 0
      }
      return 1
    }
    function public_v4(text, parts) {
      if (!parse_v4(text, parts)) return 0
      return public_v4_parts(parts[1] + 0, parts[2] + 0, parts[3] + 0, parts[4] + 0)
    }
    function hex_value(text, chars, value, i, digit) {
      chars="0123456789abcdef"
      value=0
      if (text == "" || length(text) > 4) return -1
      for (i=1; i<=length(text); i++) {
        digit=index(chars, substr(text, i, 1)) - 1
        if (digit < 0) return -1
        value=value * 16 + digit
      }
      return value
    }
    function public_v6(text, left, right, left_count, right_count, count,
                       colon, tail, i, value, nonzero, v4, left_parts,
                       right_parts, parts, words) {
      text=tolower(text)
      if (text !~ /^[0-9a-f:.]+$/) return 0
      if (text ~ /[.]/) {
        colon=0
        for (i=1; i<=length(text); i++) if (substr(text, i, 1) == ":") colon=i
        if (!colon) return 0
        tail=substr(text, colon + 1)
        if (!parse_v4(tail, v4)) return 0
        text=substr(text, 1, colon) sprintf("%x:%x",
          (v4[1] + 0) * 256 + (v4[2] + 0),
          (v4[3] + 0) * 256 + (v4[4] + 0))
      }
      colon=index(text, "::")
      if (colon) {
        if (index(substr(text, colon + 2), "::")) return 0
        left=substr(text, 1, colon - 1)
        right=substr(text, colon + 2)
        left_count=(left == "" ? 0 : split(left, left_parts, ":"))
        right_count=(right == "" ? 0 : split(right, right_parts, ":"))
        if (left_count + right_count >= 8) return 0
        for (i=1; i<=left_count; i++) {
          value=hex_value(left_parts[i])
          if (value < 0) return 0
          words[i]=value
        }
        for (i=left_count + 1; i<=8 - right_count; i++) words[i]=0
        for (i=1; i<=right_count; i++) {
          value=hex_value(right_parts[i])
          if (value < 0) return 0
          words[8 - right_count + i]=value
        }
      } else {
        count=split(text, parts, ":")
        if (count != 8) return 0
        for (i=1; i<=8; i++) {
          value=hex_value(parts[i])
          if (value < 0) return 0
          words[i]=value
        }
      }
      if (words[1] == 0 && words[2] == 0 && words[3] == 0 &&
          words[4] == 0 && words[5] == 0 && words[6] == 65535) {
        return public_v4_parts(int(words[7] / 256), words[7] % 256,
          int(words[8] / 256), words[8] % 256)
      }
      if (words[1] < hex_value("2000") || words[1] > hex_value("3fff")) return 0
      nonzero=0
      for (i=1; i<=8; i++) if (words[i] != 0) nonzero=1
      if (!nonzero) return 0
      if (words[1] == 0 && words[2] == 0 && words[3] == 0 &&
          words[4] == 0 && words[5] == 0 && words[6] == 0 &&
          words[7] == 0 && words[8] == 1) return 0
      if (words[1] >= hex_value("fc00") && words[1] <= hex_value("fdff")) return 0
      if (words[1] >= hex_value("fe80") && words[1] <= hex_value("febf")) return 0
      if (words[1] >= hex_value("ff00")) return 0
      if (words[1] == hex_value("0064") && words[2] == hex_value("ff9b") && words[3] == 0 &&
          words[4] == 0 && words[5] == 0 && words[6] == 0) return 0
      if (words[1] == hex_value("0064") && words[2] == hex_value("ff9b") && words[3] == 1) return 0
      if (words[1] == hex_value("0100") && words[2] == 0 && words[3] == 0 && words[4] == 0) return 0
      if (words[1] == hex_value("2001") && words[2] < hex_value("0200")) return 0
      if (words[1] == hex_value("2001") && words[2] == hex_value("0db8")) return 0
      if (words[1] == hex_value("2002")) return 0
      if (words[1] == hex_value("3fff") && words[2] < hex_value("1000")) return 0
      if (words[1] == hex_value("5f00")) return 0
      return 1
    }
    function public_ip(address) {
      if (address ~ /:/) return public_v6(address)
      return public_v4(address)
    }
    function add_address(address) {
      if (address in seen) return
      seen[address]=1
      address_count++
      if (!public_ip(address)) invalid=1
      else if (first_public == "") first_public=address
    }
    mode == "getent" && $1 ~ /^[0-9A-Fa-f:.]+$/ && $1 ~ /[.:]/ {
      add_address($1)
      next
    }
    mode == "nslookup" && ($1 == "Server:" || $1 == "Server") {
      in_answer=0
      next
    }
    mode == "nslookup" && ($1 == "Name:" || $1 == "Name") {
      in_answer=1
      next
    }
    mode == "nslookup" && in_answer && $1 == "Address:" {
      add_address($2)
    }
    mode == "nslookup" && in_answer && $1 == "Address" && $2 ~ /^[0-9]+:$/ {
      add_address($3)
    }
    END {
      if (invalid) exit 2
      if (!address_count) exit 1
      print first_public
    }
  '
}

resolve_public_address() {
  resolve_host=$1
  resolver_output=""
  if command -v getent >/dev/null 2>&1; then
    if ! resolver_timeout=$(fetch_remaining_timeout "$CONNECT_TIMEOUT_SECONDS"); then
      return 1
    fi
    if ! resolver_output=$(timeout -s KILL "$resolver_timeout" getent ahosts "$resolve_host") 2>/dev/null; then
      resolver_output=""
    fi
    if [ -z "$resolver_output" ]; then
      if ! resolver_timeout=$(fetch_remaining_timeout "$CONNECT_TIMEOUT_SECONDS"); then
        return 1
      fi
      if ! resolver_output=$(timeout -s KILL "$resolver_timeout" getent hosts "$resolve_host") 2>/dev/null; then
        resolver_output=""
      fi
    fi
    if [ -n "$resolver_output" ]; then
      if resolved_address=$(printf '%s\n' "$resolver_output" | validate_resolver_output getent); then
        printf '%s\n' "$resolved_address"
        return 0
      else
        resolve_rc=$?
      fi
      [ "$resolve_rc" -ne 2 ] || return 2
    fi
  fi
  if command -v nslookup >/dev/null 2>&1; then
    resolver_output=""
    if ! resolver_timeout=$(fetch_remaining_timeout "$CONNECT_TIMEOUT_SECONDS"); then
      return 1
    fi
    if ! resolver_part=$(timeout -s KILL "$resolver_timeout" nslookup -type=A "$resolve_host") 2>/dev/null; then
      resolver_part=""
    fi
    resolver_output=$resolver_part
    if ! resolver_timeout=$(fetch_remaining_timeout "$CONNECT_TIMEOUT_SECONDS"); then
      return 1
    fi
    if ! resolver_part=$(timeout -s KILL "$resolver_timeout" nslookup -type=AAAA "$resolve_host") 2>/dev/null; then
      resolver_part=""
    fi
    if [ -n "$resolver_part" ]; then
      if [ -n "$resolver_output" ]; then
        resolver_output="${resolver_output}
${resolver_part}"
      else
        resolver_output=$resolver_part
      fi
    fi
    if resolved_address=$(printf '%s\n' "$resolver_output" | validate_resolver_output nslookup); then
      printf '%s\n' "$resolved_address"
      return 0
    else
      return $?
    fi
  fi
  return 1
}

valid_redirect_dns_host() {
  case "$1" in
    '' | .* | *. | *..* | *[!A-Za-z0-9.-]*) return 1 ;;
  esac
  printf '%s\n' "$1" | awk -F . '
    length($0) > 253 { exit 1 }
    {
      for (i=1; i<=NF; i++) {
        if (length($i) < 1 || length($i) > 63 ||
            substr($i, 1, 1) == "-" || substr($i, length($i), 1) == "-") exit 1
      }
    }
  '
}

redirect_resolve_entry() {
  redirect_url=$1
  case "$redirect_url" in
    https://*) ;;
    *) return 2 ;;
  esac
  case "$redirect_url" in
    *\\*) return 2 ;;
  esac
  redirect_remainder=${redirect_url#https://}
  redirect_authority=${redirect_remainder%%[/?#]*}
  case "$redirect_authority" in
    '' | *@*) return 2 ;;
  esac
  redirect_port=443
  redirect_literal=0
  case "$redirect_authority" in
    \[*\]*)
      redirect_host=${redirect_authority#\[}
      redirect_host=${redirect_host%%\]*}
      redirect_suffix=${redirect_authority#*\]}
      [ "$redirect_authority" = "[${redirect_host}]${redirect_suffix}" ] || return 2
      case "$redirect_host" in
        '' | *[!0-9A-Fa-f:.]*) return 2 ;;
      esac
      case "$redirect_suffix" in
        '') ;;
        :*) redirect_port=${redirect_suffix#:} ;;
        *) return 2 ;;
      esac
      redirect_literal=1
      ;;
    *)
      case "$redirect_authority" in
        *:*)
          redirect_host=${redirect_authority%%:*}
          redirect_port=${redirect_authority#*:}
          case "$redirect_port" in *:*) return 2 ;; esac
          ;;
        *) redirect_host=$redirect_authority ;;
      esac
      valid_redirect_dns_host "$redirect_host" || return 2
      case "$redirect_host" in
        *[!0-9.]*) ;;
        *) redirect_literal=1 ;;
      esac
      ;;
  esac
  case "$redirect_port" in
    '' | *[!0-9]*) return 2 ;;
  esac
  [ "$redirect_port" -ge 1 ] 2>/dev/null && [ "$redirect_port" -le 65535 ] 2>/dev/null || return 2
  if [ "$redirect_literal" -eq 1 ]; then
    printf '%s STREAM literal\n' "$redirect_host" | validate_resolver_output getent >/dev/null
    return $?
  fi
  if redirect_address=$(resolve_public_address "$redirect_host"); then
    :
  else
    return $?
  fi
  case "$redirect_address" in
    *:*) redirect_address="[${redirect_address}]" ;;
  esac
  printf '%s:%s:%s\n' "$redirect_host" "$redirect_port" "$redirect_address"
}

# RLIMIT_FSIZE is the authoritative cap. It remains effective for chunked
# responses and curl versions whose --max-filesize only checks Content-Length.
# -L with --max-redirs 0 makes curl stop from the response headers, before a
# redirect body can hit RLIMIT_FSIZE. Official mirror calls return status 2 for
# every 3xx. GitHub redirects are followed manually only after public-IP checks.
fetch_once() {
  fetch_url=$1
  fetch_out=$2
  fetch_max=$3
  fetch_timeout=$4
  fetch_follow_redirects=${5-0}
  # One monotonic deadline covers the initial request, redirect DNS lookups,
  # and every subsequent hop. No DNS fallback or redirect can reset it.
  if ! fetch_deadline_ticks=$(awk -v budget="$fetch_timeout" '
    BEGIN {
      if (budget !~ /^[0-9]+([.][0-9]+)?$/ || budget + 0 <= 0) exit 1
    }
    NR == 1 && $1 ~ /^[0-9]+([.][0-9]+)?$/ {
      printf "%.0f\n", ($1 + budget) * 100
      found=1
    }
    END { if (!found) exit 1 }
  ' /proc/uptime); then
    return 1
  fi
  fetch_remaining_timeout() {
    fetch_timeout_cap=${1-}
    awk -v deadline="$fetch_deadline_ticks" -v cap="$fetch_timeout_cap" '
      BEGIN {
        if (deadline !~ /^[0-9]+$/ ||
            (cap != "" && (cap !~ /^[0-9]+([.][0-9]+)?$/ || cap + 0 <= 0))) exit 1
      }
      NR == 1 && $1 ~ /^[0-9]+([.][0-9]+)?$/ {
        remaining=(deadline - ($1 * 100)) / 100
        if (remaining <= 0) exit 1
        if (cap != "" && remaining > cap + 0) remaining=cap + 0
        printf "%.2f\n", remaining
        found=1
      }
      END { if (!found) exit 1 }
    ' /proc/uptime
  }
  fetch_blocks=$(( (fetch_max + FSIZE_BLOCK_BYTES - 1) / FSIZE_BLOCK_BYTES ))
  rm -f -- "$fetch_out" || return 1
  fetch_resolve=""
  fetch_redirect_count=0
  while :; do
    if ! fetch_call_timeout=$(fetch_remaining_timeout); then
      rm -f -- "$fetch_out" || :
      return 1
    fi
    if fetch_meta=$(
      umask 077 || exit 1
      ulimit -f "$fetch_blocks" || exit 1
      if [ -n "$fetch_resolve" ]; then
        exec timeout -s KILL "$fetch_call_timeout" curl -q -fs --location --max-redirs 0 \
          --connect-timeout "$CONNECT_TIMEOUT_SECONDS" --max-time "$fetch_call_timeout" \
          --max-filesize "$fetch_max" --proto '=https' --proto-redir '=https' --noproxy '*' \
          --resolve "$fetch_resolve" --write-out '%{http_code}\n%{redirect_url}\n' \
          "$fetch_url" -o "$fetch_out" 2>/dev/null
      else
        exec timeout -s KILL "$fetch_call_timeout" curl -q -fs --location --max-redirs 0 \
          --connect-timeout "$CONNECT_TIMEOUT_SECONDS" --max-time "$fetch_call_timeout" \
          --max-filesize "$fetch_max" --proto '=https' --proto-redir '=https' --noproxy '*' \
          --write-out '%{http_code}\n%{redirect_url}\n' "$fetch_url" -o "$fetch_out" 2>/dev/null
      fi
    ) 2>/dev/null; then
      fetch_curl_rc=0
    else
      fetch_curl_rc=$?
    fi
    fetch_http_status=$(printf '%s\n' "$fetch_meta" | awk 'NR == 1 { print; exit }')
    fetch_redirect_url=$(printf '%s\n' "$fetch_meta" | awk 'NR == 2 { print; exit }')
    case "$fetch_http_status" in
      200)
        if [ "$fetch_curl_rc" -ne 0 ]; then
          rm -f -- "$fetch_out" || :
          return 1
        fi
        if ! fetch_remaining_timeout >/dev/null; then
          rm -f -- "$fetch_out" || :
          return 1
        fi
        break
        ;;
      3??)
        rm -f -- "$fetch_out" || :
        [ "$fetch_follow_redirects" -eq 1 ] || return 2
        [ -n "$fetch_redirect_url" ] || return 1
        [ "$fetch_redirect_count" -lt 10 ] || return 2
        if fetch_resolve=$(redirect_resolve_entry "$fetch_redirect_url"); then
          :
        else
          return $?
        fi
        fetch_url=$fetch_redirect_url
        fetch_redirect_count=$((fetch_redirect_count + 1))
        ;;
      *)
        rm -f -- "$fetch_out" || :
        return 1
        ;;
    esac
  done
  if ! fetch_size=$(wc -c < "$fetch_out"); then
    rm -f -- "$fetch_out" || :
    return 1
  fi
  case "$fetch_size" in
    '' | *[!0-9]*)
      rm -f -- "$fetch_out" || :
      return 1
      ;;
  esac
  if [ "$fetch_size" -le 0 ] || [ "$fetch_size" -gt "$fetch_max" ]; then
    rm -f -- "$fetch_out" || :
    return 1
  fi
  if ! fetch_remaining_timeout >/dev/null; then
    rm -f -- "$fetch_out" || :
    return 1
  fi
}

fetch() {
  fetch_original_url=$1
  fetch_out=$2
  fetch_max=$3
  fetch_github_cache_bypass=$4
  fetch_attempts=$5
  fetch_timeout=$6
  fetch_attempt=1
  while [ "$fetch_attempt" -le "$fetch_attempts" ]; do
    fetch_url=$fetch_original_url
    if [ "$fetch_github_cache_bypass" -eq 1 ] && [ "$fetch_attempt" -ge 3 ]; then
      case "$fetch_url" in
        *\?*) fetch_url="${fetch_url}&download=1" ;;
        *) fetch_url="${fetch_url}?download=1" ;;
      esac
    fi
    if fetch_once "$fetch_url" "$fetch_out" "$fetch_max" "$fetch_timeout" \
         "$fetch_github_cache_bypass"; then
      return 0
    else
      fetch_rc=$?
    fi
    if [ "$fetch_rc" -eq 2 ]; then
      return 2
    fi
    if [ "$fetch_attempt" -eq "$fetch_attempts" ]; then
      return 1
    fi
    echo "download attempt ${fetch_attempt}/${fetch_attempts} failed; retrying" >&2
    sleep "$fetch_attempt"
    fetch_attempt=$((fetch_attempt + 1))
  done
  return 1
}

parse_mirror_manifest() {
  awk -F '"' -v root="$MIRROR_ROOT" '
    function digits(value) {
      return value != "" && value !~ /[^0-9]/
    }
    function valid_published_at(value, year, month, day, hour, minute, second, maxday, fraction) {
      if (length(value) < 20 || length(value) > 30 ||
          substr(value, 5, 1) != "-" || substr(value, 8, 1) != "-" ||
          substr(value, 11, 1) != "T" || substr(value, 14, 1) != ":" ||
          substr(value, 17, 1) != ":" || substr(value, length(value), 1) != "Z") return 0
      year=substr(value, 1, 4); month=substr(value, 6, 2); day=substr(value, 9, 2)
      hour=substr(value, 12, 2); minute=substr(value, 15, 2); second=substr(value, 18, 2)
      if (!digits(year) || year == "0000" || !digits(month) || !digits(day) ||
          !digits(hour) || !digits(minute) || !digits(second)) return 0
      if (length(value) == 20) {
        if (substr(value, 20, 1) != "Z") return 0
      } else {
        if (substr(value, 20, 1) != ".") return 0
        fraction=substr(value, 21, length(value) - 21)
        if (!digits(fraction)) return 0
      }
      month += 0; day += 0; hour += 0; minute += 0; second += 0
      if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return 0
      maxday=31
      if (month == 4 || month == 6 || month == 9 || month == 11) maxday=30
      if (month == 2) {
        maxday=28
        if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) maxday=29
      }
      return day >= 1 && day <= maxday
    }
    NR == 1 && NF == 17 &&
      $1 == "{" && $2 == "version" && $3 == ":" &&
      $5 == "," && $6 == "tag" && $7 == ":" &&
      $9 == "," && $10 == "base_url" && $11 == ":" &&
      $13 == "," && $14 == "published_at" && $15 == ":" && $17 == "}" &&
      $4 != "" && $8 == "v" $4 && $12 == root "/v" $4 && valid_published_at($16) {
        version=$4
        valid=1
      }
    END {
      if (NR != 1 || !valid) exit 1
      print version
    }
  ' "$1"
}

canonical_text_file() {
  od -An -v -t u1 "$1" | awk '
    {
      for (i=1; i<=NF; i++) {
        if ($i == 0) invalid=1
        last=$i
        count++
      }
    }
    END { if (!count || invalid || last != 10) exit 1 }
  '
}

fetch_release_set() {
  source_base=$1
  source_dir=$2
  source_github_cache_bypass=$3
  if [ "$source_github_cache_bypass" -eq 1 ]; then
    source_attempts=$GITHUB_FETCH_ATTEMPTS
    source_timeout=$GITHUB_FETCH_TIMEOUT_SECONDS
  else
    source_attempts=$MIRROR_FETCH_ATTEMPTS
    source_timeout=$MIRROR_FETCH_TIMEOUT_SECONDS
  fi
  mkdir -m 0700 "$source_dir" || return 1
  fetch "${source_base}/SHA256SUMS" "$source_dir/SHA256SUMS" \
    "$MAX_SUMS_BYTES" "$source_github_cache_bypass" "$source_attempts" "$source_timeout" \
    || { source_rc=$?; rm -f -- "$source_dir/SHA256SUMS"; return "$source_rc"; }
  fetch "${source_base}/${asset}" "$source_dir/${asset}" \
    "$MAX_BINARY_BYTES" "$source_github_cache_bypass" "$source_attempts" "$source_timeout" \
    || { source_rc=$?; rm -f -- "$source_dir/SHA256SUMS" "$source_dir/${asset}"; return "$source_rc"; }
  fetch "${source_base}/${asset}.sig" "$source_dir/${asset}.sig" \
    "$MAX_SIGNATURE_BYTES" "$source_github_cache_bypass" "$source_attempts" "$source_timeout" \
    || { source_rc=$?; rm -f -- "$source_dir/SHA256SUMS" "$source_dir/${asset}" "$source_dir/${asset}.sig"; return "$source_rc"; }
  return 0
}

mirror_base=""
github_base=""
if [ "$release" = latest ]; then
  if fetch "${MIRROR_ROOT}/latest.json" "$tmp/latest.json" "$MAX_MANIFEST_BYTES" 0 \
       "$MIRROR_FETCH_ATTEMPTS" "$MIRROR_FETCH_TIMEOUT_SECONDS"; then
    canonical_text_file "$tmp/latest.json" \
      || fail "mirror latest manifest must be NUL-free and newline-terminated"
    expected_version=$(parse_mirror_manifest "$tmp/latest.json") \
      || fail "mirror latest manifest is invalid; refusing to hide a possible integrity incident"
    [ "${#expected_version}" -le "$MAX_RELEASE_VERSION_BYTES" ] \
      || fail "mirror latest manifest release version exceeds 128 ASCII bytes"
    printf '%s\n' "$expected_version" \
      | grep -Eq '^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$' \
      || fail "mirror latest manifest contains an invalid release version"
    release_tag="v${expected_version}"
    mirror_base="${MIRROR_ROOT}/${release_tag}"
    github_base="${GITHUB_RELEASE_ROOT}/download/${release_tag}"
  else
    manifest_rc=$?
    [ "$manifest_rc" -ne 2 ] \
      || fail "official mirror index redirected; refusing source-policy fallback"
    echo "official mirror index is unavailable; falling back to GitHub" >&2
    github_base="${GITHUB_RELEASE_ROOT}/latest/download"
  fi
else
  mirror_base="${MIRROR_ROOT}/${release_tag}"
  github_base="${GITHUB_RELEASE_ROOT}/download/${release_tag}"
fi

selected_dir=""
if [ -n "$mirror_base" ]; then
  if fetch_release_set "$mirror_base" "$tmp/mirror" 0; then
    selected_dir=$tmp/mirror
    echo "downloaded the complete release set from the official mirror" >&2
  else
    release_set_rc=$?
    [ "$release_set_rc" -ne 2 ] \
      || fail "official mirror release redirected; refusing source-policy fallback"
    echo "official mirror release download is incomplete; falling back to GitHub" >&2
  fi
fi
if [ -z "$selected_dir" ]; then
  fetch_release_set "$github_base" "$tmp/github" 1 \
    || fail "could not download a complete release set from the official mirror or GitHub"
  selected_dir=$tmp/github
fi

mv -- "$selected_dir/${asset}" "$tmp/bin"
mv -- "$selected_dir/SHA256SUMS" "$tmp/sums"
mv -- "$selected_dir/${asset}.sig" "$tmp/sig"

if ! canonical_text_file "$tmp/sums"; then
  fail "SHA256SUMS must be NUL-free and newline-terminated"
fi

if ! selected_sums=$(awk -v binary="$asset" -v signature="${asset}.sig" '
  function valid_digest(value) {
    return length(value) == 64 && value !~ /[^0-9a-f]/
  }
  {
    digest=substr($0, 1, 64)
    separator=substr($0, 65, 2)
    name=substr($0, 67)
		if (!valid_digest(digest) || separator != "  " || name == "" || index(name, "  ") != 0) exit 3
    if (name == binary) {
      if (binary_found) exit 2
      binary_digest=digest
      binary_found=1
    }
    if (name == signature) {
      if (signature_found) exit 2
      signature_digest=digest
      signature_found=1
    }
  }
  END {
    if (!binary_found || !signature_found) exit 1
    print binary_digest
    print signature_digest
  }
' "$tmp/sums"); then
  fail "SHA256SUMS must be canonical and contain exactly one entry for ${asset} and ${asset}.sig"
fi
want=$(printf '%s\n' "$selected_sums" | awk 'NR == 1 { print; found=1 } END { if (!found) exit 1 }') \
  || fail "cannot read checksum for ${asset}"
sig_want=$(printf '%s\n' "$selected_sums" | awk 'NR == 2 { print; found=1 } END { if (!found) exit 1 }') \
  || fail "cannot read checksum for ${asset}.sig"
got=$(sha256sum "$tmp/bin" | awk '{print $1}')
[ "$want" = "$got" ] || fail "checksum verification failed for ${asset}"
sig_got=$(sha256sum "$tmp/sig" | awk '{print $1}')
[ "$sig_want" = "$sig_got" ] || fail "checksum verification failed for ${asset}.sig"

openssl pkeyutl -help 2>&1 | grep -q -- '-rawin' \
  || fail "openssl >= 3.0 with pkeyutl -rawin is required; unsigned fallback is not allowed"
[ "$(wc -c < "$tmp/sig")" -eq 64 ] || fail "invalid signature size for ${asset}"

if ! key_count=$(printf '%s' "$RELEASE_PUBKEY_PEMS" | awk -v dir="$tmp" '
  /^-----BEGIN PUBLIC KEY-----$/ {
    n++; inkey=1; file=sprintf("%s/release-key.%d.pem", dir, n)
  }
  inkey { print > file }
  /^-----END PUBLIC KEY-----$/ { close(file); inkey=0 }
  END { if (inkey || n == 0) exit 1; print n }
'); then
  fail "embedded release keyring is malformed"
fi

verified=0
key_index=1
while [ "$key_index" -le "$key_count" ]; do
  if openssl pkeyutl -verify -pubin -inkey "$tmp/release-key.${key_index}.pem" -rawin \
       -in "$tmp/bin" -sigfile "$tmp/sig" >/dev/null 2>&1; then
    verified=1
    break
  fi
  key_index=$((key_index + 1))
done
[ "$verified" -eq 1 ] || fail "SIGNATURE VERIFICATION FAILED for ${asset}"

dest_dir=$(dirname -- "$DEST")
existing_ancestor=$dest_dir
while [ ! -e "$existing_ancestor" ] && [ ! -L "$existing_ancestor" ]; do
  next_ancestor=$(dirname -- "$existing_ancestor")
  [ "$next_ancestor" != "$existing_ancestor" ] || fail "cannot resolve destination parent"
  existing_ancestor=$next_ancestor
done

check_safe_dir_chain() {
  check_dir=$1
  while :; do
    if [ ! -d "$check_dir" ] || [ -L "$check_dir" ]; then
      fail "unsafe destination directory: $check_dir"
    fi
    if ! check_uid=$(stat -c %u -- "$check_dir"); then
      fail "cannot inspect destination directory owner: $check_dir"
    fi
    case "$check_uid" in
      '' | *[!0-9]*) fail "invalid destination directory owner: $check_dir" ;;
    esac
    [ "$check_uid" -eq 0 ] || fail "destination directory is not root-owned: $check_dir"
    if ! check_mode=$(stat -c %A -- "$check_dir"); then
      fail "cannot inspect destination directory mode: $check_dir"
    fi
    case "$check_mode" in
      d?????????) ;;
      *) fail "invalid destination directory mode: $check_dir" ;;
    esac
    case "$check_mode" in
      ?????w????|????????w?) fail "destination directory is group/world writable: $check_dir" ;;
    esac
    case "$check_dir" in
      / | //) break ;;
    esac
    check_dir=$(dirname -- "$check_dir")
  done
}

sync_destination_directory_chain() {
  sync_dir=$1
  while :; do
    timeout -k 5 30 sync "$sync_dir" \
      || fail "custom destination directory chain could not be made durable: $sync_dir"
    case "$sync_dir" in
      / | //) break ;;
    esac
    sync_dir=$(dirname -- "$sync_dir")
  done
}

check_safe_dir_chain "$existing_ancestor"
mkdir -p -- "$dest_dir"
check_safe_dir_chain "$dest_dir"
if [ "$DEST" != "$MANAGED_DEST" ]; then
  # Sync every directory inode from the leaf through root, in leaf-to-parent
  # order. This makes each newly created component's entry durable in its parent
  # before a custom installation can report success, including on a retry after
  # an earlier visible mkdir whose parent sync failed.
  sync_destination_directory_chain "$dest_dir"
fi

if [ -L "$DEST" ]; then
  fail "destination is a symlink: $DEST"
fi
if [ -e "$DEST" ] && [ ! -f "$DEST" ]; then
  fail "destination is not a regular file: $DEST"
fi

stage=$(mktemp "${dest_dir}/.linux-temp-admin.XXXXXX")
if [ ! -f "$stage" ] || [ -L "$stage" ]; then
  fail "could not create a safe staging file"
fi
cp -- "$tmp/bin" "$stage"
chown 0:0 -- "$stage"
chmod 0755 -- "$stage"
[ "$(sha256sum "$stage" | awk '{print $1}')" = "$got" ] || fail "staging copy changed unexpectedly"

# Probe before committing. RLIMIT_FSIZE bounds stdout even if a signed but buggy
# candidate prints forever; timeout kills a hanging candidate and its children.
if ! (
  ulimit -f 1 || exit 1
  exec timeout -k 1 10 "$stage" version > "$tmp/version" 2> "$tmp/version.err"
); then
  fail "downloaded binary failed its pre-install version probe"
fi
[ "$(wc -c < "$tmp/version")" -le "$MAX_PROBE_BYTES" ] || fail "version output is too large"
if ! candidate_version=$(awk '
  NR == 1 && $0 ~ /^[0-9]+[.][0-9]+[.][0-9]+([-_+~][A-Za-z0-9._+~-]+)?$/ { version=$0; next }
  { invalid=1 }
  END { if (NR != 1 || invalid) exit 1; printf "%s", version }
' "$tmp/version"); then
  fail "downloaded binary reported an invalid or multi-line version"
fi
[ -z "$expected_version" ] || [ "$candidate_version" = "$expected_version" ] \
  || fail "downloaded binary version does not match LTA_RELEASE"

[ "$(sha256sum "$stage" | awk '{print $1}')" = "$got" ] \
  || fail "staging copy changed during the version probe"
check_safe_dir_chain "$dest_dir"
if [ -L "$DEST" ] || { [ -e "$DEST" ] && [ ! -f "$DEST" ]; }; then
  fail "destination changed before commit: $DEST"
fi
if [ "$DEST" = "$MANAGED_DEST" ]; then
  # The signed candidate owns the lifecycle lock and uninstall marker protocol.
  # Delegating the managed-path commit to it serializes reinstall with every
  # other mutation and reactivates a deliberately uninstalled host. An unsafe
  # marker is rejected before the candidate changes the stable command.
  if ! timeout -k 1 30 "$stage" --lang en install --force >/dev/null 2>&1; then
    fail "signed candidate could not complete the managed install/reactivation"
  fi
  rm -f -- "$stage" || fail "could not remove the verified staging file"
  stage=""
else
  # Flush the fully verified inode before its name is committed. Operand-based
  # sync is supported by both GNU coreutils and BusyBox without relying on their
  # differing -d/-f option details.
  timeout -k 5 30 sync "$stage" \
    || fail "custom destination staging file could not be made durable"
  if mv --help 2>&1 | grep -q -- '--no-target-directory'; then
    mv -fT -- "$stage" "$DEST"
  else
    mv -f -- "$stage" "$DEST"
  fi
  stage=""
fi

if [ -L "$DEST" ] || [ ! -f "$DEST" ]; then
  fail "installed destination is not a regular non-symlink file"
fi
[ "$(sha256sum "$DEST" | awk '{print $1}')" = "$got" ] \
  || fail "installed destination differs from the verified candidate"
if ! final_uid=$(stat -c %u -- "$DEST"); then
  fail "cannot inspect installed destination owner"
fi
case "$final_uid" in
  '' | *[!0-9]*) fail "invalid installed destination owner" ;;
esac
[ "$final_uid" -eq 0 ] || fail "installed destination is not root-owned"
if ! final_gid=$(stat -c %g -- "$DEST"); then
  fail "cannot inspect installed destination group"
fi
case "$final_gid" in
  '' | *[!0-9]*) fail "invalid installed destination group" ;;
esac
[ "$final_gid" -eq 0 ] || fail "installed destination group is not root"
if ! final_mode=$(stat -c %a -- "$DEST"); then
  fail "cannot inspect installed destination mode"
fi
[ "$final_mode" = 755 ] || fail "installed destination mode is not 0755"
if [ "$DEST" != "$MANAGED_DEST" ]; then
  timeout -k 5 30 sync "$DEST" \
    || fail "custom destination is visible but its file durability is unknown"
  timeout -k 5 30 sync "$dest_dir" \
    || fail "custom destination is visible but its directory durability is unknown"
fi
echo "installed ${DEST} (version ${candidate_version})"
