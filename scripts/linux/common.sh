# shellcheck shell=bash
# Copyright 2026 The idunn Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Shared checks for the scripts in scripts/linux/. Sourced, never run.
#
# The rules mirror the Go ones and are a second line, not the only one: the
# label rule is elevate.CheckHelperLabel (docs/helper.md §2), the directory rule
# is elevate.CheckPrivilegedRoot on Linux (owner root, writable by nobody else;
# root's group excepted; the sticky bit does not help). The helper applies its
# own checks again when it starts.

export LC_ALL=C
# These scripts run as root: no command is looked up in a PATH the caller chose.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

die() { printf '%s: FAIL: %s\n' "${0##*/}" "$*" >&2; exit 1; }
note() { printf '%s: %s\n' "${0##*/}" "$*"; }
warn() { printf '%s: WARNING: %s\n' "${0##*/}" "$*" >&2; }

# need_value <flag> <argc> <value>: a flag that takes a value must have one, and
# the value must not look like another option.
need_value() {
  [ "$2" -ge 2 ] || die "$1 needs a value"
  case "$3" in
    -*) die "$1 needs a value, got the option '$3'" ;;
  esac
}

# once <flag> <current value>: an option may be given at most once.
once() {
  [ -z "$2" ] || die "$1 given more than once"
}

# check_label <label>: reverse-DNS -- at least two dot-separated components of
# ASCII letters, digits and hyphens, none empty and none starting or ending with
# a hyphen -- and at most 62 bytes. The label becomes the unit name, a file name
# under /usr/libexec, /etc and /run, so nothing else is accepted.
check_label() {
  local s="$1"
  local comp='[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'
  local re="^${comp}(\\.${comp})+\$"
  [ -n "$s" ] || die "label is empty"
  [ "${#s}" -le 62 ] || die "label '$s' is longer than 62 bytes"
  [[ "$s" =~ $re ]] || die "label '$s' is not reverse-DNS ([A-Za-z0-9-] components, at least two, none empty or hyphen-edged)"
}

require_root() {
  [ "$(id -u)" = 0 ] || die "this script must run as root (sudo $0 ...)"
}

# require_systemd: booted with systemd, version 247 or newer (ProtectProc= and
# the other hardening keys the unit uses; an older systemd would skip them with
# a warning and run the helper less confined than the unit says).
require_systemd() {
  [ -d /run/systemd/system ] || die "this system was not booted with systemd"
  command -v systemctl >/dev/null || die "systemctl not found"
  local v
  v="$(systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')"
  [ -n "$v" ] || die "cannot read the systemd version"
  [ "$v" -ge 247 ] || die "systemd $v is too old; the unit's hardening needs 247 or newer"
}

# check_admin_only <path>: path exists, is not a symlink, is owned by root and
# is writable by nobody but root (group write only for group root). Dies
# otherwise.
check_admin_only() {
  local p="$1" uid gid mode
  [ -e "$p" ] || die "'$p' does not exist"
  [ ! -L "$p" ] || die "'$p' is a symbolic link"
  read -r uid gid mode <<<"$(stat -c '%u %g %a' -- "$p")"
  [ "$uid" = 0 ] || die "'$p' is owned by uid $uid, not root"
  # %a is octal without leading zeros: the last digit is other, the one before
  # it group.
  local other=$((8#$mode & 8#002)) group=$((8#$mode & 8#020))
  [ "$other" = 0 ] || die "'$p' is writable by other users (mode $mode)"
  if [ "$group" != 0 ] && [ "$gid" != 0 ]; then
    die "'$p' is writable by group $gid (mode $mode)"
  fi
}

# check_admin_only_tree <path>: check_admin_only on path and every directory
# above it, up to /. path must be absolute and free of symlinks.
check_admin_only_tree() {
  local p="$1"
  case "$p" in
    /*) ;;
    *) die "'$p' is not an absolute path" ;;
  esac
  while :; do
    check_admin_only "$p"
    [ "$p" = / ] && break
    p="$(dirname -- "$p")"
  done
}
