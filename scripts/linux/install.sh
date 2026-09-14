#!/usr/bin/env bash
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

# Install a publisher-built idunn helper (cmd/helper, docs/helper.md) as a
# hardened systemd service:
#
#   /usr/libexec/<label>                   the helper, root:root 0755
#   /etc/systemd/system/<label>.service    rendered from helper.service.in
#   /run/<label>/helper.sock               created by the running service
#   /etc/<label>/callers.json              written later by `<label> allow`
#
# Everything that can be judged is judged before anything changes: the label;
# root and a systemd new enough for the unit's hardening; /usr/libexec and every
# directory above it owned by root and writable by nobody else; each --rw root
# the same, and exactly the helper's embedded allowed_roots; and `<helper>
# check` passing for the copy that will be installed. After the first change, a
# failure removes what was installed, so a half-registered helper is never left
# behind.
#
# Must run from a copy of these scripts only root can modify (the product
# package's payload, say): it renders a unit that runs as root.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"

usage() {
  cat <<'EOF'
usage: install.sh --helper <binary> --label <label> --rw <root> [<root>...] [--rw <root>]...
       install.sh --render-unit --label <label> --rw <root> [<root>...]

  --helper       the helper built from cmd/helper for this label
  --label        the helper label compiled into it (reverse-DNS, [A-Za-z0-9.-],
                 at most 62 bytes)
  --rw           an install root the service may write (systemd ReadWritePaths=).
                 Together they must equal the helper's embedded allowed_roots.
                 Each must exist, be owned by root and writable by nobody else,
                 as must every directory above it.
  --render-unit  print the rendered unit and exit; changes nothing, needs no root

Installs the helper to /usr/libexec/<label>, the unit to
/etc/systemd/system/<label>.service, and enables and starts it. Refuses to
overwrite an existing installation: run uninstall.sh first.
EOF
}

helper="" label="" render=""
roots=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --helper) need_value "$1" "$#" "${2:-}"; once "$1" "$helper"; helper="$2"; shift 2 ;;
    --label) need_value "$1" "$#" "${2:-}"; once "$1" "$label"; label="$2"; shift 2 ;;
    --render-unit) once "$1" "$render"; render=1; shift ;;
    --rw)
      need_value "$1" "$#" "${2:-}"
      shift
      while [ "$#" -gt 0 ]; do
        case "$1" in
          -*) break ;;
        esac
        roots+=("$1")
        shift
      done
      ;;
    *) usage >&2; die "unknown argument '$1'" ;;
  esac
done

[ -n "$label" ] || { usage >&2; die "--label is required"; }
[ "${#roots[@]}" -gt 0 ] || { usage >&2; die "at least one --rw root is required"; }
check_label "$label"

template="$here/helper.service.in"
unit="/etc/systemd/system/$label.service"
target="/usr/libexec/$label"
state="/etc/$label"
socket="/run/$label/helper.sock"

# check_root_syntax <root>: a clean absolute path systemd can take unquoted, at
# least two components deep, outside the trees a service must never write or
# that ProtectHome=/PrivateTmp= hide from it.
check_root_syntax() {
  local r="$1" re='^(/[A-Za-z0-9._@+-]+)+$'
  [[ "$r" =~ $re ]] ||
    die "--rw '$r' must be an absolute path of [A-Za-z0-9._@+-] components (no spaces, no trailing slash)"
  case "/$r/" in
    */./* | */../*) die "--rw '$r' is not a clean path" ;;
  esac
  case "$r" in
    /*/*) ;;
    *) die "--rw '$r' is a top-level directory; an install root belongs below one (/opt/<product>)" ;;
  esac
  case "$r/" in
    /usr/local/bin/* | /usr/local/sbin/* | /usr/local/lib/* | /usr/local/lib64/* | /usr/local/libexec/* | \
      /usr/local/etc/* | /usr/local/share/* | /usr/local/include/* | /usr/local/src/*)
      die "--rw '$r' is a shared /usr/local tree; use /usr/local/<product>" ;;
    /usr/local/?*/*) ;; # /usr/local/<product>: an administrator's tree.
    /proc/* | /sys/* | /dev/* | /run/* | /tmp/* | /var/tmp/* | /home/* | /root/* | /boot/* | \
      /usr/* | /etc/* | /bin/* | /sbin/* | /lib/* | /lib32/* | /lib64/* | /libx32/*)
      die "--rw '$r' is under a system or per-user tree; the helper must not be able to write there" ;;
  esac
}

sorted_roots() { printf '%s\n' "${roots[@]}" | sort -u; }

for r in "${roots[@]}"; do check_root_syntax "$r"; done
[ "$(sorted_roots | wc -l)" = "${#roots[@]}" ] || die "--rw names a root more than once"

render_unit() {
  [ -f "$template" ] || die "unit template '$template' is missing"
  local rw
  rw="$(sorted_roots | tr '\n' ' ')"
  rw="${rw% }"
  # The template's header is for its maintainers; the rendered unit says where
  # it came from. Label and roots are restricted to characters with no meaning
  # to sed with '|' as the delimiter (checked above).
  printf '# Generated by idunn scripts/linux/install.sh from helper.service.in. Do not edit.\n\n'
  sed -n '/^\[Unit\]$/,$p' "$template" |
    sed -e "s|@LABEL@|$label|g" -e "s|@READ_WRITE_PATHS@|$rw|g"
}

if [ -n "$render" ]; then
  [ -z "$helper" ] || die "--render-unit takes no --helper"
  out="$(render_unit)"
  if printf '%s\n' "$out" | grep -q '@[A-Z_]*@'; then die "the template has an unrendered placeholder"; fi
  printf '%s\n' "$out"
  exit 0
fi

[ -n "$helper" ] || { usage >&2; die "--helper is required"; }

# --- checks: nothing below changes the system until "install" ------------------

require_root
require_systemd

if [ ! -f "$helper" ] || [ -L "$helper" ]; then die "--helper '$helper' is not a regular file"; fi

[ -d /usr/libexec ] || die "/usr/libexec does not exist"
[ "$(readlink -f /usr/libexec)" = /usr/libexec ] || die "/usr/libexec is reached through a symbolic link"
check_admin_only_tree /usr/libexec

for r in "${roots[@]}"; do
  [ -d "$r" ] || die "--rw '$r' is not an existing directory (systemd refuses to start with a missing ReadWritePaths=)"
  [ "$(readlink -f -- "$r")" = "$r" ] || die "--rw '$r' goes through a symbolic link"
  check_admin_only_tree "$r"
done

if [ -e "$unit" ] || [ -L "$unit" ]; then die "$unit already exists; run uninstall.sh --label $label first"; fi
if [ -e "$target" ] || [ -L "$target" ]; then die "$target already exists; run uninstall.sh --label $label first"; fi
if systemctl cat "$label.service" >/dev/null 2>&1; then
  die "a unit named $label.service is already known to systemd (elsewhere than $unit); refusing to shadow it"
fi

# --- install -------------------------------------------------------------------

umask 022
installed_target="" installed_unit="" tmp_target="" tmp_unit=""
rollback() {
  local rc=$?
  trap - EXIT
  [ -z "$tmp_target" ] || rm -f -- "$tmp_target"
  [ -z "$tmp_unit" ] || rm -f -- "$tmp_unit"
  if [ "$rc" != 0 ]; then
    if [ -n "$installed_unit" ]; then
      warn "installation failed; removing $unit"
      systemctl disable --now "$label.service" >/dev/null 2>&1 || true
      rm -f -- "$unit"
      systemctl daemon-reload || true
      systemctl reset-failed "$label.service" >/dev/null 2>&1 || true
    fi
    if [ -n "$installed_target" ]; then
      warn "installation failed; removing $target"
      rm -f -- "$target"
    fi
  fi
  exit "$rc"
}
trap rollback EXIT

# The copy in /usr/libexec is what gets checked and what systemd runs: once it is
# there, only root can change it, so there is no window between the check and
# the start in which the source file could be swapped.
tmp_target="$(mktemp "/usr/libexec/.$label.XXXXXX")"
cat -- "$helper" >"$tmp_target"
chown root:root "$tmp_target"
chmod 0755 "$tmp_target"

note "$tmp_target check"
if ! check_out="$("$tmp_target" check 2>&1)"; then
  printf '%s\n' "$check_out" >&2
  die "the helper's own check failed; nothing was installed"
fi
printf '%s\n' "$check_out"

# The label and roots the helper was built with must be the ones given here: a
# different label would put the socket where the application does not look, and
# a root missing from ReadWritePaths= would be read-only to the service.
got_label="$(printf '%s\n' "$check_out" | sed -n 's/^label: *//p')"
[ "$got_label" = "$label" ] || die "the helper was built for label '$got_label', not '$label'"
got_roots="$(printf '%s\n' "$check_out" | sed -n 's/^root: *//p' | sed 's/ — .*$//' | sort -u)"
[ -n "$got_roots" ] || die "cannot read the helper's allowed roots from its check output"
if [ "$got_roots" != "$(sorted_roots)" ]; then
  die "--rw ($(sorted_roots | tr '\n' ' ')) does not equal the helper's allowed_roots ($(printf '%s' "$got_roots" | tr '\n' ' '))"
fi

mv -T -- "$tmp_target" "$target"
tmp_target=""
installed_target=1
note "installed $target"

tmp_unit="$(mktemp "/etc/systemd/system/.$label.service.XXXXXX")"
render_unit >"$tmp_unit"
if grep -q '@[A-Z_]*@' "$tmp_unit"; then die "the template has an unrendered placeholder"; fi
chown root:root "$tmp_unit"
chmod 0644 "$tmp_unit"
mv -T -- "$tmp_unit" "$unit"
tmp_unit=""
installed_unit=1
note "installed $unit"

systemctl daemon-reload

note "$target check"
"$target" check >/dev/null || die "$target check failed after installation"

systemctl enable --now "$label.service"

# Active is not enough: the helper may still refuse its configuration and exit.
# It is up when its socket exists and it is still running a moment later.
for _ in $(seq 1 20); do
  [ -S "$socket" ] && break
  sleep 0.5
done
[ -S "$socket" ] || { systemctl status --no-pager "$label.service" >&2 || true; die "$socket did not appear"; }
sleep 1
systemctl is-active --quiet "$label.service" ||
  { systemctl status --no-pager "$label.service" >&2 || true; die "$label.service is not active"; }

user="${SUDO_USER:-<user>}"
cat <<EOF

$label.service is running and listening on $socket.

Nobody but root may ask it for an update yet. To allow an account, as root:

    $target allow --uid "\$(id -u $user)"
    systemctl restart $label.service

The list is kept in $state/callers.json; \`$target deny --uid N\` removes one.
EOF
