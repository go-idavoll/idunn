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

# Remove an idunn helper installed by install.sh: stop and disable
# <label>.service, delete /etc/systemd/system/<label>.service and
# /usr/libexec/<label>. /run/<label> goes with the service.
#
# The state directory /etc/<label> (callers.json: who may ask) is kept, so a
# reinstall keeps its callers, unless --remove-state is given. The install roots
# are the product's and are never touched.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"

usage() {
  cat <<'EOF'
usage: uninstall.sh --label <label> [--remove-state]

  --label         the helper label (the unit is <label>.service)
  --remove-state  also delete /etc/<label>
EOF
}

label="" remove_state=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --label) need_value "$1" "$#" "${2:-}"; once "$1" "$label"; label="$2"; shift 2 ;;
    --remove-state) once "$1" "$remove_state"; remove_state=1; shift ;;
    *) usage >&2; die "unknown argument '$1'" ;;
  esac
done

[ -n "$label" ] || { usage >&2; die "--label is required"; }
check_label "$label"
require_root
require_systemd

unit="/etc/systemd/system/$label.service"
target="/usr/libexec/$label"
state="/etc/$label"

if [ -e "$unit" ] || [ -L "$unit" ]; then
  systemctl disable --now "$label.service"
  rm -f -- "$unit"
  systemctl daemon-reload
  systemctl reset-failed "$label.service" >/dev/null 2>&1 || true
  note "removed $unit"
else
  warn "$unit does not exist"
fi
if systemctl is-active --quiet "$label.service"; then
  die "$label.service is still active (defined somewhere other than $unit?)"
fi

if [ -L "$target" ]; then
  # Only the link, never what it points to.
  rm -f -- "$target"
  note "removed the symbolic link $target"
elif [ -f "$target" ]; then
  rm -f -- "$target"
  note "removed $target"
elif [ -e "$target" ]; then
  die "$target is not a regular file; not removing it"
fi

if [ -n "$remove_state" ]; then
  if [ -L "$state" ]; then
    die "$state is a symbolic link; not removing it"
  elif [ -d "$state" ]; then
    # rm -r does not follow symbolic links inside the directory.
    rm -rf -- "$state"
    note "removed $state"
  elif [ -e "$state" ]; then
    die "$state is not a directory; not removing it"
  fi
elif [ -e "$state" ]; then
  note "kept $state (pass --remove-state to delete it)"
fi
