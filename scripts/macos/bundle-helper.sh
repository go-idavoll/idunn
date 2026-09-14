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

# Put a built privileged helper and its LaunchDaemon plist into an application
# bundle, where SMAppService expects them (docs/helper.md §3):
#
#   <App>.app/Contents/Library/HelperTools/<label>            the helper, 0755
#   <App>.app/Contents/Library/LaunchDaemons/<label>.plist    from `<helper> plist`
#
# The plist is never written by hand: it is what the helper build itself prints
# (elevate.DaemonPlist), and it is checked here before anything in the bundle
# changes — lint, exactly DaemonPlist's keys, Label and BundleProgram naming
# this helper, and AssociatedBundleIdentifiers naming this application.
#
# Everything is validated and the plist generated before the bundle is touched;
# a failure leaves the bundle as it was. Signing comes afterwards (sign.sh):
# adding files to a signed bundle breaks its signature, so a signed bundle is
# refused unless --force says a re-sign follows.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"

usage() {
  cat <<'EOF'
usage: bundle-helper.sh --app <Acme.app> --helper <built helper> --label <label> [--force]

  --app     the application bundle that will register the helper
  --helper  the helper binary built from cmd/helper for this label
  --label   the helper's label (docs/helper.md §2: reverse-DNS, [A-Za-z0-9.-],
            at most 62 bytes); must equal the label compiled into the helper
  --force   allow changing a bundle that is already signed; its signature is
            broken afterwards and sign.sh must run again

Copies the helper to Contents/Library/HelperTools/<label> (mode 0755) and writes
Contents/Library/LaunchDaemons/<label>.plist from `<helper> plist`, after
checking the plist against the bundle. Runs on macOS only.
EOF
}

app="" helper="" label="" force=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --app) need_value "$1" "$#" "${2:-}"; once "$1" "$app"; app="$2"; shift 2 ;;
    --helper) need_value "$1" "$#" "${2:-}"; once "$1" "$helper"; helper="$2"; shift 2 ;;
    --label) need_value "$1" "$#" "${2:-}"; once "$1" "$label"; label="$2"; shift 2 ;;
    --force) once "$1" "$force"; force=1; shift ;;
    *) usage >&2; die "unknown argument '$1'" ;;
  esac
done

[ -n "$app" ] || { usage >&2; die "--app is required"; }
[ -n "$helper" ] || { usage >&2; die "--helper is required"; }
[ -n "$label" ] || { usage >&2; die "--label is required"; }

require_darwin
app="${app%/}"
# A bare name would be looked up in PATH when it is run for `plist`.
case "$helper" in
  */*) ;;
  *) helper="./$helper" ;;
esac
check_label "$label"
check_app "$app"
if [ ! -f "$helper" ] || [ -L "$helper" ]; then die "--helper '$helper' is not a regular file"; fi
[ -x "$helper" ] || die "--helper '$helper' is not executable"
case "$(file -b "$helper")" in
  *Mach-O*) ;;
  *) die "--helper '$helper' is not a Mach-O executable" ;;
esac
no_symlinks "$app" Contents Contents/Library Contents/Library/HelperTools Contents/Library/LaunchDaemons \
  "Contents/Library/HelperTools/$label" "Contents/Library/LaunchDaemons/$label.plist"

bundle_id="$(app_bundle_id "$app")"

# One helper per bundle: anything else already in either directory (another
# label, a leftover) is refused now, before the bundle changes.
for entry in "$app/Contents/Library/HelperTools"/* "$app/Contents/Library/HelperTools"/.[!.]* \
  "$app/Contents/Library/LaunchDaemons"/* "$app/Contents/Library/LaunchDaemons"/.[!.]*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "$entry" in
    "$app/Contents/Library/HelperTools/$label" | "$app/Contents/Library/LaunchDaemons/$label.plist") ;;
    *) die "'$entry' is not this helper's; the bundle may carry one helper, '$label'" ;;
  esac
done

if is_signed "$app"; then
  [ -n "$force" ] || die "'$app' is signed; changing it breaks the signature. Pass --force and run sign.sh afterwards"
  warn "'$app' is signed; its signature will be invalid until sign.sh runs again"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/idunn-bundle.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# The helper describes its own job. A helper built for another label, or for
# another application, is caught here rather than by launchd at registration.
"$helper" plist >"$work/$label.plist" || die "'$helper plist' failed"
check_daemon_plist "$work/$label.plist" "$label" "$bundle_id"
note "plist checked: Label=$label BundleProgram=Contents/Library/HelperTools/$label, attributed to $bundle_id"

tools="$app/Contents/Library/HelperTools"
daemons="$app/Contents/Library/LaunchDaemons"
mkdir -p "$tools" "$daemons"

# Copy next to the destination, then rename: a reader never sees half a file.
cp "$helper" "$tools/.$label.tmp"
chmod 0755 "$tools/.$label.tmp"
mv -f "$tools/.$label.tmp" "$tools/$label"
cp "$work/$label.plist" "$daemons/.$label.plist.tmp"
chmod 0644 "$daemons/.$label.plist.tmp"
mv -f "$daemons/.$label.plist.tmp" "$daemons/$label.plist"

# Read back what is now in the bundle, not what was meant to be.
cmp -s "$helper" "$tools/$label" || die "the copied helper differs from '$helper'"
[ "$(/usr/bin/stat -f %Lp "$tools/$label")" = 755 ] || die "'$tools/$label' is not mode 0755"
check_daemon_plist "$daemons/$label.plist" "$label" "$bundle_id"
[ "$(find_label "$app")" = "$label" ] || die "the bundle carries another helper besides '$label'"

note "bundled $label into $app"
note "next: sign.sh --app '$app' --identity '<Developer ID Application: ...>'"
