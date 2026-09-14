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

# Check a bundled, signed (and, for a release, notarized) application with its
# privileged helper before it ships. Every check that fails fails the script;
# the one informational step is `<helper> check`, reported but not judged.
#
#   bundle   one helper at Contents/Library/HelperTools/<label>, mode 0755, and
#            its plist consistent with it and with the app (as bundle-helper.sh)
#   app      codesign --verify --strict --deep (verification may be deep;
#            signing never is, see sign.sh)
#   helper   codesign --verify --strict; identifier == label; hardened runtime;
#            same Team ID as the app
#   caller   with --requirement: the application's code satisfies the
#            peer_requirement compiled into the helper (helper.json), so the
#            helper will actually admit the app that calls it
#   release  spctl --assess (Gatekeeper, notarization) and stapler validate
#
# --adhoc skips what an ad-hoc CI signature cannot have: hardened runtime and
# Team ID checks, Gatekeeper and the stapled ticket.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"

usage() {
  cat <<'EOF'
usage: verify.sh --app <Acme.app> --label <label> [--requirement '<req>'] [--adhoc]

  --app          the signed bundle
  --label        the helper label the bundle must carry
  --requirement  the peer_requirement from helper.json; the app must satisfy it
  --adhoc        the bundle was signed with sign.sh --adhoc-for-ci: skip the
                 hardened runtime, Team ID, Gatekeeper and stapling checks

Exit 0 only if every check passed. `<helper> check` runs last and is reported
only: on a build machine it normally fails, because the root-owned state dir
and callers.json do not exist there. Runs on macOS only.
EOF
}

app="" label="" requirement="" adhoc=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --app) need_value "$1" "$#" "${2:-}"; once "$1" "$app"; app="$2"; shift 2 ;;
    --label) need_value "$1" "$#" "${2:-}"; once "$1" "$label"; label="$2"; shift 2 ;;
    --requirement) need_value "$1" "$#" "${2:-}"; once "$1" "$requirement"; requirement="$2"; shift 2 ;;
    --adhoc) once "$1" "$adhoc"; adhoc=1; shift ;;
    *) usage >&2; die "unknown argument '$1'" ;;
  esac
done

[ -n "$app" ] || { usage >&2; die "--app is required"; }
[ -n "$label" ] || { usage >&2; die "--label is required"; }

require_darwin
app="${app%/}"
check_label "$label"
check_app "$app"

pass() { printf '  ok    %s\n' "$*"; }

echo "== bundle"
got="$(find_label "$app")"
[ "$got" = "$label" ] || die "the bundle carries helper '$got', want '$label'"
helper="$app/Contents/Library/HelperTools/$label"
plist="$app/Contents/Library/LaunchDaemons/$label.plist"
[ "$(/usr/bin/stat -f %Lp "$helper")" = 755 ] || die "'$helper' is mode $(/usr/bin/stat -f %Lp "$helper"), want 0755"
pass "helper Contents/Library/HelperTools/$label, mode 0755"
bundle_id="$(app_bundle_id "$app")"
main_exe="$(app_executable "$app")"
check_daemon_plist "$plist" "$label" "$bundle_id"
pass "plist lints, has exactly DaemonPlist's keys, names the helper, attributed to $bundle_id"

echo "== application signature"
codesign --verify --strict --deep --verbose=2 "$app" || die "'$app' does not verify"
pass "codesign --verify --strict --deep"
app_team="$(sig_field "$app" TeamIdentifier)"
if [ -z "$adhoc" ]; then
  [ "$(sig_field "$app" Signature)" != adhoc ] || die "'$app' is ad-hoc signed (pass --adhoc only for CI bundles)"
  has_runtime "$app" || die "'$app' is not signed with the hardened runtime"
  case "$app_team" in
    "" | "not set") die "'$app' has no Team ID" ;;
  esac
  pass "hardened runtime, Team ID $app_team"
fi

echo "== helper signature"
codesign --verify --strict --verbose=2 "$helper" || die "'$helper' does not verify"
pass "codesign --verify --strict"
ident="$(sig_field "$helper" Identifier)"
[ "$ident" = "$label" ] || die "helper identifier is '$ident', want '$label' (sign.sh sets it)"
pass "identifier $label"
if [ -z "$adhoc" ]; then
  [ "$(sig_field "$helper" Signature)" != adhoc ] || die "'$helper' is ad-hoc signed"
  has_runtime "$helper" || die "'$helper' is not signed with the hardened runtime"
  helper_team="$(sig_field "$helper" TeamIdentifier)"
  [ "$helper_team" = "$app_team" ] || die "helper Team ID '$helper_team' differs from the app's '$app_team'"
  pass "hardened runtime, Team ID $helper_team"
fi

if [ -n "$requirement" ]; then
  echo "== caller requirement"
  # The helper judges the calling process, whose code is the bundle's main
  # executable; check the bundle and that executable both.
  codesign --verify --strict -R="$requirement" "$app" ||
    die "'$app' does not satisfy the requirement; the helper would refuse this app"
  codesign --verify --strict -R="$requirement" "$main_exe" ||
    die "'$main_exe' does not satisfy the requirement; the helper would refuse this app"
  pass "application satisfies: $requirement"
else
  warn "no --requirement: not checked that the helper's peer_requirement admits this app"
fi

if [ -z "$adhoc" ]; then
  echo "== release"
  spctl --assess --type execute -vv "$app" || die "Gatekeeper refuses '$app' (not notarized, or not Developer ID)"
  pass "spctl --assess --type execute"
  xcrun stapler validate "$app" || die "'$app' has no valid stapled notarization ticket"
  pass "stapled ticket"
fi

echo "== helper self-check (informational)"
"$helper" version || warn "'$label version' failed"
rc=0
"$helper" check --json || rc=$?
if [ "$rc" -eq 0 ]; then
  note "'$label check' exit 0: serve would start with this machine's state dir"
else
  note "'$label check' exit $rc: expected on a build machine without the root-owned state dir" \
    "(/Library/Application Support/$label/ and callers.json, created by 'helper allow'); not judged here"
fi

note "verified $app"
