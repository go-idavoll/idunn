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

# Notarize a signed application bundle and staple the ticket to it.
#
#   ditto -c -k --keepParent   zip the bundle as Apple expects
#   notarytool submit --wait   upload, wait for the verdict
#   notarytool log             on anything but Accepted: print why, fail
#   stapler staple / validate  attach the ticket so a first launch offline passes
#
# Credentials come only from a notarytool keychain profile, created once per
# machine with
#
#   xcrun notarytool store-credentials <profile> \
#     --apple-id <id> --team-id <TEAMID>          # prompts for an app-specific password
#   xcrun notarytool store-credentials <profile> \
#     --key AuthKey_XXXX.p8 --key-id <id> --issuer <uuid>   # App Store Connect API key
#
# and never from the command line or the environment of this script: an Apple
# ID password or an API key in argv is visible to every process on the machine
# and ends up in shell history and CI logs.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"

usage() {
  cat <<'EOF'
usage: notarize.sh --app <Acme.app> --keychain-profile <profile>

  --app               bundle signed by sign.sh with a Developer ID identity
  --keychain-profile  name of a profile stored with `xcrun notarytool store-credentials`

Submits the bundle to Apple's notary service, waits, fails unless the status is
Accepted (printing the notary log), then staples and validates the ticket.
Apple ID, password, API key and team ID are never accepted here; store them in
the keychain profile instead (see scripts/macos/README.md). Runs on macOS only.
EOF
}

app="" profile=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --app) need_value "$1" "$#" "${2:-}"; once "$1" "$app"; app="$2"; shift 2 ;;
    --keychain-profile) need_value "$1" "$#" "${2:-}"; once "$1" "$profile"; profile="$2"; shift 2 ;;
    --apple-id | --password | --team-id | --key | --key-id | --issuer | --apple-id=* | --password=* | --team-id=* | --key=* | --key-id=* | --issuer=*)
      die "credentials are never taken on the command line; store them with 'xcrun notarytool store-credentials' and pass --keychain-profile"
      ;;
    *) usage >&2; die "unknown argument '$1'" ;;
  esac
done

[ -n "$app" ] || { usage >&2; die "--app is required"; }
[ -n "$profile" ] || { usage >&2; die "--keychain-profile is required"; }
case "$profile" in
  -*) die "--keychain-profile '$profile' starts with '-'" ;;
esac

require_darwin
app="${app%/}"
check_app "$app"

# Submitting an unsigned, ad-hoc or broken bundle only wastes a round trip.
codesign --verify --strict --deep "$app" || die "'$app' does not verify; run sign.sh first"
[ "$(sig_field "$app" Signature)" != adhoc ] || die "'$app' is ad-hoc signed; ad-hoc code cannot be notarized"

work="$(mktemp -d "${TMPDIR:-/tmp}/idunn-notarize.XXXXXX")"
trap 'rm -rf "$work"' EXIT
zip="$work/$(basename "$app" .app).zip"

note "zipping $app"
ditto -c -k --keepParent "$app" "$zip"

note "submitting to the notary service (profile '$profile'); this waits for the verdict"
rc=0
xcrun notarytool submit "$zip" --keychain-profile "$profile" --wait --output-format json >"$work/submit.json" || rc=$?
cat "$work/submit.json"
echo

# The JSON, not the exit code, is the verdict: read both, trust neither alone.
status="$(plutil -extract status raw -o - "$work/submit.json" 2>/dev/null || true)"
id="$(plutil -extract id raw -o - "$work/submit.json" 2>/dev/null || true)"

if [ "$rc" -ne 0 ] || [ "$status" != Accepted ]; then
  if [ -n "$id" ]; then
    note "notary log for submission $id:"
    xcrun notarytool log "$id" --keychain-profile "$profile" || warn "could not fetch the notary log"
  fi
  die "notarization not accepted (status '${status:-none}', notarytool exit $rc)"
fi
note "accepted: submission $id"

xcrun stapler staple "$app"
xcrun stapler validate "$app"

note "notarized and stapled $app"
note "next: verify.sh --app '$app' --label <label> --requirement '<peer_requirement from helper.json>'"
