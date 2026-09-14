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

# Sign an application bundle that carries a privileged helper (bundle-helper.sh
# ran first), inside out:
#
#   1. nested code: frameworks, dylibs, plug-ins, XPC services, login items and
#      extra executables under Contents/MacOS and Contents/Helpers, deepest first
#   2. the helper, Contents/Library/HelperTools/<label>, with the identifier
#      <label> and its own entitlements
#   3. the application bundle, which seals everything above
#
# Every piece gets the hardened runtime and a secure timestamp — both are
# preconditions for notarization.
#
# Never `codesign --deep` for SIGNING. --deep signs every nested item with the
# options of the outer one: the application's entitlements would land on the
# root helper, the helper could not get <label> as its identifier (which the
# launchd job and a peer's code requirement rely on), and nested code would be
# signed in whatever order codesign walks it. Apple's guidance is to sign each
# item explicitly from the inside out. Verification with --deep (verify.sh) is
# fine: it only reads.
#
# The identity comes from --identity or IDUNN_SIGN_IDENTITY and is never
# defaulted. The private key stays in the keychain; this script only names it.
# "-" (ad-hoc, no certificate) is accepted only with --adhoc-for-ci, so that CI
# can exercise the flow — an ad-hoc bundle is not shippable: it cannot be
# notarized and Gatekeeper refuses it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"

usage() {
  cat <<'EOF'
usage: sign.sh --app <Acme.app> --identity "<Developer ID Application: Name (TEAMID)>"
               [--entitlements-helper <file>] [--entitlements-app <file>]
       sign.sh --app <Acme.app> --identity - --adhoc-for-ci

  --app                  bundle prepared by bundle-helper.sh
  --identity             signing identity: "Developer ID Application: ..." or its
                         40-hex SHA-1; default: $IDUNN_SIGN_IDENTITY; never empty
  --entitlements-helper  entitlements for the helper (optional; most helpers need
                         none). Entitlements that weaken a root process are refused.
  --entitlements-app     entitlements for the application (optional)
  --adhoc-for-ci         allow --identity - (ad-hoc). CI only: not notarizable,
                         not accepted by Gatekeeper, no secure timestamp.

Signs nested code, then the helper (identifier = its label), then the bundle.
Runs on macOS only.
EOF
}

app="" identity="" ent_helper="" ent_app="" adhoc=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --app) need_value "$1" "$#" "${2:-}"; once "$1" "$app"; app="$2"; shift 2 ;;
    --identity) need_value "$1" "$#" "${2:-}"; once "$1" "$identity"; identity="$2"; shift 2 ;;
    --entitlements-helper) need_value "$1" "$#" "${2:-}"; once "$1" "$ent_helper"; ent_helper="$2"; shift 2 ;;
    --entitlements-app) need_value "$1" "$#" "${2:-}"; once "$1" "$ent_app"; ent_app="$2"; shift 2 ;;
    --adhoc-for-ci) once "$1" "$adhoc"; adhoc=1; shift ;;
    *) usage >&2; die "unknown argument '$1'" ;;
  esac
done

[ -n "$app" ] || { usage >&2; die "--app is required"; }
if [ -z "$identity" ]; then
  identity="${IDUNN_SIGN_IDENTITY:-}"
  [ -n "$identity" ] || { usage >&2; die "no signing identity: pass --identity or set IDUNN_SIGN_IDENTITY"; }
fi

if [ "$identity" = - ]; then
  [ -n "$adhoc" ] || die "--identity - (ad-hoc) is for CI only and needs --adhoc-for-ci"
else
  [ -z "$adhoc" ] || die "--adhoc-for-ci is only valid with --identity -"
  case "$identity" in
    "Developer ID Application: "?*) ;;
    *)
      [[ "$identity" =~ ^[0-9A-Fa-f]{40}$ ]] ||
        die "identity '$identity' is neither 'Developer ID Application: ...' nor a 40-hex SHA-1; only Developer ID can be notarized"
      ;;
  esac
fi

require_darwin
app="${app%/}"
check_app "$app"

# check_entitlements <file> <helper|app>
check_entitlements() {
  local file="$1" role="$2" key val
  if [ ! -f "$file" ] || [ -L "$file" ]; then die "entitlements '$file' is not a regular file"; fi
  plutil -lint "$file" >/dev/null || die "entitlements '$file' does not lint"
  # get-task-allow lets any process of the same user attach a debugger;
  # notarization rejects it anyway.
  key=com.apple.security.get-task-allow
  val="$(plist_get "$file" "$key" || true)"
  [ "$val" != true ] || die "$role entitlements '$file' set $key"
  # For a process that runs as root, each of these re-opens a door the hardened
  # runtime closes: code injection through DYLD_* or unsigned libraries,
  # writable-executable memory, attaching to other processes.
  for key in com.apple.security.cs.allow-dyld-environment-variables \
    com.apple.security.cs.disable-library-validation \
    com.apple.security.cs.allow-unsigned-executable-memory \
    com.apple.security.cs.allow-jit \
    com.apple.security.cs.disable-executable-page-protection \
    com.apple.security.cs.debugger; do
    val="$(plist_get "$file" "$key" || true)"
    if [ "$val" = true ]; then
      [ "$role" = app ] || die "helper entitlements '$file' set $key; the helper runs as root and may not"
      warn "app entitlements set $key; it weakens the hardened runtime of the process the helper trusts"
    fi
  done
}

[ -z "$ent_helper" ] || check_entitlements "$ent_helper" helper
[ -z "$ent_app" ] || check_entitlements "$ent_app" app

if [ -z "$adhoc" ]; then
  # Fail before touching the bundle if the keychain has no such valid identity.
  security find-identity -v -p codesigning | grep -F -i -- "$identity" >/dev/null ||
    die "no valid code-signing identity '$identity' in the keychain search list (security find-identity -v -p codesigning)"
fi

# Sign only a bundle whose helper and plist are consistent: whatever is sealed
# here is what launchd will be asked to run as root.
label="$(find_label "$app")"
bundle_id="$(app_bundle_id "$app")"
main_exe="$(app_executable "$app")"
check_daemon_plist "$app/Contents/Library/LaunchDaemons/$label.plist" "$label" "$bundle_id"

# sign_one <path> <identifier or ""> <entitlements or "">
sign_one() {
  local path="$1" ident="$2" ent="$3"
  set -- --force --sign "$identity" --options runtime
  if [ -n "$adhoc" ]; then set -- "$@" --timestamp=none; else set -- "$@" --timestamp; fi
  if [ -n "$ident" ]; then set -- "$@" --identifier "$ident"; fi
  if [ -n "$ent" ]; then set -- "$@" --entitlements "$ent"; fi
  note "codesign ${path#"$app"/}${ident:+ (identifier $ident)}${ent:+ (entitlements $ent)}"
  codesign "$@" "$path"
}

is_macho() { case "$(file -b "$1")" in *Mach-O*) return 0 ;; *) return 1 ;; esac; }

# 1. Nested code, deepest first (find -depth lists contents before their
# directory). Symlinks are not signed: they point at something that is.
for dir in Frameworks PlugIns XPCServices Library/LoginItems Library/SystemExtensions; do
  [ -d "$app/Contents/$dir" ] || continue
  no_symlinks "$app" "Contents/$dir"
  while IFS= read -r -d '' item; do
    sign_one "$item" "" ""
  done < <(find "$app/Contents/$dir" -depth ! -type l \( -name '*.dylib' -o -name '*.so' -o -name '*.framework' \
    -o -name '*.bundle' -o -name '*.xpc' -o -name '*.appex' -o -name '*.app' -o -name '*.systemextension' \) -print0)
done
for dir in MacOS Helpers; do
  [ -d "$app/Contents/$dir" ] || continue
  no_symlinks "$app" "Contents/$dir"
  while IFS= read -r -d '' item; do
    [ "$item" != "$main_exe" ] || continue
    if is_macho "$item"; then sign_one "$item" "" ""; fi
  done < <(find "$app/Contents/$dir" -type f -print0)
done

# 2. The helper. Its identifier is the label: that is what verify.sh checks and
# what a code requirement naming the helper would match.
sign_one "$app/Contents/Library/HelperTools/$label" "$label" "$ent_helper"

# 3. The bundle, sealing the helper, the plist and everything else.
sign_one "$app" "" "$ent_app"

codesign --verify --strict --deep --verbose=2 "$app" || die "the freshly signed bundle does not verify"
if [ -n "$adhoc" ]; then
  warn "ad-hoc signed for CI: not notarizable and not shippable"
  note "next: verify.sh --app '$app' --label '$label' --adhoc"
else
  note "signed $app as '$identity'"
  note "next: notarize.sh --app '$app' --keychain-profile <profile>"
fi
