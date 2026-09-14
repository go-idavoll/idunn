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

# Shared checks for the scripts in scripts/macos/. Sourced, never run.
#
# Written for the bash macOS ships (3.2): no associative arrays, no mapfile, and
# no expansion of a possibly empty array under `set -u`.
#
# The rules here mirror the Go ones on purpose and are a second line, not the
# only one: the label rule is docs/helper.md §2, the plist shape is
# elevate.DaemonPlist (core/elevate/launchd.go). A bundle that passes these
# checks still has to pass the helper's own validation and launchd's.

export LC_ALL=C

plistbuddy=/usr/libexec/PlistBuddy

die() { printf '%s: FAIL: %s\n' "${0##*/}" "$*" >&2; exit 1; }
note() { printf '%s: %s\n' "${0##*/}" "$*"; }
warn() { printf '%s: WARNING: %s\n' "${0##*/}" "$*" >&2; }

# need_value <flag> <argc> <value>: a flag that takes a value must have one,
# and the value must not look like another option (a forgotten value would
# otherwise swallow the next flag). A lone "-" is a value (ad-hoc identity).
need_value() {
  [ "$2" -ge 2 ] || die "$1 needs a value"
  case "$3" in
    --*) die "$1 needs a value, got the option '$3'" ;;
  esac
}

# once <flag> <current value>: every option may be given at most once, so a
# second value can never silently replace the one a reviewer saw first.
once() {
  [ -z "$2" ] || die "$1 given more than once"
}

require_darwin() {
  [ "$(uname -s)" = Darwin ] || die "this script runs on macOS only (it needs codesign, plutil, PlistBuddy)"
  [ -x "$plistbuddy" ] || die "$plistbuddy not found"
}

# check_reverse_dns <what> <value> <max bytes>: at least two dot-separated
# components of ASCII letters, digits and hyphens, none empty and none starting
# or ending with a hyphen (elevate.checkReverseDNS).
check_reverse_dns() {
  local what="$1" s="$2" max="$3"
  local comp='[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'
  local re="^${comp}(\\.${comp})+\$"
  [ -n "$s" ] || die "$what is empty"
  [ "${#s}" -le "$max" ] || die "$what '$s' is longer than $max bytes"
  [[ "$s" =~ $re ]] || die "$what '$s' is not reverse-DNS ([A-Za-z0-9-] components, at least two, none empty or hyphen-edged)"
}

# check_label <label>: docs/helper.md §2 and elevate.CheckHelperLabel —
# reverse-DNS, [A-Za-z0-9.-], at most 62 bytes. 62 because the macOS socket
# path "/Library/Application Support/<label>/helper.sock" must fit the
# kernel's 103-byte sun_path. The label becomes a file name in the bundle, the
# launchd job, the socket directory and the code-signing identifier, so nothing
# else is accepted.
check_label() { check_reverse_dns "label" "$1" 62; }

# check_app <path>: an existing .app directory, not a symlink, with an
# Info.plist. Prints nothing; dies on anything else.
check_app() {
  local app="$1"
  [ -n "$app" ] || die "--app is required"
  case "$app" in
    *.app) ;;
    *) die "--app '$app' does not name a .app bundle" ;;
  esac
  [ ! -L "$app" ] || die "--app '$app' is a symlink; pass the bundle itself"
  [ -d "$app" ] || die "--app '$app' is not a directory"
  [ -f "$app/Contents/Info.plist" ] || die "'$app' has no Contents/Info.plist"
}

# no_symlinks <app> <relative dir>...: none of the bundle directories the
# helper and its plist go through may be a symlink, or a copy or a check could
# land somewhere the signature does not cover.
no_symlinks() {
  local app="$1" rel
  shift
  for rel in "$@"; do
    [ ! -L "$app/$rel" ] || die "'$app/$rel' is a symlink"
  done
}

# plist_get <file> <PlistBuddy key path>: print a value, or fail.
plist_get() { "$plistbuddy" -c "Print :$2" "$1" 2>/dev/null; }

# app_bundle_id <app>: the validated CFBundleIdentifier.
app_bundle_id() {
  local id
  id="$(plist_get "$1/Contents/Info.plist" CFBundleIdentifier)" || die "'$1' has no CFBundleIdentifier"
  check_reverse_dns "CFBundleIdentifier" "$id" 200
  printf '%s\n' "$id"
}

# app_executable <app>: the path of the bundle's main executable.
app_executable() {
  local exe
  exe="$(plist_get "$1/Contents/Info.plist" CFBundleExecutable)" || die "'$1' has no CFBundleExecutable"
  case "$exe" in
    "" | */* | .*) die "CFBundleExecutable '$exe' is not a plain file name" ;;
  esac
  [ -f "$1/Contents/MacOS/$exe" ] || die "main executable Contents/MacOS/$exe is missing"
  printf '%s\n' "$1/Contents/MacOS/$exe"
}

# The only top-level keys elevate.DaemonPlist writes. Anything else in a
# LaunchDaemon plist — EnvironmentVariables, Program, UserName, Sockets, ... —
# was not produced by it and is refused.
daemon_plist_keys="AssociatedBundleIdentifiers BundleProgram KeepAlive Label ProgramArguments RunAtLoad"

# check_daemon_plist <plist> <label> <bundle id>: the plist lints, has exactly
# DaemonPlist's keys, names this label, runs the helper at
# Contents/Library/HelperTools/<label> with that name as argv[0], and is
# attributed to the application it ships in.
check_daemon_plist() {
  local plist="$1" label="$2" bundle_id="$3"
  local want_program="Contents/Library/HelperTools/$label"
  local got keys i id found

  plutil -lint "$plist" >/dev/null || die "plist '$plist' does not lint"

  # Canonical XML: top-level keys are the ones indented by exactly one tab.
  keys="$(plutil -convert xml1 -o - "$plist" | awk -F '</?key>' '/^\t<key>/ { print $2 }' | sort | tr '\n' ' ')"
  keys="${keys% }"
  [ "$keys" = "$daemon_plist_keys" ] ||
    die "plist '$plist' has keys [$keys], want exactly [$daemon_plist_keys] (elevate.DaemonPlist)"

  got="$(plist_get "$plist" Label)" || die "plist has no Label"
  [ "$got" = "$label" ] || die "plist Label is '$got', want '$label'"

  got="$(plist_get "$plist" BundleProgram)" || die "plist has no BundleProgram"
  [ "$got" = "$want_program" ] || die "plist BundleProgram is '$got', want '$want_program'"

  got="$(plist_get "$plist" ProgramArguments:0)" || die "plist has no ProgramArguments"
  [ "$got" = "$label" ] || die "plist ProgramArguments[0] is '$got', want '$label'"

  found=""
  i=0
  while id="$(plist_get "$plist" "AssociatedBundleIdentifiers:$i")"; do
    if [ "$id" = "$bundle_id" ]; then found=1; fi
    i=$((i + 1))
  done
  [ "$i" -gt 0 ] || die "plist has no AssociatedBundleIdentifiers"
  [ -n "$found" ] || die "plist AssociatedBundleIdentifiers does not contain the app's CFBundleIdentifier '$bundle_id'"
}

# is_signed <path>: the bundle or file carries a code signature.
is_signed() {
  [ -d "$1/Contents/_CodeSignature" ] || codesign --display "$1" >/dev/null 2>&1
}

# find_label <app>: the label of the one helper this bundle carries, derived
# from its single LaunchDaemon plist and cross-checked against HelperTools.
find_label() {
  local app="$1" n plist label
  no_symlinks "$app" Contents Contents/Library Contents/Library/LaunchDaemons Contents/Library/HelperTools
  [ -d "$app/Contents/Library/LaunchDaemons" ] || die "'$app' has no Contents/Library/LaunchDaemons (run bundle-helper.sh first)"
  [ -d "$app/Contents/Library/HelperTools" ] || die "'$app' has no Contents/Library/HelperTools (run bundle-helper.sh first)"
  n="$(find "$app/Contents/Library/LaunchDaemons" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
  [ "$n" = 1 ] || die "'$app/Contents/Library/LaunchDaemons' must hold exactly one plist, holds $n"
  plist="$(find "$app/Contents/Library/LaunchDaemons" -mindepth 1 -maxdepth 1)"
  label="${plist##*/}"
  case "$label" in
    *.plist) label="${label%.plist}" ;;
    *) die "'$plist' is not a .plist" ;;
  esac
  check_label "$label"
  n="$(find "$app/Contents/Library/HelperTools" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
  [ "$n" = 1 ] || die "'$app/Contents/Library/HelperTools' must hold exactly one helper, holds $n"
  if [ ! -f "$app/Contents/Library/HelperTools/$label" ] || [ -L "$app/Contents/Library/HelperTools/$label" ]; then
    die "HelperTools does not hold a regular file named '$label'"
  fi
  printf '%s\n' "$label"
}

# sig_field <path> <Field>: one field of `codesign --display --verbose=2`.
# Captured first, so no reader closing the pipe early can fail the pipeline.
sig_field() {
  local out
  out="$(codesign --display --verbose=2 "$1" 2>&1)" || return 1
  printf '%s\n' "$out" | sed -n "s/^$2=//p" | sed -n 1p
}

# has_runtime <path>: the CodeDirectory flags include the hardened runtime,
# e.g. "CodeDirectory v=20500 size=... flags=0x10000(runtime) hashes=...".
has_runtime() {
  local out
  out="$(codesign --display --verbose=2 "$1" 2>&1)" || return 1
  printf '%s\n' "$out" | grep '^CodeDirectory ' | grep 'flags=0x[0-9a-fA-F]*([^)]*runtime' >/dev/null
}
