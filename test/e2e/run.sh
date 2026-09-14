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

# End-to-end update test against real packages on GitHub.
#
# Every scenario publishes e2eapp with cmd/packer as the assets of its own
# GitHub release, installs it from there, publishes further releases into the
# same repository, and lets the installed application update itself through
# the launcher, headless. Every download goes through github.com.
#
# Scenarios:
#   minor      1.0.0 -> 1.1.0 -> 1.2.0   minor update, then a sequential one
#   major      1.0.0 -> 2.0.0 -> 2.1.0   major update, then a sequential one
#   floor-gap  1.0.0 -/-> 1.2.0          1.2.0 requires min_from_version 1.1.0,
#                                        which is never published: refused
#   elevated   1.0.0 -> 1.1.0            Windows only, interactive: installs into
#                                        %ProgramFiles% and updates there through
#                                        UAC prompts someone has to accept (four:
#                                        a hostile helper start, install, update,
#                                        removal). Also refuses a user-owned root,
#                                        before the prompt and in the elevated
#                                        helper. Not in the default set and not in
#                                        CI — a runner is already elevated and has
#                                        no one to click.
#
# Every step is a case with an expectation, a verdict and an attestation — the
# observed exit code, installed version (pointer and recorded state agreeing),
# version the launcher actually starts, version directories, last journal
# record and staging leftovers. Cases are written per scenario as JSON and
# Markdown; a failed case ends its scenario, the other scenarios still run.
#
# Environment:
#   E2E_MODE        github (default) or local — local serves the assets from
#                   127.0.0.1 instead of GitHub, to check this script offline.
#   E2E_SCENARIOS   scenarios to run (default "minor major floor-gap").
#   E2E_REPO        release repository (default go-idavoll/idunn-e2e).
#   E2E_TAG         release tag prefix; each scenario appends -<scenario>
#                   (default e2e-local-<unix time>).
#   E2E_REPORT_DIR  where <scenario>.json reports go (default <work>/reports).
#   E2E_KEEP        if set, releases are left in place after a successful run.
#   E2E_WORK        parent of the scratch directory (default RUNNER_TEMP or TMPDIR).
#   E2E_PORT        local mode listen port (default 18765).
#   GH_TOKEN        github mode: token with contents:write on E2E_REPO.
#
# Exit status is 0 only if every case of every scenario passed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/../.."

mode="${E2E_MODE:-github}"
scenarios="${E2E_SCENARIOS:-minor major floor-gap}"
repo="${E2E_REPO:-go-idavoll/idunn-e2e}"
tag="${E2E_TAG:-e2e-local-$(date +%s)}"
port="${E2E_PORT:-18765}"

# Go on Windows does not understand Git Bash paths such as /tmp/x.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
step() { printf '\n==> %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
oneline() { tr '\t\r\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//'; }

if [ -n "${E2E_WORK:-}" ]; then mkdir -p "$E2E_WORK"; fi
work="$(native "$(mktemp -d "${E2E_WORK:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}/idunn-e2e.XXXXXX")")"
reports="$(native "${E2E_REPORT_DIR:-$work/reports}")"
exe="$(go env GOEXE)"
goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
bin="$work/bin"
mkdir -p "$bin" "$work/assets" "$reports"

case "$mode" in
  github|local) ;;
  *) die "E2E_MODE must be github or local, not $mode" ;;
esac

server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$work/keys" "$work/keys.env"
}
trap cleanup EXIT

step "work dir $work, $mode mode, $goos/$goarch, scenarios: $scenarios"

step "build tools"
go build -o "$bin/packer$exe" ./cmd/packer
go build -o "$bin/e2etool$exe" ./test/e2e/cmd/e2etool
go build -ldflags "-X main.appBinary=bin/e2eapp$exe" -o "$bin/launcher$exe" ./cmd/launcher

step "generate throwaway keys and root"
"$bin/e2etool$exe" init-repo --repo "$work/root" --keys "$work/keys" >"$work/keys.env"
while IFS= read -r kv; do
  export "${kv?}"
done <"$work/keys.env"
cp "$work/root/metadata/1.root.json" test/e2e/cmd/e2eapp/anchor/root.json

if [ "$mode" = local ]; then
  "$bin/e2etool$exe" serve --dir "$work/assets" --addr "127.0.0.1:$port" &
  server_pid=$!
fi

# --- scenario state -----------------------------------------------------------

scen="" stag="" url="" stuf="" sassets="" sroot="" slauncher="" results=""

begin() {
  scen="$1"
  stag="$tag-$scen"
  if [ "$mode" = github ]; then
    url="https://github.com/$repo/releases/download/$stag"
  else
    url="http://127.0.0.1:$port/download/$scen"
  fi
  stuf="$work/$scen/repo"
  sassets="$work/assets/$scen"
  sroot="$work/$scen/install"
  slauncher="$sroot/launcher$exe"
  results="$work/$scen/results.tsv"
  mkdir -p "$stuf/metadata" "$sassets"
  cp "$work/root/metadata/1.root.json" "$stuf/metadata/1.root.json"
  : >"$results"
  step "scenario $scen ($url)"
}

# record <case> <expected> <PASS|FAIL> <attestation>
record() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(printf '%s' "$4" | oneline)" >>"$results"
  printf '  [%s] %s — %s\n' "$3" "$1" "$4"
}

# publish <version> [min_from_version]: build e2eapp at that version, publish it
# into the scenario's repository, and put the repository where the client
# looks. A failure is recorded as a case of its own.
publish() {
  local version="$1" min_from="${2:-}" dir="$work/$scen/build/$1" log="$work/$scen/publish-$1.log"
  mkdir -p "$dir/bin"
  {
    go build -ldflags "-X main.version=$version -X main.buildTime=$(now) -X main.releaseURL=$url" \
      -o "$dir/bin/e2eapp$exe" ./test/e2e/cmd/e2eapp &&
      {
        printf 'name: e2eapp\nversion: %s\nchannel: stable\n' "$version"
        if [ -n "$min_from" ]; then printf 'requirements:\n  min_from_version: %s\n' "$min_from"; fi
        printf 'targets:\n  - os: %s\n    arch: %s\n    files:\n' "$goos" "$goarch"
        printf '      - { src: bin/e2eapp%s, dst: bin/e2eapp%s, kind: exe, mode: "0755" }\n' "$exe" "$exe"
      } >"$dir/pack.yaml" &&
      "$bin/packer$exe" publish --config "$dir/pack.yaml" --repo "$stuf" --now "$(now)" &&
      rm -rf "$sassets" && mkdir -p "$sassets" &&
      "$bin/e2etool$exe" flatten "$stuf" "$sassets" &&
      if [ "$mode" = github ]; then
        if gh release view "$stag" --repo "$repo" >/dev/null 2>&1; then
          gh release upload "$stag" --repo "$repo" --clobber "$sassets"/*
        else
          gh release create "$stag" --repo "$repo" --prerelease --title "$stag" \
            --notes "idunn e2e update test, scenario $scen (${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}). Throwaway; deleted after a successful run." \
            "$sassets"/*
        fi
      fi &&
      # The timestamp is what a client reads first and the file a --clobber
      # upload replaces; once it is served, the rest of this publish is too.
      "$bin/e2etool$exe" wait-asset --url "$url/metadata__timestamp.json" --file "$sassets/metadata__timestamp.json"
  } >"$log" 2>&1
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    record "publish $version" "published and served" FAIL "rc=$rc $(tail -n 5 "$log")"
    return 1
  fi
  printf '  published %s%s\n' "$version" "${min_from:+ (min_from_version $min_from)}"
}

launch() { "$slauncher" --quiet --root "$sroot" -- "$@"; }

# observe: read back the install state into st_* and the attestation line.
observe() {
  local line key val
  st_installed="" st_versions="" st_journal="" st_staging="" st_running=""
  while IFS= read -r line; do
    line="${line%$'\r'}"
    key="${line%%=*}" val="${line#*=}"
    case "$key" in
      installed) st_installed="$val" ;;
      versions) st_versions="$val" ;;
      journal) st_journal="$val" ;;
      staging) st_staging="$val" ;;
    esac
  done < <("$bin/e2eapp-status$exe" status --root "$sroot" 2>&1 || true)
  st_running="$(launch version 2>&1 | tr -d '\r' | oneline)" || true
  attestation="installed=$st_installed running=$st_running versions=$st_versions journal=$st_journal staging=$st_staging"
}

# want <name> <got> <expected>: collect a mismatch into $why.
want() { if [ "$2" != "$3" ]; then why="${why}$1='$2' want '$3'; "; fi; }
contains() { case "$2" in *"$3"*) ;; *) why="${why}$1 lacks '$3'; " ;; esac; }

# verdict <case> <expected> <extra attestation>: record PASS if $why is empty.
verdict() {
  if [ -z "$why" ]; then
    record "$1" "$2" PASS "$3 $attestation"
  else
    record "$1" "$2" FAIL "$why| $3 $attestation"
    return 1
  fi
}

# settled <version> <versions>: the state a committed step must leave behind.
settled() {
  want installed "$st_installed" "$1"
  want running "$st_running" "$1"
  want versions "$st_versions" "$2"
  contains journal "$st_journal" "COMMITTED:"
  contains journal "$st_journal" "->$1"
  want staging "$st_staging" 0
}

install_case() {
  local v="$1" out rc
  out="$("$work/$scen/build/$v/bin/e2eapp$exe" install --root "$sroot" 2>&1)"
  rc=$?
  if [ "$slauncher" = "$sroot/launcher$exe" ]; then cp "$bin/launcher$exe" "$slauncher" 2>/dev/null || true; fi
  observe
  why=""
  want rc "$rc" 0
  contains output "$out" "installed $v"
  settled "$v" "$v"
  verdict "install $v" "installs $v from the release" "rc=$rc"
}

# update_case <case> <from> <to> <versions after>
update_case() {
  local out rc
  out="$(launch update --root "$sroot" 2>&1)"
  rc=$?
  out="${out//$'\r'/}"
  observe
  why=""
  want rc "$rc" 0
  contains output "$out" "updated $2 -> $3"
  settled "$3" "$4"
  verdict "$1" "$2 -> $3 applied, $3 runs, previous kept for rollback" "rc=$rc"
}

# uptodate_case <version>
uptodate_case() {
  local out rc
  out="$(launch update --root "$sroot" 2>&1)"
  rc=$?
  out="${out//$'\r'/}"
  observe
  why=""
  want rc "$rc" 0
  contains output "$out" "up to date at $1"
  want installed "$st_installed" "$1"
  want running "$st_running" "$1"
  verdict "no update beyond $1" "channel head is installed, nothing changes" "rc=$rc"
}

# refuse_case <case> <from> <to> <min_from>
refuse_case() {
  local out rc
  out="$(launch update --root "$sroot" 2>&1)"
  rc=$?
  out="${out//$'\r'/}"
  observe
  why=""
  want rc "$rc" 3
  contains output "$out" "migration floor"
  contains output "$out" "$3 migrates only from $4 or newer, this install is $2"
  settled "$2" "$2"
  verdict "$1" "refused by policy (exit 3), $2 untouched and still runs" \
    "rc=$rc error=$(printf '%s' "$out" | grep 'e2eapp:' | oneline)"
}

# user_owned_readonly <dir>: create dir so that this user may only read it and
# administrators may write it. It is the shape of a root that passes the probe
# (NeedsElevation says yes) and must still be refused: the user owns it, so the
# user can take its ACL back and redirect a privileged write through it at any
# time (IDN-22). The user keeps DELETE, so the tree can be removed afterwards.
user_owned_readonly() {
  mkdir -p "$1"
  MSYS_NO_PATHCONV=1 icacls "$(cygpath -w "$1")" /inheritance:r \
    /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "$USERDOMAIN\\$USERNAME:(OI)(CI)(RX,D)" >/dev/null
}

# as_admin <exe> <args...>: run a program elevated through a UAC prompt, wait,
# and return its exit code. Arguments must not contain spaces or quotes.
as_admin() {
  local exe="$1" list="" a
  shift
  for a in "$@"; do list="$list,'$a'"; done
  powershell.exe -NoProfile -NonInteractive -Command \
    "\$p = Start-Process -FilePath '$(cygpath -w "$exe")' -ArgumentList @(${list#,}) -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit \$p.ExitCode"
}

# unwritable_case <dir>: attest that this process cannot create in dir, so an
# elevated case that passes cannot have passed without elevating.
unwritable_case() {
  why=""
  if (: >"$1/.e2e-probe") 2>/dev/null; then
    rm -f "$1/.e2e-probe"
    why="created a file in $1 without privileges; "
  fi
  attestation="dir=$1"
  verdict "$2" "an unprivileged create in $1 is denied" ""
}

# elevated_case <case> <from> <to> <versions after> <verb> <expected output>
elevated_case() {
  local out rc
  if [ "$5" = install ]; then
    out="$("$work/$scen/build/$3/bin/e2eapp$exe" install --root "$sroot" 2>&1)"
  else
    out="$(launch update --root "$sroot" 2>&1)"
  fi
  rc=$?
  out="${out//$'\r'/}"
  printf '%s\n' "$out" | sed 's/^/    | /'
  observe
  why=""
  want rc "$rc" 0
  contains output "$out" "needs privileges"
  contains output "$out" "$6"
  settled "$3" "$4"
  # The helper refreshed on its own, into its own cache inside the root.
  if [ ! -f "$sroot/.updater/tuf/metadata/timestamp.json" ]; then why="${why}no helper cache in the root; "; fi
  verdict "$1" "UAC accepted, $2 -> $3 applied by the elevated helper" "rc=$rc"
}

# unsafe_root_cases <dir>: a root the user controls is refused — by the caller
# before any prompt, and by the helper itself when a hostile caller starts it
# elevated directly. Either way nothing is created.
unsafe_root_cases() {
  local root="$1/e2eapp" out rc
  out="$("$work/$scen/build/1.0.0/bin/e2eapp$exe" install --root "$root" 2>&1)"
  rc=$?
  out="${out//$'\r'/}"
  why=""
  attestation="root=$root"
  want rc "$rc" 5
  contains output "$out" "administrators-only"
  if [ -e "$root" ]; then why="${why}the root was created; "; fi
  verdict "refuse a user-owned root before the prompt" "exit 5, no UAC prompt, nothing created" \
    "error=$(printf '%s' "$out" | grep 'e2eapp:' | oneline)" || return 1

  step "accept the UAC prompt: a hostile caller starts the helper elevated on a user-owned root"
  as_admin "$work/$scen/build/1.0.0/bin/e2eapp$exe" apply --root "$(cygpath -w "$root")" --channel stable --version 1.0.0
  rc=$?
  why=""
  attestation="root=$root"
  want rc "$rc" 5
  if [ -e "$root" ]; then why="${why}the elevated helper created the root; "; fi
  verdict "elevated helper refuses a user-owned root" "helper exits 5 before any write" "rc=$rc"
}

# --- scenarios ----------------------------------------------------------------

scenario_minor() {
  publish 1.0.0 || return 1
  install_case 1.0.0 || return 1
  publish 1.1.0 || return 1
  update_case "minor update 1.0.0 -> 1.1.0" 1.0.0 1.1.0 "1.0.0,1.1.0" || return 1
  publish 1.2.0 || return 1
  update_case "sequential minor update 1.1.0 -> 1.2.0" 1.1.0 1.2.0 "1.1.0,1.2.0" || return 1
  uptodate_case 1.2.0
}

scenario_major() {
  publish 1.0.0 || return 1
  install_case 1.0.0 || return 1
  publish 2.0.0 || return 1
  update_case "major update 1.0.0 -> 2.0.0" 1.0.0 2.0.0 "1.0.0,2.0.0" || return 1
  publish 2.1.0 || return 1
  update_case "sequential update 2.0.0 -> 2.1.0" 2.0.0 2.1.0 "2.0.0,2.1.0" || return 1
  uptodate_case 2.1.0
}

scenario_floor_gap() {
  publish 1.0.0 || return 1
  install_case 1.0.0 || return 1
  publish 1.2.0 1.1.0 || return 1
  refuse_case "refuse minor update 1.0.0 -> 1.2.0 (min_from_version 1.1.0 unpublished)" 1.0.0 1.2.0 1.1.0
}

scenario_elevated() {
  if [ "$goos" != windows ]; then
    record "elevated" "Windows host" FAIL "the elevated scenario needs Windows and UAC, this is $goos"
    return 1
  fi
  local programs
  programs="$(cygpath -m "$PROGRAMFILES")"
  sroot="$programs/idunn-$stag/e2eapp"
  slauncher="$work/$scen/launcher$exe"
  cp "$bin/launcher$exe" "$slauncher"
  unwritable_case "$programs" "Program Files is administrators-only" || return 1

  publish 1.0.0 || return 1
  user_owned_readonly "$work/$scen/user-owned"
  unsafe_root_cases "$work/$scen/user-owned" || return 1

  step "accept the UAC prompt for the elevated install of 1.0.0 into $sroot"
  elevated_case "elevated install 1.0.0" "" 1.0.0 "1.0.0" install "installed 1.0.0" || return 1
  publish 1.1.0 || return 1
  step "accept the UAC prompt for the elevated update to 1.1.0"
  elevated_case "elevated update 1.0.0 -> 1.1.0" 1.0.0 1.1.0 "1.0.0,1.1.0" update "updated 1.0.0 -> 1.1.0" || return 1
  # No prompt for this one: checking needs no privileges, and a check that
  # tried to write the root would fail here.
  uptodate_case 1.1.0
}

# cleanup_elevated removes the install from Program Files, which takes one more
# prompt. Declining it leaves the directory and says where.
cleanup_elevated() {
  local dir
  dir="$(cygpath -w "$(cygpath -m "$PROGRAMFILES")/idunn-$tag-elevated")"
  [ -d "$dir" ] || return 0
  if [ -n "${E2E_KEEP:-}" ]; then
    printf 'install kept: %s\n' "$dir"
    return 0
  fi
  step "accept the UAC prompt to remove $dir"
  powershell.exe -NoProfile -NonInteractive -Command \
    "Start-Process -FilePath cmd.exe -ArgumentList '/c rmdir /s /q \"$dir\"' -Verb RunAs -Wait -WindowStyle Hidden" ||
    true
  if [ -d "$dir" ]; then printf 'not removed: %s\n' "$dir"; fi
}

# --- run ----------------------------------------------------------------------

# A status reader that never goes through the launcher, so a broken pointer is
# attested as such instead of as a launcher failure. Any version will do: status
# reads only the disk.
go build -o "$bin/e2eapp-status$exe" ./test/e2e/cmd/e2eapp

commit="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
run_url=""
if [ -n "${GITHUB_RUN_ID:-}" ]; then run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"; fi

failed=0
for s in $scenarios; do
  fn="scenario_${s//-/_}"
  declare -F "$fn" >/dev/null || die "unknown scenario $s"
  begin "$s"
  "$fn" || true
  if ! "$bin/e2etool$exe" report --results "$results" --out "$reports/$s.json" \
    --scenario "$s" --platform "$goos/$goarch" --commit "$commit" --run "$run_url" >"$work/$s/report.md"; then
    failed=1
  fi
  if [ "$s" = elevated ] && [ "$goos" = windows ]; then cleanup_elevated; fi
  cat "$work/$s/report.md"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$work/$s/report.md" >>"$GITHUB_STEP_SUMMARY"; fi
done

if [ "$mode" = github ]; then
  for s in $scenarios; do
    if [ "$failed" -eq 0 ] && [ -z "${E2E_KEEP:-}" ]; then
      gh release delete "$tag-$s" --repo "$repo" --cleanup-tag --yes >/dev/null 2>&1 || true
    else
      printf 'release kept: https://github.com/%s/releases/tag/%s\n' "$repo" "$tag-$s"
    fi
  done
fi

[ "$failed" -eq 0 ] || die "not every case passed; reports in $reports"
step "PASS: $scenarios on $goos/$goarch"
