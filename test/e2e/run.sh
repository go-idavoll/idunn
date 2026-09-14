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
# Publishes e2eapp 1.0.0 with cmd/packer as the assets of a GitHub release,
# installs it from there, publishes 1.1.0 into the same release, and lets the
# installed application update itself through the launcher, headless. Every
# download goes through github.com and its object store.
#
# Environment:
#   E2E_MODE      github (default) or local — local serves the assets from
#                 127.0.0.1 instead of GitHub, to check this script offline.
#   E2E_REPO      release repository (default go-idavoll/idunn-e2e).
#   E2E_TAG       release tag (default e2e-local-<unix time>).
#   E2E_KEEP      if set, the release is left in place after a successful run.
#   E2E_WORK      parent of the scratch directory (default RUNNER_TEMP or TMPDIR).
#   E2E_PORT      local mode listen port (default 18765).
#   GH_TOKEN      github mode: token with contents:write on E2E_REPO.
#
# Run from anywhere; it works on the repository this script lives in.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/../.."

mode="${E2E_MODE:-github}"
repo="${E2E_REPO:-go-idavoll/idunn-e2e}"
tag="${E2E_TAG:-e2e-local-$(date +%s)}"
port="${E2E_PORT:-18765}"

# Go on Windows does not understand Git Bash paths such as /tmp/x.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

if [ -n "${E2E_WORK:-}" ]; then mkdir -p "$E2E_WORK"; fi
work="$(native "$(mktemp -d "${E2E_WORK:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}/idunn-e2e.XXXXXX")")"
exe="$(go env GOEXE)"
goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
bin="$work/bin"
tuf="$work/repo"
assets="$work/assets"
root="$work/install"
mkdir -p "$bin" "$assets"

case "$mode" in
  github) url="https://github.com/$repo/releases/download/$tag" ;;
  local)  url="http://127.0.0.1:$port/download" ;;
  *) fail "E2E_MODE must be github or local, not $mode" ;;
esac

server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  # Keys and repository are throwaway; the release is handled below.
  rm -rf "$work/keys" "$work/keys.env"
}
trap cleanup EXIT

step "work dir $work, release $url ($goos/$goarch)"

step "build tools"
go build -o "$bin/packer$exe" ./cmd/packer
go build -o "$bin/e2etool$exe" ./test/e2e/cmd/e2etool
go build -ldflags "-X main.appBinary=bin/e2eapp$exe" -o "$bin/launcher$exe" ./cmd/launcher

step "generate throwaway keys and root"
"$bin/e2etool$exe" init-repo --repo "$tuf" --keys "$work/keys" >"$work/keys.env"
while IFS= read -r kv; do
  export "${kv?}"
done <"$work/keys.env"
cp "$tuf/metadata/1.root.json" test/e2e/cmd/e2eapp/anchor/root.json

# build_and_publish <version>: build e2eapp at that version, publish it into the
# repository, and put the repository where the client will look for it.
build_and_publish() {
  local version="$1" dir="$work/build/$1"
  mkdir -p "$dir/bin"
  go build -ldflags "-X main.version=$version -X main.buildTime=$(now) -X main.releaseURL=$url" \
    -o "$dir/bin/e2eapp$exe" ./test/e2e/cmd/e2eapp
  cat >"$dir/pack.yaml" <<EOF
name: e2eapp
version: $version
channel: stable
targets:
  - os: $goos
    arch: $goarch
    files:
      - { src: bin/e2eapp$exe, dst: bin/e2eapp$exe, kind: exe, mode: "0755" }
EOF
  "$bin/packer$exe" publish --config "$dir/pack.yaml" --repo "$tuf" --now "$(now)"

  rm -rf "$assets" && mkdir -p "$assets"
  "$bin/e2etool$exe" flatten "$tuf" "$assets"
  if [ "$mode" = github ]; then
    if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
      gh release upload "$tag" --repo "$repo" --clobber "$assets"/*
    else
      gh release create "$tag" --repo "$repo" --prerelease \
        --title "$tag" --notes "idunn e2e update test (${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}). Throwaway; deleted after a successful run." \
        "$assets"/*
    fi
  fi
  # The timestamp is what a client reads first and the file a --clobber upload
  # replaces; once it is served, the rest of this publish is too.
  "$bin/e2etool$exe" wait-asset --url "$url/metadata__timestamp.json" --file "$assets/metadata__timestamp.json"
}

# launch <args>: start the installed application through the launcher.
launch() { "$root/launcher$exe" --quiet -- "$@"; }

if [ "$mode" = local ]; then
  "$bin/e2etool$exe" serve --dir "$assets" --addr "127.0.0.1:$port" &
  server_pid=$!
fi

step "publish 1.0.0"
build_and_publish 1.0.0

step "install 1.0.0 from the release"
"$work/build/1.0.0/bin/e2eapp$exe" install --root "$root"
cp "$bin/launcher$exe" "$root/launcher$exe"
got="$(launch version | tr -d '\r')"
[ "$got" = 1.0.0 ] || fail "installed version is '$got', want 1.0.0"

step "publish 1.1.0 into the same release"
build_and_publish 1.1.0

step "headless self-update through the launcher"
out="$(launch update --root "$root" 2>&1 | tr -d '\r')" || fail "update failed: $out"
printf '%s\n' "$out"
grep -q '^updated 1.0.0 -> 1.1.0$' <<<"$out" || fail "update did not report 1.0.0 -> 1.1.0"

got="$(launch version | tr -d '\r')"
[ "$got" = 1.1.0 ] || fail "running version after update is '$got', want 1.1.0"
[ -d "$root/versions/1.1.0" ] || fail "versions/1.1.0 is missing"

out="$(launch update --root "$root" 2>&1 | tr -d '\r')" || fail "second update failed: $out"
grep -q '^up to date at 1.1.0$' <<<"$out" || fail "second update did not report up to date: $out"

step "PASS: 1.0.0 -> 1.1.0 on $goos/$goarch"

if [ "$mode" = github ] && [ -z "${E2E_KEEP:-}" ]; then
  gh release delete "$tag" --repo "$repo" --cleanup-tag --yes
fi
