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

# Reproducible build check (IDN-18): build the shipped commands twice and fail
# unless every binary is byte-identical.
#
# TUF says the bytes you received are the bytes the publisher signed. This says
# the bytes the publisher signed are the ones this source produces, so an
# independent rebuild can check a release instead of trusting it (AGENTS.md
# §1.7, docs/design.md §9, §15).
#
# The two passes are made to differ in the inputs that must NOT matter:
#
#   * a different source directory -- pass b builds a copy of the tree, so an
#     absolute path that -trimpath failed to remove shows up as a difference;
#   * a fresh, separate GOCACHE each -- otherwise the second pass is a cache
#     hit that relinks nothing and would compare equal by construction.
#
# and pinned in the inputs that are allowed to matter only if recorded:
#
#   -trimpath         no build directory or module cache path in the binary
#   -buildvcs=false   no VCS stamp: the bytes depend on the source, not on
#                     whether .git is present or a stray file marks it dirty
#   -ldflags=-buildid=  no build ID
#   CGO_ENABLED=0     no host C toolchain as an unrecorded input
#
# What it does not catch is a difference between two machines or two Go
# toolchains; the digests and the exact `go version` are written out so an
# independent rebuild has something to compare against.
#
# Environment:
#   REPRO_DIR       output directory              (default dist/repro)
#   REPRO_CMDS      commands under ./cmd          (default "installer launcher packer")
#   REPRO_TARGETS   GOOS/GOARCH pairs             (default: linux, windows, darwin x amd64, arm64)
#
# Output: $REPRO_DIR/a/idunn-<cmd>-<goos>-<goarch>[.exe], $REPRO_DIR/SHA256SUMS
# (names relative to $REPRO_DIR/a) and $REPRO_DIR/go-version.txt. The names are
# flat and unique because they become attestation subject names.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

out="${REPRO_DIR:-dist/repro}"
cmds="${REPRO_CMDS:-installer launcher packer}"
targets="${REPRO_TARGETS:-linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64}"

case "$out" in
  /*|[A-Za-z]:*) ;;
  *) out="$root/$out" ;;
esac

rm -rf "$out"
mkdir -p "$out"
work="$(mktemp -d "${TMPDIR:-/tmp}/idunn-repro.XXXXXX")"
trap 'chmod -R u+w "$work" 2>/dev/null || true; rm -rf "$work"' EXIT

# Nothing from the caller's environment may reach the build: a GOFLAGS with
# -ldflags or a GOAMD64 level would change the bytes without the flags below
# saying so.
unset GOFLAGS GOAMD64 GOARM64 GOEXPERIMENT GO386 GOARM
export CGO_ENABLED=0 GOTOOLCHAIN=local

build() { # build <pass> <source dir>
  local pass="$1" src="$2" target goos goarch ext cmd
  mkdir -p "$out/$pass"
  for target in $targets; do
    goos="${target%/*}"
    goarch="${target#*/}"
    ext=""
    [ "$goos" = windows ] && ext=".exe"
    for cmd in $cmds; do
      (cd "$src" && GOCACHE="$work/cache-$pass" GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath -buildvcs=false -ldflags=-buildid= \
          -o "$out/$pass/idunn-$cmd-$goos-$goarch$ext" "./cmd/$cmd")
    done
  done
}

# Pass b builds a copy of the source in another directory. Generated and
# ignored trees stay behind; none of them is an input to ./cmd.
mkdir -p "$work/src"
tar -C "$root" \
  --exclude=./.git --exclude=./dist --exclude=./bin --exclude=./.gotmp \
  --exclude=./.claude --exclude=./.idea --exclude=./test/redteam/fixtures \
  -cf - . | tar -C "$work/src" -xf -

echo ">> pass a: $root"
build a "$root"
echo ">> pass b: $work/src"
build b "$work/src"

go version >"$out/go-version.txt"
(cd "$out/a" && sha256sum -- *) >"$out/SHA256SUMS"
(cd "$out/b" && sha256sum -- *) >"$work/b.sha256"

if ! diff -u "$out/SHA256SUMS" "$work/b.sha256"; then
  echo "NOT reproducible: two builds of the same tree differ" >&2
  exit 1
fi
rm -rf "$out/b"
echo "reproducible ($(cat "$out/go-version.txt")):"
cat "$out/SHA256SUMS"
