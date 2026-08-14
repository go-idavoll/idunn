// Copyright 2026 The idunn Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// The delegation scheme (docs/design.md §4.1, docs/packer.md §5).
//
// The top-level targets.json holds no targets at all. It delegates, and every
// target lives in a delegated role, from the first publish on — retrofitting
// delegations later is a migration for every deployed client, which is why the
// design calls them mandatory rather than optional.
//
// There are two kinds of delegated role, and their path patterns are disjoint by
// construction:
//
//	stable   channels/stable/*/latest.json          the channel pointers
//	v2       releases/*/2.*.json, payloads/v2/*     one release line's content
//
// Disjointness is the point. TUF resolves a target by walking the delegation
// tree, so overlapping patterns would make a client fetch delegated metadata it
// has no use for — the exact cost delegations exist to avoid — and would leave
// which role may provide a given target to traversal order. Here, every target
// path matches exactly one role, and each delegation is terminating: if the role
// that owns a path does not have the target, resolution stops instead of letting
// some other role supply it.
//
// The split is per channel and per release line rather than one role per
// (channel, major) pair, because a release descriptor's target path deliberately
// carries no channel: `releases/<os>-<arch>/<version>.json` is what the client
// derives from the version a pointer claims, and what `--version` resolves
// without knowing a channel at all. A (channel, major) role would therefore have
// to claim `releases/*/2.*.json` in every channel at once, and the patterns
// would overlap. Splitting the two dimensions keeps them disjoint and still gives
// a client following one channel only what it needs: its own pointer role, and
// the one release line it is installing. It never sees another channel's pointers
// or another major's history.
//
// Payload targets are content-addressed — `payloads/v<major>/<sha256>`. That is
// what makes the dedup claim in §4.1 true rather than aspirational: an unchanged
// file across releases is literally the same target, so metadata and server
// storage grow with *changed* files, not with releases × files. It also makes
// every payload target immutable, so a republish can never change what an already
// published path resolves to.

// majorRoleRe matches a release-line role name. Channel names are refused if they
// match it, so the two role namespaces cannot collide.
var majorRoleRe = regexp.MustCompile(`^v[0-9]+$`)

// channelRole is the delegated role that owns one channel's pointers.
func channelRole(channel string) string { return channel }

// lineRole is the delegated role that owns one release line's descriptors and
// payloads. major is the major component of a SemVer version.
func lineRole(major string) string { return "v" + major }

// channelPaths is the path pattern set of a channel role: the pointer of that
// channel, for every platform.
func channelPaths(channel string) []string {
	return []string{fmt.Sprintf("channels/%s/*/latest.json", channel)}
}

// linePaths is the path pattern set of a release-line role: every descriptor of
// that major, for every platform, and every payload of that line.
//
// go-tuf matches a pattern segment by segment, so neither wildcard can cross a
// "/" and neither pattern can be widened by a crafted target path.
func linePaths(major string) []string {
	return []string{
		fmt.Sprintf("releases/*/%s.*.json", major),
		fmt.Sprintf("payloads/v%s/*", major),
	}
}

// payloadTarget is the target path of a payload file with the given content.
func payloadTarget(major string, sum [sha256.Size]byte) string {
	return fmt.Sprintf("payloads/v%s/%s", major, hex.EncodeToString(sum[:]))
}

// majorOf returns the major component of a SemVer version. The version must
// already be valid; callers validate before they get here.
func majorOf(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}

// roleLess orders delegated roles deterministically for the delegations list:
// channel roles first, alphabetically, then release lines by descending major so
// the newest line is found first. Nothing depends on the order — the patterns are
// disjoint — but the emitted metadata has to be byte-identical across runs.
func roleLess(a, b string) bool {
	am, aok := majorNum(a)
	bm, bok := majorNum(b)
	switch {
	case !aok && !bok:
		return a < b
	case !aok:
		return true
	case !bok:
		return false
	default:
		return am > bm
	}
}

// majorNum parses a release-line role name back into its major number.
func majorNum(role string) (uint64, bool) {
	if !majorRoleRe.MatchString(role) {
		return 0, false
	}
	n, err := strconv.ParseUint(role[1:], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// hashPrefixedPath returns the on-disk name of a target under consistent
// snapshots: <dir>/<sha256>.<basename>. It is the exact rule go-tuf's client
// builds its request URL from, which is why it lives next to the code that
// decides target paths rather than being derived twice.
func hashPrefixedPath(targetPath string, sum [sha256.Size]byte) string {
	base := path.Base(targetPath)
	dir := path.Dir(targetPath)
	name := hex.EncodeToString(sum[:]) + "." + base
	if dir == "." {
		return name
	}
	return path.Join(dir, name)
}
