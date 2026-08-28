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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
)

// MinRetain is the smallest keep window a publish may be run with.
//
// One is not enough, for three separate reasons, and any of them alone would do:
// a client that is mid-download when a publish lands would have its target
// deleted underneath it; `MinFromVersion` chains need a predecessor to still be
// fetchable; and delta stage 2 patches are computed against previous releases
// (§6.4). Two is the floor, not a recommendation — a real product keeps more.
const MinRetain = 2

// retirement is what one retention pass decided to remove.
type retirement struct {
	// Targets are the target paths that leave the delegated role, sorted.
	Targets []string

	// Files are the repository-relative paths under targets/ that back them.
	// They are deleted only after the new metadata is published, so no client
	// is ever pointed at a file that is already gone.
	Files []string
}

// retire drops releases beyond the keep window from the line role this publish
// touches, and with them every payload no retained release still names.
//
// Content addressing turns this into reference counting rather than path
// guessing: a payload target is retired exactly when no retained descriptor
// mentions it, which is also what makes it safe for two releases to share one.
//
// Three things it deliberately does not do:
//
//   - It touches only the release line being published. Retiring an old major
//     is an end-of-life decision, not something a routine publish does on the
//     side — and it would need that line's signing key, which the operator did
//     not offer for this release (docs/packer.md §4).
//   - It never retires a release a channel pointer still names. That would be a
//     publisher denying its own clients an update they are entitled to, which is
//     the freeze attack with the publisher holding the knife.
//   - It removes nothing until the new metadata is written. Deleting first would
//     open a window where the repository names files that are not there.
//
// A client that is holding a snapshot older than this publish can still resolve
// a retired target and get a 404. That is inherent to retention of any kind; the
// keep window is what bounds it, which is why the minimum is not one.
func retire(o Options, cfg *Config, st *state, blobs []blob,
	roleTargets map[string]map[string]*metadata.TargetFiles, contentRole string) (*retirement, error) {
	if o.Retain == 0 {
		return nil, nil
	}
	if o.Retain < MinRetain {
		return nil, fmt.Errorf("%w: retain %d would leave nothing behind the channel head (minimum %d)",
			ErrConfig, o.Retain, MinRetain)
	}

	targets := roleTargets[contentRole]
	if targets == nil {
		return nil, nil
	}
	// The reader spans every role, not just the one being retired: the channel
	// pointers that decide what may not be retired live in the channel roles.
	read := newTargetReader(st, blobs, roleTargets)

	protected, err := pointedAt(roleTargets, read)
	if err != nil {
		return nil, err
	}

	keep, drop, err := partition(targets, o.Retain, cfg.Version, protected)
	if err != nil {
		return nil, err
	}

	// Every payload a retained descriptor names survives, whichever release
	// first published it. This is the reference count.
	referenced := map[string]bool{}
	for _, descTarget := range keep {
		raw, err := read(descTarget)
		if err != nil {
			return nil, err
		}
		d, err := release.ParseDescriptor(raw)
		if err != nil {
			// A descriptor already published that we can no longer read is not
			// something to retire around: we cannot tell what it protects.
			return nil, fmt.Errorf("%w: %s is published but cannot be parsed, so retention cannot tell what it still needs: %w",
				ErrRepo, descTarget, err)
		}
		for i := range d.Files {
			referenced[d.Files[i].Target] = true
		}
	}

	payloadPrefix := "payloads/" + contentRole + "/"
	for target := range targets {
		if strings.HasPrefix(target, payloadPrefix) && !referenced[target] {
			drop = append(drop, target)
		}
	}
	if len(drop) == 0 {
		return nil, nil
	}
	sort.Strings(drop)

	r := &retirement{Targets: drop}
	for _, target := range drop {
		file, err := targetFilePath(target, targets[target])
		if err != nil {
			return nil, err
		}
		r.Files = append(r.Files, file)
		delete(targets, target)
	}
	return r, nil
}

// partition splits the descriptors of one line role into what is kept and what
// is retired, per platform.
//
// The window is counted per (os, arch) rather than across the role: a product
// that ships four platforms would otherwise retire three of them to keep four
// releases of the fourth.
func partition(targets map[string]*metadata.TargetFiles, retain int,
	publishing string, protected map[string]bool) (keep, drop []string, err error) {
	byPlatform := map[string][]string{} // "os-arch" -> versions

	for target := range targets {
		goos, goarch, version, ok := parseDescriptorTarget(target)
		if !ok {
			continue // a payload, not a descriptor.
		}
		byPlatform[goos+"-"+goarch] = append(byPlatform[goos+"-"+goarch], version)
	}

	for _, platform := range sortedKeys(byPlatform) {
		versions := byPlatform[platform]
		var cmpErr error
		sort.Slice(versions, func(i, j int) bool {
			c, err := release.Compare(versions[i], versions[j])
			if err != nil && cmpErr == nil {
				cmpErr = err
			}
			return c > 0 // newest first
		})
		if cmpErr != nil {
			return nil, nil, fmt.Errorf("%w: ordering the published releases of %s: %w", ErrRepo, platform, cmpErr)
		}

		goos, goarch, _ := strings.Cut(platform, "-")
		for i, v := range versions {
			target := release.DescriptorPath(goos, goarch, v)
			switch {
			case i < retain, v == publishing, protected[platform+"@"+v]:
				keep = append(keep, target)
			default:
				drop = append(drop, target)
			}
		}
	}
	sort.Strings(keep)
	sort.Strings(drop)
	return keep, drop, nil
}

// pointedAt returns the releases a channel pointer currently names, keyed
// "os-arch@version".
//
// The pointers are read and parsed with the client's own parser rather than
// inferred: what a pointer names is a property of its content, and guessing it
// from a path is how a publisher would eventually retire the release its own
// channel head points at.
func pointedAt(roleTargets map[string]map[string]*metadata.TargetFiles,
	read targetReader) (map[string]bool, error) {
	protected := map[string]bool{}
	for _, role := range sortedKeys(roleTargets) {
		if _, isLine := majorNum(role); isLine {
			continue
		}
		for _, target := range sortedKeys(roleTargets[role]) {
			if !strings.HasPrefix(target, "channels/") {
				continue
			}
			raw, err := read(target)
			if err != nil {
				return nil, err
			}
			p, err := release.ParsePointer(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: channel pointer %s is published but cannot be parsed, so retention cannot tell what it protects: %w",
					ErrRepo, target, err)
			}
			protected[p.OS+"-"+p.Arch+"@"+p.Version] = true
		}
	}
	return protected, nil
}

// targetReader returns the published bytes of one target.
type targetReader func(target string) ([]byte, error)

// newTargetReader reads a target from this publish if it is part of it, and from
// the repository otherwise.
//
// A target this publish emits is not on disk yet when retention runs — the write
// happens last, on purpose — so the in-memory blob is the only copy. Everything
// else is read back from the repository and checked against the length and
// hashes the role signed for it, exactly as loadState does for metadata: a
// publisher that builds on a file it cannot vouch for is publishing a guess.
func newTargetReader(st *state, blobs []blob, roleTargets map[string]map[string]*metadata.TargetFiles) targetReader {
	pending := make(map[string][]byte, len(blobs))
	for i := range blobs {
		pending[blobs[i].target] = blobs[i].data
	}
	// The delegation patterns are disjoint, so one flat view of every published
	// target cannot hide two different targets behind one path.
	targets := map[string]*metadata.TargetFiles{}
	for _, role := range sortedKeys(roleTargets) {
		for target, info := range roleTargets[role] {
			targets[target] = info
		}
	}
	return func(target string) ([]byte, error) {
		if raw, ok := pending[target]; ok {
			return raw, nil
		}
		info, ok := targets[target]
		if !ok {
			return nil, fmt.Errorf("%w: %s is not a published target", ErrRepo, target)
		}
		rel, err := targetFilePath(target, info)
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(filepath.Join(st.targetsDir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("%w: reading published target %s: %w", ErrRepo, target, err)
		}
		if err := info.VerifyLengthHashes(raw); err != nil {
			return nil, fmt.Errorf("%w: published target %s does not match what the role signed for it: %w",
				ErrRepo, target, err)
		}
		return raw, nil
	}
}

// targetFilePath is the repository-relative path a target's bytes live at under
// consistent snapshots.
func targetFilePath(target string, info *metadata.TargetFiles) (string, error) {
	if info == nil {
		return "", fmt.Errorf("%w: %s has no target info", ErrRepo, target)
	}
	sum, ok := info.Hashes["sha256"]
	if !ok {
		return "", fmt.Errorf("%w: %s carries no sha256 hash", ErrRepo, target)
	}
	base := path.Base(target)
	dir := path.Dir(target)
	name := sum.String() + "." + base
	if dir == "." {
		return name, nil
	}
	return path.Join(dir, name), nil
}

// parseDescriptorTarget is the inverse of release.DescriptorPath. It reports
// false for anything that is not a descriptor target, which is how payloads are
// told apart from releases without a second naming rule.
func parseDescriptorTarget(target string) (goos, goarch, version string, ok bool) {
	rest, found := strings.CutPrefix(target, "releases/")
	if !found {
		return "", "", "", false
	}
	platform, file, found := strings.Cut(rest, "/")
	if !found {
		return "", "", "", false
	}
	goos, goarch, found = strings.Cut(platform, "-")
	if !found || goos == "" || goarch == "" {
		return "", "", "", false
	}
	version, found = strings.CutSuffix(file, ".json")
	if !found || !release.ValidVersion(version) {
		return "", "", "", false
	}
	// The path a descriptor lives at is derivable from what it describes, so a
	// round trip is the cheapest way to refuse anything that only looks like one.
	if release.DescriptorPath(goos, goarch, version) != target {
		return "", "", "", false
	}
	return goos, goarch, version, true
}
