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
	"sort"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/delta"
)

// Delta stage 2 on the publisher's side (docs/design.md §6.4).
//
// For each payload this release introduces, look at what the previous releases
// installed to the same destination on the same platform, and publish a patch
// from those bytes to these. The client names such a patch by convention — the
// hash it has and the hash it wants — so nothing has to point at it: a descriptor
// never mentions patches, and a publisher can start or stop emitting them
// between releases without any client noticing except in its bandwidth bill.
//
// Nothing here can make an update wrong. A patch is a signed target like any
// other, the client checks what it reconstructs against the signed hash of the
// real payload, and a patch that reconstructs anything else is discarded in
// favour of the full download. The worst a bad patch can do is waste a round
// trip, which is why this side is allowed to be a greedy approximation rather
// than an optimal one.

// patchWorthPublishing is how small a patch has to be, relative to the payload it
// reconstructs, to be published at all.
//
// A patch that is nearly as large as the file buys nothing and costs the
// repository the space twice. Two thirds is generous: it catches "a binary was
// rebuilt with a small change" and rejects "these two files have nothing in
// common".
const patchWorthPublishing = 2 // published when len(patch)*patchWorthPublishing < len(payload)

// buildPatches emits the delta patches for this publish.
func buildPatches(o Options, st *state, blobs []blob, contentRole, major string) ([]blob, error) {
	if o.PatchAgainst <= 0 || contentRole == "" {
		return nil, nil
	}
	published := st.delegated[contentRole]
	if published == nil {
		return nil, nil // a first publish into this line has no predecessor.
	}
	targets := published.Signed.Targets
	read := newTargetReader(st, blobs, map[string]map[string]*metadata.TargetFiles{contentRole: targets})

	bases, err := previousInstalls(targets, read, o.PatchAgainst)
	if err != nil {
		return nil, err
	}

	var out []blob
	seen := map[string]bool{}
	for i := range blobs {
		b := &blobs[i]
		if b.dst == "" {
			continue // not a payload.
		}
		for _, old := range bases[b.platform] {
			oldTarget, ok := old[b.dst]
			if !ok || oldTarget == b.target {
				continue // nothing installed there before, or the same bytes.
			}
			base, err := read(oldTarget)
			if err != nil {
				// A predecessor we cannot read is a predecessor we cannot patch
				// from. It is not a reason to fail a publish: the client's
				// fallback is the full download, and that still works.
				continue
			}
			patch := delta.Diff(base, b.data)
			if len(patch)*patchWorthPublishing >= len(b.data) {
				continue
			}
			sum := sha256.Sum256(base)
			target := release.PatchPath(major, hex.EncodeToString(sum[:]), hex.EncodeToString(b.sum[:]))
			if seen[target] {
				continue // two platforms installing identical bytes.
			}
			seen[target] = true

			blob, err := makeBlob(target, patch, contentRole, false)
			if err != nil {
				return nil, err
			}
			out = append(out, blob)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].target < out[j].target })
	return out, nil
}

// previousInstalls maps each platform to the destination→target maps of its most
// recent n releases, newest first.
func previousInstalls(targets map[string]*metadata.TargetFiles, read targetReader, n int) (map[string][]map[string]string, error) {
	byPlatform := map[string][]string{}
	for target := range targets {
		goos, goarch, version, ok := parseDescriptorTarget(target)
		if !ok {
			continue
		}
		byPlatform[goos+"-"+goarch] = append(byPlatform[goos+"-"+goarch], version)
	}

	out := map[string][]map[string]string{}
	for _, platform := range sortedKeys(byPlatform) {
		versions := byPlatform[platform]
		var cmpErr error
		sort.Slice(versions, func(i, j int) bool {
			c, err := release.Compare(versions[i], versions[j])
			if err != nil && cmpErr == nil {
				cmpErr = err
			}
			return c > 0
		})
		if cmpErr != nil {
			return nil, fmt.Errorf("%w: ordering the published releases of %s: %w", ErrRepo, platform, cmpErr)
		}

		goos, goarch := splitPlatform(platform)
		for i := 0; i < len(versions) && len(out[platform]) < n; i++ {
			raw, err := read(release.DescriptorPath(goos, goarch, versions[i]))
			if err != nil {
				continue
			}
			d, err := release.ParseDescriptor(raw)
			if err != nil {
				continue
			}
			installs := make(map[string]string, len(d.Files))
			for j := range d.Files {
				installs[d.Files[j].Dst] = d.Files[j].Target
			}
			out[platform] = append(out[platform], installs)
		}
	}
	return out, nil
}

// splitPlatform undoes the "os-arch" key previousInstalls and partition build.
func splitPlatform(platform string) (goos, goarch string) {
	for i := range platform {
		if platform[i] == '-' {
			return platform[:i], platform[i+1:]
		}
	}
	return platform, ""
}
