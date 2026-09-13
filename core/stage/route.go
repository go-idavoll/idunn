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

package stage

import (
	"math"

	"github.com/go-idavoll/idunn/core/release"
)

// Route is the byte-level history of the release being staged: for each
// install-relative destination, the payload targets that destination had at the
// releases being walked, oldest first, ending at the target this release
// installs. Keys are destinations in the clean form a descriptor carries.
//
// It exists because a patch is not a target. A full target is self-contained,
// so any client can fetch any release directly; a patch turns one exact set of
// bytes into another, so a client that skipped releases has to follow them.
// Producing that walk needs the descriptors of the releases in between, which
// is resolution work — the updater's job, not staging's. So the updater hands
// the history down as data and staging decides, per file, which hops to take.
//
// A nil Route means no history is known, which is not an error anywhere: every
// file is then reused from disk or fetched whole, exactly as before.
type Route map[string][]string

// hop is one patch application: the patch target to fetch, and the payload it
// must produce.
type hop struct {
	patch string
	to    string
}

// patched reconstructs f's target from a local file plus patches, or returns nil
// if that cannot be done or is not worth doing.
//
// Nothing here can lower the bar for what gets installed. Each hop's output is
// checked against the signed target of the release that hop belongs to before
// it becomes the base of the next one, so a chain is exactly as trustworthy as
// a direct download — and any failure along the way is answered by fetching the
// full target, never by accepting bytes that did not verify. A repository that
// serves a broken patch therefore costs its clients bandwidth and nothing else.
func (s *Stager) patched(f *release.FileRef, dst string, sources []string, route Route) []byte {
	lineage := collapse(route[dst])
	if len(lineage) < 2 || lineage[len(lineage)-1] != f.Target {
		// No history, or a history that does not end at the file this
		// descriptor installs. The second is a caller bug rather than an
		// attack — the route is local data — but it is not something to
		// patch towards on a guess.
		return nil
	}
	full, err := s.Trust.TargetLength(f.Target)
	if err != nil {
		return nil
	}

	hops, cost := cheapest(lineage, s.Trust)
	if hops == nil || cost >= full {
		// Either the repository does not publish patches that span the walk, or
		// the ones it publishes come to more than the file itself. Downloading
		// is then simply better, and it is always available.
		return nil
	}

	data := s.local(lineage[0], dst, sources)
	if data == nil {
		// Nothing on disk still holds the bytes this walk starts from.
		return nil
	}
	for _, h := range hops {
		patch, err := s.Trust.Target(h.patch)
		if err != nil {
			return nil
		}
		want, err := s.Trust.TargetLength(h.to)
		if err != nil {
			return nil
		}
		out, err := ApplyPatch(data, patch, want)
		if err != nil {
			return nil
		}
		if err := s.Trust.VerifyTarget(h.to, out); err != nil {
			return nil
		}
		data = out
	}
	return data
}

// cheapest picks the hops that reconstruct the last payload of a lineage from
// the first for the fewest bytes on the wire, and reports what they cost.
//
// It is a shortest path over a handful of nodes, so it is written as one: the
// direct patch across the whole walk is an edge like any other, and whether it
// is cheaper than three small ones is a question with an answer rather than a
// guess. Every edge weight comes from the signed metadata — the length of a
// patch target is known before a byte of it is fetched — so the decision costs
// no network at all, and a patch the repository does not publish is simply an
// edge that is not there.
func cheapest(lineage []string, trust Materializer) ([]hop, int64) {
	n := len(lineage)
	cost := make([]int64, n)
	from := make([]int, n)
	for i := 1; i < n; i++ {
		cost[i] = math.MaxInt64
		from[i] = -1
	}

	for i := range n - 1 {
		if cost[i] == math.MaxInt64 {
			continue
		}
		for j := i + 1; j < n; j++ {
			patch, ok := release.PatchPath(lineage[i], lineage[j])
			if !ok {
				continue
			}
			size, err := trust.TargetLength(patch)
			if err != nil || size <= 0 {
				continue
			}
			if total := cost[i] + size; total < cost[j] {
				cost[j] = total
				from[j] = i
			}
		}
	}
	if cost[n-1] == math.MaxInt64 {
		return nil, 0
	}

	var hops []hop
	for j := n - 1; j > 0; j = from[j] {
		patch, _ := release.PatchPath(lineage[from[j]], lineage[j])
		hops = append(hops, hop{patch: patch, to: lineage[j]})
	}
	for i, j := 0, len(hops)-1; i < j; i, j = i+1, j-1 {
		hops[i], hops[j] = hops[j], hops[i]
	}
	return hops, cost[n-1]
}

// collapse drops repeats from a lineage. A file that did not change between two
// releases has the same content-addressed target at both, and there is no patch
// from a payload to itself — nor any need for one.
func collapse(lineage []string) []string {
	out := make([]string, 0, len(lineage))
	for _, target := range lineage {
		if len(out) == 0 || out[len(out)-1] != target {
			out = append(out, target)
		}
	}
	return out
}
