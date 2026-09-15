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
	"fmt"
	"io"
	"io/fs"
	"math"

	"github.com/go-idavoll/idunn/core/fsx"
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

// patched writes f's target into the staging tree from a local file plus
// patches, and reports whether it could.
//
// Nothing here can lower the bar for what gets installed. Each hop's output is
// checked against the signed target of the release that hop belongs to before
// it becomes the base of the next one, so a chain is exactly as trustworthy as
// a direct download — and any failure along the way is answered by fetching the
// full target, never by accepting bytes that did not verify. A repository that
// serves a broken patch therefore costs its clients bandwidth and nothing else.
//
// Everything a hop needs is a file rather than a buffer: the base, the patch,
// and the intermediate outputs of a multi-hop chain. That is what keeps a delta
// affordable in memory as well as on the wire — the old form held a base, a
// patch and an output at once, three allocations the size of a payload, which
// for the release this optimisation exists for is gigabytes (IDN-12).
func (s *Stager) patched(full string, f *release.FileRef, dst string, sources []string, route Route, scratch string, c *counter) bool {
	lineage := collapse(route[dst])
	if len(lineage) < 2 || lineage[len(lineage)-1] != f.Target {
		// No history, or a history that does not end at the file this
		// descriptor installs. The second is a caller bug rather than an
		// attack — the route is local data — but it is not something to
		// patch towards on a guess.
		return false
	}
	size, err := s.Trust.TargetLength(f.Target)
	if err != nil {
		return false
	}

	hops, cost := cheapest(lineage, s.Trust)
	if hops == nil || cost >= size {
		// Either the repository does not publish patches that span the walk, or
		// the ones it publishes come to more than the file itself. Downloading
		// is then simply better, and it is always available.
		return false
	}

	base, ok := s.localBase(lineage[0], dst, sources)
	if !ok {
		// Nothing on disk still holds the bytes this walk starts from.
		return false
	}

	// Intermediate hops land in the scratch area, never in the staging tree:
	// what becomes versions/<v> must hold the release and nothing else, and a
	// chain abandoned halfway must leave nothing behind that a later pass could
	// mistake for a staged file.
	var spills []string
	defer func() {
		for _, name := range spills {
			_ = s.FS.RemoveAll(name)
		}
	}()

	for i, h := range hops {
		patch, ok := s.spill(scratch, fmt.Sprintf("patch%d", i), h.patch, &spills)
		if !ok {
			return false
		}
		want, err := s.Trust.TargetLength(h.to)
		if err != nil {
			return false
		}

		// Each hop writes a name of its own. Rewriting the previous one would
		// mean renaming over a file this hop still has open, which POSIX
		// tolerates and Windows refuses — and the whole point of the scratch
		// area is that nothing here depends on that difference.
		last := i == len(hops)-1
		out, outMode := fsx.Join(scratch, fmt.Sprintf("hop%d", i)), fs.FileMode(0o600)
		if last {
			out, outMode = full, mode(f)
		} else {
			spills = append(spills, out)
		}

		err = fsx.WriteStreamAtomic(s.FS, out, outMode, func(w io.Writer) error {
			if last {
				c.begin(w, SourcePatch)
				w = c
			}
			return s.hop(base, patch, h.to, want, w)
		})
		if err != nil {
			return false
		}
		base = out
	}
	return true
}

// hop applies one patch and returns the trust layer's verdict on what came out.
//
// The reconstruction is streamed straight into w with a verifier teed off it, so
// the bytes that were checked are the bytes that landed and neither the base nor
// the output is ever held whole. A verdict that refuses discards the scratch
// file through fsx.WriteStreamAtomic, so a failed hop leaves nothing to be
// mistaken for a reconstruction that worked.
func (s *Stager) hop(base, patch, target string, want int64, w io.Writer) error {
	bf, baseLen, err := fsx.OpenReaderAt(s.FS, base)
	if err != nil {
		return err
	}
	defer func() { _ = bf.Close() }()

	pf, patchLen, err := fsx.OpenReaderAt(s.FS, patch)
	if err != nil {
		return err
	}
	defer func() { _ = pf.Close() }()

	// The verifier is fed by a pipe rather than by a tee, because a patch
	// produces its output instead of reading it: there is no reader to tee off,
	// only a writer to fan out to.
	pr, pw := io.Pipe()
	verdict := make(chan error, 1)
	go func() {
		err := s.Trust.VerifyStream(target, pr)
		// Closing the read side is not tidiness: a verifier that stops early —
		// because it refused the target outright, or because the stream ran
		// past the signed length — leaves nobody reading the pipe, and the
		// apply below would block on it forever.
		_ = pr.CloseWithError(err)
		verdict <- err
	}()

	err = ApplyPatchStream(bf, baseLen, pf, patchLen, io.MultiWriter(w, pw), want)
	// Closing with the error stops the verifier's read rather than leaving it
	// blocked on a stream that will never be finished.
	_ = pw.CloseWithError(err)
	if verr := <-verdict; err == nil {
		err = verr
	}
	return err
}

// spill materializes a patch into the scratch area so it can be read at offsets:
// the three streams of a patch container are consumed together, not one after
// another, so a sequential reader will not do.
//
// A patch is untrusted data whose only job is to be cheaper than the file it
// rebuilds, and it is bounded by its signed length like every other target —
// what admits its output is the signed hash of the result, checked in hop.
func (s *Stager) spill(scratch, name, target string, spills *[]string) (string, bool) {
	name = fsx.Join(scratch, name)
	err := fsx.WriteStreamAtomic(s.FS, name, 0o600, func(w io.Writer) error {
		return s.Trust.Materialize(target, w)
	})
	if err != nil {
		return "", false
	}
	*spills = append(*spills, name)
	return name, true
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
