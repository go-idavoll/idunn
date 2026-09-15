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
	"io"
	"sort"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/layout"
)

// reuseSources lists the version directories a new release may take unchanged
// files from, in the order they are worth trying: the live version first, then
// the remaining ones newest to oldest. A file that survived the last update is
// far more likely to be the one still on disk than one three releases back.
//
// Reuse is an optimisation with a complete, safe fallback — the signed target
// itself — so anything that goes wrong while looking for sources yields no
// sources rather than an error. A version directory that cannot be listed must
// not be able to stop an update; the network path is always there.
func (s *Stager) reuseSources(live, staging string) []string {
	versions, err := layout.InstalledVersions(s.FS, s.Root)
	if err != nil {
		return nil
	}

	others := make([]string, 0, len(versions))
	for _, v := range versions {
		if v == live || v == staging {
			continue
		}
		others = append(others, v)
	}
	// Compare returns an error only for a version that is not SemVer, and
	// InstalledVersions has already dropped those; an unorderable pair would
	// only cost reuse efficiency, never correctness, so the order settles for
	// what Compare says and does not fail the update over it.
	sort.SliceStable(others, func(i, j int) bool {
		c, _ := release.Compare(others[i], others[j])
		return c > 0
	})
	if live != "" {
		others = append([]string{live}, others...)
	}

	// Joining the names directly is safe here and nowhere else: they come from
	// a listing that already dropped everything that is not SemVer, and from a
	// pointer that layout refuses to read unless it names a version directory.
	// Nothing caller-supplied reaches this join.
	dirs := make([]string, 0, len(others))
	for _, v := range others {
		dirs = append(dirs, fsx.Join(layout.Versions(s.Root), v))
	}
	return dirs
}

// reuse writes f's target into the staging tree from a version already installed
// and reports whether it could. dst must already be sanitized.
//
// This is the local half of delta stage 1 (docs/design.md §6.4): unchanged files
// come off the disk instead of the network. The saving is the whole point for a
// release whose bulk is a browser runtime that changes on few of its files, and
// it is the groundwork stage 2 needs — an intra-file patch has to have a base,
// and this is where a verified base comes from.
//
// What makes it safe is that nothing here decides anything about trust: a
// candidate is admitted only by Trust.VerifyStream, the same check a download
// passes. A locally tampered, bit-rotted, or simply changed file fails that
// check and is skipped — reuse never degrades into "close enough", it degrades
// into a download (AGENTS.md §1.5).
//
// The copy and the verification are the same pass: the bytes are teed into the
// scratch file as they are hashed, so what was checked is exactly what landed,
// and neither side is ever held whole in memory. A candidate that fails takes
// its scratch file with it (fsx.WriteStreamAtomic) and the next source is tried
// against a fresh one.
func (s *Stager) reuse(full string, f *release.FileRef, dst string, sources []string, c *counter) bool {
	want, err := s.Trust.TargetLength(f.Target)
	if err != nil || want <= 0 {
		// A zero-length target is not worth a filesystem walk: fetching it
		// costs nothing and there is nothing to save.
		return false
	}
	for _, dir := range sources {
		name := fsx.Join(dir, dst)
		if !s.plausible(name, want) {
			continue
		}
		err := fsx.WriteStreamAtomic(s.FS, full, mode(f), func(w io.Writer) error {
			c.begin(w, SourceReuse)
			return s.copyVerified(name, f.Target, c)
		})
		if err == nil {
			return true
		}
	}
	return false
}

// localBase finds a file on disk that holds exactly the signed bytes of target
// at dst, and returns the name it lives under.
//
// It is what a delta patch starts from. That it answers with a *name* rather
// than with bytes is the streaming half of the same idea: a patch walks
// backwards through its base as often as forwards, so the base is read at
// offsets from the file it already occupies instead of being copied into memory
// first.
//
// The verdict is the same one reuse gets — Trust.VerifyStream, nothing else — so
// a patch can never start from bytes a reuse would have refused. The file is
// verified and then opened again to be used, and what happens in between does
// not weaken anything: a base that changed produces a reconstruction that fails
// its own signed hash, which is where the patched file is admitted or refused
// anyway.
func (s *Stager) localBase(target, dst string, sources []string) (string, bool) {
	want, err := s.Trust.TargetLength(target)
	if err != nil || want <= 0 {
		return "", false
	}
	for _, dir := range sources {
		name := fsx.Join(dir, dst)
		if !s.plausible(name, want) {
			continue
		}
		if err := s.copyVerified(name, target, io.Discard); err == nil {
			return name, true
		}
	}
	return "", false
}

// plausible is the cheap pre-filter in front of every candidate read: for a
// changed multi-hundred-megabyte binary the answer is usually "different length"
// and costs a stat rather than a full read and a full scratch write.
//
// A symlink is refused outright — not because verification would miss what it
// points at (it would not), but because following one turns a bounded read of
// our own install tree into a read of whatever a local attacker aimed it at. A
// symlinked *parent* directory can still redirect the read, and is left to the
// same verdict: what comes back is verified, the read is bounded by the signed
// length, and nothing about a rejected candidate is reported, so the redirect
// buys a wasted read and nothing else.
func (s *Stager) plausible(name string, want int64) bool {
	info, err := fsx.Lstat(s.FS, name)
	return err == nil && info.Mode().IsRegular() && info.Size() == want
}

// copyVerified streams name into w and returns the trust layer's verdict on what
// it read.
//
// The tee is the point: the verifier and w see the same bytes, so a caller that
// only gets a nil error back knows that what it wrote is what was signed. w may
// be io.Discard when only the verdict is wanted.
func (s *Stager) copyVerified(name, target string, w io.Writer) error {
	src, err := s.FS.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	return s.Trust.VerifyStream(target, io.TeeReader(src, w))
}
