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

// reuse returns the bytes of f's target from a version already installed, or nil
// if no local copy can stand in for it. dst must already be sanitized.
//
// This is the local half of delta stage 1 (docs/design.md §6.4): unchanged files
// come off the disk instead of the network. The saving is the whole point for a
// release whose bulk is a browser runtime that changes on few of its files, and
// it is the groundwork stage 2 needs — an intra-file patch has to have a base,
// and this is where a verified base comes from.
//
// What makes it safe is that nothing here decides anything about trust: a
// candidate is admitted only by Trust.VerifyTarget, the same check a download
// passes. A locally tampered, bit-rotted, or simply changed file fails that
// check and is skipped — reuse never degrades into "close enough", it degrades
// into a download (AGENTS.md §1.5).
func (s *Stager) reuse(f *release.FileRef, dst string, sources []string) []byte {
	return s.local(f.Target, dst, sources)
}

// local returns the bytes of a payload target from an installed version, or nil
// if no version on disk holds them at dst.
//
// The target need not be the one being installed: the same lookup finds the base
// a delta patch starts from, which is a payload of an older release. That the
// two share this code is the point — a base is admitted by the same verdict as a
// reused file, so a patch cannot start from bytes a reuse would have refused.
func (s *Stager) local(target, dst string, sources []string) []byte {
	if len(sources) == 0 {
		return nil
	}
	want, err := s.Trust.TargetLength(target)
	if err != nil || want <= 0 {
		// A zero-length target is not worth a filesystem walk: fetching it
		// costs nothing, and fsx.ReadFile has no meaningful limit to run with.
		return nil
	}

	for _, dir := range sources {
		if data := s.candidate(fsx.Join(dir, dst), want, target); data != nil {
			return data
		}
	}
	return nil
}

// candidate reads one possible source file and returns its bytes if they are the
// signed content of target, nil otherwise.
//
// The size check in front of the read is what keeps this affordable: for a
// changed multi-hundred-megabyte binary the answer is usually "different length"
// and costs a stat. A symlink is refused outright — not because verification
// would miss what it points at (it would not), but because following one turns a
// bounded read of our own install tree into a read of whatever a local attacker
// aimed it at. A symlinked *parent* directory can still redirect the read, and
// is left to the same verdict: what comes back is verified, the read is bounded
// by the signed length, and nothing about a rejected candidate is reported, so
// the redirect buys a wasted read and nothing else.
func (s *Stager) candidate(name string, want int64, target string) []byte {
	info, err := fsx.Lstat(s.FS, name)
	if err != nil || !info.Mode().IsRegular() || info.Size() != want {
		return nil
	}
	data, err := fsx.ReadFile(s.FS, name, want)
	if err != nil {
		return nil
	}
	if err := s.Trust.VerifyTarget(target, data); err != nil {
		return nil
	}
	return data
}
