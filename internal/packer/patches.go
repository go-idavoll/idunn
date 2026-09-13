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
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/delta"
)

// buildPatches produces the delta patch targets this publish adds: for each
// destination, a patch from what the last few releases shipped there to what
// this one ships (docs/design.md §6.4 stage 2).
//
// A patch is published under a path derived from the two content hashes, which
// is the whole discovery mechanism: a client holding the old release and the new
// descriptor can name the patch it wants, and the signed metadata answers
// whether it exists. Nothing references it, nothing has to be added to a
// descriptor, and a client that knows nothing about patches is unaffected.
//
// None of this is trusted work. The patch is a hint; the client checks the
// result against the signed target hash and falls back to the full target if it
// does not match. What the packer owes is only that the hint be worth having,
// which is why a patch that is not appreciably smaller than the file it
// reconstructs is not published at all.
func buildPatches(cfg *Config, st *state, contentRole string, blobs []blob) ([]blob, error) {
	against, ratio := cfg.Delta.settings()
	if against == 0 {
		return nil, nil
	}

	payloads := map[string][]byte{}
	var releases []*release.Descriptor
	for i := range blobs {
		b := &blobs[i]
		switch {
		case strings.HasPrefix(b.target, "payloads/"):
			payloads[b.target] = b.data
		case strings.HasPrefix(b.target, "releases/"):
			d, err := release.ParseDescriptor(b.data)
			if err != nil {
				return nil, fmt.Errorf("%w: re-reading the descriptor for %s: %w", ErrConfig, b.target, err)
			}
			releases = append(releases, d)
		}
	}

	var out []blob
	seen := map[string]bool{}
	for _, d := range releases {
		for _, prev := range previousReleases(st, d.OS, d.Arch, d.Version, against) {
			older, err := readDescriptor(st, prev)
			if err != nil {
				// A release whose descriptor is no longer on disk is simply
				// not a base to patch from. Retention removes old targets on
				// purpose, and a publish must not start failing because it
				// did.
				continue
			}
			was := make(map[string]string, len(older.Files))
			for i := range older.Files {
				was[older.Files[i].Dst] = older.Files[i].Target
			}

			for i := range d.Files {
				f := &d.Files[i]
				from, ok := was[f.Dst]
				if !ok || from == f.Target {
					// The file is new in this release, or it did not change:
					// content-addressed reuse already covers the second, and
					// there is nothing to patch from for the first.
					continue
				}
				target, ok := release.PatchPath(from, f.Target)
				if ok && seen[target] {
					// Two platforms shipping the same bytes share the patch,
					// exactly as they share the payload.
					continue
				}
				if !ok {
					continue
				}
				b, ok, err := patchBlob(st, target, from, payloads[f.Target], ratio, contentRole)
				if err != nil {
					return nil, err
				}
				seen[target] = true
				if ok {
					out = append(out, b)
				}
			}
		}
	}

	// Publish order must not depend on map iteration; the repository this
	// produces has to be byte-identical for byte-identical inputs (AGENTS.md
	// §1.7).
	sort.Slice(out, func(i, j int) bool { return out[i].target < out[j].target })
	return out, nil
}

// patchBlob builds one patch target, reporting false when the patch is not worth
// publishing or the base is no longer in the repository.
func patchBlob(st *state, target, from string, to []byte, ratio float64, role string) (blob, bool, error) {
	if len(to) == 0 {
		return blob{}, false, nil
	}
	base, ok := availableBase(st, from)
	if !ok {
		return blob{}, false, nil
	}
	patch, err := delta.Diff(base, to)
	if err != nil {
		return blob{}, false, fmt.Errorf("%w: building %s: %w", ErrRepo, target, err)
	}
	if float64(len(patch)) > ratio*float64(len(to)) {
		// Below the line where a patch pays for itself. The client would
		// weigh it against the full target and pick the download anyway;
		// not publishing it saves the repository the space and the client
		// the metadata.
		return blob{}, false, nil
	}
	b, err := makeBlob(target, patch, role, false)
	return b, err == nil, err
}

// availableBase returns the bytes of a payload this publish can patch away
// from, and false when it cannot.
//
// The two ways it cannot are deliberately the same answer. A payload retention
// has removed is not a base, and neither is one whose bytes no longer match the
// hash they are published under: the first is normal housekeeping, the second is
// bit rot in the publisher's own tree, and in both cases the release still
// publishes fine — with one patch fewer.
func availableBase(st *state, target string) ([]byte, bool) {
	raw, err := readPayload(st, target)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// published is one release the repository already holds, and where its
// descriptor lives.
type published struct {
	version string
	target  string
	sum     [sha256.Size]byte
}

// previousReleases returns up to n releases of a platform that precede version,
// newest first. They come out of the signed metadata the repository already has,
// which is the same list a client walks (trust.Versions).
func previousReleases(st *state, goos, goarch, version string, n int) []published {
	var found []published
	for _, role := range st.delegated {
		if role == nil {
			continue
		}
		for target, info := range role.Signed.Targets {
			v, ok := release.VersionOfDescriptorPath(target, goos, goarch)
			if !ok {
				continue
			}
			if c, err := release.Compare(v, version); err != nil || c >= 0 {
				continue
			}
			sum, ok := sumOf(info.Hashes["sha256"])
			if !ok {
				continue
			}
			found = append(found, published{version: v, target: target, sum: sum})
		}
	}

	sort.Slice(found, func(i, j int) bool {
		c, err := release.Compare(found[i].version, found[j].version)
		if err != nil {
			return false
		}
		return c > 0 // newest first
	})
	if len(found) > n {
		found = found[:n]
	}
	return found
}

// readDescriptor reads a published descriptor back out of the repository.
func readDescriptor(st *state, p published) (*release.Descriptor, error) {
	raw, err := readTarget(st, p.target, p.sum)
	if err != nil {
		return nil, err
	}
	return release.ParseDescriptor(raw)
}

// readPayload reads a published payload back out of the repository. Payload
// targets are content-addressed, so the path itself states the hash the bytes
// must have.
func readPayload(st *state, target string) ([]byte, error) {
	raw, err := hex.DecodeString(path.Base(target))
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a content-addressed payload", ErrRepo, target)
	}
	sum, ok := sumOf(raw)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a content-addressed payload", ErrRepo, target)
	}
	return readTarget(st, target, sum)
}

// readTarget reads one published target and checks it against the hash the
// repository holds it under.
//
// The check is not a trust decision — this is the publisher reading its own
// output — but a publish that built a patch from a locally corrupted base would
// ship a patch that fails on every client instead of failing here.
//
// Containment is the operating system's job (os.Root), as it is everywhere else
// the packer reads its repository. There is no size ceiling: unlike metadata, a
// payload is as large as the product ships, and the packer has already read the
// new one from the build tree.
func readTarget(st *state, target string, sum [sha256.Size]byte) ([]byte, error) {
	root, err := os.OpenRoot(st.targetsDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(hashPrefixedPath(target, sum))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(raw) != sum {
		return nil, fmt.Errorf("%w: %s does not match the hash it is published under", ErrRepo, target)
	}
	return raw, nil
}

func sumOf(h []byte) ([sha256.Size]byte, bool) {
	var sum [sha256.Size]byte
	if len(h) != sha256.Size {
		return sum, false
	}
	copy(sum[:], h)
	return sum, true
}
