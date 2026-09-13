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

package release

import (
	"fmt"
	"slices"
	"sort"
)

// Chain returns the published releases to walk from one version to another,
// both ends included, oldest first.
//
// A full target is self-contained, so reaching the newest release is one step:
// fetch it. A binary patch is not — it turns one exact set of bytes into
// another — so a client that skipped releases cannot jump. It has to follow the
// releases it missed, hop by hop, and this is the order they come in. The bytes
// of every intermediate version are reconstructed and checked against *that*
// version's signed target hash before they become the base of the next hop, so
// a chain is as trustworthy as its weakest hop, which is to say: exactly as
// trustworthy as a direct download.
//
// The result is a walk, not a plan: [1.0.0 1.1.0 1.2.0] means two hops. What
// the caller does with them is its own decision — reconstructing file bytes
// through them is one thing, actually installing each release is another, and
// only a migration floor (Requirements.MinFromVersion) forces the second.
//
// available is what the repository publishes, in any order; entries that are
// not versions this project accepts are ignored, the way a stray file under
// versions/ is ignored. What is not ignored is two releases of equal
// precedence: a repository that publishes 1.0.0 twice under different spellings
// gives no unambiguous order to walk, and an ambiguous order is refused rather
// than resolved by a tie-break nobody could predict.
//
// Both ends must be published: the walk needs `from`'s own descriptor to know
// which bytes it is patching away from, and a `from` that has been garbage
// collected from the repository is exactly the case where the client fetches
// full targets instead.
//
// Channels and prereleases are the caller's filter, not this function's: hand it
// the versions that are eligible. Length is the caller's too — twenty hops of
// patches may well cost more than one download.
func Chain(available []string, from, to string) ([]string, error) {
	walk, err := Between(available, from, to)
	if err != nil {
		return nil, err
	}
	// The release the walk starts from is the one whose bytes the first patch
	// is applied to, so it has to be published too — a version the repository
	// has garbage collected is exactly the case where a client fetches full
	// targets instead.
	if !slices.Contains(available, from) {
		return nil, fmt.Errorf("%w: no published chain from %s to %s", ErrInvalid, from, to)
	}
	return append([]string{from}, walk...), nil
}

// Between returns the published releases after one version up to and including
// another, oldest first.
//
// It is the walk without its starting point, which is the difference between
// the two things a path is needed for. Reconstructing bytes hop by hop has to
// begin at the exact release the bytes on disk came from (Chain). Stepping
// through releases because a migration floor demands it does not: what those
// releases migrate is the host's own state, and the only thing that matters is
// that each one is installed on top of the one before it. A client whose own
// release the repository no longer publishes can still be walked forwards.
//
// The rules are otherwise Chain's: entries that are not versions this project
// accepts are ignored, two releases of equal precedence under different
// spellings are refused as an order nobody could predict, and `to` must be
// published.
func Between(available []string, after, to string) ([]string, error) {
	up, err := Compare(after, to)
	if err != nil {
		return nil, err
	}
	if up >= 0 {
		return nil, fmt.Errorf("%w: %s to %s is not an upgrade; a walk only goes forwards", ErrInvalid, after, to)
	}

	seen := make(map[string]bool, len(available))
	var walk []string
	for _, v := range available {
		// The same release listed twice is one release; two different spellings
		// of the same precedence are the ambiguity checked for below.
		if !ValidVersion(v) || seen[v] {
			continue
		}
		seen[v] = true
		lo, err := Compare(v, after)
		if err != nil {
			return nil, err
		}
		hi, err := Compare(v, to)
		if err != nil {
			return nil, err
		}
		if lo > 0 && hi <= 0 {
			walk = append(walk, v)
		}
	}

	var cmpErr error
	sort.SliceStable(walk, func(i, j int) bool {
		c, err := Compare(walk[i], walk[j])
		if err != nil && cmpErr == nil {
			cmpErr = err
		}
		return c < 0
	})
	if cmpErr != nil {
		return nil, cmpErr
	}
	for i := 1; i < len(walk); i++ {
		c, err := Compare(walk[i-1], walk[i])
		if err != nil {
			return nil, err
		}
		if c == 0 {
			return nil, fmt.Errorf("%w: %s and %s have the same precedence; the repository publishes no unambiguous order",
				ErrInvalid, walk[i-1], walk[i])
		}
	}

	if len(walk) == 0 || walk[len(walk)-1] != to {
		return nil, fmt.Errorf("%w: %s is not published, so nothing leads to it", ErrInvalid, to)
	}
	return walk, nil
}
