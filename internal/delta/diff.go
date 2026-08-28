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

package delta

import (
	"bytes"
	"encoding/binary"
)

// Diff is the publisher's half. It runs offline, in the packer, and its output
// is checked by the client against the signed target hash — so a bad match costs
// bandwidth and a wrong one costs a fallback, never a wrong install.
//
// The matcher is a greedy one over a hash index of fixed-size windows: for each
// position in the new file, look up whether that window occurs in the base, and
// if it does, extend the match as far as it goes. It finds what a rebuilt binary
// mostly is — long unchanged runs with small edits between them — and it does
// not find what a suffix sort would. Since the alternative was a dependency in
// the apply path (see the package comment), that is the trade taken.

// window is the number of bytes that have to match before a copy is worth
// looking for. Too small and the index is noise; too large and small unchanged
// runs are missed. 32 is comfortably inside both.
const window = 32

// minCopy is the shortest run worth encoding as a copy rather than as literals.
// A copy costs an opcode and two varints — around five bytes — so anything below
// that is cheaper written out.
const minCopy = 16

// Diff produces a patch that Apply turns base into next with.
//
// It never returns an error: any two byte slices have a patch, in the worst case
// one that inserts the whole of next literally. The caller decides whether the
// result is small enough to be worth publishing.
func Diff(base, next []byte) []byte {
	index := buildIndex(base)

	out := make([]byte, 0, len(next)/4+len(magic)+16)
	out = append(out, magic...)
	out = binary.AppendUvarint(out, uint64(len(next)))

	var literal []byte
	flush := func() {
		if len(literal) == 0 {
			return
		}
		out = append(out, opAdd)
		out = binary.AppendUvarint(out, uint64(len(literal)))
		out = append(out, literal...)
		literal = literal[:0]
	}

	for i := 0; i < len(next); {
		offset, length := longestMatch(base, next, i, index)
		if length < minCopy {
			literal = append(literal, next[i])
			i++
			continue
		}
		flush()
		out = append(out, opCopy)
		out = binary.AppendUvarint(out, offset)
		out = binary.AppendUvarint(out, length)
		i += int(length) //nolint:gosec // G115: length is at most len(next), an int.
	}
	flush()
	return out
}

// buildIndex maps the hash of every window-sized run in base to where it starts.
//
// Only the first occurrence of a hash is kept. Keeping every one would turn a
// file full of repeated blocks — zero padding, say — into a lookup that walks
// thousands of candidates for no better match.
func buildIndex(base []byte) map[uint64]int {
	if len(base) < window {
		return nil
	}
	index := make(map[uint64]int, len(base)/window)
	for i := 0; i+window <= len(base); i++ {
		h := hashAt(base, i)
		if _, seen := index[h]; !seen {
			index[h] = i
		}
	}
	return index
}

// longestMatch finds where next[at:] continues inside base, and for how long.
func longestMatch(base, next []byte, at int, index map[uint64]int) (offset, length uint64) {
	if index == nil || at+window > len(next) {
		return 0, 0
	}
	start, ok := index[hashAt(next, at)]
	if !ok {
		return 0, 0
	}
	// The hash is a hint, not an answer: confirm the window really matches
	// before extending it, or a collision writes the wrong bytes into a patch
	// that then fails verification for no reason anyone can see.
	if !bytes.Equal(base[start:start+window], next[at:at+window]) {
		return 0, 0
	}
	n := window
	for start+n < len(base) && at+n < len(next) && base[start+n] == next[at+n] {
		n++
	}
	// Both are indexes into slices, so both are non-negative and no wider than
	// an int; the patch format spells them as varints.
	//
	//nolint:gosec // G115: slice indexes are never negative.
	return uint64(start), uint64(n)
}

// hashAt is FNV-1a over one window. It is a lookup key and nothing more — no
// decision rests on it, because longestMatch confirms every hit against the
// bytes themselves.
func hashAt(b []byte, at int) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, c := range b[at : at+window] {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}
