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

package delta_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/delta"
)

// roundTrip is the only property that matters for a generator: whatever it
// emits, the reader in core/stage turns it back into exactly the file it was
// given. Nothing here asserts how the patch is built — that is free to change.
func roundTrip(t *testing.T, older, newer []byte) []byte {
	t.Helper()
	patch, err := delta.Diff(older, newer)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	got, err := stage.ApplyPatch(older, patch, int64(len(newer)))
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	if !bytes.Equal(got, newer) {
		t.Fatalf("reconstructed %d bytes that are not the target", len(got))
	}
	return patch
}

// binary stands in for a build artefact: incompressible on its own, so a small
// patch can only come from what the two versions have in common.
func binary(seed int64, size int) []byte {
	out := make([]byte, size)
	rand.New(rand.NewSource(seed)).Read(out)
	return out
}

func TestDiffRoundTrips(t *testing.T) {
	base := binary(1, 1<<16)

	for name, newer := range map[string][]byte{
		"identical":              append([]byte(nil), base...),
		"one byte changed":       flip(base, 1234),
		"a byte at the very end": flip(base, len(base)-1),
		"truncated":              base[:len(base)/2],
		"appended to":            append(append([]byte(nil), base...), binary(2, 4096)...),
		"prepended to":           append(binary(3, 4096), base...),
		"inserted in the middle": insert(base, len(base)/2, binary(4, 1000)),
		"cut from the middle":    append(append([]byte(nil), base[:1000]...), base[9000:]...),
		"reordered halves":       append(append([]byte(nil), base[len(base)/2:]...), base[:len(base)/2]...),
		"nothing in common":      binary(5, 1<<16),
		"empty base":             nil,
		"a single byte":          {0x2a},
		"shorter than a block":   base[:17],
	} {
		t.Run(name, func(t *testing.T) {
			if len(newer) == 0 {
				t.Skip("a target with no bytes is not something a patch expresses")
			}
			roundTrip(t, base, newer)
		})
	}

	// The base side deserves the same treatment: a first install has nothing to
	// patch from, and a base shorter than an anchor must not confuse the search.
	for name, older := range map[string][]byte{
		"no base at all":       nil,
		"a base of one byte":   {0x2a},
		"a base under a block": binary(6, 17),
		"a huge base":          binary(7, 1<<18),
	} {
		t.Run("base "+name, func(t *testing.T) {
			roundTrip(t, older, base)
		})
	}
}

func flip(b []byte, at int) []byte {
	out := append([]byte(nil), b...)
	out[at] ^= 0xff
	return out
}

func insert(b []byte, at int, what []byte) []byte {
	out := append([]byte(nil), b[:at]...)
	out = append(out, what...)
	return append(out, b[at:]...)
}

// The shape idunn exists for: a large binary rebuilt with a small change. The
// patch has to be a fraction of the file, or delta stage 2 buys nothing over
// simply fetching the target.
func TestDiffIsSmallForARebuiltBinary(t *testing.T) {
	const size = 4 << 20
	older := binary(11, size)

	rng := rand.New(rand.NewSource(12))
	newer := append([]byte(nil), older...)
	// 1% of the file rewritten in 4 KiB blocks, as a recompile would.
	for range size / 4096 / 100 {
		off := rng.Intn(size - 4096)
		rng.Read(newer[off : off+4096])
	}
	// Scattered single-byte changes, the pointer patches a relink leaves.
	for range 2000 {
		newer[rng.Intn(size)] ^= 0x01
	}
	// And an insertion, which shifts every offset after it.
	newer = insert(newer, size/3, binary(13, 8192))

	patch := roundTrip(t, older, newer)
	ratio := 100 * float64(len(patch)) / float64(len(newer))
	t.Logf("patch %d bytes for %d bytes of target (%.2f%%)", len(patch), len(newer), ratio)
	if ratio > 15 {
		t.Fatalf("patch is %.2f%% of the target; the delta is not paying for itself", ratio)
	}
}

// Two files with nothing in common cost the whole target plus the container. The
// packer decides by size whether to publish a patch at all, so the generator
// must not pretend otherwise.
func TestDiffOfUnrelatedFilesIsNotSmaller(t *testing.T) {
	patch := roundTrip(t, binary(21, 1<<16), binary(22, 1<<16))
	if len(patch) < 1<<15 {
		t.Fatalf("patch of %d bytes for unrelated files: too good to be true", len(patch))
	}
}

// The packer publishes what this returns, and reproducible builds mean the same
// inputs must give the same bytes — not merely a patch that works (AGENTS.md
// §1.7).
func TestDiffIsDeterministic(t *testing.T) {
	older, newer := binary(31, 1<<17), binary(32, 1<<12)
	newer = insert(binary(31, 1<<17), 5000, newer)

	first, err := delta.Diff(older, newer)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for range 3 {
		again, err := delta.Diff(older, newer)
		if err != nil {
			t.Fatalf("Diff: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("the same inputs produced a different patch")
		}
	}
}

// Generated shapes, because the interesting bugs in an emitter are at the seams:
// a run that starts at the first byte, a run that ends at the last, a gap of
// exactly nothing between two runs.
func TestDiffRoundTripsOnGeneratedShapes(t *testing.T) {
	rng := rand.New(rand.NewSource(41))
	for i := range 300 {
		older := binary(int64(100+i), 1+rng.Intn(1<<14))
		newer := append([]byte(nil), older...)

		for range rng.Intn(6) {
			switch rng.Intn(4) {
			case 0: // rewrite a stretch
				if len(newer) > 8 {
					at := rng.Intn(len(newer) - 8)
					rng.Read(newer[at : at+8])
				}
			case 1: // insert
				at := rng.Intn(len(newer) + 1)
				newer = insert(newer, at, binary(int64(i), 1+rng.Intn(200)))
			case 2: // cut
				if len(newer) > 16 {
					at := rng.Intn(len(newer) - 16)
					newer = append(newer[:at], newer[at+16:]...)
				}
			case 3: // append
				newer = append(newer, binary(int64(i*7), 1+rng.Intn(100))...)
			}
		}
		if len(newer) == 0 {
			continue
		}
		roundTrip(t, older, newer)
	}
}

// FuzzDiffRoundTrip drives the generator with arbitrary pairs. A patch that does
// not reconstruct its target would be caught in production by the signed hash —
// as a failed update, every time, for every user on that release.
func FuzzDiffRoundTrip(f *testing.F) {
	f.Add([]byte("the quick brown fox"), []byte("the quick brown fox jumps"))
	f.Add(bytes.Repeat([]byte("ab"), 200), bytes.Repeat([]byte("ab"), 199))
	f.Add([]byte(nil), []byte("x"))
	f.Add(binary(51, 4096), flip(binary(51, 4096), 100))

	f.Fuzz(func(t *testing.T, older, newer []byte) {
		if len(newer) == 0 {
			return
		}
		patch, err := delta.Diff(older, newer)
		if err != nil {
			t.Fatalf("Diff: %v", err)
		}
		got, err := stage.ApplyPatch(older, patch, int64(len(newer)))
		if err != nil {
			t.Fatalf("ApplyPatch: %v", err)
		}
		if !bytes.Equal(got, newer) {
			t.Fatal("the patch does not reconstruct its target")
		}
	})
}
