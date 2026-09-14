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
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/delta"
)

// TestPatchAtReleaseScale is the measurement the format was chosen on, kept so
// the numbers can be re-taken rather than believed. It is skipped unless
// IDUNN_SCALE is set, because it allocates roughly a gigabyte:
//
//	IDUNN_SCALE=1 go test ./internal/delta -run ReleaseScale -v
//
// The shape is a 200 MiB shared library — a browser runtime is the case that
// makes stage 2 worth having at all — rebuilt with 1% of it rewritten, fifty
// thousand scattered single-byte changes, and a megabyte inserted so that every
// offset after it moves. Measured on the reference machine: a 3.3 MiB patch
// (1.64% of the target), six seconds and about 400 MiB above the two files to
// generate, a quarter of a second to apply.
func TestPatchAtReleaseScale(t *testing.T) {
	if os.Getenv("IDUNN_SCALE") == "" {
		t.Skip("set IDUNN_SCALE=1 to run the release-scale measurement")
	}
	const size = 200 << 20
	older := binary(1, size)

	rng := rand.New(rand.NewSource(2))
	newer := append([]byte(nil), older...)
	for range size / 4096 / 100 {
		off := rng.Intn(size - 4096)
		rng.Read(newer[off : off+4096])
	}
	for range 50000 {
		newer[rng.Intn(size)] ^= 0x01
	}
	newer = insert(newer, size/3, binary(3, 1<<20))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	patch, err := delta.Diff(older, newer)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	generated := time.Since(start)
	runtime.ReadMemStats(&after)

	start = time.Now()
	got, err := stage.ApplyPatch(older, patch, int64(len(newer)))
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	applied := time.Since(start)

	if len(got) != len(newer) {
		t.Fatalf("reconstructed %d bytes, want %d", len(got), len(newer))
	}
	ratio := 100 * float64(len(patch)) / float64(len(newer))
	t.Logf("target %d MiB, patch %.2f MiB (%.2f%%), generate %v (+%d MiB heap), apply %v",
		len(newer)>>20, float64(len(patch))/(1<<20), ratio,
		generated.Truncate(time.Millisecond), (after.HeapAlloc-before.HeapAlloc)>>20,
		applied.Truncate(time.Millisecond))

	if ratio > 10 {
		t.Fatalf("patch is %.2f%% of the target at release scale", ratio)
	}
}
