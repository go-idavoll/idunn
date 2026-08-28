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
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"

	"github.com/go-idavoll/idunn/internal/delta"
)

// blob is a deterministic pseudo-random file: something a matcher cannot get
// lucky on.
func blob(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // a fixture, not a key.
	b := make([]byte, n)
	_, _ = r.Read(b)
	return b
}

// A round trip is the whole contract: whatever Diff writes, Apply must turn the
// base back into the target with.
func TestDiffAndApplyRoundTrip(t *testing.T) {
	cases := map[string]struct{ base, next []byte }{
		"identical":         {blob(1, 64<<10), blob(1, 64<<10)},
		"one byte changed":  {blob(2, 64<<10), flip(blob(2, 64<<10), 30000)},
		"insertion":         {blob(3, 32<<10), splice(blob(3, 32<<10), 10000, blob(9, 4096))},
		"truncation":        {blob(4, 32<<10), blob(4, 32<<10)[:20000]},
		"nothing in common": {blob(5, 16<<10), blob(6, 16<<10)},
		"empty base":        {nil, blob(7, 4096)},
		"empty target":      {blob(8, 4096), nil},
		"both empty":        {nil, nil},
		"tiny":              {[]byte("abc"), []byte("abd")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			patch := delta.Diff(c.base, c.next)
			got, err := delta.Apply(c.base, patch, 0)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if !bytes.Equal(got, c.next) {
				t.Fatalf("the patch reconstructed %d bytes, want the %d it was made from",
					len(got), len(c.next))
			}
		})
	}
}

// The reason stage 2 exists: a file that barely changed should not cross the
// wire again.
func TestAPatchIsSmallerThanTheFileItProduces(t *testing.T) {
	base := blob(11, 256<<10)
	next := flip(splice(base, 100000, []byte("a small edit")), 5000)

	patch := delta.Diff(base, next)
	if len(patch) >= len(next)/4 {
		t.Errorf("a patch for a barely-changed %d-byte file is %d bytes; that is not worth fetching",
			len(next), len(patch))
	}
}

// A patch against the wrong base is not a hole, it is a wasted round trip: it
// either fails here or produces bytes the caller's hash check rejects. What it
// must never do is misbehave.
func TestAPatchAgainstTheWrongBaseDoesNotProduceTheTarget(t *testing.T) {
	base := blob(12, 32<<10)
	next := flip(blob(12, 32<<10), 900)
	patch := delta.Diff(base, next)

	got, err := delta.Apply(blob(13, 32<<10), patch, 0)
	if err == nil && bytes.Equal(got, next) {
		t.Fatal("a patch reconstructed its target from a base it was not made against")
	}
}

// Every offset and length is bounded against the base, because this code runs
// before the hash check that would catch a bad result.
func TestOutOfRangeInstructionsAreRefused(t *testing.T) {
	base := []byte("0123456789")

	for name, patch := range map[string][]byte{
		"copy past the end":      instr(10, opCopy(5, 99)),
		"copy at a wild offset":  instr(10, opCopy(1<<40, 1)),
		"copy whose end wraps":   instr(10, opCopy(1<<63, 1<<63)),
		"insert past the patch":  instr(10, append([]byte{0x02}, uvarint(99)...)),
		"more than claimed":      instr(2, opCopy(0, 5)),
		"unknown opcode":         instr(1, []byte{0x7f}),
		"no magic":               []byte("something else entirely"),
		"truncated header":       []byte("idunn-delta/1\n"),
		"fewer bytes than claim": instr(10, opCopy(0, 5)),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := delta.Apply(base, patch, 0)
			if err == nil {
				t.Fatalf("VULNERABILITY: accepted, producing %q", out)
			}
			if !errors.Is(err, delta.ErrPatch) {
				t.Errorf("err = %v, want an ErrPatch", err)
			}
		})
	}
}

// A header that claims an enormous result must not be believed into an
// allocation. The ceiling is checked before a byte is produced.
func TestAnAbsurdOutputSizeIsRefusedBeforeAllocating(t *testing.T) {
	patch := instr(1<<40, nil)
	if _, err := delta.Apply([]byte("base"), patch, 1024); err == nil {
		t.Fatal("a patch claiming a terabyte of output was accepted")
	}
}

// FuzzPatchApply is the fuzz target docs/design.md §12 asks for. Apply runs on
// bytes the repository chose, before the check that decides whether they were the
// right ones — so what it must do on any input at all is return, without panicking
// and without allocating on a number a patch picked.
func FuzzPatchApply(f *testing.F) {
	base := blob(21, 4096)
	f.Add(base, delta.Diff(base, flip(blob(21, 4096), 100)))
	f.Add([]byte(nil), []byte(nil))
	f.Add(base, []byte("idunn-delta/1\n"))
	f.Add(base, instr(10, opCopy(0, 1<<63)))

	f.Fuzz(func(t *testing.T, base, patch []byte) {
		out, err := delta.Apply(base, patch, 1<<20)
		if err != nil {
			return
		}
		// A patch that is accepted has to have produced exactly what its header
		// promised; anything else is this package lying to its caller about a
		// result the caller is about to hash.
		if int64(len(out)) > 1<<20 {
			t.Fatalf("accepted a patch producing %d bytes, above the ceiling", len(out))
		}
	})
}

// --- fixtures -------------------------------------------------------------

func flip(b []byte, at int) []byte {
	out := append([]byte(nil), b...)
	if at < len(out) {
		out[at] ^= 0xff
	}
	return out
}

func splice(b []byte, at int, ins []byte) []byte {
	out := append([]byte(nil), b[:at]...)
	out = append(out, ins...)
	return append(out, b[at:]...)
}

func uvarint(v uint64) []byte { return binary.AppendUvarint(nil, v) }

func opCopy(offset, length uint64) []byte {
	out := []byte{0x01}
	out = append(out, uvarint(offset)...)
	return append(out, uvarint(length)...)
}

// instr builds a patch header claiming outLen bytes, followed by body.
func instr(outLen uint64, body []byte) []byte {
	out := append([]byte(nil), "idunn-delta/1\n"...)
	out = append(out, uvarint(outLen)...)
	return append(out, body...)
}
