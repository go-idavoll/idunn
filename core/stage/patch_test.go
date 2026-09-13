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

package stage_test

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"testing"

	"github.com/go-idavoll/idunn/core/stage"
)

// builder assembles a patch in the container ApplyPatch reads. It is written out
// by hand rather than taken from the generator so that these tests pin the
// format itself: if the reader ever starts accepting something else, this is
// where it shows.
type builder struct {
	newLen uint64
	ctrl   []byte
	diff   []byte
	extra  []byte

	// Overrides for the malformed cases. A nil override means "as built".
	magic     string
	rawCtrl   []byte
	rawDiff   []byte
	rawExtra  []byte
	ctrlLen   *uint64
	diffLen   *uint64
	declared  *uint64
	truncated int
}

// add appends one control triple: n bytes taken from the difference stream, m
// from the literal stream, and a move of the base read position afterwards.
func (b *builder) add(n, m uint64, seek int64) *builder {
	var buf [24]byte
	binary.LittleEndian.PutUint64(buf[0:8], n)
	binary.LittleEndian.PutUint64(buf[8:16], m)
	binary.LittleEndian.PutUint64(buf[16:24], uint64(seek))
	b.ctrl = append(b.ctrl, buf[:]...)
	return b
}

func deflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := flate.NewWriter(&out, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return out.Bytes()
}

func (b *builder) build(t *testing.T) []byte {
	t.Helper()
	magic := "IDNDELT1"
	if b.magic != "" {
		magic = b.magic
	}
	ctrl, diff, extra := deflate(t, b.ctrl), deflate(t, b.diff), deflate(t, b.extra)
	if b.rawCtrl != nil {
		ctrl = b.rawCtrl
	}
	if b.rawDiff != nil {
		diff = b.rawDiff
	}
	if b.rawExtra != nil {
		extra = b.rawExtra
	}

	declared, ctrlLen, diffLen := b.newLen, uint64(len(ctrl)), uint64(len(diff))
	if b.declared != nil {
		declared = *b.declared
	}
	if b.ctrlLen != nil {
		ctrlLen = *b.ctrlLen
	}
	if b.diffLen != nil {
		diffLen = *b.diffLen
	}

	out := make([]byte, 0, len(magic)+24+len(ctrl)+len(diff)+len(extra))
	out = append(out, magic...)
	out = binary.LittleEndian.AppendUint64(out, declared)
	out = binary.LittleEndian.AppendUint64(out, ctrlLen)
	out = binary.LittleEndian.AppendUint64(out, diffLen)
	out = append(out, ctrl...)
	out = append(out, diff...)
	out = append(out, extra...)
	if b.truncated > 0 && b.truncated < len(out) {
		out = out[:len(out)-b.truncated]
	}
	return out
}

// diffBytes is the difference stream for a run: what has to be added to the base
// bytes, byte by byte, to get the wanted output. Wrapping is the point — this is
// the arithmetic the reader performs.
func diffBytes(want, base []byte) []byte {
	out := make([]byte, len(want))
	for i := range want {
		out[i] = want[i] - base[i]
	}
	return out
}

func ptr[T any](v T) *T { return &v }

// The three shapes a delta is made of: a run that follows the base, a run of
// content the base does not have, and a jump backwards or forwards in the base.
func TestApplyPatchReconstructsATarget(t *testing.T) {
	base := []byte("the quick brown fox jumps over the lazy dog")

	for _, tc := range []struct {
		name  string
		want  []byte
		build func(*builder, []byte)
	}{
		{
			name: "an unchanged file",
			want: base,
			build: func(b *builder, want []byte) {
				b.diff = diffBytes(want, base)
				b.add(uint64(len(want)), 0, 0)
			},
		},
		{
			name: "a byte changed in place",
			want: []byte("the quick brown FOX jumps over the lazy dog"),
			build: func(b *builder, want []byte) {
				b.diff = diffBytes(want, base)
				b.add(uint64(len(want)), 0, 0)
			},
		},
		{
			name: "content inserted, shifting the rest",
			want: []byte("the quick brown and clever fox jumps over the lazy dog"),
			build: func(b *builder, want []byte) {
				const head = len("the quick brown ")
				b.diff = append(b.diff, diffBytes(want[:head], base[:head])...)
				b.extra = []byte("and clever ")
				b.add(uint64(head), uint64(len(b.extra)), 0)
				tail := want[head+len(b.extra):]
				b.diff = append(b.diff, diffBytes(tail, base[head:])...)
				b.add(uint64(len(tail)), 0, 0)
			},
		},
		{
			name: "a run repeated from earlier in the base",
			want: []byte("the quick the quick"),
			build: func(b *builder, want []byte) {
				b.diff = append(b.diff, diffBytes(want[:10], base[:10])...)
				b.add(10, 0, -10) // back to the start of the base
				b.diff = append(b.diff, diffBytes(want[10:], base[:9])...)
				b.add(9, 0, 0)
			},
		},
		{
			name: "nothing but literals, with no base at all",
			want: []byte("a wholly new file"),
			build: func(b *builder, want []byte) {
				b.extra = want
				b.add(0, uint64(len(want)), 0)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &builder{newLen: uint64(len(tc.want))}
			tc.build(b, tc.want)

			got, err := stage.ApplyPatch(base, b.build(t), int64(len(tc.want)))
			if err != nil {
				t.Fatalf("ApplyPatch: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A patch is untrusted input from the network with no signature of its own, so
// every one of these has to be a rejection rather than a surprise. The output is
// verified against the signed hash afterwards either way — but a parser that can
// be talked into an unbounded allocation, a read out of range, or a loop that
// never ends is a defect before verification ever gets a say.
func TestApplyPatchRefusesMalformedInput(t *testing.T) {
	base := []byte("the quick brown fox jumps over the lazy dog")
	const maxOut = 64

	// A well-formed patch of the same shape, for the cases that tamper with one
	// field of an otherwise valid document.
	valid := func() *builder {
		b := &builder{newLen: uint64(len(base))}
		b.diff = diffBytes(base, base)
		return b.add(uint64(len(base)), 0, 0)
	}

	for _, tc := range []struct {
		name  string
		patch func() []byte
	}{
		{
			name:  "empty",
			patch: func() []byte { return nil },
		},
		{
			name:  "shorter than the header",
			patch: func() []byte { return []byte("IDNDELT1\x00\x00") },
		},
		{
			name: "another format's magic",
			patch: func() []byte {
				b := valid()
				b.magic = "BSDIFF40"
				return b.build(t)
			},
		},
		{
			name: "an output longer than the target",
			patch: func() []byte {
				b := valid()
				b.declared = ptr(uint64(maxOut + 1))
				return b.build(t)
			},
		},
		{
			name: "an output of gigabytes over a few bytes of patch",
			patch: func() []byte {
				b := valid()
				b.declared = ptr(uint64(1) << 40)
				return b.build(t)
			},
		},
		{
			name: "an output length that does not fit a signed integer",
			patch: func() []byte {
				b := valid()
				b.declared = ptr(uint64(1) << 63)
				return b.build(t)
			},
		},
		{
			name: "a control stream length that does not fit a signed integer",
			patch: func() []byte {
				b := valid()
				b.ctrlLen = ptr(uint64(1) << 63)
				return b.build(t)
			},
		},
		{
			name: "a difference stream length that does not fit a signed integer",
			patch: func() []byte {
				b := valid()
				b.diffLen = ptr(uint64(1) << 63)
				return b.build(t)
			},
		},
		{
			name: "a difference run that does not fit a signed integer",
			patch: func() []byte {
				b := &builder{newLen: 4}
				return b.add(uint64(1)<<63, 0, 0).build(t)
			},
		},
		{
			name: "a literal run that does not fit a signed integer",
			patch: func() []byte {
				b := &builder{newLen: 4}
				return b.add(0, uint64(1)<<63, 0).build(t)
			},
		},
		{
			name: "a control stream longer than the patch",
			patch: func() []byte {
				b := valid()
				b.ctrlLen = ptr(uint64(1) << 40)
				return b.build(t)
			},
		},
		{
			name: "a difference stream longer than what is left",
			patch: func() []byte {
				b := valid()
				b.diffLen = ptr(uint64(1) << 40)
				return b.build(t)
			},
		},
		{
			name: "streams that are not deflate at all",
			patch: func() []byte {
				b := valid()
				b.rawCtrl = []byte("not compressed")
				return b.build(t)
			},
		},
		{
			name: "a control entry that produces nothing",
			patch: func() []byte {
				b := &builder{newLen: uint64(len(base))}
				return b.add(0, 0, 1).build(t)
			},
		},
		{
			name: "a difference run past the end of the output",
			patch: func() []byte {
				b := &builder{newLen: 4}
				b.diff = diffBytes(base[:8], base[:8])
				return b.add(8, 0, 0).build(t)
			},
		},
		{
			name: "a difference run past the end of the base",
			patch: func() []byte {
				b := &builder{newLen: uint64(len(base) + 8)}
				b.diff = make([]byte, len(base)+8)
				return b.add(uint64(len(base)+8), 0, 0).build(t)
			},
		},
		{
			name: "a literal run past the end of the output",
			patch: func() []byte {
				b := &builder{newLen: 4}
				b.extra = []byte("longer than four")
				return b.add(0, uint64(len(b.extra)), 0).build(t)
			},
		},
		{
			name: "a difference stream that ends early",
			patch: func() []byte {
				b := &builder{newLen: 8}
				b.diff = []byte{0, 0, 0}
				return b.add(8, 0, 0).build(t)
			},
		},
		{
			name: "a literal stream that ends early",
			patch: func() []byte {
				b := &builder{newLen: 8}
				b.extra = []byte("abc")
				return b.add(0, 8, 0).build(t)
			},
		},
		{
			name: "a control stream that ends early",
			patch: func() []byte {
				b := &builder{newLen: 8}
				b.ctrl = []byte{1, 2, 3}
				return b.build(t)
			},
		},
		{
			name: "a seek before the start of the base",
			patch: func() []byte {
				b := &builder{newLen: 4}
				b.diff = diffBytes(base[:4], base[:4])
				return b.add(4, 0, -10).build(t)
			},
		},
		{
			name: "a seek past the end of the base",
			patch: func() []byte {
				b := &builder{newLen: 4}
				b.diff = diffBytes(base[:4], base[:4])
				return b.add(4, 0, int64(len(base))).build(t)
			},
		},
		{
			name: "a seek that overflows",
			patch: func() []byte {
				b := &builder{newLen: 4}
				b.diff = diffBytes(base[:4], base[:4])
				return b.add(4, 0, math.MaxInt64).build(t)
			},
		},
		{
			name: "trailing control entries",
			patch: func() []byte {
				b := valid()
				return b.add(1, 0, 0).build(t)
			},
		},
		{
			name: "trailing difference bytes",
			patch: func() []byte {
				b := valid()
				b.diff = append(b.diff, 0, 0, 0)
				return b.build(t)
			},
		},
		{
			name: "trailing literal bytes",
			patch: func() []byte {
				b := valid()
				b.extra = []byte("left over")
				return b.build(t)
			},
		},
		{
			name: "bytes after the last stream",
			patch: func() []byte {
				return append(valid().build(t), 0x00, 0x01, 0x02)
			},
		},
		{
			name: "bytes between two streams",
			patch: func() []byte {
				b := valid()
				b.rawCtrl = append(deflate(t, b.ctrl), 0xff)
				return b.build(t)
			},
		},
		{
			name: "truncated mid-stream",
			patch: func() []byte {
				b := valid()
				b.truncated = 3
				return b.build(t)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stage.ApplyPatch(base, tc.patch(), maxOut)
			if err == nil {
				t.Fatalf("accepted a malformed patch, producing %d bytes", len(got))
			}
			if !errors.Is(err, stage.ErrStage) {
				t.Fatalf("err = %v, want ErrStage", err)
			}
			if got != nil {
				t.Fatalf("returned %d bytes beside the error", len(got))
			}
		})
	}
}

// Without a bound there is no answer to "how much may this allocate", so there
// is no patch to apply either.
func TestApplyPatchRefusesToWorkWithoutABound(t *testing.T) {
	for _, maxOut := range []int64{0, -1, math.MinInt64} {
		if _, err := stage.ApplyPatch(nil, nil, maxOut); !errors.Is(err, stage.ErrStage) {
			t.Fatalf("maxOut %d: err = %v, want ErrStage", maxOut, err)
		}
	}
}

// FuzzPatchApply is the fuzz target docs/design.md §12 asks for: arbitrary bytes
// in the place of a patch must end in an error, never a panic, never an
// allocation past the bound, and never a hang.
func FuzzPatchApply(f *testing.F) {
	base := []byte("the quick brown fox jumps over the lazy dog")
	valid := &builder{newLen: uint64(len(base))}
	valid.diff = diffBytes(base, base)
	valid.add(uint64(len(base)), 0, 0)

	literals := &builder{newLen: 5, extra: []byte("hello")}
	literals.add(0, 5, 0)

	f.Add(base, valid.build(&testing.T{}))
	f.Add(base, literals.build(&testing.T{}))
	f.Add([]byte(nil), []byte("IDNDELT1"))
	f.Add(base, []byte(nil))

	const maxOut = 1 << 16
	f.Fuzz(func(t *testing.T, base, patch []byte) {
		out, err := stage.ApplyPatch(base, patch, maxOut)
		if err != nil {
			if out != nil {
				t.Fatalf("returned %d bytes with an error", len(out))
			}
			return
		}
		if len(out) > maxOut {
			t.Fatalf("produced %d bytes, past the bound of %d", len(out), maxOut)
		}
	})
}

// A patch is only ever a cheaper way to obtain bytes that are then checked
// against the signed hash. This is the property that makes that split safe: the
// same patch against a different base produces different output, and it is the
// verification afterwards — not this function — that notices.
func TestApplyPatchAgainstTheWrongBaseIsNotDetectedHere(t *testing.T) {
	base := []byte("the quick brown fox jumps over the lazy dog")
	want := []byte("the quick brown FOX jumps over the lazy dog")

	b := &builder{newLen: uint64(len(want))}
	b.diff = diffBytes(want, base)
	b.add(uint64(len(want)), 0, 0)
	patch := b.build(t)

	other := append([]byte(nil), base...)
	other[0] = 'T'

	got, err := stage.ApplyPatch(other, patch, int64(len(want)))
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	if bytes.Equal(got, want) {
		t.Fatal("the wrong base produced the right bytes, which would make the test vacuous")
	}
}

// A run of realistic shapes: the reader must reproduce exactly what the
// difference and literal streams describe, whatever mix of them a generator
// happens to emit.
func TestApplyPatchOnGeneratedShapes(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := range 200 {
		size := 1 + rng.Intn(4096)
		base := make([]byte, size)
		rng.Read(base)

		want := append([]byte(nil), base...)
		for j := 0; j < rng.Intn(8); j++ {
			want[rng.Intn(size)] ^= byte(1 + rng.Intn(255))
		}
		if rng.Intn(2) == 0 {
			cut := rng.Intn(size)
			want = append(want[:cut], append([]byte("inserted"), want[cut:]...)...)
		}

		// One difference run over the common prefix, the rest as literals.
		common := min(len(base), len(want))
		b := &builder{newLen: uint64(len(want))}
		b.diff = diffBytes(want[:common], base[:common])
		b.extra = want[common:]
		b.add(uint64(common), uint64(len(want)-common), 0)

		got, err := stage.ApplyPatch(base, b.build(t), int64(len(want)))
		if err != nil {
			t.Fatalf("case %d: ApplyPatch: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: reconstructed the wrong bytes", i)
		}
	}
}
