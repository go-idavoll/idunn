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

// Package delta is the intra-file patch format of docs/design.md §6.4 stage 2:
// the instruction stream that turns one file into another, and the two halves
// that write and read it.
//
// # Why a format of our own
//
// The design named zstd --patch-from and bsdiff as candidates. Both would be a
// dependency in the apply path — the one place in this project where a bug is a
// bug in what lands on a user's disk — and both bring a decoder far larger than
// the problem. What is actually needed here is small: copy a run from the old
// file, or insert literal bytes, until the new file is complete. That is two
// instructions, and an apply that is a few dozen lines is one a reviewer can
// hold in their head and a fuzzer can cover exhaustively.
//
// The trade is compression ratio: a greedy matcher does not find what bsdiff's
// suffix sort finds. That trade is cheap here, because a worse patch costs
// bandwidth and nothing else — the result is checked against the signed target
// hash either way, and a patch that does not produce it is discarded in favour
// of the full download (§6.4).
//
// # Why the apply side is not a trust decision
//
// Nothing in this package decides whether bytes are acceptable. It produces
// candidate bytes; the caller hands them to the trust layer, which compares them
// against the signed hash exactly as it does a download. A hostile patch — one
// that reconstructs something other than the target — is not a hole, it is a
// wasted round trip (AGENTS.md §1.5).
//
// What this package *must* not do is misbehave on hostile input, because it runs
// before that check. Every offset and length is bounded against the base and the
// declared output size, the output is preallocated exactly once from a size the
// header states and the header is itself bounded, and there is no path that
// panics or allocates on a number a patch chose. It is the fuzz target
// FuzzPatchApply (§12).
package delta

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrPatch is the class of every rejection here: a patch that is not one, or one
// that does not describe a file this base can produce.
var ErrPatch = errors.New("delta patch")

// magic identifies the format and its version. A patch that does not begin with
// it is not read further — the byte after an unknown header means nothing, and
// guessing is how a format grows a second interpretation.
var magic = []byte("idunn-delta/1\n")

// The instruction set. Two opcodes, and no room for a third: an unknown opcode
// is a refusal, so a patch cannot carry an instruction a client of another
// version would skip.
const (
	opCopy = 0x01 // copy length bytes from the base at offset.
	opAdd  = 0x02 // insert the next length bytes literally.
)

// MaxOutput bounds the file a patch may claim to produce. It is the ceiling on
// what a header can make this package allocate, and it is deliberately checked
// against the caller's own limit too (see Apply).
//
// It is one below 2 GiB rather than 2 GiB exactly so that every length this
// package accepts also fits in an int on a 32-bit platform. That is not
// pedantry: the conversion from a patch-chosen uint64 to an index is the one
// place a number could wrap into something small and positive, and the bound is
// what makes it provably safe rather than probably safe.
const MaxOutput uint64 = 1<<31 - 1

// Apply reconstructs a file from base and patch.
//
// The result is a *candidate*. It is the caller's job — and only the caller's —
// to check it against the signed target hash before anything is written; this
// function has no idea what the answer should be, which is exactly why it cannot
// be talked into accepting the wrong one.
func Apply(base, patch []byte, maxOutput uint64) ([]byte, error) {
	if maxOutput == 0 || maxOutput > MaxOutput {
		maxOutput = MaxOutput
	}
	r := &reader{buf: patch}

	if !r.expect(magic) {
		return nil, fmt.Errorf("%w: not an idunn delta patch", ErrPatch)
	}
	outLen, ok := r.uvarint()
	if !ok {
		return nil, fmt.Errorf("%w: truncated header", ErrPatch)
	}
	if outLen > maxOutput {
		return nil, fmt.Errorf("%w: patch claims a %d-byte result, above the %d-byte ceiling",
			ErrPatch, outLen, maxOutput)
	}

	// One allocation, from a bounded number, and never grown: an instruction
	// stream cannot make this loop reallocate its way through memory.
	out := make([]byte, 0, outLen)

	for !r.done() {
		op, ok := r.byte()
		if !ok {
			return nil, fmt.Errorf("%w: truncated instruction", ErrPatch)
		}
		switch op {
		case opCopy:
			offset, n, ok := r.pair()
			if !ok {
				return nil, fmt.Errorf("%w: truncated copy", ErrPatch)
			}
			end := offset + n
			// The two-sided check matters: offset+n can wrap, and a wrapped
			// end that happens to land inside the base would be a read of
			// whatever precedes it.
			if end < offset || end > uint64(len(base)) {
				return nil, fmt.Errorf("%w: copy of %d bytes at %d is outside a %d-byte base",
					ErrPatch, n, offset, len(base))
			}
			if uint64(len(out))+n > outLen {
				return nil, fmt.Errorf("%w: the instructions produce more than the %d bytes claimed", ErrPatch, outLen)
			}
			out = append(out, base[offset:end]...)
		case opAdd:
			n, ok := r.uvarint()
			if !ok {
				return nil, fmt.Errorf("%w: truncated insert", ErrPatch)
			}
			if uint64(len(out))+n > outLen {
				return nil, fmt.Errorf("%w: the instructions produce more than the %d bytes claimed", ErrPatch, outLen)
			}
			lit, ok := r.take(n)
			if !ok {
				return nil, fmt.Errorf("%w: insert of %d bytes runs past the end of the patch", ErrPatch, n)
			}
			out = append(out, lit...)
		default:
			return nil, fmt.Errorf("%w: unknown opcode %#x", ErrPatch, op)
		}
	}

	if uint64(len(out)) != outLen {
		return nil, fmt.Errorf("%w: the instructions produced %d bytes, the header claimed %d",
			ErrPatch, len(out), outLen)
	}
	return out, nil
}

// reader walks a patch without ever indexing past it.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) done() bool { return r.pos >= len(r.buf) }

func (r *reader) expect(want []byte) bool {
	if len(r.buf)-r.pos < len(want) {
		return false
	}
	for i, b := range want {
		if r.buf[r.pos+i] != b {
			return false
		}
	}
	r.pos += len(want)
	return true
}

func (r *reader) byte() (byte, bool) {
	if r.done() {
		return 0, false
	}
	b := r.buf[r.pos]
	r.pos++
	return b, true
}

func (r *reader) uvarint() (uint64, bool) {
	v, n := binary.Uvarint(r.buf[r.pos:])
	if n <= 0 {
		return 0, false
	}
	r.pos += n
	return v, true
}

func (r *reader) pair() (a, b uint64, ok bool) {
	if a, ok = r.uvarint(); !ok {
		return 0, 0, false
	}
	if b, ok = r.uvarint(); !ok {
		return 0, 0, false
	}
	return a, b, true
}

func (r *reader) take(n uint64) ([]byte, bool) {
	// Bound first, convert second. n comes from the patch, and MaxOutput is
	// chosen so that anything at or below it fits in an int on every platform
	// this builds for — which is what makes the conversion below an identity
	// rather than a wrap.
	if n > MaxOutput {
		return nil, false
	}
	want := int(n) //nolint:gosec // G115: bounded by MaxOutput on the line above.
	if want > len(r.buf)-r.pos {
		return nil, false
	}
	out := r.buf[r.pos : r.pos+want]
	r.pos += want
	return out, true
}
