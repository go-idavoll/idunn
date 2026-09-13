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

// Package delta builds the intra-file binary patches core/stage applies
// (docs/design.md §6.4 stage 2).
//
// It is deliberately not in core. Producing a patch is a packer job that runs
// once per release on a build machine; applying one runs on every user's
// machine against bytes an attacker chose. Only the second half belongs in the
// trust path, and only the second half has to be small enough to audit.
//
// The generator may be replaced by a better one at any time — a patch is only a
// cheaper way to obtain bytes that are checked against their signed hash
// afterwards, so a worse patch costs bandwidth and nothing else. What must not
// change silently is the container, which core/stage pins.
package delta

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
)

// The container core/stage reads. Kept as literals rather than shared constants
// because the two sides are deliberately independent: the reader must not learn
// the format from the writer.
const (
	magic      = "IDNDELT1"
	controlLen = 24
)

// How the matcher looks for common ground.
const (
	// blockSize is the length of an anchor. Long enough that a random collision
	// is not worth defending against beyond the byte comparison that follows,
	// short enough to find the unchanged stretches between two builds of the
	// same binary.
	blockSize = 64

	// window and windowMatches govern how far a run is carried past the point
	// where the two files stop being identical. Differences inside a run cost
	// one non-zero byte each and compress away; ending the run costs a control
	// entry, a literal run, and the chance to keep tracking the base. So a run
	// continues while at least half of the next window still agrees, which is
	// what absorbs the scattered pointer changes of a recompiled binary.
	window        = 32
	windowMatches = window / 2
)

// Diff returns a patch that reconstructs newer from older.
//
// The result is always a valid patch, including when the two files have nothing
// in common — then it is simply the whole of newer as literals, and the caller
// decides by size whether publishing it is worth anything.
func Diff(older, newer []byte) ([]byte, error) {
	return encode(older, newer, matches(older, newer))
}

// match is a stretch of newer that is described by reading older from oldStart:
// mostly identical, with whatever differences the run absorbed.
type match struct {
	newStart, oldStart, length int
}

// matches finds the stretches of newer worth describing in terms of older.
//
// It anchors on identical blocks — every block-aligned position of older goes
// into a hash table, and newer is scanned with a rolling hash — and then grows
// each anchor in both directions for as long as the two files keep roughly
// agreeing. A suffix array would find more, at a cost in memory that a build
// machine feels on a several-hundred-megabyte binary; the container does not
// care which of the two produced the runs.
func matches(older, newer []byte) []match {
	if len(older) < blockSize || len(newer) < blockSize {
		return nil
	}
	idx := indexBlocks(older)

	var found []match
	// covered is how much of newer is already described, so a run never
	// overlaps the one before it.
	covered := 0
	h := rollingHash(newer[:blockSize])
	for i := 0; ; {
		if i >= covered {
			if at, ok := idx.lookup(h, older, newer[i:i+blockSize]); ok {
				m := grow(older, newer, at, i, covered)
				found = append(found, m)
				covered = m.newStart + m.length
			}
		}
		if i+blockSize >= len(newer) {
			break
		}
		h = roll(h, newer[i], newer[i+blockSize])
		i++
	}
	return found
}

// grow extends an anchor backwards to the end of the previous run and forwards
// to the end of either file, for as long as the two keep agreeing.
func grow(older, newer []byte, oldAt, newAt, covered int) match {
	start, oldStart := newAt, oldAt
	for start > covered && oldStart > 0 && newer[start-1] == older[oldStart-1] {
		start--
		oldStart--
	}

	end, oldEnd := newAt+blockSize, oldAt+blockSize
	last := end // the last position at which the two actually agreed
	for end < len(newer) && oldEnd < len(older) {
		n := min(window, min(len(newer)-end, len(older)-oldEnd))
		agree := 0
		for k := range n {
			if newer[end+k] == older[oldEnd+k] {
				agree++
			}
		}
		if agree*window < windowMatches*n {
			break
		}
		for k := range n {
			if newer[end+k] == older[oldEnd+k] {
				last = end + k + 1
			}
		}
		end += n
		oldEnd += n
	}
	return match{newStart: start, oldStart: oldStart, length: last - start}
}

// encode writes the runs and everything between them into the container.
func encode(older, newer []byte, found []match) ([]byte, error) {
	var ctrl, diff, extra bytes.Buffer

	newPos, basePos := 0, 0
	for i, m := range found {
		// The base has to be at the start of the run before the run can be
		// written, and the format only moves it at the end of a control entry.
		// So a leading entry carries the literals before the run and the seek;
		// when there are no literals to carry, one byte of the run becomes a
		// literal, because an entry that produces nothing is refused by the
		// reader — rightly, since it is how a patch would loop forever.
		if gap := m.newStart - newPos; gap > 0 || basePos != m.oldStart {
			if gap == 0 {
				extra.WriteByte(newer[m.newStart])
				m.newStart++
				m.oldStart++
				m.length--
				gap = 1
			} else {
				extra.Write(newer[newPos : newPos+gap])
			}
			control(&ctrl, 0, gap, m.oldStart-basePos)
			newPos += gap
			basePos = m.oldStart
		}

		for k := range m.length {
			diff.WriteByte(newer[m.newStart+k] - older[m.oldStart+k])
		}
		newPos += m.length
		basePos += m.length

		// Everything up to the next run — or to the end of the file — is
		// carried as literals by this entry, together with the seek that lands
		// the base on the next run.
		tail := len(newer)
		seek := 0
		if i+1 < len(found) {
			tail = found[i+1].newStart
			seek = found[i+1].oldStart - basePos
		}
		extra.Write(newer[newPos:tail])
		control(&ctrl, m.length, tail-newPos, seek)
		newPos = tail
		basePos += seek
	}
	if newPos < len(newer) {
		extra.Write(newer[newPos:])
		control(&ctrl, 0, len(newer)-newPos, 0)
	}

	return assemble(len(newer), ctrl.Bytes(), diff.Bytes(), extra.Bytes())
}

// control appends one entry: bytes to take from the difference stream, bytes to
// take from the literal stream, and how far to move the base afterwards.
func control(buf *bytes.Buffer, add, literal, seek int) {
	var out [controlLen]byte
	binary.LittleEndian.PutUint64(out[0:8], u64(add))
	binary.LittleEndian.PutUint64(out[8:16], u64(literal))
	binary.LittleEndian.PutUint64(out[16:24], u64(seek))
	buf.Write(out[:])
}

// u64 reinterprets a machine int as the 64 unsigned bits everything here counts
// in. Run lengths and slice lengths cannot be negative; a seek is signed on
// purpose and goes out in two's complement, which is exactly how the reader
// takes it back apart.
//
//nolint:gosec // G115: the reinterpretation is the encoding.
func u64(n int) uint64 { return uint64(n) }

// assemble compresses the three streams and writes the header in front of them.
func assemble(newLen int, ctrl, diff, extra []byte) ([]byte, error) {
	parts := make([][]byte, 0, 3)
	for _, raw := range [][]byte{ctrl, diff, extra} {
		var out bytes.Buffer
		w, err := flate.NewWriter(&out, flate.BestCompression)
		if err != nil {
			return nil, fmt.Errorf("delta: %w", err)
		}
		if _, err := w.Write(raw); err != nil {
			return nil, fmt.Errorf("delta: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("delta: %w", err)
		}
		parts = append(parts, out.Bytes())
	}

	patch := make([]byte, 0, len(magic)+24+len(parts[0])+len(parts[1])+len(parts[2]))
	patch = append(patch, magic...)
	patch = binary.LittleEndian.AppendUint64(patch, u64(newLen))
	patch = binary.LittleEndian.AppendUint64(patch, u64(len(parts[0])))
	patch = binary.LittleEndian.AppendUint64(patch, u64(len(parts[1])))
	for _, p := range parts {
		patch = append(patch, p...)
	}
	return patch, nil
}
