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

import "bytes"

// The rolling hash over a block. It is a plain polynomial in a prime base, which
// is enough for an anchor: a collision costs one wasted byte comparison, never a
// wrong patch — every candidate is compared byte for byte before it is used, and
// the reconstructed file is checked against its signed hash on the client.
const hashBase = 0x100000001b3

// hashPow is hashBase^(blockSize-1), the weight of the byte leaving the window.
var hashPow = func() uint64 {
	p := uint64(1)
	for range blockSize - 1 {
		p *= hashBase
	}
	return p
}()

func rollingHash(block []byte) uint64 {
	var h uint64
	for _, b := range block {
		h = h*hashBase + uint64(b)
	}
	return h
}

// roll moves the window one byte to the right: out leaves it, in joins it.
func roll(h uint64, out, in byte) uint64 {
	return (h-uint64(out)*hashPow)*hashBase + uint64(in)
}

// blockIndex maps the hash of a block-aligned stretch of the old file to where
// it starts. It is open-addressed with linear probing rather than a map: a
// several-hundred-megabyte input has millions of blocks, and a map of those
// costs several times the memory and gives nothing back here.
type blockIndex struct {
	mask   uint64
	hashes []uint64
	starts []int64 // start+1, so that a zero slot means "empty"
}

func indexBlocks(older []byte) *blockIndex {
	blocks := len(older) / blockSize
	size := uint64(8)
	for size < u64(blocks)*2 {
		size <<= 1
	}
	ix := &blockIndex{mask: size - 1, hashes: make([]uint64, size), starts: make([]int64, size)}
	for i := 0; i+blockSize <= len(older); i += blockSize {
		ix.insert(rollingHash(older[i:i+blockSize]), int64(i))
	}
	return ix
}

// insert records where a block first occurs. A repeat of the same content keeps
// the earlier position: anchors that stay in order keep the seeks between runs
// small, and the runs themselves are what carry the content.
func (ix *blockIndex) insert(h uint64, start int64) {
	for slot := h & ix.mask; ; slot = (slot + 1) & ix.mask {
		if ix.starts[slot] == 0 {
			ix.hashes[slot] = h
			ix.starts[slot] = start + 1
			return
		}
		if ix.hashes[slot] == h {
			return
		}
	}
}

// lookup returns where block occurs in older, if an anchor for it was recorded.
// The byte comparison is not an optimisation but the actual test: the hash only
// decides where to look.
func (ix *blockIndex) lookup(h uint64, older, block []byte) (int, bool) {
	for slot := h & ix.mask; ; slot = (slot + 1) & ix.mask {
		if ix.starts[slot] == 0 {
			return 0, false
		}
		if ix.hashes[slot] == h {
			at := int(ix.starts[slot] - 1)
			return at, bytes.Equal(older[at:at+blockSize], block)
		}
	}
}
