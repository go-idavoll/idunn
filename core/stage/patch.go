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

package stage

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/go-idavoll/idunn/core/fsx"
)

// The delta patch container (docs/design.md §6.4 stage 2).
//
// It is the bsdiff arrangement — a control stream of runs, a stream of
// byte-wise differences against the base, and a stream of literals — in a
// container of our own so that the client half is a few hundred lines of the
// standard library instead of a dependency in the trust path. The three streams
// are deflate-compressed, which is what makes the difference stream nearly free:
// for a recompiled binary it is mostly zeros.
//
// A patch is not trusted, signed, or authenticated in any way. It is a hint
// about how to spend fewer bytes on the network, and the only thing that decides
// whether its output may be installed is the TUF-signed hash of the result. This
// parser therefore has exactly one job beyond decoding: never to be talked into
// an allocation, a read, or a write it was not told the size of.
const (
	// patchMagic identifies the container and its version. A patch that does
	// not start with exactly this is refused rather than guessed at, so a
	// future version can change the layout without any risk of a v1 client
	// half-understanding it.
	patchMagic = "IDNDELT1"

	// patchHeaderLen is magic + the length of the output + the compressed
	// lengths of the control and difference streams. The literal stream is
	// whatever follows them, so exactly one length is implicit and cannot
	// disagree with the others.
	patchHeaderLen = len(patchMagic) + 8 + 8 + 8

	// streamBufferSize is how much of a compressed stream is read ahead at a
	// time. It is small: the three streams are read in lockstep, so three of
	// these exist at once, and a patch is by construction smaller than the file
	// it rebuilds.
	streamBufferSize = 32 << 10

	// patchControlLen is one control triple: how many bytes to take from the
	// difference stream, how many from the literal stream, and how far to move
	// the read position in the base afterwards.
	patchControlLen = 8 + 8 + 8
)

// ApplyPatch reconstructs a target from a base file and a delta patch held in
// memory, refusing to produce more than maxOut bytes.
//
// It is the buffered form of ApplyPatchStream and exists for the callers that
// genuinely have both sides in memory — the packer's round-trip check and the
// fuzz target. The staging path uses the streaming form: holding a base, a patch
// and an output at once is three allocations the size of a payload, which for a
// release whose bulk is a browser runtime is the memory this whole layer exists
// to avoid (IDN-12).
//
// The result is only a candidate: the caller must check it against the signed
// target hash before anything is installed, and a patch that reconstructs the
// wrong bytes is caught there, not here.
//
// It is the fuzz target FuzzPatchApply (§12) and must never panic, allocate
// beyond maxOut, or fail to terminate.
func ApplyPatch(base, patch []byte, maxOut int64) ([]byte, error) {
	out := &cappedBuffer{limit: maxOut}
	if err := ApplyPatchStream(bytes.NewReader(base), int64(len(base)),
		bytes.NewReader(patch), int64(len(patch)), out, maxOut); err != nil {
		return nil, err
	}
	return out.b, nil
}

// cappedBuffer collects the output of a streaming apply without ever growing
// past the bound the caller declared. ApplyPatchStream never writes more than
// maxOut, so the cap is a second lock on the same door rather than a behaviour —
// but it is the door the fuzzer rattles.
type cappedBuffer struct {
	b     []byte
	limit int64
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if int64(len(c.b))+int64(len(p)) > c.limit {
		return 0, fmt.Errorf("%w: patch: output past the %d-byte bound", ErrStage, c.limit)
	}
	c.b = append(c.b, p...)
	return len(p), nil
}

// ApplyPatchStream reconstructs a target from a base file and a delta patch
// without holding any of the three in memory.
//
// base is read at offsets because a delta walks backwards through it as often as
// forwards; patch is read at offsets because its three streams are consumed
// together, not one after another. out receives the reconstruction sequentially,
// which is what lets it be the scratch file of an atomic write with a verifier
// teed into it: the bytes are checked as they land and the file is promoted only
// if they were right.
//
// maxOut is the signed length of the target the caller is trying to build, so a
// patch that claims a longer output is refused before a single byte is read.
// Nothing here ever produces more than the header declared and the base can
// supply: every run is bounded by what is left of the output and by what is left
// of the base, and a run that advances neither is refused rather than looped on.
//
// Like ApplyPatch, it decides nothing about trust. Its output is a candidate the
// caller must put to the signed hash.
func ApplyPatchStream(base io.ReaderAt, baseLen int64, patch io.ReaderAt, patchLen int64, out io.Writer, maxOut int64) error {
	if maxOut <= 0 {
		return fmt.Errorf("%w: patch: no output bound", ErrStage)
	}
	if baseLen < 0 || patchLen < 0 {
		return fmt.Errorf("%w: patch: negative input length", ErrStage)
	}
	ctrlRaw, diffRaw, extraRaw, newLen, err := splitPatch(patch, patchLen, maxOut)
	if err != nil {
		return err
	}

	ctrl, diff, extra := newStream(ctrlRaw), newStream(diffRaw), newStream(extraRaw)
	defer func() { _, _ = ctrl.Close(), diff.Close() }()
	defer func() { _ = extra.Close() }()

	buf := make([]byte, fsx.CopyBufferSize)
	var newPos, basePos int64
	for newPos < newLen {
		add, literal, seek, err := readControl(ctrl)
		if err != nil {
			return err
		}
		// A triple that produces no output cannot be the reason the loop runs
		// again. Refusing it is what makes termination a property of the
		// format rather than of the patch we happen to have been handed.
		if add == 0 && literal == 0 {
			return fmt.Errorf("%w: patch: a control entry that produces nothing", ErrStage)
		}

		if err := addRun(out, base, baseLen, diff, add, &newPos, &basePos, newLen, buf); err != nil {
			return err
		}
		if err := literalRun(out, extra, literal, &newPos, newLen, buf); err != nil {
			return err
		}

		next := basePos + seek
		if (seek > 0) != (next > basePos) && seek != 0 {
			return fmt.Errorf("%w: patch: base position overflows", ErrStage)
		}
		if next < 0 || next > baseLen {
			return fmt.Errorf("%w: patch: seek leaves the base file", ErrStage)
		}
		basePos = next
	}

	// Everything the patch declared has been spent, so every stream must now be
	// at a clean end: no bytes left over, and no stream that turns out not to
	// decompress after all. Both mean the patch says something this reader did
	// not act on, which is the kind of "understood most of it" that fails
	// closed here — including for a stream the control entries never used.
	for _, s := range []struct {
		name string
		s    *stream
	}{{"control", ctrl}, {"difference", diff}, {"literal", extra}} {
		if n, err := s.s.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: patch: the %s stream does not end cleanly", ErrStage, s.name)
		}
		if rest := s.s.unread(); rest != 0 {
			return fmt.Errorf("%w: patch: %d bytes follow the %s stream", ErrStage, rest, s.name)
		}
	}
	return nil
}

// stream is one of the three deflate streams of a patch, decompressed from a
// view of the patch container.
//
// The buffer in the middle is not an optimisation to taste: flate drives its
// input a byte at a time through io.ByteReader, which an io.SectionReader does
// not implement, so without one flate would wrap it in a buffer of its own —
// and that buffer is invisible, which would cost the check that no bytes follow
// a stream. Owning the buffer is how "how much did the decompressor actually
// use" stays answerable (see unread).
type stream struct {
	io.ReadCloser
	sec *io.SectionReader
	buf *bufio.Reader
}

func newStream(sec *io.SectionReader) *stream {
	buf := bufio.NewReaderSize(sec, streamBufferSize)
	return &stream{ReadCloser: flate.NewReader(buf), sec: sec, buf: buf}
}

// unread is how many compressed bytes of this stream the decompressor never
// consumed: what the section still holds, plus what was read ahead into the
// buffer and handed on to nobody.
func (s *stream) unread() int64 {
	off, err := s.sec.Seek(0, io.SeekCurrent)
	if err != nil {
		// Unreachable for a SectionReader seeking to where it already is;
		// reporting "something is left" keeps the caller failing closed.
		return 1
	}
	return s.sec.Size() - off + int64(s.buf.Buffered())
}

// addRun writes the next n bytes of output as base bytes plus the byte-wise
// differences the patch carries for them. This is the run that makes a delta
// worth having: for a rebuilt binary most of these differences are zero.
//
// It works through buf, so a run spanning a whole payload costs the window and
// not the payload.
func addRun(out io.Writer, base io.ReaderAt, baseLen int64, diff io.Reader, n int64, newPos, basePos *int64, newLen int64, buf []byte) error {
	if n > newLen-*newPos {
		return fmt.Errorf("%w: patch: a difference run runs past the end of the output", ErrStage)
	}
	if n > baseLen-*basePos {
		return fmt.Errorf("%w: patch: a difference run runs past the end of the base file", ErrStage)
	}
	for n > 0 {
		span := buf[:min(n, int64(len(buf)))]
		if _, err := io.ReadFull(diff, span); err != nil {
			return fmt.Errorf("%w: patch: difference stream: %w", ErrStage, err)
		}
		if err := addBase(span, base, *basePos); err != nil {
			return err
		}
		if _, err := out.Write(span); err != nil {
			return fmt.Errorf("%w: patch: %w", ErrStage, err)
		}
		*newPos += int64(len(span))
		*basePos += int64(len(span))
		n -= int64(len(span))
	}
	return nil
}

// addBase adds the base bytes at off into span, one window at a time.
//
// The base is read through a second buffer rather than in place, because span
// already holds the differences that are about to be added to it: a ReadAt into
// span would overwrite them.
func addBase(span []byte, base io.ReaderAt, off int64) error {
	var window [4 << 10]byte
	for done := 0; done < len(span); {
		chunk := window[:min(len(span)-done, len(window))]
		if _, err := base.ReadAt(chunk, off+int64(done)); err != nil {
			return fmt.Errorf("%w: patch: base file: %w", ErrStage, err)
		}
		for i := range chunk {
			span[done+i] += chunk[i]
		}
		done += len(chunk)
	}
	return nil
}

// literalRun writes the next n bytes of output straight from the patch: the
// content that has no counterpart in the base file at all.
func literalRun(out io.Writer, extra io.Reader, n int64, newPos *int64, newLen int64, buf []byte) error {
	if n > newLen-*newPos {
		return fmt.Errorf("%w: patch: a literal run runs past the end of the output", ErrStage)
	}
	for n > 0 {
		span := buf[:min(n, int64(len(buf)))]
		if _, err := io.ReadFull(extra, span); err != nil {
			return fmt.Errorf("%w: patch: literal stream: %w", ErrStage, err)
		}
		if _, err := out.Write(span); err != nil {
			return fmt.Errorf("%w: patch: %w", ErrStage, err)
		}
		*newPos += int64(len(span))
		n -= int64(len(span))
	}
	return nil
}

// readControl reads one control triple. The two run lengths arrive as unsigned
// 64-bit values and are refused unless they fit a signed one, so everything
// downstream is ordinary signed arithmetic that cannot wrap into a valid-looking
// bound.
func readControl(ctrl io.Reader) (add, literal, seek int64, err error) {
	var buf [patchControlLen]byte
	if _, err := io.ReadFull(ctrl, buf[:]); err != nil {
		return 0, 0, 0, fmt.Errorf("%w: patch: control stream: %w", ErrStage, err)
	}
	add, err = asLength(binary.LittleEndian.Uint64(buf[0:8]))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%w: patch: difference run: %w", ErrStage, err)
	}
	literal, err = asLength(binary.LittleEndian.Uint64(buf[8:16]))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%w: patch: literal run: %w", ErrStage, err)
	}
	// The seek is signed on purpose: a delta walks backwards through the base
	// as often as forwards, so reinterpreting the 64 bits is the decoding
	// itself. Where it lands is checked against the base by the caller.
	//nolint:gosec // G115: a deliberate two's complement reinterpretation.
	seek = int64(binary.LittleEndian.Uint64(buf[16:24]))
	return add, literal, seek, nil
}

// asLength converts a length off the wire, refusing one that does not fit a
// signed 64-bit integer. Such a value cannot describe a real file; accepting it
// would only mean carrying a number that wraps when it meets a bound.
func asLength(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, errors.New("a length no file can have")
	}
	return int64(v), nil
}

// splitPatch validates the header and hands back the three compressed streams
// as independent views of the patch, plus the declared output length.
//
// Every length is checked against the patch that actually arrived before it is
// used for anything, so a header claiming megabytes over a few bytes of data is
// an error here rather than a read that runs off the end.
func splitPatch(patch io.ReaderAt, patchLen, maxOut int64) (ctrl, diff, extra *io.SectionReader, newLen int64, err error) {
	fail := func(format string, args ...any) (*io.SectionReader, *io.SectionReader, *io.SectionReader, int64, error) {
		return nil, nil, nil, 0, fmt.Errorf("%w: patch: "+format, append([]any{ErrStage}, args...)...)
	}
	if patchLen < int64(patchHeaderLen) {
		return fail("shorter than its header")
	}
	var head [patchHeaderLen]byte
	if _, err := patch.ReadAt(head[:], 0); err != nil {
		return fail("header: %w", err)
	}
	if string(head[:len(patchMagic)]) != patchMagic {
		return fail("not an idunn delta patch")
	}
	h := head[len(patchMagic):]
	declared, err := asLength(binary.LittleEndian.Uint64(h[0:8]))
	if err != nil {
		return fail("output length: %w", err)
	}
	ctrlLen, err := asLength(binary.LittleEndian.Uint64(h[8:16]))
	if err != nil {
		return fail("control stream length: %w", err)
	}
	diffLen, err := asLength(binary.LittleEndian.Uint64(h[16:24]))
	if err != nil {
		return fail("difference stream length: %w", err)
	}

	if declared > maxOut {
		return fail("declares %d bytes of output, more than the %d the target has", declared, maxOut)
	}
	body := patchLen - int64(patchHeaderLen)
	if ctrlLen > body || diffLen > body-ctrlLen {
		return fail("stream lengths do not fit the patch")
	}

	base := int64(patchHeaderLen)
	return io.NewSectionReader(patch, base, ctrlLen),
		io.NewSectionReader(patch, base+ctrlLen, diffLen),
		io.NewSectionReader(patch, base+ctrlLen+diffLen, body-ctrlLen-diffLen),
		declared, nil
}
