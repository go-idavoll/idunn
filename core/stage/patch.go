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
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
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

	// patchControlLen is one control triple: how many bytes to take from the
	// difference stream, how many from the literal stream, and how far to move
	// the read position in the base afterwards.
	patchControlLen = 8 + 8 + 8
)

// ApplyPatch reconstructs a target from a base file and a delta patch, refusing
// to produce more than maxOut bytes. The result is only a candidate: the caller
// must check it against the signed target hash before anything is installed, and
// a patch that reconstructs the wrong bytes is caught there, not here.
//
// maxOut is the signed length of the target the caller is trying to build, so a
// patch that claims a longer output is refused before a single byte is
// allocated. Nothing else in this function ever grows past what the header
// declared and the base can supply: every run is bounded by what is left of the
// output and by what is left of the base, and a run that advances neither is
// refused rather than looped on.
//
// It is the fuzz target FuzzPatchApply (§12) and must never panic, allocate
// beyond maxOut, or fail to terminate.
func ApplyPatch(base, patch []byte, maxOut int64) ([]byte, error) {
	if maxOut <= 0 {
		return nil, fmt.Errorf("%w: patch: no output bound", ErrStage)
	}
	ctrlRaw, diffRaw, extraRaw, newLen, err := splitPatch(patch, maxOut)
	if err != nil {
		return nil, err
	}

	ctrl, diff, extra := flate.NewReader(ctrlRaw), flate.NewReader(diffRaw), flate.NewReader(extraRaw)
	defer func() { _, _ = ctrl.Close(), diff.Close() }()
	defer func() { _ = extra.Close() }()

	out := make([]byte, newLen)
	var newPos, basePos int64
	for newPos < newLen {
		add, literal, seek, err := readControl(ctrl)
		if err != nil {
			return nil, err
		}
		// A triple that produces no output cannot be the reason the loop runs
		// again. Refusing it is what makes termination a property of the
		// format rather than of the patch we happen to have been handed.
		if add == 0 && literal == 0 {
			return nil, fmt.Errorf("%w: patch: a control entry that produces nothing", ErrStage)
		}

		if err := addRun(out, base, diff, add, &newPos, &basePos, newLen); err != nil {
			return nil, err
		}
		if err := literalRun(out, extra, literal, &newPos, newLen); err != nil {
			return nil, err
		}

		next := basePos + seek
		if (seek > 0) != (next > basePos) && seek != 0 {
			return nil, fmt.Errorf("%w: patch: base position overflows", ErrStage)
		}
		if next < 0 || next > int64(len(base)) {
			return nil, fmt.Errorf("%w: patch: seek leaves the base file", ErrStage)
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
		r    io.Reader
	}{{"control", ctrl}, {"difference", diff}, {"literal", extra}} {
		if n, err := s.r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: patch: the %s stream does not end cleanly", ErrStage, s.name)
		}
	}
	return out, nil
}

// addRun writes the next n bytes of output as base bytes plus the byte-wise
// differences the patch carries for them. This is the run that makes a delta
// worth having: for a rebuilt binary most of these differences are zero.
func addRun(out, base []byte, diff io.Reader, n int64, newPos, basePos *int64, newLen int64) error {
	if n > newLen-*newPos {
		return fmt.Errorf("%w: patch: a difference run runs past the end of the output", ErrStage)
	}
	if n > int64(len(base))-*basePos {
		return fmt.Errorf("%w: patch: a difference run runs past the end of the base file", ErrStage)
	}
	span := out[*newPos : *newPos+n]
	if _, err := io.ReadFull(diff, span); err != nil {
		return fmt.Errorf("%w: patch: difference stream: %w", ErrStage, err)
	}
	for i := range span {
		span[i] += base[*basePos+int64(i)]
	}
	*newPos += n
	*basePos += n
	return nil
}

// literalRun writes the next n bytes of output straight from the patch: the
// content that has no counterpart in the base file at all.
func literalRun(out []byte, extra io.Reader, n int64, newPos *int64, newLen int64) error {
	if n > newLen-*newPos {
		return fmt.Errorf("%w: patch: a literal run runs past the end of the output", ErrStage)
	}
	if _, err := io.ReadFull(extra, out[*newPos:*newPos+n]); err != nil {
		return fmt.Errorf("%w: patch: literal stream: %w", ErrStage, err)
	}
	*newPos += n
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
// and the declared output length.
//
// Every length is checked against the patch that actually arrived before it is
// used for anything, so a header claiming megabytes over a few bytes of data is
// an error here rather than an allocation.
func splitPatch(patch []byte, maxOut int64) (ctrl, diff, extra *bytes.Reader, newLen int64, err error) {
	fail := func(format string, args ...any) (*bytes.Reader, *bytes.Reader, *bytes.Reader, int64, error) {
		return nil, nil, nil, 0, fmt.Errorf("%w: patch: "+format, append([]any{ErrStage}, args...)...)
	}
	if len(patch) < patchHeaderLen {
		return fail("shorter than its header")
	}
	if string(patch[:len(patchMagic)]) != patchMagic {
		return fail("not an idunn delta patch")
	}
	h := patch[len(patchMagic):patchHeaderLen]
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
	body := int64(len(patch) - patchHeaderLen)
	if ctrlLen > body || diffLen > body-ctrlLen {
		return fail("stream lengths do not fit the patch")
	}

	rest := patch[patchHeaderLen:]
	return bytes.NewReader(rest[:ctrlLen]),
		bytes.NewReader(rest[ctrlLen : ctrlLen+diffLen]),
		bytes.NewReader(rest[ctrlLen+diffLen:]),
		declared, nil
}
