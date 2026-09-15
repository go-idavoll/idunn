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

// Streaming a target means deciding, byte by byte, a question go-tuf only
// answers for a whole slice. That is a check written by hand beside the one
// AGENTS.md §1.2 says must not be duplicated, and the only thing that makes it
// acceptable is that it is not a second opinion: these tests exist to fail the
// build the moment it becomes one.
//
// The property under test is total equivalence. For any bytes and any signed
// description — including the ones no honest repository would publish — the
// streaming verifier and metadata.TargetFiles.VerifyLengthHashes must reach the
// same verdict. The cases below pin the individual refusals so a failure says
// which one drifted; FuzzVerifyStreamMatchesGoTUF is what makes the claim a
// property rather than a list.
package trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// streamVerdict is the streaming verifier's answer on data, arrived at the way a
// caller reaches it: a verifier that refuses to exist at all is a refusal like
// any other.
func streamVerdict(info *metadata.TargetFiles, data []byte) error {
	v, err := (&Client{}).newVerifier(info)
	if err != nil {
		return err
	}
	if _, err := v.Write(data); err != nil {
		return err
	}
	return v.Verify()
}

// signedAs builds the signed description of data for the named algorithms. It is
// deliberately willing to build ones go-tuf will refuse — no algorithms, an
// algorithm nobody implements — because those are the cases where a lenient
// reimplementation would differ.
func signedAs(data []byte, algorithms ...string) *metadata.TargetFiles {
	info := &metadata.TargetFiles{Path: "targets/payload", Length: int64(len(data)), Hashes: metadata.Hashes{}}
	for _, alg := range algorithms {
		switch alg {
		case "sha256":
			sum := sha256.Sum256(data)
			info.Hashes[alg] = sum[:]
		case "sha512":
			sum := sha512.Sum512(data)
			info.Hashes[alg] = sum[:]
		default:
			// A digest of the right shape for an algorithm this client does not
			// implement. What matters is the name, not the bytes.
			sum := sha256.Sum256(data)
			info.Hashes[alg] = sum[:]
		}
	}
	return info
}

// The streaming verifier accepts exactly what go-tuf accepts and refuses exactly
// what go-tuf refuses, case by case. Each row is a way a reimplementation could
// plausibly be more generous than the original.
func TestVerifyStreamAgreesWithGoTUF(t *testing.T) {
	payload := bytes.Repeat([]byte("idunn payload "), 977) // not a multiple of any buffer

	cases := []struct {
		name string
		info *metadata.TargetFiles
		data []byte
		want bool // the bytes are the signed ones
	}{
		{"sha256 only", signedAs(payload, "sha256"), payload, true},
		{"sha512 only", signedAs(payload, "sha512"), payload, true},
		{"both algorithms", signedAs(payload, "sha256", "sha512"), payload, true},
		{"empty target", signedAs(nil, "sha256"), nil, true},
		{"no hashes at all", signedAs(payload), payload, false},
		{"an algorithm this client does not implement", signedAs(payload, "sha256", "md5"), payload, false},
		{"one byte flipped", signedAs(payload, "sha256"), flip(payload), false},
		{"truncated by one byte", signedAs(payload, "sha256"), payload[:len(payload)-1], false},
		{"one byte too many", signedAs(payload, "sha256"), append(append([]byte(nil), payload...), 0), false},
		{"empty against a non-empty target", signedAs(payload, "sha256"), nil, false},
		{"non-empty against an empty target", signedAs(nil, "sha256"), payload, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref := c.info.VerifyLengthHashes(c.data)
			if (ref == nil) != c.want {
				t.Fatalf("the fixture is wrong: go-tuf says %v, the case claims accepted=%v", ref, c.want)
			}
			got := streamVerdict(c.info, c.data)
			if (got == nil) != c.want {
				t.Fatalf("streaming verdict = %v, want accepted=%v (go-tuf: %v)", got, c.want, ref)
			}
		})
	}
}

// A hash set with one algorithm in common and one that differs is the case
// metadata.TargetFiles.Equal gets wrong — its Hashes.Equal passes as soon as any
// shared algorithm matches. Using it to build a streaming verdict would have
// admitted bytes VerifyLengthHashes refuses, so this pins that the streaming
// path requires every signed algorithm, exactly as verifyHashes does.
func TestVerifyStreamRequiresEverySignedAlgorithm(t *testing.T) {
	payload := []byte("the real payload")
	info := signedAs(payload, "sha256", "sha512")
	// sha256 still describes the payload; sha512 describes something else.
	other := sha512.Sum512([]byte("a different payload"))
	info.Hashes["sha512"] = other[:]

	if err := info.VerifyLengthHashes(payload); err == nil {
		t.Fatal("go-tuf accepted a target one of whose signed digests is wrong")
	}
	if err := streamVerdict(info, payload); err == nil {
		t.Fatal("the streaming verdict accepted a target one of whose signed digests is wrong")
	}

	// The lenient comparison this must not be built on, for the record: it
	// accepts the very same input.
	if !(&metadata.TargetFiles{Length: info.Length, Hashes: signedAs(payload, "sha256", "sha512").Hashes}).
		Equal(metadata.TargetFiles{Length: info.Length, Hashes: metadata.Hashes{"sha256": info.Hashes["sha256"]}}) {
		t.Fatal("TargetFiles.Equal no longer behaves as the comment in stream.go describes; revisit it")
	}
}

// A stream that keeps going past the signed length is a case the []byte form
// cannot encounter, so there is no go-tuf verdict to agree with — only the
// fail-closed one. The excess must not be hashed away either: a producer cannot
// buy a match by appending bytes the verifier quietly drops.
func TestVerifyStreamRefusesAStreamPastTheSignedLength(t *testing.T) {
	payload := []byte("the real payload")
	info := signedAs(payload, "sha256")

	v, err := (&Client{}).newVerifier(info)
	if err != nil {
		t.Fatal(err)
	}
	// Written in two goes, so the overrun is noticed across writes and not only
	// within one.
	if _, err := v.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Write([]byte("and more")); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(); !errors.Is(err, ErrStream) {
		t.Fatalf("err = %v, want ErrStream", err)
	}
}

// The refusals have to be diagnosable: an operator reading a log needs to know
// whether the repository names an algorithm this client cannot check or the
// bytes simply did not match.
func TestVerifierRefusalsSayWhy(t *testing.T) {
	c := &Client{}
	if _, err := c.newVerifier(signedAs([]byte("x"))); err == nil ||
		!strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("empty hash set: err = %v", err)
	}
	if _, err := c.newVerifier(signedAs([]byte("x"), "whirlpool")); err == nil ||
		!strings.Contains(err.Error(), "unknown hashing algorithm - whirlpool") {
		t.Errorf("unknown algorithm: err = %v", err)
	}
}

// The equivalence as a property. Every input the fuzzer can reach is a target
// description and a stream; the two verdicts must be the same one.
func FuzzVerifyStreamMatchesGoTUF(f *testing.F) {
	f.Add([]byte("payload"), []byte("payload"), uint8(1), int64(0))
	f.Add([]byte("payload"), []byte("payloae"), uint8(3), int64(0))
	f.Add([]byte(nil), []byte(nil), uint8(2), int64(0))
	f.Add([]byte("payload"), []byte("payload"), uint8(7), int64(0))
	f.Add([]byte("payload"), []byte("payload"), uint8(0), int64(0))
	f.Add([]byte("payload"), []byte("payload"), uint8(1), int64(3))

	f.Fuzz(func(t *testing.T, signed, data []byte, algorithms uint8, lengthSkew int64) {
		var names []string
		if algorithms&1 != 0 {
			names = append(names, "sha256")
		}
		if algorithms&2 != 0 {
			names = append(names, "sha512")
		}
		if algorithms&4 != 0 {
			names = append(names, "md5")
		}
		info := signedAs(signed, names...)
		// A signed length that disagrees with the signed digests is not a
		// repository anyone would publish, and is exactly where a verifier that
		// checks one and not the other shows up.
		if lengthSkew != 0 {
			info.Length += lengthSkew
		}

		ref := info.VerifyLengthHashes(data)
		got := streamVerdict(info, data)
		if (ref == nil) != (got == nil) {
			t.Fatalf("go-tuf says %v, streaming says %v for %d signed bytes, %d given, algorithms %v, length %d",
				ref, got, len(signed), len(data), names, info.Length)
		}
	})
}

// flip returns data with its last byte changed, or a single byte if it is empty.
func flip(data []byte) []byte {
	out := append([]byte(nil), data...)
	if len(out) == 0 {
		return []byte{0}
	}
	out[len(out)-1] ^= 0x01
	return out
}
