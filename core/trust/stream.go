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

package trust

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/fsx"
)

// Streaming targets: why a hash is computed here, and what keeps that from
// becoming a second opinion about trust.
//
// Every byte of a release used to exist in memory at least twice — once as the
// []byte go-tuf hands over, once as the buffer staging writes — and a delta
// added a base and an output beside them. For a release whose bulk is a browser
// runtime that is gigabytes of resident memory for an operation whose working
// set is one file at a time (IDN-12).
//
// Streaming it away needs one thing that go-tuf v2.4.2 does not offer: a verdict
// on bytes that are never all in memory at once. metadata.TargetFiles exposes
// only VerifyLengthHashes([]byte), and TargetFiles.Equal is not a substitute —
// its Hashes.Equal passes as soon as ONE algorithm in common matches and ignores
// the rest, where VerifyLengthHashes requires EVERY signed algorithm to match
// and refuses one it does not know. Using Equal would have been a weakening
// dressed as reuse.
//
// So the digest is computed incrementally here. That is a hand-written check
// sitting next to go-tuf's, which AGENTS.md §1.2 is about, and the answer is not
// that it is small — it is that it is held to being *the same check*:
//
//   - It lives in this package, the only one that may see signed material.
//     Nothing outside ever receives a hash, so nothing outside can compare one
//     leniently.
//   - The signed length and hashes still come from go-tuf alone
//     (Updater.GetTargetInfo), through targetInfo, ceiling included.
//   - It refuses what go-tuf refuses, in the same cases: no hashes at all, an
//     algorithm that is not sha256 or sha512, a digest that differs, a length
//     that differs — and additionally a stream that runs past the signed length,
//     which the []byte form cannot encounter.
//   - The equivalence is a test, not a claim: FuzzVerifyStreamMatchesGoTUF fails
//     the build the moment this verifier and TargetFiles.VerifyLengthHashes
//     disagree on any input, and the cases beside it pin each refusal
//     individually (stream_internal_test.go).
//
// Fixing this upstream — a Fetcher that can hand back an io.ReadCloser and a
// DownloadTarget that verifies incrementally — remains the real answer, and
// would delete this file. See docs/backlog.md IDN-12.

// ErrStream is the class of a stream that did not verify, kept separate from
// ErrTrust so a caller can tell "these bytes are not the signed ones" from "this
// target could not be resolved at all". Both are refusals; only the first has a
// local fallback (fetching the target instead).
var ErrStream = errors.New("trust: stream does not match the signed target")

// verifier accumulates a stream and answers whether it was exactly the signed
// bytes of one target.
//
// It is an io.Writer so it can be teed into whatever is being written: a staged
// file is verified by the very bytes that land on disk, not by a separate read
// of them.
type verifier struct {
	info   *metadata.TargetFiles
	hashes map[string]hash.Hash
	n      int64
	over   bool // the stream ran past the signed length
}

// newVerifier prepares a verifier for one target, refusing a signed hash set
// this client cannot check in full.
//
// Both refusals mirror go-tuf's: TargetFiles.VerifyLengthHashes rejects an empty
// hash set outright, and verifyHashes rejects an algorithm it does not know
// rather than skipping it. Refusing here means an unknown algorithm costs a
// download that is never started, instead of bytes that were only partly
// checked.
func (c *Client) newVerifier(info *metadata.TargetFiles) (*verifier, error) {
	if len(info.Hashes) == 0 {
		return nil, fmt.Errorf("%w: target %q: hashes must not be empty for target files", ErrTrust, info.Path)
	}
	hashes := make(map[string]hash.Hash, len(info.Hashes))
	for _, alg := range sortedAlgorithms(info.Hashes) {
		switch alg {
		case "sha256":
			hashes[alg] = sha256.New()
		case "sha512":
			hashes[alg] = sha512.New()
		default:
			return nil, fmt.Errorf("%w: target %q: hash verification failed - unknown hashing algorithm - %s",
				ErrTrust, info.Path, alg)
		}
	}
	return &verifier{info: info, hashes: hashes}, nil
}

// sortedAlgorithms orders the signed algorithm names so a repository that names
// an unsupported one is refused by the same name every time. Map iteration would
// make the error message — and a fuzz failure — depend on the run.
func sortedAlgorithms(h metadata.Hashes) []string {
	out := make([]string, 0, len(h))
	for alg := range h {
		out = append(out, alg)
	}
	sort.Strings(out)
	return out
}

// Write feeds the next bytes of the stream.
//
// It never returns an error for an overlong stream: the producer is usually a
// copy loop that would report it as an I/O failure, and this is not one — it is
// a verdict, and verdicts are Verify's to give. The overrun is recorded and the
// bytes past the length are not hashed, because there is no answer they could
// change.
func (v *verifier) Write(p []byte) (int, error) {
	room := v.info.Length - v.n
	if int64(len(p)) > room {
		v.over = true
		p = p[:max(room, 0)]
	}
	for _, h := range v.hashes {
		// hash.Hash never returns an error (documented on the interface).
		_, _ = h.Write(p)
	}
	v.n += int64(len(p))
	return len(p), nil
}

// Verify reports whether the stream written so far is exactly the signed bytes.
//
// The comparison is constant-time. go-tuf's own compares hex strings, which for
// a public digest leaks nothing worth having; this costs nothing and removes the
// question.
func (v *verifier) Verify() error {
	if v.over {
		return fmt.Errorf("%w: target %q: longer than the signed %d bytes", ErrStream, v.info.Path, v.info.Length)
	}
	if v.n != v.info.Length {
		return fmt.Errorf("%w: target %q: length verification failed - expected %d, got %d",
			ErrStream, v.info.Path, v.info.Length, v.n)
	}
	for _, alg := range sortedAlgorithms(v.info.Hashes) {
		if !hmac.Equal(v.hashes[alg].Sum(nil), v.info.Hashes[alg]) {
			return fmt.Errorf("%w: target %q: hash verification failed - mismatch for algorithm %s",
				ErrStream, v.info.Path, alg)
		}
	}
	return nil
}

// VerifyStream reports whether r yields exactly the signed bytes of a target.
//
// It is the streaming form of VerifyTarget and exists for the same reason: bytes
// that did not come out of go-tuf's own download path — a file reused from an
// installed version, the output of a delta patch, an installed file re-read by
// VerifyAfterApply — are admitted by the same check that guards a download.
// Callers still get one verdict and no material to build a check of their own.
func (c *Client) VerifyStream(targetPath string, r io.Reader) error {
	info, err := c.targetInfo(targetPath)
	if err != nil {
		return err
	}
	v, err := c.newVerifier(info)
	if err != nil {
		return err
	}
	if _, err := fsx.Copy(v, r, info.Length); err != nil {
		return fmt.Errorf("%w: target %q: %w", ErrStream, targetPath, err)
	}
	return v.Verify()
}

// Materialize streams the verified bytes of one target into w.
//
// This is what core/stage consumes in place of Target: the bytes go past in a
// window instead of arriving as one allocation the size of the file, and they
// are verified on the way, so what w received is what was signed.
//
// It is done in two passes over the cache, and the second one is not a
// formality. The first decides whether the cached file is worth using at all
// and writes nowhere, because a verdict on a stream arrives after the stream
// does: a single pass that fed w while it made up its mind would have handed a
// planted cache entry to the caller and only then refused it. The second is the
// real materialization, verified again — a file that passed a probe is not a
// promise about the read after it.
//
// A cache entry that does not verify is removed rather than merely skipped, so
// a bit-rotted or planted one is not re-read on every attempt, and the download
// below replaces it. This is also the path where Updater.FindCachedTarget's
// unbounded os.ReadFile used to read an oversized planted entry whole, which is
// why it is not used (T23).
//
// A target that is not cached is downloaded through go-tuf, which still holds it
// once as a []byte — the upstream half of IDN-12 — and persists it; this then
// streams it on from there, so the peak is one copy rather than the two or three
// it used to be.
func (c *Client) Materialize(targetPath string, w io.Writer) error {
	info, err := c.targetInfo(targetPath)
	if err != nil {
		return err
	}
	return c.materialize(targetPath, info, w)
}

// materialize is Materialize with the target already resolved, so the one caller
// that needs the bytes as a slice (target, for the small documents this package
// parses itself) reaches the same bounded, verifying cache read rather than
// go-tuf's unbounded one.
func (c *Client) materialize(targetPath string, info *metadata.TargetFiles, w io.Writer) error {
	cache, err := c.cachePath(info)
	if err != nil {
		return err
	}

	if err := c.streamCached(cache, info, io.Discard); err != nil {
		_ = os.Remove(cache)
		// filePath is passed explicitly rather than left to go-tuf, so the file
		// streamed below is by construction the file go-tuf just wrote.
		if _, _, err := c.up.DownloadTarget(info, cache, ""); err != nil {
			return fmt.Errorf("%w: download %q: %w", ErrTrust, targetPath, err)
		}
	}
	if err := c.streamCached(cache, info, w); err != nil {
		return fmt.Errorf("%w: target %q: %w", ErrStream, targetPath, err)
	}
	return nil
}

// streamCached copies a cached target into w, verifying as it goes, and reports
// failure without having promised anything to w.
//
// The verdict is taken before the error is reported so a truncated or oversized
// cache file is a refusal like any other, never a partial success.
func (c *Client) streamCached(name string, info *metadata.TargetFiles, w io.Writer) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	v, err := c.newVerifier(info)
	if err != nil {
		return err
	}
	if _, err := fsx.Copy(io.MultiWriter(w, v), f, info.Length); err != nil {
		return err
	}
	return v.Verify()
}

// cachePath is where go-tuf keeps the target with this signed description.
//
// It mirrors Updater.generateTargetFilePath, which is unexported, and the mirror
// is kept honest by never relying on it: DownloadTarget is always told this path
// explicitly, so the two cannot drift into pointing at different files. What the
// mirror buys is reading the cache without FindCachedTarget's unbounded
// os.ReadFile (T23).
func (c *Client) cachePath(info *metadata.TargetFiles) (string, error) {
	if c.cfg.LocalTargetsDir == "" {
		return "", fmt.Errorf("%w: no local targets directory", ErrTrust)
	}
	return filepath.Join(c.cfg.LocalTargetsDir, url.PathEscape(info.Path)), nil
}
