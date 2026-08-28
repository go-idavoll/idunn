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

package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Resumable downloads exist for one reason: a corporate link that drops a
// connection at forty megabytes turns a hundred-megabyte release into an update
// that never completes, however many times it is retried from the start
// (docs/design.md §14.4, T18). Restarting is not a strategy on a link that will
// drop again.
//
// It changes nothing about trust, and the way it changes nothing is worth being
// precise about. The bytes this returns are a concatenation of two or more
// responses, and a server — or a proxy sitting inside the TLS session, which
// §14.4 tolerates by design — is perfectly able to serve a different second half
// than it served a first. That produces the wrong hash, and go-tuf refuses it,
// exactly as it refuses a wrong first half. Resume widens *how* bytes are
// obtained and not *what* is acceptable, which is the same statement delta stage
// 1 makes about reuse (AGENTS.md §1.5).
//
// What this code does have to be careful about is the offset. A server that
// answers a request for byte 40 000 000 with a body starting somewhere else, and
// is believed, produces a file that is neither of the two things it was made
// from. That is not a hash failure waiting to happen — it is a corruption this
// layer introduced — so the Content-Range is checked and a mismatch is refused
// rather than concatenated.

// DefaultResumeAttempts is how many times a download is resumed before it is
// given up on, when Options.ResumeAttempts is unset.
const DefaultResumeAttempts = 4

// resumeBackoff is the pause before the nth resume, counting from one.
//
// It is exponential and short. The failure this recovers from is a dropped
// connection, not a loaded server, so the point is to get back on the link
// quickly while still not hammering something that is genuinely down.
func resumeBackoff(attempt int) time.Duration {
	d := time.Second
	for range attempt - 1 {
		d *= 2
	}
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// resumingFetcher is a go-tuf Fetcher that continues an interrupted body with a
// ranged request instead of starting over.
type resumingFetcher struct {
	client   *http.Client
	ua       string
	attempts int

	// sleep is the pause between attempts, injected so a test does not have to
	// wait out a real backoff.
	sleep func(time.Duration)
}

var _ Fetcher = (*resumingFetcher)(nil)

// DownloadFile implements the go-tuf fetcher contract.
//
// The error types are go-tuf's own (ErrDownloadHTTP, ErrDownloadLengthMismatch)
// because the client workflow above acts on them — a 404 while probing for the
// next root version is a normal, expected answer there, and an error of some
// other type would make it look like a failure.
func (r *resumingFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	var body []byte
	var lastErr error

	for attempt := 0; attempt <= r.attempts; attempt++ {
		if attempt > 0 {
			r.sleep(resumeBackoff(attempt))
		}
		data, done, err := r.fetchFrom(urlPath, body, maxLength)
		body = data
		if done {
			return body, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("fetch: %s was interrupted %d times and could not be resumed: %w",
		urlPath, r.attempts+1, lastErr)
}

// fetchFrom issues one request, continuing after have if there is anything to
// continue from. It reports whether the download is finished — successfully or
// unrecoverably — and only an unfinished one is worth another attempt.
func (r *resumingFetcher) fetchFrom(urlPath string, have []byte, maxLength int64) (body []byte, done bool, err error) {
	// go-tuf's Fetcher contract carries no context — it takes a deprecated
	// timeout it does not use — so there is none to propagate. The request is
	// bounded by the client's own Timeout instead.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, urlPath, nil)
	if err != nil {
		return have, true, err
	}
	if r.ua != "" {
		req.Header.Set("User-Agent", r.ua)
	}
	offset := int64(len(have))
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	res, err := r.client.Do(req)
	if err != nil {
		// The connection failed before an answer. Worth another attempt: this is
		// the flaky link this whole file exists for.
		return have, false, err
	}
	defer func() { _ = res.Body.Close() }()

	switch {
	case offset == 0 && res.StatusCode == http.StatusOK:
		// The ordinary first request.
	case offset > 0 && res.StatusCode == http.StatusOK:
		// The server ignored the Range and is sending the whole file again.
		// Legal, and the honest response is to start over rather than splice a
		// complete body onto a partial one.
		have = nil
		offset = 0
	case offset > 0 && res.StatusCode == http.StatusPartialContent:
		if err := checkContentRange(res.Header.Get("Content-Range"), offset); err != nil {
			// A range that does not begin where we asked would produce a file
			// that is neither of the two it was made from. Refusing is not
			// pedantry: believing it would be this layer corrupting a download.
			return have, true, err
		}
	default:
		return have, true, &metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
	}

	if err := checkAdvertisedLength(res, urlPath, offset, maxLength); err != nil {
		return have, true, err
	}

	// One byte past the ceiling, so an oversized body is detected rather than
	// silently truncated into something that still parses.
	room := maxLength + 1 - int64(len(have))
	chunk, readErr := io.ReadAll(io.LimitReader(res.Body, room))
	have = append(have, chunk...)

	if int64(len(have)) > maxLength {
		return have, true, &metadata.ErrDownloadLengthMismatch{
			Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d",
				urlPath, len(have), maxLength),
		}
	}
	if readErr != nil {
		// Progress means the next attempt has somewhere to continue from. No
		// progress means the link is not merely flaky, and retrying the same
		// zero-byte read is how a fetcher turns a failure into a hang.
		return have, len(chunk) == 0, readErr
	}
	return have, true, nil
}

// checkContentRange verifies that a 206 begins exactly where the request asked.
func checkContentRange(header string, want int64) error {
	spec, ok := strings.CutPrefix(header, "bytes ")
	if !ok {
		return fmt.Errorf("fetch: resumed response has no byte Content-Range (%q)", header)
	}
	first, _, ok := strings.Cut(spec, "-")
	if !ok {
		return fmt.Errorf("fetch: malformed Content-Range %q", header)
	}
	got, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		return fmt.Errorf("fetch: malformed Content-Range %q", header)
	}
	if got != want {
		return fmt.Errorf("fetch: resumed at byte %d, asked for %d", got, want)
	}
	return nil
}

// checkAdvertisedLength refuses a response that says up front it is too large.
//
// It is the cheap half of the ceiling — the read is bounded regardless — and it
// exists so an oversized target is refused before its bytes are transferred.
func checkAdvertisedLength(res *http.Response, urlPath string, offset, maxLength int64) error {
	header := res.Header.Get("Content-Length")
	if header == "" {
		return nil
	}
	length, err := strconv.ParseInt(header, 10, 64)
	if err != nil {
		return err
	}
	if offset+length > maxLength {
		return &metadata.ErrDownloadLengthMismatch{
			Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d",
				urlPath, offset+length, maxLength),
		}
	}
	return nil
}
