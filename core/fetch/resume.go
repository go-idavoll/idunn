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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Resumable downloads exist for one reason: a corporate link that drops a
// connection at forty megabytes turns a hundred-megabyte release into an update
// that never completes, however many times it is retried from the start
// (docs/design.md §14.4, T18).
//
// Resume changes nothing about trust. The bytes returned are a concatenation of
// two or more responses, and a server — or a TLS-terminating proxy, which §14.4
// tolerates by design — can serve a different second half than it served first.
// That produces the wrong hash and go-tuf refuses it, exactly as it refuses a wrong
// first half. Resume widens how bytes are obtained, not what is acceptable
// (AGENTS.md §1.5).
//
// What this layer must get right is the offset. A 206 believed to start where the
// request asked, but starting elsewhere, produces a file that is neither of the
// two it was made from — corruption introduced here. So every partial response is
// checked before a single byte of it is appended: the Content-Range must be a
// single, well-formed byte range that starts exactly at the requested offset, is
// consistent with its own Content-Length and with the total length seen before,
// and the body must not run past it. Anything else fails closed. A server that
// ignores Range (200) or no longer has the range (416) is legal, and the answer
// there is to start over from zero, never to splice.

// DefaultResumeAttempts is how many further requests one download may issue after
// the first, when Options.ResumeAttempts is unset.
const DefaultResumeAttempts = 4

// resumeBackoff is the pause before the nth further request, counting from one.
//
// It is exponential and short: the failure this recovers from is a dropped
// connection, not a loaded server.
func resumeBackoff(attempt int) time.Duration {
	d := time.Second
	for i := 1; i < attempt && d < 30*time.Second; i++ {
		d *= 2
	}
	return min(d, 30*time.Second)
}

// resumingFetcher is a go-tuf Fetcher that continues an interrupted body with a
// ranged request instead of starting over.
type resumingFetcher struct {
	client   *http.Client
	ua       string
	attempts int
	sleep    func(time.Duration)
}

var _ Fetcher = (*resumingFetcher)(nil)

// partial is the state of one download across its requests.
type partial struct {
	body  []byte
	total int64  // the representation's full length, -1 while unknown
	etag  string // strong validator of the representation, "" if none
}

func (p *partial) restart() {
	p.body, p.total, p.etag = nil, -1, ""
}

// errRangeMismatch marks a partial response that is inconsistent with the
// request or with what was received before. It is never retried.
var errRangeMismatch = errors.New("fetch: inconsistent partial response")

// DownloadFile implements the go-tuf fetcher contract.
//
// Error types stay go-tuf's own (ErrDownloadHTTP, ErrDownloadLengthMismatch)
// because the client workflow above acts on them: a 404 while probing for the
// next root version is a normal answer there. On any error no bytes are returned.
func (r *resumingFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	if maxLength < 0 {
		return nil, fmt.Errorf("fetch: negative length ceiling %d", maxLength)
	}
	p := &partial{total: -1}
	var lastErr error
	for attempt := 0; attempt <= r.attempts; attempt++ {
		if attempt > 0 {
			r.sleep(resumeBackoff(attempt))
		}
		done, err := r.request(urlPath, maxLength, p)
		if done {
			if err != nil {
				return nil, err
			}
			return p.body, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("fetch: %s did not complete in %d requests: %w", urlPath, r.attempts+1, lastErr)
}

// request issues one request, continuing after p.body if there is anything to
// continue from. It reports whether the download is finished — successfully or
// unrecoverably; only an unfinished one is worth another request.
func (r *resumingFetcher) request(urlPath string, maxLength int64, p *partial) (done bool, err error) {
	// go-tuf's Fetcher contract carries no context, so there is none to
	// propagate; the client's Timeout bounds the request instead.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, urlPath, nil)
	if err != nil {
		return true, err
	}
	if r.ua != "" {
		req.Header.Set("User-Agent", r.ua)
	}
	offset := int64(len(p.body))
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
		if p.etag != "" {
			// A representation that changed since the first half answers
			// with 200 and the whole new body, which restarts below.
			req.Header.Set("If-Range", p.etag)
		}
	}

	res, err := r.client.Do(req)
	if err != nil {
		return permanent(err), err
	}
	defer func() { _ = res.Body.Close() }()

	want := int64(-1) // bytes this response must carry, -1 while unknown
	switch {
	case res.StatusCode == http.StatusOK:
		// The first request, or a server that ignored Range or saw the
		// representation change: either way this body is the whole file, so
		// whatever was held is discarded rather than spliced onto.
		p.restart()
		offset = 0
		p.etag = strongETag(res.Header)
		if res.ContentLength >= 0 {
			p.total, want = res.ContentLength, res.ContentLength
		}
	case offset > 0 && res.StatusCode == http.StatusPartialContent:
		n, err := checkPartial(res, offset, p)
		if err != nil {
			return true, fmt.Errorf("%w from %s: %w", errRangeMismatch, urlPath, err)
		}
		want = n
	case offset > 0 && res.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		// The server no longer has this range. Start over from zero.
		p.restart()
		return false, &metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
	default:
		// Includes a 206 to a request that asked for no range.
		return true, &metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
	}

	if p.total > maxLength || (want >= 0 && offset+want > maxLength) {
		return true, lengthMismatch(urlPath, max(p.total, offset+want), maxLength)
	}

	// Read at most one byte past whichever bound is tighter — the ceiling or
	// what this response declared — so an overrun is detected, not truncated.
	limit := maxLength - offset + 1
	if want >= 0 {
		limit = min(limit, want+1)
	}
	chunk, readErr := io.ReadAll(io.LimitReader(res.Body, limit))
	got := int64(len(chunk))
	if want >= 0 && got > want {
		return true, fmt.Errorf("%w from %s: body runs past the declared %d bytes", errRangeMismatch, urlPath, want)
	}
	p.body = append(p.body, chunk...)
	if int64(len(p.body)) > maxLength {
		return true, lengthMismatch(urlPath, int64(len(p.body)), maxLength)
	}

	short := readErr
	if short == nil && want >= 0 && got < want {
		short = io.ErrUnexpectedEOF
	}
	if short == nil && p.total >= 0 && int64(len(p.body)) < p.total {
		short = io.ErrUnexpectedEOF
	}
	if short != nil {
		// Progress gives the next request somewhere to continue from. None
		// means the link is not merely flaky, and retrying a zero-byte read
		// is how a fetcher turns a failure into a hang.
		return got == 0, short
	}
	return true, nil
}

// checkPartial verifies a 206 against the request and against what was received
// before, and returns how many bytes its body must carry. It records the total
// length and validator on first sight.
func checkPartial(res *http.Response, offset int64, p *partial) (int64, error) {
	values := res.Header.Values("Content-Range")
	if len(values) != 1 {
		return 0, fmt.Errorf("want exactly one content-range, got %d", len(values))
	}
	first, last, total, err := parseContentRange(values[0])
	if err != nil {
		return 0, err
	}
	if first != offset {
		return 0, fmt.Errorf("resumed at byte %d, asked for %d", first, offset)
	}
	n := last - first + 1
	if res.ContentLength >= 0 && res.ContentLength != n {
		return 0, fmt.Errorf("content-length %d disagrees with content-range %q", res.ContentLength, values[0])
	}
	if total >= 0 && p.total >= 0 && total != p.total {
		return 0, fmt.Errorf("total length changed from %d to %d", p.total, total)
	}
	if etag := strongETag(res.Header); p.etag != "" && etag != "" && etag != p.etag {
		return 0, errors.New("entity tag changed between requests")
	}
	if total >= 0 {
		p.total = total
	}
	return n, nil
}

// parseContentRange parses "bytes first-last/total" or "bytes first-last/*",
// strictly: decimal digits only, first <= last, and last < total when total is
// known. total is -1 when the server did not state it.
func parseContentRange(header string) (first, last, total int64, err error) {
	spec, ok := strings.CutPrefix(header, "bytes ")
	if !ok {
		return 0, 0, 0, fmt.Errorf("content-range %q is not a byte range", header)
	}
	rng, size, ok := strings.Cut(spec, "/")
	if !ok {
		return 0, 0, 0, fmt.Errorf("malformed content-range %q", header)
	}
	a, b, ok := strings.Cut(rng, "-")
	if !ok {
		return 0, 0, 0, fmt.Errorf("malformed content-range %q", header)
	}
	if first, err = parseDecimal(a); err != nil {
		return 0, 0, 0, fmt.Errorf("malformed content-range %q", header)
	}
	if last, err = parseDecimal(b); err != nil || last < first {
		return 0, 0, 0, fmt.Errorf("malformed content-range %q", header)
	}
	total = -1
	if size != "*" {
		if total, err = parseDecimal(size); err != nil || last >= total {
			return 0, 0, 0, fmt.Errorf("malformed content-range %q", header)
		}
	}
	return first, last, total, nil
}

// parseDecimal accepts only non-empty ASCII digits — no sign, space or base
// prefix, all of which strconv would otherwise tolerate or reinterpret.
func parseDecimal(s string) (int64, error) {
	if s == "" || len(s) > 18 {
		return 0, strconv.ErrSyntax
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

// strongETag returns the response's entity tag if it is a strong validator, the
// only kind If-Range may carry (RFC 9110 §13.1.5).
func strongETag(h http.Header) string {
	etag := h.Get("ETag")
	if len(etag) < 2 || etag[0] != '"' || etag[len(etag)-1] != '"' {
		return ""
	}
	return etag
}

func lengthMismatch(urlPath string, got, maxLength int64) error {
	return &metadata.ErrDownloadLengthMismatch{
		Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, got, maxLength),
	}
}

// permanent reports whether a request that produced no response is not worth
// repeating: a refused proxy login, or a TLS failure that the next handshake
// would repeat identically. Everything else is the flaky link resume exists for.
func permanent(err error) bool {
	if errors.Is(err, ErrProxyAuth) {
		return true
	}
	var (
		verify   *tls.CertificateVerificationError
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
		record   tls.RecordHeaderError
		op       *net.OpError
	)
	switch {
	case errors.As(err, &verify), errors.As(err, &unknown), errors.As(err, &hostname),
		errors.As(err, &invalid), errors.As(err, &record):
		return true
	case errors.As(err, &op) && op.Op == "remote error":
		// A TLS alert from the far side, such as "certificate required".
		return true
	}
	return false
}
