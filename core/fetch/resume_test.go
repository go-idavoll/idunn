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

package fetch_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/fetch"
)

// payload is a body big enough that "half of it" is a meaningful thing to serve.
func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// script is a server whose nth response is the nth handler. It records the
// Range and If-Range each request carried, and refuses to answer more requests
// than it has handlers — a fetcher that keeps asking fails the test.
type script struct {
	t        *testing.T
	mu       sync.Mutex
	steps    []http.HandlerFunc
	ranges   []string
	ifRanges []string
}

func (s *script) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	n := len(s.ranges)
	s.ranges = append(s.ranges, r.Header.Get("Range"))
	s.ifRanges = append(s.ifRanges, r.Header.Get("If-Range"))
	s.mu.Unlock()
	if n >= len(s.steps) {
		s.t.Errorf("request %d was not expected (Range %q)", n+1, r.Header.Get("Range"))
		w.WriteHeader(http.StatusTeapot)
		return
	}
	s.steps[n](w, r)
}

func (s *script) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ranges...)
}

func startScript(t *testing.T, steps ...http.HandlerFunc) (*script, string) {
	t.Helper()
	s := &script{t: t, steps: steps}
	srv := httptest.NewUnstartedServer(s)
	// net/http reports the aborted handlers these tests use on purpose; the
	// abort is the scenario, not a defect worth printing.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Start()
	t.Cleanup(srv.Close)
	return s, srv.URL + "/target"
}

// cut sends the first n bytes of body as a 200 without Content-Length and then
// drops the connection without a terminating chunk — the shape of a corporate
// link that drops long transfers. The client sees a truncated body, never a
// complete one.
func cut(body []byte, n int, header ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body[:n])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
}

// whole answers 200 with the complete body.
func whole(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}
}

// ranged answers 206 honestly from the offset the Range asked for, serving
// content instead of body's own bytes when content is non-nil (a poisoned half).
func ranged(body, content []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var start int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-", &start); err != nil || start > len(body) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		rest := body[start:]
		if content != nil {
			rest = content[start:]
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(body)-1, len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(len(rest)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(rest)
	}
}

// partialWith answers 206 with the given headers and body, whatever was asked.
// Without a Content-Length header the body is sent chunked, so a body longer than
// the range it claims actually reaches the client.
func partialWith(body []byte, header ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Add(header[i], header[i+1])
		}
		w.WriteHeader(http.StatusPartialContent)
		w.(http.Flusher).Flush()
		_, _ = w.Write(body)
	}
}

// resuming builds a resuming fetcher whose pauses are counted, not slept.
func resuming(t *testing.T, attempts int) (fetch.Fetcher, *[]time.Duration) {
	t.Helper()
	var pauses []time.Duration
	f, err := fetch.NewWithSleep(fetch.Options{UserAgent: "idunn-test", Resume: true, ResumeAttempts: attempts},
		func(d time.Duration) { pauses = append(pauses, d) })
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	return f, &pauses
}

// The whole point: a link that drops partway does not mean starting over.
func TestAnInterruptedDownloadIsResumed(t *testing.T) {
	body := payload(64 << 10)
	s, url := startScript(t, cut(body, 8<<10), ranged(body, nil))
	f, pauses := resuming(t, 3)

	got, err := f.DownloadFile(url, int64(len(body)), 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %d bytes, want the %d that were published", len(got), len(body))
	}
	if reqs := s.requests(); len(reqs) != 2 || reqs[1] != "bytes=8192-" {
		t.Errorf("requests carried Range %q, want a resume from byte 8192", reqs)
	}
	if len(*pauses) != 1 {
		t.Errorf("paused %d times, want once", len(*pauses))
	}
}

// A strong ETag from the first response is sent as If-Range, so a representation
// that changed in between is answered with the whole new file rather than a range
// of it.
func TestAResumeCarriesIfRange(t *testing.T) {
	body := payload(16 << 10)
	s, url := startScript(t, cut(body, 1024, "ETag", `"v1"`), ranged(body, nil))
	f, _ := resuming(t, 2)
	if _, err := f.DownloadFile(url, int64(len(body)), 0); err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.ifRanges[1]; got != `"v1"` {
		t.Errorf("If-Range = %q, want the first response's ETag", got)
	}
}

// Resume changes how bytes are obtained, not what is acceptable. A server that
// serves a different second half produces a different file, and the hash — go-tuf's
// check, one layer up, which the fetcher neither performs nor duplicates
// (AGENTS.md §1.2) — is what refuses it. The fetcher must not paper over it.
func TestAPoisonedResumeProducesTheWrongBytes(t *testing.T) {
	body := payload(64 << 10)
	poison := bytes.Repeat([]byte{'Z'}, len(body))
	_, url := startScript(t, cut(body, 8<<10), ranged(body, poison))
	f, _ := resuming(t, 3)

	got, err := f.DownloadFile(url, int64(len(body)), 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if sha256.Sum256(got) == sha256.Sum256(body) {
		t.Fatal("VULNERABILITY: a poisoned resume hashes to the honest file")
	}
}

// A 206 that is inconsistent with the request, or with what came before, would
// splice bytes at the wrong offset. Every such answer fails closed: no bytes, and
// no further request that could paper over it.
func TestAnInconsistentPartialResponseIsRefused(t *testing.T) {
	body := payload(4096)
	const at = 1024
	rest := body[at:]
	n3 := strconv.Itoa(len(rest) / 3)

	for _, tt := range []struct {
		name string
		step http.HandlerFunc
	}{
		{"starts at zero", partialWith(body, "Content-Range", "bytes 0-4095/4096")},
		{"starts too late", partialWith(rest[1:], "Content-Range", "bytes 1025-4095/4096")},
		{"starts too early", partialWith(body[at-1:], "Content-Range", "bytes 1023-4095/4096")},
		{"no content-range", partialWith(rest)},
		{"two content-ranges", partialWith(rest, "Content-Range", "bytes 1024-4095/4096", "Content-Range", "bytes 0-4095/4096")},
		{"not bytes", partialWith(rest, "Content-Range", "items 1024-4095/4096")},
		{"open-ended", partialWith(rest, "Content-Range", "bytes 1024-/4096")},
		{"signed start", partialWith(rest, "Content-Range", "bytes +1024-4095/4096")},
		{"spaced start", partialWith(rest, "Content-Range", "bytes  1024-4095/4096")},
		{"last before first", partialWith(rest, "Content-Range", "bytes 1024-1000/4096")},
		{"last past total", partialWith(rest, "Content-Range", "bytes 1024-4096/4096")},
		{"no total", partialWith(rest, "Content-Range", "bytes 1024-4095")},
		{"unsatisfied range form", partialWith(nil, "Content-Range", "bytes */4096")},
		{"content-length disagrees", partialWith(rest[:len(rest)/3], "Content-Range", "bytes 1024-4095/4096", "Content-Length", n3)},
		{"body runs past the range", partialWith(rest, "Content-Range", "bytes 1024-2047/4096")},
		{"entity tag changed", partialWith(rest, "Content-Range", "bytes 1024-4095/4096", "ETag", `"v2"`)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, url := startScript(t, cut(body, at, "ETag", `"v1"`), tt.step)
			f, _ := resuming(t, 3)
			got, err := f.DownloadFile(url, 1<<20, 0)
			if err == nil {
				t.Fatalf("an inconsistent partial response was accepted (%d bytes)", len(got))
			}
			if got != nil {
				t.Errorf("%d bytes were returned alongside the error", len(got))
			}
			if reqs := s.requests(); len(reqs) != 2 {
				t.Errorf("the fetcher issued %d requests; an inconsistent range must end the download", len(reqs))
			}
		})
	}
}

// The total a resumed range states must match the length the first response
// declared, not merely be well-formed.
func TestAResumedTotalMustMatchTheFirstResponse(t *testing.T) {
	body := payload(4096)
	first := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body[:1024])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	_, url := startScript(t, first, partialWith(body[1024:2048], "Content-Range", "bytes 1024-2047/2048"))
	f, _ := resuming(t, 3)
	if _, err := f.DownloadFile(url, 1<<20, 0); err == nil {
		t.Fatal("a resumed range with a different total length was accepted")
	}
}

// A server that ignores Range and sends a 200 is legal. The honest answer is to
// start over — the result is exactly the second response, never a splice of a
// complete body onto a partial one, even when the file changed in between.
func TestA200ToARangeRequestStartsOver(t *testing.T) {
	old := payload(16 << 10)
	updated := bytes.Repeat([]byte{'N'}, 12<<10)
	s, url := startScript(t, cut(old, 4096), whole(updated))
	f, _ := resuming(t, 3)

	got, err := f.DownloadFile(url, 1<<20, 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if !bytes.Equal(got, updated) {
		t.Errorf("got %d bytes, want exactly the %d of the whole-file response", len(got), len(updated))
	}
	if reqs := s.requests(); len(reqs) != 2 || reqs[1] != "bytes=4096-" {
		t.Errorf("requests carried Range %q", reqs)
	}
}

// A 416 to a resume means the server no longer has that range; the next request
// starts from zero rather than guessing.
func TestA416RestartsFromZero(t *testing.T) {
	body := payload(8192)
	s, url := startScript(t,
		cut(body, 2048),
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusRequestedRangeNotSatisfiable) },
		whole(body),
	)
	f, _ := resuming(t, 3)
	got, err := f.DownloadFile(url, 1<<20, 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("got %d bytes, want %d", len(got), len(body))
	}
	if reqs := s.requests(); len(reqs) != 3 || reqs[2] != "" {
		t.Errorf("requests carried Range %q, want the third to start from zero", reqs)
	}
}

// A resume that is itself truncated still made progress, and is resumed again
// from where it actually stopped — not from where it claimed it would end.
func TestATruncatedResumeIsResumedFromWhereItStopped(t *testing.T) {
	body := payload(8192)
	truncated206 := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Range", "bytes 1000-8191/8192")
		w.Header().Set("Content-Length", "7192")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body[1000:3000])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	s, url := startScript(t, cut(body, 1000), truncated206, ranged(body, nil))
	f, _ := resuming(t, 3)
	got, err := f.DownloadFile(url, 1<<20, 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %d bytes, want %d", len(got), len(body))
	}
	if reqs := s.requests(); len(reqs) != 3 || reqs[2] != "bytes=3000-" {
		t.Errorf("requests carried Range %q", reqs)
	}
}

// A 206 that ends cleanly but short of the range it declared is truncated, not
// complete: without progress it fails closed and returns nothing.
func TestAResumeThatDeliversNothingFailsClosed(t *testing.T) {
	body := payload(8192)
	empty206 := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Range", "bytes 1000-8191/8192")
		w.WriteHeader(http.StatusPartialContent)
		w.(http.Flusher).Flush()
	}
	s, url := startScript(t, cut(body, 1000), empty206)
	f, _ := resuming(t, 3)
	got, err := f.DownloadFile(url, 1<<20, 0)
	if err == nil || got != nil {
		t.Fatalf("got %d bytes, err %v; want nothing and an error", len(got), err)
	}
	if n := len(s.requests()); n != 2 {
		t.Errorf("issued %d requests; a zero-byte answer must not be retried", n)
	}
}

// A link that never lets a download finish is given up on after the configured
// number of requests, with nothing returned.
func TestAttemptsAreBounded(t *testing.T) {
	body := payload(8192)
	s, url := startScript(t,
		cut(body, 1000),
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Range", "bytes 1000-8191/8192")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body[1000:1001])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		},
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Range", "bytes 1001-8191/8192")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body[1001:1002])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		},
	)
	f, pauses := resuming(t, 2)
	got, err := f.DownloadFile(url, 1<<20, 0)
	if err == nil || got != nil {
		t.Fatalf("got %d bytes, err %v; want nothing and an error", len(got), err)
	}
	if n := len(s.requests()); n != 3 {
		t.Errorf("issued %d requests, want 1 + 2 attempts", n)
	}
	if len(*pauses) != 2 {
		t.Errorf("paused %d times, want 2", len(*pauses))
	}
}

// The error types are go-tuf's, because the client workflow above acts on them:
// a 404 while probing for the next root version is a normal answer there.
func TestHTTPErrorsKeepTheirGoTUFType(t *testing.T) {
	_, url := startScript(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	f, _ := resuming(t, 3)
	_, err := f.DownloadFile(url, 1024, 0)
	var httpErr *metadata.ErrDownloadHTTP
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %#v, want *metadata.ErrDownloadHTTP with 404", err)
	}
}

// A 206 to a request that asked for no range has nothing to be consistent with.
func TestAnUnrequestedPartialResponseIsRefused(t *testing.T) {
	body := payload(1024)
	_, url := startScript(t, partialWith(body, "Content-Range", "bytes 0-1023/1024"))
	f, _ := resuming(t, 3)
	if got, err := f.DownloadFile(url, 1<<20, 0); err == nil || got != nil {
		t.Fatalf("got %d bytes, err %v; want a refusal", len(got), err)
	}
}

// The ceiling holds across a resume: it is the total that must not exceed the
// signed length, not each piece of it.
func TestTheLengthCeilingHoldsAcrossAResume(t *testing.T) {
	body := payload(32 << 10)
	_, url := startScript(t, cut(body, 4096), ranged(body, nil))
	f, _ := resuming(t, 3)
	_, err := f.DownloadFile(url, 8192, 0)
	var lenErr *metadata.ErrDownloadLengthMismatch
	if !errors.As(err, &lenErr) {
		t.Fatalf("err = %#v, want *metadata.ErrDownloadLengthMismatch", err)
	}
}

// A resumed range whose declared total exceeds the signed length is refused as
// soon as it is declared, not after more requests have been spent on it.
func TestADeclaredTotalAboveTheCeilingIsRefusedAtOnce(t *testing.T) {
	body := payload(8192)
	s, url := startScript(t, cut(body, 1024), partialWith(body[1024:2048], "Content-Range", "bytes 1024-2047/8192"))
	f, _ := resuming(t, 3)
	_, err := f.DownloadFile(url, 4096, 0)
	var lenErr *metadata.ErrDownloadLengthMismatch
	if !errors.As(err, &lenErr) {
		t.Fatalf("err = %#v, want *metadata.ErrDownloadLengthMismatch", err)
	}
	if n := len(s.requests()); n != 2 {
		t.Errorf("issued %d requests, want the refusal on the second", n)
	}
}

// A TLS failure is not a flaky link: the next handshake would fail identically,
// so it is reported at once instead of retried with backoff.
func TestATLSFailureIsNotRetried(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer srv.Close()

	f, pauses := resuming(t, 3)
	if _, err := f.DownloadFile(srv.URL+"/target", 1024, 0); err == nil {
		t.Fatal("a certificate signed by an unknown authority was accepted")
	}
	if len(*pauses) != 0 {
		t.Errorf("paused %d times; an untrusted certificate was retried", len(*pauses))
	}
}

func TestResumeBackoffIsExponentialAndCapped(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := fetch.ResumeBackoff(i + 1); got != w {
			t.Errorf("backoff(%d) = %s, want %s", i+1, got, w)
		}
	}
	if got := fetch.ResumeBackoff(1000); got != 30*time.Second {
		t.Errorf("backoff(1000) = %s, want the cap", got)
	}
}
