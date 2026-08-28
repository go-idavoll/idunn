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
	"strings"
	"sync/atomic"
	"testing"

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

// flaky serves body, but cuts the first response short after cut bytes — the
// shape of a corporate link that drops long transfers.
//
// It honours Range on the requests that follow, which is what a resuming client
// needs and what an ordinary static file server already does.
type flaky struct {
	body    []byte
	cut     int
	served  atomic.Int64
	corrupt bool // serve different bytes on the resumed half.
}

func (f *flaky) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := f.served.Add(1)
	body := f.body
	start := 0

	if spec := r.Header.Get("Range"); spec != "" {
		raw := strings.TrimSuffix(strings.TrimPrefix(spec, "bytes="), "-")
		v, err := strconv.Atoi(raw)
		if err != nil || v > len(body) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		start = v
		rest := body[start:]
		if f.corrupt {
			rest = bytes.Repeat([]byte{'Z'}, len(rest))
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(body)-1, len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(len(rest)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(rest)
		return
	}

	if n == 1 && f.cut > 0 {
		// No Content-Length: the point is a body that ends before it should.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body[:f.cut])
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		// Panicking out of the handler makes net/http drop the connection
		// without a terminating chunk, which is what the client must see as a
		// truncated body rather than as a complete one.
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func resumingFetcher(t *testing.T) fetch.Fetcher {
	t.Helper()
	f, err := fetch.New(fetch.Options{UserAgent: "idunn-test", Resume: true, ResumeAttempts: 3})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	return f
}

// The whole point: a link that drops halfway does not mean starting over.
func TestAnInterruptedDownloadIsResumed(t *testing.T) {
	body := payload(64 << 10)
	h := &flaky{body: body, cut: 8 << 10}
	srv := httptest.NewServer(h)
	defer srv.Close()
	srv.Config.ErrorLog = quietLog()

	got, err := resumingFetcher(t).DownloadFile(srv.URL+"/target", int64(len(body)), 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %d bytes, want the %d that were published", len(got), len(body))
	}
	if n := h.served.Load(); n < 2 {
		t.Errorf("the server saw %d requests; the download was not resumed", n)
	}
}

// Resume changes how bytes are obtained, not what is acceptable. A server that
// serves a different second half produces a different file — and the hash is what
// says so. The fetcher's job is to not paper over it.
func TestAPoisonedResumeProducesTheWrongBytes(t *testing.T) {
	body := payload(64 << 10)
	h := &flaky{body: body, cut: 8 << 10, corrupt: true}
	srv := httptest.NewServer(h)
	defer srv.Close()
	srv.Config.ErrorLog = quietLog()

	got, err := resumingFetcher(t).DownloadFile(srv.URL+"/target", int64(len(body)), 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if bytes.Equal(got, body) {
		t.Fatal("the corrupted half came back as the honest file")
	}
	// This is the check that rejects it, one layer up, and it is go-tuf's — the
	// fetcher neither performs nor duplicates it (AGENTS.md §1.2).
	if sha256.Sum256(got) == sha256.Sum256(body) {
		t.Fatal("VULNERABILITY: a poisoned resume hashes to the honest file")
	}
}

// A server that answers a resume at the wrong offset would produce a file that is
// neither of the two it was made from. That is corruption this layer would be
// introducing, so it is refused rather than concatenated.
func TestAResumeAtTheWrongOffsetIsRefused(t *testing.T) {
	body := payload(32 << 10)
	served := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		if r.Header.Get("Range") == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body[:1024])
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			panic(http.ErrAbortHandler)
		}
		// Asked for byte 1024; answer from byte 0 and claim it is a range.
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	srv.Config.ErrorLog = quietLog()

	_, err := resumingFetcher(t).DownloadFile(srv.URL+"/target", int64(len(body)), 0)
	if err == nil {
		t.Fatal("a resume that began at the wrong offset was accepted")
	}
	if !strings.Contains(err.Error(), "resumed at byte") {
		t.Errorf("err = %v, want the offset mismatch", err)
	}
}

// A server that ignores the Range and sends the whole file again is legal, and
// the honest answer is to start over rather than splice a complete body onto a
// partial one.
func TestAServerThatIgnoresRangeIsStartedOver(t *testing.T) {
	body := payload(16 << 10)
	served := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		if served == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body[:4096])
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body) // 200, no Content-Range: Range ignored.
	}))
	defer srv.Close()
	srv.Config.ErrorLog = quietLog()

	got, err := resumingFetcher(t).DownloadFile(srv.URL+"/target", int64(len(body)), 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("got %d bytes, want %d; the whole-file response was spliced onto the partial one",
			len(got), len(body))
	}
}

// The error types are go-tuf's, because the client workflow above acts on them:
// a 404 while probing for the next root version is a normal answer there, not a
// failure.
func TestHTTPErrorsKeepTheirGoTUFType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := resumingFetcher(t).DownloadFile(srv.URL+"/missing", 1024, 0)
	var httpErr *metadata.ErrDownloadHTTP
	if !errors.As(err, &httpErr) {
		t.Fatalf("err = %#v, want *metadata.ErrDownloadHTTP", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", httpErr.StatusCode)
	}
}

// The ceiling still holds across a resume: it is the total that must not exceed
// the signed length, not each piece of it.
func TestTheLengthCeilingHoldsAcrossAResume(t *testing.T) {
	body := payload(32 << 10)
	h := &flaky{body: body, cut: 4096}
	srv := httptest.NewServer(h)
	defer srv.Close()
	srv.Config.ErrorLog = quietLog()

	_, err := resumingFetcher(t).DownloadFile(srv.URL+"/target", 8192, 0)
	var lenErr *metadata.ErrDownloadLengthMismatch
	if !errors.As(err, &lenErr) {
		t.Fatalf("err = %#v, want *metadata.ErrDownloadLengthMismatch", err)
	}
}

// quietLog silences net/http's own report of the aborted handlers these tests
// use on purpose. The abort is the scenario, not a defect worth printing for
// every case.
func quietLog() *log.Logger { return log.New(io.Discard, "", 0) }
