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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fetch"
)

// maxLen is a length ceiling comfortably above every payload these tests serve.
// go-tuf passes the signed length here in production; the bytes are verified
// against signed metadata afterwards either way (AGENTS.md §1.5).
const maxLen = 1 << 20

// serve starts an HTTP server that answers every request with body, and returns
// the URL to fetch.
func serve(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/timestamp.json"
}

func TestDownloadsAFile(t *testing.T) {
	url := serve(t, "hello")
	f, err := fetch.New(fetch.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := f.DownloadFile(url, maxLen, 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("body = %q, want %q", got, "hello")
	}
}

// A repository that answers with anything but 200 has not delivered the bytes,
// and the fetcher must say so rather than hand up an error page as content.
func TestHTTPErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	f, err := fetch.New(fetch.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f.DownloadFile(srv.URL+"/timestamp.json", maxLen, 0); err == nil {
		t.Fatal("a 404 was not reported as an error")
	}
}

// The user agent is what an enterprise proxy allow-lists on, so a configured one
// has to reach the wire.
func TestUserAgentReachesTheServer(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.UserAgent()
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	f, err := fetch.New(fetch.Options{UserAgent: "idunn-test/1.0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f.DownloadFile(srv.URL+"/timestamp.json", maxLen, 0); err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if got != "idunn-test/1.0" {
		t.Errorf("User-Agent = %q, want %q", got, "idunn-test/1.0")
	}
}

// A server whose certificate chains to nothing the client trusts is not talked
// to. TLS is transport hardening rather than the basis of trust here, but a
// silent fallback to no verification would still be the wrong default.
func TestUntrustedTLSIsRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	f, err := fetch.New(fetch.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f.DownloadFile(srv.URL+"/timestamp.json", maxLen, 0); err == nil {
		t.Fatal("a certificate signed by an unknown authority was accepted")
	}
}

// The enterprise case (§14.4): an interception CA handed to the client makes its
// own server verifiable. The same request that failed above now succeeds, and
// nothing else about the fetcher changed.
func TestExtraCAsMakeAPrivateAuthorityVerifiable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("trusted"))
	}))
	defer srv.Close()

	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	f, err := fetch.New(fetch.Options{ExtraCAs: [][]byte{ca}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := f.DownloadFile(srv.URL+"/timestamp.json", maxLen, 0)
	if err != nil {
		t.Fatalf("DownloadFile with the server's CA: %v", err)
	}
	if string(got) != "trusted" {
		t.Errorf("body = %q", got)
	}
}

// An ExtraCA that contains no certificate is a misconfiguration, and a
// misconfigured trust store must not be built and used. The error names which
// entry to fix.
func TestUnusableExtraCAIsRejected(t *testing.T) {
	for _, tt := range []struct{ name, pem string }{
		{"not pem", "these are not certificates"},
		{"empty", ""},
		{"pem of the wrong type", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetch.New(fetch.Options{ExtraCAs: [][]byte{[]byte(tt.pem)}})
			if err == nil {
				t.Fatal("an ExtraCA with no usable certificate was accepted")
			}
			if !strings.Contains(err.Error(), "ExtraCAs[0]") {
				t.Errorf("err = %v, want it to name the entry", err)
			}
		})
	}
}

// A request that never completes has to end somewhere: an update that hangs on a
// black-holed connection is an outage, and the timeout is what bounds it.
func TestTimeoutBoundsARequest(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte("late"))
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	f, err := fetch.New(fetch.Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	if _, err := f.DownloadFile(srv.URL+"/timestamp.json", maxLen, 0); err == nil {
		t.Fatal("a request that never answered returned successfully")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the request took %s; the timeout did not bound it", elapsed)
	}
}

// Options.Resume is accepted and ignored until there is a fetcher that issues
// ranged requests (the TODO in fetch.go). It is pinned here so the field cannot
// quietly start meaning something else: a flag that is documented as ignored and
// then silently honoured is worse than either.
func TestResumeIsAcceptedAndIgnored(t *testing.T) {
	url := serve(t, "body")
	f, err := fetch.New(fetch.Options{Resume: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f.DownloadFile(url, maxLen, 0); err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
}

// stubTransport stands in for something that replaced the process-wide default.
type stubTransport struct{}

func (stubTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

// Building on an unknown transport would silently lose the proxy and trust-store
// configuration above it, so it is refused instead.
func TestUnknownDefaultTransportIsRefused(t *testing.T) {
	saved := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = saved })
	http.DefaultTransport = stubTransport{}

	_, err := fetch.New(fetch.Options{})
	if err == nil {
		t.Fatal("a fetcher was built on an unknown default transport")
	}
	if !strings.Contains(err.Error(), "DefaultTransport") {
		t.Errorf("err = %v", err)
	}
}
