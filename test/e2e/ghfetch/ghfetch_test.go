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

package ghfetch

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/fetch"
)

// newServer mimics a release download: the release URL redirects to an object
// store, which holds the flat assets.
func newServer(t *testing.T, assets map[string]string) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/o/r/releases/download/tag/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/store/"+r.URL.Path[len("/o/r/releases/download/tag/"):], http.StatusFound)
	})
	mux.HandleFunc("/store/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := assets[r.URL.Path[len("/store/"):]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/o/r/releases/download/tag"
}

func newFetcher(t *testing.T, release string) fetch.Fetcher {
	t.Helper()
	base, err := fetch.New(fetch.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f, err := New(base, release)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFlatName(t *testing.T) {
	cases := map[string]string{
		"metadata/timestamp.json":          "metadata__timestamp.json",
		"targets/payloads/v1/ab.ab":        "targets__payloads__v1__ab.ab",
		"metadata/1.root.json":             "metadata__1.root.json",
		"targets/releases/linux-amd64/x.j": "targets__releases__linux-amd64__x.j",
	}
	for in, want := range cases {
		if got := FlatName(in); got != want {
			t.Errorf("FlatName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDownloadFollowsRedirectToFlatAsset(t *testing.T) {
	_, release := newServer(t, map[string]string{
		"metadata__timestamp.json":     "ts",
		"targets__payloads__v1__ab.ab": "payload",
	})
	f := newFetcher(t, release)

	for path, want := range map[string]string{
		"/metadata/timestamp.json":   "ts",
		"/targets/payloads/v1/ab.ab": "payload",
	} {
		got, err := f.DownloadFile(release+path, 1024, 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

// go-tuf probes for <n+1>.root.json and reads a 404 as "no newer root". The
// wrapper must hand that error through unchanged.
func TestMissingAssetIsHTTP404(t *testing.T) {
	_, release := newServer(t, nil)
	f := newFetcher(t, release)

	_, err := f.DownloadFile(release+"/metadata/2.root.json", 1024, 0)
	var httpErr *metadata.ErrDownloadHTTP
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %v, want ErrDownloadHTTP 404", err)
	}
}

func TestRefusesURLOutsideRelease(t *testing.T) {
	srv, release := newServer(t, map[string]string{"metadata__timestamp.json": "ts"})
	f := newFetcher(t, release)

	for _, u := range []string{
		srv.URL + "/o/r/releases/download/other/metadata/timestamp.json",
		release,
		release + "/metadata/a__b.json",
	} {
		if _, err := f.DownloadFile(u, 1024, 0); err == nil {
			t.Errorf("DownloadFile(%s) succeeded, want refusal", u)
		}
	}
}

func TestNewValidates(t *testing.T) {
	base, err := fetch.New(fetch.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(nil, "https://x"); err == nil {
		t.Error("New(nil base) succeeded")
	}
	if _, err := New(base, ""); err == nil {
		t.Error("New(empty release) succeeded")
	}
}
