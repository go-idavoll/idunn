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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeFlat(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPlanAssetsComparesBytes(t *testing.T) {
	prev := writeFlat(t, map[string]string{
		timestampAsset: "ts1", "metadata__1.snapshot.json": "s1", "payload": "same", "gone": "x", "resized": "ab",
	})
	cur := writeFlat(t, map[string]string{
		timestampAsset: "ts2", "metadata__1.snapshot.json": "s1", "metadata__2.snapshot.json": "s2",
		"payload": "same", "resized": "ba", // same size, other bytes
	})
	p, err := planAssets(cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	want := assetPlan{
		New:       []string{"metadata__2.snapshot.json"},
		Changed:   []string{"resized", timestampAsset},
		Deleted:   []string{"gone"},
		Unchanged: []string{"metadata__1.snapshot.json", "payload"},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("plan = %+v, want %+v", p, want)
	}

	p, err = planAssets(cur, filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(p.New) != 5 || p.New[4] != timestampAsset || len(p.Changed)+len(p.Deleted)+len(p.Unchanged) != 0 {
		t.Fatalf("no previous publish: every asset is new, timestamp last: %+v err=%v", p, err)
	}
}

// fakeGitHub is the release API surface release-publish uses.
type fakeGitHub struct {
	mu       sync.Mutex
	srv      *httptest.Server
	token    string
	release  *ghRelease
	assets   map[string][]byte
	ids      map[string]int64
	nextID   int64
	requests []string // "METHOD path?name" in order
	// fail returns a canned response for the n-th request matching key, if set.
	fail func(key string, n int) (int, http.Header, string, bool)
	seen map[string]int
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{token: "t0k", assets: map[string][]byte{}, ids: map[string]int64{}, nextID: 100, seen: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	if n := r.URL.Query().Get("name"); n != "" {
		key += "?" + n
	}
	f.requests = append(f.requests, key)
	f.seen[key]++
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	if f.fail != nil {
		if code, h, body, ok := f.fail(key, f.seen[key]); ok {
			for k, v := range h {
				w.Header()[k] = v
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
			return
		}
	}
	const repo = "/repos/o/r"
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, repo+"/releases/tags/"):
		if f.release == nil {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(f.release)
	case r.Method == http.MethodPost && r.URL.Path == repo+"/releases":
		f.release = &ghRelease{ID: 7, UploadURL: f.srv.URL + "/upload" + repo + "/releases/7/assets{?name,label}"}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(f.release)
	case r.Method == http.MethodGet && r.URL.Path == repo+"/releases/7/assets":
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var list []ghAsset
		if page == 1 {
			for n, b := range f.assets {
				list = append(list, ghAsset{ID: f.ids[n], Name: n, Size: int64(len(b))})
			}
		}
		_ = json.NewEncoder(w).Encode(list)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, repo+"/releases/assets/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, repo+"/releases/assets/"), 10, 64)
		for n, i := range f.ids {
			if i == id {
				delete(f.ids, n)
				delete(f.assets, n)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	case r.Method == http.MethodPost && r.URL.Path == "/upload"+repo+"/releases/7/assets":
		name := r.URL.Query().Get("name")
		if _, ok := f.assets[name]; ok {
			http.Error(w, `{"errors":[{"code":"already_exists"}]}`, http.StatusUnprocessableEntity)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if int64(len(body)) != r.ContentLength || r.Header.Get("Content-Type") != "application/octet-stream" {
			http.Error(w, "bad upload", http.StatusBadRequest)
			return
		}
		f.nextID++
		f.assets[name], f.ids[name] = body, f.nextID
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ghAsset{ID: f.nextID, Name: name, Size: int64(len(body))})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, repo+"/releases/7"):
		f.release, f.assets, f.ids = nil, map[string][]byte{}, map[string]int64{}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, repo+"/git/refs/tags/"):
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected "+key, http.StatusTeapot)
	}
}

func (f *fakeGitHub) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.requests
	f.requests = nil
	return r
}

// publishWith runs release-publish against the fake with sleeping recorded
// instead of done.
func publishWith(t *testing.T, f *fakeGitHub, dir, prev string) (string, []time.Duration, error) {
	t.Helper()
	t.Setenv("GH_TOKEN", f.token)
	var slept []time.Duration
	var out bytes.Buffer
	err := releasePublish([]string{"--api", f.srv.URL, "--repo", "o/r", "--tag", "e2e-x", "--dir", dir, "--prev", prev,
		"--replaced", filepath.Join(t.TempDir(), "replaced")}, &out, func(d time.Duration) { slept = append(slept, d) })
	return out.String(), slept, err
}

func TestReleasePublishUploadsOnlyWhatChanged(t *testing.T) {
	f := newFakeGitHub(t)
	v1 := writeFlat(t, map[string]string{timestampAsset: "ts1", "metadata__1.snapshot.json": "s1", "payload": "big", "old": "o"})
	if out, _, err := publishWith(t, f, v1, ""); err != nil {
		t.Fatalf("first publish: %v\n%s", err, out)
	}
	got := f.take()
	if got[0] != "GET /repos/o/r/releases/tags/e2e-x" || got[1] != "POST /repos/o/r/releases" {
		t.Fatalf("first publish must look up, then create the release: %v", got)
	}
	if last := got[len(got)-1]; last != "POST /upload/repos/o/r/releases/7/assets?"+timestampAsset {
		t.Fatalf("the timestamp must be uploaded last, got %v", got)
	}

	v2 := writeFlat(t, map[string]string{timestampAsset: "ts2", "metadata__1.snapshot.json": "s1", "metadata__2.snapshot.json": "s2", "payload": "big"})
	out, _, err := publishWith(t, f, v2, v1)
	if err != nil {
		t.Fatalf("second publish: %v\n%s", err, out)
	}
	got = f.take()
	want := []string{
		"GET /repos/o/r/releases/tags/e2e-x",
		"GET /repos/o/r/releases/7/assets",
		fmt.Sprintf("DELETE /repos/o/r/releases/assets/%d", 102), // "old": removed explicitly
		"POST /upload/repos/o/r/releases/7/assets?metadata__2.snapshot.json",
		fmt.Sprintf("DELETE /repos/o/r/releases/assets/%d", 104), // the old timestamp
		"POST /upload/repos/o/r/releases/7/assets?" + timestampAsset,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("second publish requests:\n got %q\nwant %q", got, want)
	}
	for n, c := range map[string]string{timestampAsset: "ts2", "metadata__1.snapshot.json": "s1", "metadata__2.snapshot.json": "s2", "payload": "big"} {
		if string(f.assets[n]) != c {
			t.Errorf("asset %s = %q, want %q", n, f.assets[n], c)
		}
	}
	if len(f.assets) != 4 {
		t.Errorf("release holds %d assets, want exactly the 4 of this publish: %v", len(f.assets), f.assets)
	}
}

func TestReleasePublishRepairsAMissingUnchangedAsset(t *testing.T) {
	f := newFakeGitHub(t)
	v1 := writeFlat(t, map[string]string{timestampAsset: "ts1", "payload": "big"})
	if out, _, err := publishWith(t, f, v1, ""); err != nil {
		t.Fatalf("first publish: %v\n%s", err, out)
	}
	delete(f.assets, "payload")
	out, _, err := publishWith(t, f, v1, v1)
	if err != nil || string(f.assets["payload"]) != "big" || !strings.Contains(out, "uploading it again") {
		t.Fatalf("a lost unchanged asset must be uploaded again: err=%v assets=%v\n%s", err, f.assets, out)
	}
}

func TestReleasePublishHonoursRateLimits(t *testing.T) {
	f := newFakeGitHub(t)
	reset := strconv.FormatInt(time.Now().Add(90*time.Second).Unix(), 10)
	f.fail = func(key string, n int) (int, http.Header, string, bool) {
		switch {
		case key == "GET /repos/o/r/releases/tags/e2e-x" && n == 1:
			return http.StatusForbidden, http.Header{"Retry-After": {"30"}, "X-Ratelimit-Remaining": {"4000"}},
				`{"message":"You have exceeded a secondary rate limit."}`, true
		case key == "POST /repos/o/r/releases" && n == 1:
			return http.StatusTooManyRequests, http.Header{}, `{"message":"slow down"}`, true
		case key == "POST /upload/repos/o/r/releases/7/assets?payload" && n == 1:
			return http.StatusForbidden, http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {reset}},
				`{"message":"API rate limit exceeded"}`, true
		case key == "GET /repos/o/r/releases/7/assets" && n == 1:
			return http.StatusForbidden, http.Header{}, `{"message":"You have exceeded a secondary rate limit"}`, true
		}
		return 0, nil, "", false
	}
	v1 := writeFlat(t, map[string]string{timestampAsset: "ts1", "payload": "big"})
	out, slept, err := publishWith(t, f, v1, "")
	if err != nil {
		t.Fatalf("rate limited publish must succeed after waiting: %v\n%s", err, out)
	}
	if len(slept) != 4 || slept[0] != 30*time.Second || slept[1] != time.Minute || slept[2] != time.Minute ||
		slept[3] < 80*time.Second || slept[3] > 92*time.Second {
		t.Fatalf("waits = %v, want retry-after 30s, 1m for 429 and a secondary limit, then until the primary reset", slept)
	}
	for _, s := range []string{"retry-after: 30", "secondary rate limit", "x-ratelimit-remaining: 0", "x-ratelimit-reset: " + reset} {
		if !strings.Contains(out, s) {
			t.Errorf("diagnostics lack %q:\n%s", s, out)
		}
	}
	if string(f.assets["payload"]) != "big" || string(f.assets[timestampAsset]) != "ts1" {
		t.Fatalf("assets after retries: %v", f.assets)
	}
}

func TestReleasePublishFailsFastOnAForbiddenToken(t *testing.T) {
	f := newFakeGitHub(t)
	f.fail = func(string, int) (int, http.Header, string, bool) {
		return http.StatusForbidden, http.Header{
			"X-Accepted-Github-Permissions":          {"contents=read"},
			"Github-Authentication-Token-Expiration": {"2026-09-14 09:00:00 UTC"},
		}, `{"message":"Resource not accessible by personal access token"}`, true
	}
	v1 := writeFlat(t, map[string]string{timestampAsset: "ts1"})
	out, slept, err := publishWith(t, f, v1, "")
	if err == nil {
		t.Fatalf("a 403 that is not a rate limit must fail:\n%s", out)
	}
	if len(slept) != 0 || len(f.take()) != 1 {
		t.Fatalf("a permission 403 must not be retried: slept %v", slept)
	}
	for _, s := range []string{"HTTP 403", "Resource not accessible", "contents=read", "2026-09-14 09:00:00 UTC"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error lacks %q: %v", s, err)
		}
	}
}

func TestReleasePublishGivesUpWithinItsBudget(t *testing.T) {
	f := newFakeGitHub(t)
	f.fail = func(string, int) (int, http.Header, string, bool) {
		return http.StatusForbidden, http.Header{"Retry-After": {"3600"}}, `{"message":"secondary rate limit"}`, true
	}
	v1 := writeFlat(t, map[string]string{timestampAsset: "ts1"})
	out, slept, err := publishWith(t, f, v1, "")
	if err == nil || len(slept) != 0 || !strings.Contains(err.Error(), "giving up after 1 of 6 attempts") {
		t.Fatalf("a wait beyond the budget must fail now: err=%v slept=%v\n%s", err, slept, out)
	}
}

func TestReleasePublishRecoversALostUploadResponse(t *testing.T) {
	f := newFakeGitHub(t)
	v1 := writeFlat(t, map[string]string{timestampAsset: "ts1"})
	// The asset exists already (an attempt whose response was lost), with
	// other bytes; the upload gets 422 and must replace it.
	if out, _, err := publishWith(t, f, writeFlat(t, map[string]string{"x": "y"}), ""); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	f.assets[timestampAsset], f.ids[timestampAsset] = []byte("stale"), 999
	f.fail = func(key string, n int) (int, http.Header, string, bool) {
		// Hide the asset from the first listing only.
		if key == "GET /repos/o/r/releases/7/assets" && n == 2 {
			return http.StatusOK, http.Header{}, `[]`, true
		}
		return 0, nil, "", false
	}
	out, _, err := publishWith(t, f, v1, "")
	if err != nil || string(f.assets[timestampAsset]) != "ts1" || !strings.Contains(out, "HTTP 422") {
		t.Fatalf("422 recovery: err=%v asset=%q\n%s", err, f.assets[timestampAsset], out)
	}
}

func TestGitHubTokenStaysOnItsHosts(t *testing.T) {
	g, err := newGitHub("https://api.github.com", "secret", io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.do(http.MethodGet, "https://example.com/x", nil); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("the token must not go to another host: %v", err)
	}
	if !g.hosts["uploads.github.com"] {
		t.Fatal("uploads.github.com must be allowed next to api.github.com")
	}
}

func TestReleasePublishLocal(t *testing.T) {
	served := t.TempDir()
	v1 := writeFlat(t, map[string]string{timestampAsset: "ts1", "a": "1", "gone": "g"})
	v2 := writeFlat(t, map[string]string{timestampAsset: "ts2", "a": "1", "b": "2"})
	var out bytes.Buffer
	if err := releasePublish([]string{"--local", served, "--dir", v1}, &out, nil); err != nil {
		t.Fatal(err)
	}
	repl := filepath.Join(t.TempDir(), "replaced")
	if err := releasePublish([]string{"--local", served, "--dir", v2, "--prev", v1, "--replaced", repl}, &out, nil); err != nil {
		t.Fatal(err)
	}
	have, err := readFlat(served)
	if err != nil {
		t.Fatal(err)
	}
	if len(have) != 3 || string(have[timestampAsset]) != "ts2" || string(have["b"]) != "2" || string(have["a"]) != "1" {
		t.Fatalf("served dir = %v", have)
	}
	if raw, _ := os.ReadFile(repl); string(raw) != timestampAsset+"\n" {
		t.Fatalf("replaced = %q, want only the timestamp", raw)
	}
}

func TestWaitAssetNeedsConsecutiveFreshReads(t *testing.T) {
	var mu sync.Mutex
	n := 0
	// fresh, stale, fresh, fresh: one fresh read is not enough, the streak
	// restarts after the stale one.
	serve := []string{"new", "old", "new", "new"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Cache-Control") != "" {
			http.Error(w, "the client sends no Cache-Control", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, serve[min(n, len(serve)-1)])
		n++
	}))
	defer srv.Close()
	want := filepath.Join(t.TempDir(), "ts")
	if err := os.WriteFile(want, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := waitAsset([]string{"--url", srv.URL, "--file", want, "--reads", "2", "--spacing", "1ms", "--timeout", "1m"}, &out); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("reads = %d, want 4 (the stale read restarts the streak)", n)
	}

	n = 1 // serves "old" first
	err := waitAsset([]string{"--url", srv.URL, "--file", want, "--reads", "1", "--timeout", "0"}, &out)
	if err == nil || !strings.Contains(err.Error(), "content differs") {
		t.Fatalf("a single stale read with no time to wait must fail: %v", err)
	}
}
