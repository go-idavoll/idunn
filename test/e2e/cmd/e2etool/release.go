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
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Publishing a scenario's repository as release assets used to re-upload every
// asset with `gh release upload --clobber` — the unchanged payloads and the
// versioned metadata of earlier publishes included — from nine parallel jobs.
// That is hundreds of content-creating requests per run, which is what GitHub's
// secondary rate limit counts, and gh hid the error body that would have said
// so. release-publish sends only what changed since the scenario's previous
// publish, retries a rate-limited request as GitHub asks, and prints every
// failed response with the headers that explain it.

// timestampAsset is the one metadata file a client reads by a fixed name. It
// goes last, so a client never sees a timestamp whose snapshot is not there yet.
const timestampAsset = "metadata__timestamp.json"

// assetPlan is what one publish changes, relative to the previous one.
type assetPlan struct {
	New       []string // not in the previous publish
	Changed   []string // in the previous publish with other bytes
	Deleted   []string // in the previous publish, gone now
	Unchanged []string // byte-identical to the previous publish
}

// planAssets compares the flat asset directory of this publish with the kept
// copy of the previous one, byte by byte. prev may be "" or missing: then every
// asset is new.
func planAssets(dir, prev string) (assetPlan, error) {
	var p assetPlan
	cur, err := readFlat(dir)
	if err != nil {
		return p, err
	}
	old := map[string][]byte{}
	if prev != "" {
		if old, err = readFlat(prev); err != nil && !errors.Is(err, os.ErrNotExist) {
			return p, err
		}
	}
	for name, data := range cur {
		was, ok := old[name]
		switch {
		case !ok:
			p.New = append(p.New, name)
		case !bytes.Equal(was, data):
			p.Changed = append(p.Changed, name)
		default:
			p.Unchanged = append(p.Unchanged, name)
		}
	}
	for name := range old {
		if _, ok := cur[name]; !ok {
			p.Deleted = append(p.Deleted, name)
		}
	}
	for _, s := range []*[]string{&p.New, &p.Changed, &p.Deleted, &p.Unchanged} {
		sortUploads(*s)
	}
	return p, nil
}

// sortUploads orders names alphabetically with the timestamp last.
func sortUploads(names []string) {
	sort.Slice(names, func(i, j int) bool {
		if (names[i] == timestampAsset) != (names[j] == timestampAsset) {
			return names[j] == timestampAsset
		}
		return names[i] < names[j]
	})
}

func readFlat(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("%s: %s is a directory, a flat asset directory has none", dir, e.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = data
	}
	return out, nil
}

// assetStore is where assets are published: a GitHub release, or the directory
// the local mode serves.
type assetStore interface {
	// list returns the size of every asset currently published.
	list() (map[string]int64, error)
	// put publishes the file at path as name, replacing an asset of that name.
	put(name, path string) error
	// remove unpublishes name.
	remove(name string) error
}

// syncAssets applies plan to store and returns the names whose bytes were
// replaced under an existing name — the assets a cache can still serve stale.
// An asset the plan calls unchanged but the store does not hold with that size
// is uploaded again and reported, so a store that lost something is repaired
// rather than trusted.
func syncAssets(store assetStore, dir string, plan assetPlan, log io.Writer) ([]string, error) {
	have, err := store.list()
	if err != nil {
		return nil, err
	}
	var uploads, replaced []string
	uploads = append(uploads, plan.New...)
	uploads = append(uploads, plan.Changed...)
	repaired := 0
	for _, name := range plan.Unchanged {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if size, ok := have[name]; !ok || size != fi.Size() {
			_, _ = fmt.Fprintf(log, "release: %s is unchanged but not published as such (present=%v size=%d), uploading it again\n", name, ok, size)
			uploads = append(uploads, name)
			repaired++
		}
	}
	sortUploads(uploads)

	for _, name := range plan.Deleted {
		if _, ok := have[name]; !ok {
			continue
		}
		if err := store.remove(name); err != nil {
			return nil, err
		}
	}
	for _, name := range uploads {
		if _, ok := have[name]; ok {
			replaced = append(replaced, name)
		}
		if err := store.put(name, filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	_, _ = fmt.Fprintf(log, "release: uploaded %d (new %d, changed %d, repaired %d), deleted %d, unchanged %d\n",
		len(uploads), len(plan.New), len(plan.Changed), repaired, len(plan.Deleted), len(plan.Unchanged)-repaired)
	return replaced, nil
}

// dirStore publishes into a local directory, for E2E_MODE=local.
type dirStore struct{ dir string }

func (d dirStore) list() (map[string]int64, error) {
	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		if !e.IsDir() {
			out[e.Name()] = fi.Size()
		}
	}
	return out, nil
}

func (d dirStore) put(name, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tmp := filepath.Join(d.dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d.dir, name))
}

func (d dirStore) remove(name string) error { return os.Remove(filepath.Join(d.dir, name)) }

// --- GitHub -------------------------------------------------------------------

// github is a minimal client for the release endpoints, with bounded retries.
type github struct {
	api     string // https://api.github.com
	token   string
	client  *http.Client
	log     io.Writer
	sleep   func(time.Duration)
	now     func() time.Time
	budget  time.Duration // total time all retries of one request may wait
	tries   int           // attempts per request
	hosts   map[string]bool
	seenTok bool
}

func newGitHub(api, token string, log io.Writer, sleep func(time.Duration)) (*github, error) {
	u, err := url.Parse(api)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("github: bad API URL %q", api)
	}
	if token == "" {
		return nil, errors.New("github: GH_TOKEN is not set")
	}
	hosts := map[string]bool{u.Host: true}
	if u.Host == "api.github.com" {
		hosts["uploads.github.com"] = true
	}
	return &github{
		api: strings.TrimSuffix(api, "/"), token: token, log: log,
		client: &http.Client{Timeout: 10 * time.Minute},
		sleep:  sleep, now: time.Now,
		budget: 12 * time.Minute, tries: 6, hosts: hosts,
	}, nil
}

// apiError is a response the client gave up on.
type apiError struct {
	Method, URL string
	Status      int
	Detail      string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("github: %s %s: HTTP %d\n%s", e.Method, e.URL, e.Status, e.Detail)
}

// diagnose renders what a failed response says about why: the rate limit
// headers, the token's expiry and permissions GitHub reports, and the body.
func diagnose(res *http.Response, body []byte) string {
	var b strings.Builder
	for _, h := range []string{
		"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Used",
		"X-RateLimit-Reset", "X-RateLimit-Resource", "X-GitHub-Request-Id",
		"X-Accepted-GitHub-Permissions", "GitHub-Authentication-Token-Expiration",
	} {
		if v := res.Header.Get(h); v != "" {
			if h == "X-RateLimit-Reset" {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					v += " (" + time.Unix(n, 0).UTC().Format(time.RFC3339) + ")"
				}
			}
			fmt.Fprintf(&b, "  %s: %s\n", strings.ToLower(h), v)
		}
	}
	const maxBody = 2000
	s := strings.Join(strings.Fields(string(body)), " ")
	if len(s) > maxBody {
		s = s[:maxBody] + " ...[truncated]"
	}
	fmt.Fprintf(&b, "  body: %s", s)
	return b.String()
}

// rateLimited reports whether res is GitHub asking the client to slow down —
// a 429, or a 403 that carries a retry-after, an exhausted primary limit or a
// rate-limit message — and how long to wait. attempt counts from 0. Any other
// 403 is final: a token without access does not get better by waiting.
func rateLimited(res *http.Response, body []byte, attempt int, now time.Time) (time.Duration, bool) {
	if res.StatusCode != http.StatusTooManyRequests && res.StatusCode != http.StatusForbidden {
		return 0, false
	}
	if ra := res.Header.Get("Retry-After"); ra != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && n >= 0 {
			return time.Duration(n) * time.Second, true
		}
	}
	if res.Header.Get("X-RateLimit-Remaining") == "0" {
		if n, err := strconv.ParseInt(res.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			if d := time.Unix(n, 0).Sub(now) + time.Second; d > 0 {
				return d, true
			}
			return time.Second, true
		}
	}
	if res.StatusCode == http.StatusTooManyRequests || bytes.Contains(bytes.ToLower(body), []byte("rate limit")) {
		// GitHub's guidance for a secondary limit without retry-after: wait at
		// least a minute, longer on every repeat.
		return time.Minute << attempt, true
	}
	return 0, false
}

// do sends a request built by mk (called again for every attempt, so a body
// can be reopened) and returns the body of a 2xx, or the status in ok for
// the codes the caller handles itself.
func (g *github) do(method, rawURL string, mk func() (io.Reader, int64, string, error), ok ...int) (int, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, nil, err
	}
	if !g.hosts[u.Host] {
		// The upload URL comes from a response; the token goes nowhere else.
		return 0, nil, fmt.Errorf("github: refusing to send the token to %s", u.Host)
	}
	var waited time.Duration
	for attempt := 0; ; attempt++ {
		var body io.Reader
		var length int64
		var ctype string
		if mk != nil {
			if body, length, ctype, err = mk(); err != nil {
				return 0, nil, err
			}
		}
		req, err := http.NewRequest(method, rawURL, body)
		if err != nil {
			return 0, nil, err
		}
		if body != nil {
			req.ContentLength = length
			req.Header.Set("Content-Type", ctype)
		}
		req.Header.Set("Authorization", "Bearer "+g.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		var wait time.Duration
		var why, detail string
		status := 0
		res, err := g.client.Do(req)
		if c, isCloser := body.(io.Closer); isCloser {
			_ = c.Close()
		}
		if err != nil {
			wait, why = 5*time.Second<<attempt, "transport error: "+err.Error()
		} else {
			data, rerr := io.ReadAll(io.LimitReader(res.Body, 8<<20))
			_ = res.Body.Close()
			status = res.StatusCode
			if rerr == nil && res.StatusCode/100 == 2 {
				if !g.seenTok {
					// Not secret, and the first thing to look at when a later
					// call is refused: when the token expires and how much of
					// its primary rate limit is left.
					g.seenTok = true
					_, _ = fmt.Fprintf(g.log, "github: token expiry %q, %s rate limit remaining %s of %s\n",
						res.Header.Get("GitHub-Authentication-Token-Expiration"), res.Header.Get("X-RateLimit-Resource"),
						res.Header.Get("X-RateLimit-Remaining"), res.Header.Get("X-RateLimit-Limit"))
				}
				return res.StatusCode, data, nil
			}
			for _, code := range ok {
				if rerr == nil && res.StatusCode == code {
					return res.StatusCode, data, nil
				}
			}
			detail = diagnose(res, data)
			var limited bool
			switch {
			case rerr != nil:
				wait, why = 5*time.Second<<attempt, "reading the response: "+rerr.Error()
			case res.StatusCode >= 500:
				wait, why = 5*time.Second<<attempt, "server error"
			default:
				if wait, limited = rateLimited(res, data, attempt, g.now()); !limited {
					return res.StatusCode, data, &apiError{Method: method, URL: rawURL, Status: res.StatusCode, Detail: detail}
				}
				why = "rate limited"
			}
		}
		if attempt+1 >= g.tries || waited+wait > g.budget {
			return status, nil, &apiError{Method: method, URL: rawURL, Status: status, Detail: fmt.Sprintf(
				"  %s; giving up after %d of %d attempts and %s of waiting (next wait %s, budget %s)\n%s",
				why, attempt+1, g.tries, waited, wait, g.budget, detail)}
		}
		_, _ = fmt.Fprintf(g.log, "github: %s %s: HTTP %d, %s (attempt %d/%d), retrying in %s\n%s\n",
			method, rawURL, status, why, attempt+1, g.tries, wait, detail)
		g.sleep(wait)
		waited += wait
	}
}

func jsonBody(v any) func() (io.Reader, int64, string, error) {
	return func() (io.Reader, int64, string, error) {
		raw, err := json.Marshal(v)
		return bytes.NewReader(raw), int64(len(raw)), "application/json", err
	}
}

type ghRelease struct {
	ID        int64  `json:"id"`
	UploadURL string `json:"upload_url"`
}

type ghAsset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// releaseByTag returns the release of tag, or nil if there is none.
func (g *github) releaseByTag(repo, tag string) (*ghRelease, error) {
	code, data, err := g.do(http.MethodGet, g.api+"/repos/"+repo+"/releases/tags/"+url.PathEscape(tag), nil, http.StatusNotFound)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, nil
	}
	var r ghRelease
	return &r, json.Unmarshal(data, &r)
}

func (g *github) createRelease(repo, tag, notes string) (*ghRelease, error) {
	code, data, err := g.do(http.MethodPost, g.api+"/repos/"+repo+"/releases", jsonBody(map[string]any{
		"tag_name": tag, "name": tag, "body": notes, "prerelease": true,
	}), http.StatusUnprocessableEntity)
	if err != nil {
		return nil, err
	}
	if code == http.StatusUnprocessableEntity {
		// An earlier attempt may have created it without its response arriving.
		r, err := g.releaseByTag(repo, tag)
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, fmt.Errorf("github: create release %s: HTTP 422: %s", tag, bytes.TrimSpace(data))
		}
		return r, nil
	}
	var r ghRelease
	return &r, json.Unmarshal(data, &r)
}

// ghStore publishes into one release.
type ghStore struct {
	g     *github
	repo  string
	rel   *ghRelease
	names map[string]ghAsset
}

func (s *ghStore) list() (map[string]int64, error) {
	s.names = map[string]ghAsset{}
	for page := 1; ; page++ {
		_, data, err := s.g.do(http.MethodGet, fmt.Sprintf("%s/repos/%s/releases/%d/assets?per_page=100&page=%d", s.g.api, s.repo, s.rel.ID, page), nil)
		if err != nil {
			return nil, err
		}
		var batch []ghAsset
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, err
		}
		for _, a := range batch {
			s.names[a.Name] = a
		}
		if len(batch) < 100 {
			break
		}
	}
	out := map[string]int64{}
	for n, a := range s.names {
		out[n] = a.Size
	}
	return out, nil
}

func (s *ghStore) remove(name string) error {
	a, ok := s.names[name]
	if !ok {
		return nil
	}
	if _, _, err := s.g.do(http.MethodDelete, fmt.Sprintf("%s/repos/%s/releases/assets/%d", s.g.api, s.repo, a.ID), nil, http.StatusNotFound); err != nil {
		return err
	}
	delete(s.names, name)
	return nil
}

func (s *ghStore) put(name, path string) error {
	if err := s.remove(name); err != nil {
		return err
	}
	base, _, _ := strings.Cut(s.rel.UploadURL, "{")
	target := base + "?name=" + url.QueryEscape(name)
	open := func() (io.Reader, int64, string, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, "", err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, 0, "", err
		}
		return f, fi.Size(), "application/octet-stream", nil
	}
	for try := 0; ; try++ {
		code, data, err := s.g.do(http.MethodPost, target, open, http.StatusUnprocessableEntity)
		if err != nil {
			return err
		}
		if code != http.StatusUnprocessableEntity {
			var a ghAsset
			if err := json.Unmarshal(data, &a); err != nil {
				return err
			}
			s.names[name] = a
			return nil
		}
		// 422 already_exists: an earlier attempt landed although its response
		// did not. Delete what is there and upload once more — the bytes of
		// that attempt are not known to be these.
		if try > 0 {
			return fmt.Errorf("github: upload %s: HTTP 422 again after replacing the asset: %s", name, bytes.TrimSpace(data))
		}
		_, _ = fmt.Fprintf(s.g.log, "github: upload %s: HTTP 422 %s; replacing the existing asset\n", name, bytes.TrimSpace(data))
		if _, err := s.list(); err != nil {
			return err
		}
		if err := s.remove(name); err != nil {
			return err
		}
	}
}

// releasePublish makes a release hold exactly the flat assets of --dir,
// uploading only what differs from --prev, and writes the names it replaced to
// --replaced (one per line) for the caller to wait on.
func releasePublish(args []string, stdout io.Writer, sleep func(time.Duration)) error {
	fl := flag.NewFlagSet("release-publish", flag.ContinueOnError)
	repo := fl.String("repo", "", "owner/name of the release repository")
	tag := fl.String("tag", "", "release tag")
	notes := fl.String("notes", "", "release notes, when the release is created")
	local := fl.String("local", "", "publish into this directory instead of a GitHub release")
	dir := fl.String("dir", "", "flat assets of this publish")
	prev := fl.String("prev", "", "flat assets of the previous publish (empty: none)")
	replacedOut := fl.String("replaced", "", "file to write the replaced asset names to")
	api := fl.String("api", "https://api.github.com", "GitHub API base URL")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *dir == "" || (*local == "" && (*repo == "" || *tag == "")) {
		return errors.New("release-publish: --dir and either --local or --repo and --tag are required")
	}
	plan, err := planAssets(*dir, *prev)
	if err != nil {
		return err
	}
	var store assetStore
	if *local != "" {
		store = dirStore{dir: *local}
	} else {
		g, err := newGitHub(*api, os.Getenv("GH_TOKEN"), stdout, sleep)
		if err != nil {
			return err
		}
		rel, err := g.releaseByTag(*repo, *tag)
		if err != nil {
			return err
		}
		if rel == nil {
			if rel, err = g.createRelease(*repo, *tag, *notes); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "release: created %s\n", *tag)
		}
		store = &ghStore{g: g, repo: *repo, rel: rel}
	}
	replaced, err := syncAssets(store, *dir, plan, stdout)
	if err != nil {
		return err
	}
	if *replacedOut != "" {
		var b strings.Builder
		for _, n := range replaced {
			b.WriteString(n + "\n")
		}
		return os.WriteFile(*replacedOut, []byte(b.String()), 0o644)
	}
	return nil
}

// releaseDelete removes a release and its tag. Neither existing is fine.
func releaseDelete(args []string, stdout io.Writer, sleep func(time.Duration)) error {
	fl := flag.NewFlagSet("release-delete", flag.ContinueOnError)
	repo := fl.String("repo", "", "owner/name of the release repository")
	tag := fl.String("tag", "", "release tag")
	api := fl.String("api", "https://api.github.com", "GitHub API base URL")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *repo == "" || *tag == "" {
		return errors.New("release-delete: --repo and --tag are required")
	}
	g, err := newGitHub(*api, os.Getenv("GH_TOKEN"), stdout, sleep)
	if err != nil {
		return err
	}
	rel, err := g.releaseByTag(*repo, *tag)
	if err != nil {
		return err
	}
	if rel != nil {
		if _, _, err := g.do(http.MethodDelete, fmt.Sprintf("%s/repos/%s/releases/%d", g.api, *repo, rel.ID), nil, http.StatusNotFound); err != nil {
			return err
		}
	}
	_, _, err = g.do(http.MethodDelete, g.api+"/repos/"+*repo+"/git/refs/tags/"+url.PathEscape(*tag), nil,
		http.StatusNotFound, http.StatusUnprocessableEntity)
	return err
}
