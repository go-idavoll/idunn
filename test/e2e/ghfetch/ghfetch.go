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

// Package ghfetch serves a TUF repository out of the assets of one GitHub
// release.
//
// A TUF repository is a tree (metadata/1.stable.json,
// targets/payloads/v1/<sha>.<sha>), and a release is a flat list of assets whose
// names cannot contain a slash. The end-to-end test publishes the tree with every
// "/" spelled "__" (FlatName), and this fetcher undoes that on the way in: a
// request for <release>/metadata/timestamp.json becomes a download of the asset
// <release>/metadata__timestamp.json.
//
// Only the URL is rewritten. The download itself — redirects to GitHub's object
// store, the system trust store, and the 404 go-tuf reads as "no newer root" —
// is the wrapped fetcher's, so the client under test exercises the transport a
// real deployment would.
package ghfetch

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-idavoll/idunn/core/fetch"
)

// Separator replaces "/" in a flattened asset name.
const Separator = "__"

// FlatName is the asset name of a repository-relative path such as
// "metadata/timestamp.json".
func FlatName(rel string) string {
	return strings.ReplaceAll(rel, "/", Separator)
}

// fetcher rewrites repository URLs below base onto flat asset names.
type fetcher struct {
	base    fetch.Fetcher
	release string // "https://github.com/<owner>/<repo>/releases/download/<tag>/"
}

// New wraps base so that every URL below releaseURL is fetched from the flat
// asset of the same repository-relative path. releaseURL is the download prefix
// of one release, https://github.com/<owner>/<repo>/releases/download/<tag>.
//
// A URL outside releaseURL is refused rather than passed through: the trust
// client is configured with URLs below it, and anything else is a
// misconfiguration the test should report, not paper over.
func New(base fetch.Fetcher, releaseURL string) (fetch.Fetcher, error) {
	if base == nil {
		return nil, fmt.Errorf("ghfetch: no base fetcher")
	}
	if releaseURL == "" {
		return nil, fmt.Errorf("ghfetch: no release URL")
	}
	return &fetcher{base: base, release: strings.TrimSuffix(releaseURL, "/") + "/"}, nil
}

// DownloadFile implements fetch.Fetcher.
func (f *fetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	rel, ok := strings.CutPrefix(urlPath, f.release)
	if !ok || rel == "" {
		return nil, fmt.Errorf("ghfetch: %s is not below %s", urlPath, f.release)
	}
	if strings.Contains(rel, Separator) {
		// A flattened name already carries the separator, so a path that does
		// too would map onto an asset two different paths could claim.
		return nil, fmt.Errorf("ghfetch: %s contains the separator %q", rel, Separator)
	}
	return f.base.DownloadFile(f.release+FlatName(rel), maxLength, timeout)
}
