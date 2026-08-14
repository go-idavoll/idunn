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

// Package fetch provides the enterprise-aware transport go-tuf downloads through:
// OS proxy/PAC, the system trust store, and ranged/resumable requests.
//
// It moves bytes and nothing else. Every byte it returns is still verified against
// signed TUF target metadata before use (AGENTS.md §1.5). See docs/design.md §14.4.
package fetch

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	tuffetcher "github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// Fetcher is go-tuf's fetcher contract, re-exported so the rest of core depends on
// this package rather than on go-tuf directly (docs/design.md §2).
type Fetcher = tuffetcher.Fetcher

// Options configures the enterprise-aware fetcher.
type Options struct {
	// UserAgent identifies the client to proxies and servers.
	UserAgent string

	// Timeout bounds a single request.
	Timeout time.Duration

	// ExtraCAs are additional PEM-encoded roots appended to the system trust
	// store, for enterprises that TLS-intercept. Never a replacement for it.
	ExtraCAs [][]byte

	// Resume enables ranged/resumable downloads for large payload targets.
	//
	// TODO(fetch): go-tuf's default fetcher reads whole responses; honouring this
	// needs an own Fetcher implementation that issues Range requests and resumes
	// from a partial file. Until then the field is accepted and ignored.
	Resume bool
}

// DefaultTimeout bounds a single request when Options.Timeout is zero.
const DefaultTimeout = 60 * time.Second

// New builds a Fetcher that honours the OS proxy configuration and the system
// trust store.
//
// ExtraCAs are appended to the system pool, never substituted for it: an
// enterprise that adds an interception CA still trusts the public roots, and a
// misconfigured deployment cannot silently narrow trust to one attacker-supplied
// certificate. TLS is transport hardening only — server authenticity here does not
// make any byte trusted; TUF signatures do (AGENTS.md §1.5).
func New(o Options) (Fetcher, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("fetch: system cert pool: %w", err)
	}
	for i, pem := range o.ExtraCAs {
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("fetch: ExtraCAs[%d] contains no usable PEM certificate", i)
		}
	}

	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment // honours WPAD/PAC via the OS on Windows
	tr.TLSClientConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	tr.ForceAttemptHTTP2 = true

	f := tuffetcher.NewDefaultFetcher()
	f.SetHTTPClient(&http.Client{Transport: tr, Timeout: timeout})
	if o.UserAgent != "" {
		f.SetHTTPUserAgent(o.UserAgent)
	}
	return f, nil
}
