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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
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

	// Resume enables ranged/resumable downloads for large payload targets: an
	// interrupted body is continued with a Range request instead of started
	// over. See resume.go for why that changes nothing about trust.
	Resume bool

	// ResumeAttempts bounds how many times one download is resumed. Zero
	// selects DefaultResumeAttempts. It has no effect unless Resume is set.
	ResumeAttempts int

	// ProxyResolver decides which proxy to use, if any. Nil reads the
	// environment, which is what Go does by default and what a service
	// environment usually configures.
	//
	// It is an injection point rather than an implementation because the
	// OS-native answers — WinHTTP/WinINET including PAC, macOS SCDynamicStore,
	// Linux GSettings — each need platform code this package would rather not
	// grow (docs/design.md §14.4, and the remainder of IDN-13). A host that
	// needs one plugs it in here.
	ProxyResolver ProxyResolver

	// ProxyUser and ProxyPassword authenticate to an HTTP proxy that demands
	// it. They are sent as Basic credentials on the CONNECT request, which is
	// the one that matters here: every URL idunn fetches is https, so the proxy
	// sees a tunnel and never a request it could authenticate individually.
	//
	// A proxy URL carrying its own userinfo works too, and is the more usual
	// deployment; these exist so credentials do not have to be written into a
	// URL that ends up in logs.
	ProxyUser     string
	ProxyPassword string

	// ClientCertPEM and ClientKeyPEM are a PEM-encoded certificate and private
	// key for mutual TLS, where an enterprise requires the client to identify
	// itself to the proxy or the origin.
	//
	// Like everything else about TLS here, this is transport hardening. It does
	// not make any byte trusted — TUF signatures do — and a deployment that
	// cannot present a certificate is refused by the far side rather than
	// falling back to something weaker (AGENTS.md §1.5).
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

// ProxyResolver decides which proxy a request goes through.
//
// The signature is http.Transport.Proxy's, deliberately: a nil URL means "go
// direct", an error fails the request, and an implementation can be handed
// straight to a transport without an adapter that could get the convention
// wrong.
type ProxyResolver interface {
	Proxy(req *http.Request) (*url.URL, error)
}

// DefaultTimeout bounds a single request when Options.Timeout is zero.
const DefaultTimeout = 60 * time.Second

// New builds a Fetcher that honours the proxy configuration and the system trust
// store, and optionally resumes an interrupted download.
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

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Something replaced the process-wide default transport. We refuse to
		// build a fetcher on an unknown transport rather than silently losing
		// the proxy and trust-store configuration below.
		return nil, fmt.Errorf("fetch: http.DefaultTransport is %T, not *http.Transport", http.DefaultTransport)
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	if len(o.ClientCertPEM) != 0 || len(o.ClientKeyPEM) != 0 {
		cert, err := tls.X509KeyPair(o.ClientCertPEM, o.ClientKeyPEM)
		if err != nil {
			// Half a client certificate is not a reason to connect anonymously
			// and find out later: an enterprise that configured mTLS meant it.
			return nil, fmt.Errorf("fetch: client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	tr := base.Clone()
	tr.Proxy = http.ProxyFromEnvironment
	if o.ProxyResolver != nil {
		tr.Proxy = o.ProxyResolver.Proxy
	}
	if o.ProxyUser != "" || o.ProxyPassword != "" {
		// Every URL idunn fetches is https, so the proxy sees a CONNECT and
		// never an individual request: this header is where proxy credentials
		// have to go.
		tr.ProxyConnectHeader = http.Header{
			"Proxy-Authorization": []string{"Basic " + basicAuth(o.ProxyUser, o.ProxyPassword)},
		}
	}
	tr.TLSClientConfig = tlsCfg
	tr.ForceAttemptHTTP2 = true

	client := &http.Client{Transport: tr, Timeout: timeout}
	if o.Resume {
		attempts := o.ResumeAttempts
		if attempts <= 0 {
			attempts = DefaultResumeAttempts
		}
		return &resumingFetcher{
			client:   client,
			ua:       o.UserAgent,
			attempts: attempts,
			sleep:    time.Sleep,
		}, nil
	}

	f := tuffetcher.NewDefaultFetcher()
	f.SetHTTPClient(client)
	if o.UserAgent != "" {
		f.SetHTTPUserAgent(o.UserAgent)
	}
	return f, nil
}

// basicAuth renders proxy credentials the way RFC 7617 asks for them.
func basicAuth(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}
