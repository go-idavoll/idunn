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
// proxy resolution and authentication, the system trust store, mutual TLS, and
// ranged/resumable requests.
//
// It moves bytes and nothing else. Every byte it returns is still verified against
// signed TUF target metadata before use (AGENTS.md §1.5). See docs/design.md §14.4.
package fetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

	// Resume enables ranged/resumable downloads: a body interrupted mid-transfer
	// is continued with a Range request instead of started over. See resume.go
	// for why that changes nothing about trust, and for the checks that keep a
	// resumed body from ever being spliced at the wrong offset.
	Resume bool

	// ResumeAttempts bounds how many further requests one download may issue
	// after the first. Zero selects DefaultResumeAttempts. It has no effect
	// unless Resume is set.
	ResumeAttempts int

	// ProxyResolver decides which proxy a request goes through. Nil selects
	// http.ProxyFromEnvironment.
	//
	// It is a seam rather than an implementation: the OS-native answers —
	// WinHTTP/WinINET including PAC, macOS SCDynamicStore, Linux GSettings — are
	// the open remainder of IDN-13 (docs/design.md §14.4). A host that needs one
	// today supplies it here.
	ProxyResolver ProxyResolver

	// ProxyUser and ProxyPassword authenticate to a proxy that demands it, as
	// Basic credentials. They are attached only to a proxy the resolver actually
	// chose — never to a direct request, so they cannot reach an origin — and a
	// proxy URL that carries its own userinfo keeps it. They go on the CONNECT
	// for https URLs and on the forwarded request for http ones.
	//
	// They are never logged; a 407 on CONNECT is reported as ErrProxyAuth,
	// which carries neither the credentials nor the proxy URL.
	ProxyUser     string
	ProxyPassword string

	// ClientCertPEM and ClientKeyPEM are a PEM-encoded certificate chain and
	// private key for mutual TLS, where an enterprise requires the client to
	// identify itself to a proxy or the origin. Key material is accepted only
	// from the caller; this package never reads it from a path of its own.
	//
	// Like everything else about TLS here, this is transport hardening. It does
	// not make any byte trusted — TUF signatures do (AGENTS.md §1.5).
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

// ProxyResolver decides which proxy a request goes through.
//
// The signature is http.Transport.Proxy's, deliberately: a nil URL means "go
// direct", and an error fails the request — it never falls back to a direct
// connection.
type ProxyResolver interface {
	Proxy(req *http.Request) (*url.URL, error)
}

// ErrProxyAuth reports that a proxy answered a CONNECT with 407: the configured
// credentials were refused, or none were configured. It is never retried — an
// enterprise account that locks after a few failed logins must not be locked by
// an update client.
var ErrProxyAuth = errors.New("fetch: proxy authentication required or refused (407)")

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
	return newFetcher(o, time.Sleep)
}

// newFetcher is New with the pause between resume attempts injected, so a test
// need not wait out a real backoff.
func newFetcher(o Options, sleep func(time.Duration)) (Fetcher, error) {
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

	if o.ProxyPassword != "" && o.ProxyUser == "" {
		return nil, errors.New("fetch: ProxyPassword is set without ProxyUser")
	}
	if strings.Contains(o.ProxyUser, ":") {
		// RFC 7617: a Basic user-id cannot contain a colon; the far side would
		// split it into a different user and password.
		return nil, errors.New("fetch: ProxyUser contains a colon")
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Something replaced the process-wide default transport. We refuse to
		// build a fetcher on an unknown transport rather than silently losing
		// the proxy and trust-store configuration below.
		return nil, fmt.Errorf("fetch: http.DefaultTransport is %T, not *http.Transport", http.DefaultTransport)
	}
	tr := base.Clone()
	resolve := http.ProxyFromEnvironment
	if o.ProxyResolver != nil {
		resolve = o.ProxyResolver.Proxy
	}
	tr.Proxy = withProxyCredentials(resolve, o.ProxyUser, o.ProxyPassword)
	tr.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
		// The proxy URL handed to this hook may carry credentials, so it is
		// deliberately not part of the error.
		if res.StatusCode == http.StatusProxyAuthRequired {
			return ErrProxyAuth
		}
		return nil
	}
	tr.TLSClientConfig = tlsCfg
	tr.ForceAttemptHTTP2 = true

	client := &http.Client{Transport: tr, Timeout: timeout}
	if o.Resume {
		attempts := o.ResumeAttempts
		if attempts <= 0 {
			attempts = DefaultResumeAttempts
		}
		return &resumingFetcher{client: client, ua: o.UserAgent, attempts: attempts, sleep: sleep}, nil
	}

	f := tuffetcher.NewDefaultFetcher()
	f.SetHTTPClient(client)
	if o.UserAgent != "" {
		f.SetHTTPUserAgent(o.UserAgent)
	}
	return f, nil
}

// withProxyCredentials attaches user and password to whichever proxy resolve
// picks. A direct connection (nil URL) gets nothing, so the credentials can never
// be sent to an origin, and a proxy URL with its own userinfo keeps it. The
// resolver's URL is copied, never modified.
func withProxyCredentials(resolve func(*http.Request) (*url.URL, error), user, password string) func(*http.Request) (*url.URL, error) {
	if user == "" {
		return resolve
	}
	return func(req *http.Request) (*url.URL, error) {
		u, err := resolve(req)
		if err != nil || u == nil || u.User != nil {
			return u, err
		}
		withAuth := *u
		withAuth.User = url.UserPassword(user, password)
		return &withAuth, nil
	}
}
