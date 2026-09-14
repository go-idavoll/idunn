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
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fetch"
)

// authority is a throwaway CA and the certificates it issues. TEST ONLY — it
// exists so mutual TLS is exercised against a real handshake instead of asserted
// about a struct field. Its keys live in memory for one test and nowhere else.
type authority struct {
	certPEM []byte
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "idunn test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &authority{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		cert:    cert,
	}
}

// issue signs a leaf certificate for cn, for server or client authentication.
func (a *authority) issue(t *testing.T, cn string, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn},
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// tlsOrigin starts an https server with a certificate from ca. With clientCAs
// set it requires and verifies a client certificate chaining to them.
func tlsOrigin(t *testing.T, ca *authority, clientCAs *x509.CertPool, body string) *httptest.Server {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, "localhost", true)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	if clientCAs != nil {
		srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		srv.TLS.ClientCAs = clientCAs
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func poolOf(t *testing.T, ca *authority) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.certPEM) {
		t.Fatal("the test CA is not usable")
	}
	return pool
}

// An origin that demands a client certificate gets one, and the handshake proves
// it. Without a certificate, or with one from an authority the origin does not
// accept, the far side refuses — on both fetchers, and nothing here falls back to
// something weaker.
func TestMutualTLS(t *testing.T) {
	ca := newAuthority(t)
	srv := tlsOrigin(t, ca, poolOf(t, ca), "payload")
	goodCert, goodKey := ca.issue(t, "idunn-client", false)
	rogue := newAuthority(t)
	rogueCert, rogueKey := rogue.issue(t, "idunn-client", false)

	for _, resume := range []bool{false, true} {
		name := "default"
		if resume {
			name = "resume"
		}
		t.Run(name, func(t *testing.T) {
			build := func(cert, key []byte) (fetch.Fetcher, *int) {
				pauses := 0
				f, err := fetch.NewWithSleep(fetch.Options{
					ExtraCAs:      [][]byte{ca.certPEM},
					ClientCertPEM: cert,
					ClientKeyPEM:  key,
					Resume:        resume,
				}, func(time.Duration) { pauses++ })
				if err != nil {
					t.Fatalf("fetch.New: %v", err)
				}
				return f, &pauses
			}

			f, _ := build(goodCert, goodKey)
			got, err := f.DownloadFile(srv.URL+"/target", 64, 0)
			if err != nil {
				t.Fatalf("with a client certificate: %v", err)
			}
			if string(got) != "payload" {
				t.Errorf("got %q", got)
			}

			for _, tt := range []struct {
				name      string
				cert, key []byte
			}{
				{"without a certificate", nil, nil},
				{"with a certificate from another authority", rogueCert, rogueKey},
			} {
				f, pauses := build(tt.cert, tt.key)
				got, err := f.DownloadFile(srv.URL+"/target", 64, 0)
				if err == nil || got != nil {
					t.Errorf("%s: served %q (err %v) by an origin that requires a valid client certificate", tt.name, got, err)
				}
				// Under TLS 1.3 the server refuses a client certificate after
				// the client's handshake has finished, so the refusal can
				// surface as a plain connection reset instead of the alert,
				// which is indistinguishable from a flaky link and may be
				// retried. What must hold is that retrying stays bounded and
				// ends in the refusal.
				if *pauses > fetch.DefaultResumeAttempts {
					t.Errorf("%s: a refused handshake was retried %d times (%v)", tt.name, *pauses, err)
				}
			}
		})
	}
}

// Half a client certificate, or a certificate with someone else's key, is not a
// reason to connect anonymously and find out later: an enterprise that
// configured mTLS meant it. The refusal names no key material.
func TestAnUnusableClientCertificateIsRefusedAtConstruction(t *testing.T) {
	ca := newAuthority(t)
	cert, key := ca.issue(t, "idunn-client", false)
	_, otherKey := ca.issue(t, "someone-else", false)

	for _, tt := range []struct {
		name      string
		cert, key []byte
	}{
		{"garbage", []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"), []byte("nor a key")},
		{"certificate only", cert, nil},
		{"key only", nil, key},
		{"mismatched key", cert, otherKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetch.New(fetch.Options{ClientCertPEM: tt.cert, ClientKeyPEM: tt.key})
			if err == nil {
				t.Fatal("an unusable client certificate was accepted")
			}
			if !strings.Contains(err.Error(), "client certificate") {
				t.Errorf("err = %v, want it to name the client certificate", err)
			}
			if len(tt.key) > 0 && strings.Contains(err.Error(), string(tt.key)) {
				t.Error("the error contains the private key")
			}
		})
	}
}

// proxy is the smallest thing that is honestly a proxy: it tunnels CONNECT and
// forwards absolute-form requests. It records every Proxy-Authorization it was
// offered, because credentials that are configured but never sent are worse
// than none — the deployment looks correct.
type proxy struct {
	ln       net.Listener
	requires string // the Proxy-Authorization it demands, "" for none

	mu   sync.Mutex
	seen []string // "METHOD auth" per request
}

func newProxy(t *testing.T, requires string) *proxy {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln, requires: requires}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *proxy) url() *url.URL { return &url.URL{Scheme: "http", Host: p.ln.Addr().String()} }

func (p *proxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func (p *proxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *proxy) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	auth := req.Header.Get("Proxy-Authorization")
	p.mu.Lock()
	p.seen = append(p.seen, req.Method+" "+auth)
	p.mu.Unlock()

	if p.requires != "" && auth != p.requires {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}

	if req.Method != http.MethodConnect {
		req.RequestURI = ""
		req.Header.Del("Proxy-Authorization")
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer func() { _ = res.Body.Close() }()
		res.Close = true
		_ = res.Write(conn)
		return
	}

	var d net.Dialer
	upstream, err := d.DialContext(req.Context(), "tcp", req.Host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer func() { _ = upstream.Close() }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstream, br) }()
	_, _ = io.Copy(conn, upstream)
}

// staticResolver sends every request through one proxy, or direct when u is nil.
type staticResolver struct{ u *url.URL }

func (s staticResolver) Proxy(*http.Request) (*url.URL, error) { return s.u, nil }

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// Configured credentials reach the proxy: on the CONNECT for an https origin, on
// the forwarded request for an http one.
func TestProxyCredentialsReachTheProxy(t *testing.T) {
	want := basic("user", "s3cret")
	ca := newAuthority(t)

	t.Run("https via CONNECT", func(t *testing.T) {
		srv := tlsOrigin(t, ca, nil, "through the proxy")
		p := newProxy(t, want)
		f, err := fetch.New(fetch.Options{
			ExtraCAs:      [][]byte{ca.certPEM},
			ProxyResolver: staticResolver{u: p.url()},
			ProxyUser:     "user",
			ProxyPassword: "s3cret",
		})
		if err != nil {
			t.Fatalf("fetch.New: %v", err)
		}
		got, err := f.DownloadFile(srv.URL+"/target", 64, 0)
		if err != nil {
			t.Fatalf("through the proxy: %v", err)
		}
		if string(got) != "through the proxy" {
			t.Errorf("got %q", got)
		}
		if seen := p.requests(); len(seen) != 1 || seen[0] != "CONNECT "+want {
			t.Errorf("the proxy saw %q, want one CONNECT with the credentials", seen)
		}
	})

	t.Run("http forwarded", func(t *testing.T) {
		var originSaw string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			originSaw = r.Header.Get("Proxy-Authorization")
			_, _ = w.Write([]byte("forwarded"))
		}))
		defer srv.Close()
		p := newProxy(t, want)
		f, err := fetch.New(fetch.Options{
			ProxyResolver: staticResolver{u: p.url()},
			ProxyUser:     "user",
			ProxyPassword: "s3cret",
			Resume:        true,
		})
		if err != nil {
			t.Fatalf("fetch.New: %v", err)
		}
		got, err := f.DownloadFile(srv.URL+"/target", 64, 0)
		if err != nil || string(got) != "forwarded" {
			t.Fatalf("got %q, err %v", got, err)
		}
		if seen := p.requests(); len(seen) != 1 || seen[0] != "GET "+want {
			t.Errorf("the proxy saw %q, want one GET with the credentials", seen)
		}
		srv.Close() // waits for the handler, so originSaw is settled
		if originSaw != "" {
			t.Errorf("the origin received proxy credentials %q", originSaw)
		}
	})
}

// A proxy URL that carries its own userinfo keeps it; the options do not
// silently replace credentials an administrator put into the proxy URL.
func TestProxyURLCredentialsWin(t *testing.T) {
	ca := newAuthority(t)
	srv := tlsOrigin(t, ca, nil, "ok")
	want := basic("from-url", "pw")
	p := newProxy(t, want)
	u := p.url()
	u.User = url.UserPassword("from-url", "pw")

	f, err := fetch.New(fetch.Options{
		ExtraCAs:      [][]byte{ca.certPEM},
		ProxyResolver: staticResolver{u: u},
		ProxyUser:     "from-options",
		ProxyPassword: "other",
	})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	if _, err := f.DownloadFile(srv.URL+"/target", 64, 0); err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if u.User.Username() != "from-url" {
		t.Error("the resolver's URL was modified")
	}
}

// A proxy that refuses the credentials fails the download with ErrProxyAuth, at
// once — a resuming fetcher does not retry a login, because an enterprise account
// that locks after a few failures must not be locked by an updater — and nothing
// about the credentials appears in the error.
func TestProxyAuthFailureFailsClosed(t *testing.T) {
	ca := newAuthority(t)
	srv := tlsOrigin(t, ca, nil, "must not be reached")

	for _, tt := range []struct {
		name, user, password string
	}{
		{"wrong credentials", "user", "wr0ng-pass"},
		{"no credentials", "", ""},
	} {
		for _, resume := range []bool{false, true} {
			t.Run(tt.name, func(t *testing.T) {
				p := newProxy(t, basic("user", "right-pass"))
				pauses := 0
				f, err := fetch.NewWithSleep(fetch.Options{
					ExtraCAs:      [][]byte{ca.certPEM},
					ProxyResolver: staticResolver{u: p.url()},
					ProxyUser:     tt.user,
					ProxyPassword: tt.password,
					Resume:        resume,
				}, func(time.Duration) { pauses++ })
				if err != nil {
					t.Fatalf("fetch.New: %v", err)
				}
				got, err := f.DownloadFile(srv.URL+"/target", 64, 0)
				if err == nil || got != nil {
					t.Fatalf("got %q, err %v; want a refusal", got, err)
				}
				if !errors.Is(err, fetch.ErrProxyAuth) {
					t.Errorf("err = %v, want ErrProxyAuth", err)
				}
				if tt.password != "" {
					for _, secret := range []string{tt.password, basic(tt.user, tt.password)[len("Basic "):]} {
						if strings.Contains(err.Error(), secret) {
							t.Errorf("the error %q discloses the credentials", err)
						}
					}
				}
				if n := len(p.requests()); n != 1 || pauses != 0 {
					t.Errorf("the proxy saw %d logins after %d pauses; a refused login must not be retried", n, pauses)
				}
			})
		}
	}
}

// A resolver that names no proxy means direct, and credentials configured for a
// proxy are then not sent anywhere — least of all to the origin.
func TestProxyCredentialsAreNeverSentDirect(t *testing.T) {
	var sawAuth, sawAuthz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth, sawAuthz = r.Header.Get("Proxy-Authorization"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte("direct"))
	}))
	defer srv.Close()

	f, err := fetch.New(fetch.Options{ProxyResolver: staticResolver{u: nil}, ProxyUser: "user", ProxyPassword: "s3cret"})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	got, err := f.DownloadFile(srv.URL+"/target", 64, 0)
	if err != nil || string(got) != "direct" {
		t.Fatalf("got %q, err %v", got, err)
	}
	srv.Close() // waits for the handler, so what it saw is settled
	if sawAuth != "" || sawAuthz != "" {
		t.Errorf("the origin received credentials: %q / %q", sawAuth, sawAuthz)
	}
}

// failingResolver cannot decide.
type failingResolver struct{}

func (failingResolver) Proxy(*http.Request) (*url.URL, error) {
	return nil, errors.New("PAC script unavailable")
}

// A resolver that cannot decide fails the request; it never falls back to a
// direct connection that the enterprise's network policy may forbid.
func TestAFailingResolverDoesNotGoDirect(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte("direct"))
	}))
	defer srv.Close()

	for _, resume := range []bool{false, true} {
		f, err := fetch.NewWithSleep(fetch.Options{ProxyResolver: failingResolver{}, Resume: resume, ResumeAttempts: 1},
			func(time.Duration) {})
		if err != nil {
			t.Fatalf("fetch.New: %v", err)
		}
		if got, err := f.DownloadFile(srv.URL+"/target", 64, 0); err == nil || got != nil {
			t.Errorf("resume=%v: got %q, err %v; want a refusal", resume, got, err)
		}
	}
	srv.Close() // waits for any handler, so reached is settled
	if reached {
		t.Error("a failing resolver let the request go direct")
	}
}

// Credentials that cannot be expressed as Basic are refused at construction
// rather than sent mangled.
func TestMalformedProxyCredentialsAreRefused(t *testing.T) {
	for _, o := range []fetch.Options{
		{ProxyPassword: "orphan"},
		{ProxyUser: "domain:user", ProxyPassword: "pw"},
	} {
		if _, err := fetch.New(o); err == nil {
			t.Errorf("fetch.New accepted user %q", o.ProxyUser)
		} else if strings.Contains(err.Error(), o.ProxyPassword) {
			t.Errorf("the error %q discloses the password", err)
		}
	}
}

// A resolver that names no proxy goes direct, which is http.Transport's own
// convention and the reason ProxyResolver has that signature.
func TestAResolverThatNamesNoProxyGoesDirect(t *testing.T) {
	url := serve(t, "direct")
	f, err := fetch.New(fetch.Options{ProxyResolver: staticResolver{u: nil}})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	got, err := f.DownloadFile(url, 64, 0)
	if err != nil || string(got) != "direct" {
		t.Fatalf("got %q, err %v", got, err)
	}
}
