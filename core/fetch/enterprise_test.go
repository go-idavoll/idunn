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
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fetch"
)

// authority is a throwaway CA and the certificates it issues. TEST ONLY — it
// exists so mutual TLS can be exercised against a real handshake instead of
// asserted about a struct field.
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

// issue signs a leaf certificate for the given name.
func (a *authority) issue(t *testing.T, cn string, server bool, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  ips,
		DNSNames:     []string{cn},
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

// An origin that demands a client certificate gets one, and the handshake is
// what proves it: this is not a struct field being asserted about.
func TestMutualTLSPresentsTheClientCertificate(t *testing.T) {
	ca := newAuthority(t)
	serverCert, serverKey := ca.issue(t, "localhost", true, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	clientCert, clientKey := ca.issue(t, "idunn-client", false, nil)

	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.certPEM) {
		t.Fatal("the test CA is not usable")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()
	srv.Config.ErrorLog = quietLog()

	withCert, err := fetch.New(fetch.Options{
		ExtraCAs:      [][]byte{ca.certPEM},
		ClientCertPEM: clientCert,
		ClientKeyPEM:  clientKey,
	})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	got, err := withCert.DownloadFile(srv.URL+"/target", 64, 0)
	if err != nil {
		t.Fatalf("with a client certificate: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("got %q", got)
	}

	// And without one the far side refuses, rather than anything here falling
	// back to something weaker.
	without, err := fetch.New(fetch.Options{ExtraCAs: [][]byte{ca.certPEM}})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	if _, err := without.DownloadFile(srv.URL+"/target", 64, 0); err == nil {
		t.Error("a client with no certificate was served by an origin that requires one")
	}
}

// Half a client certificate is not a reason to connect anonymously and find out
// later: an enterprise that configured mTLS meant it.
func TestAnUnusableClientCertificateIsRefusedAtConstruction(t *testing.T) {
	_, err := fetch.New(fetch.Options{
		ClientCertPEM: []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"),
		ClientKeyPEM:  []byte("nor a key"),
	})
	if err == nil {
		t.Fatal("an unusable client certificate was accepted")
	}
	if !strings.Contains(err.Error(), "client certificate") {
		t.Errorf("err = %v, want it to name the client certificate", err)
	}
}

// connectProxy is the smallest thing that is honestly a proxy: it answers
// CONNECT and then shovels bytes. It records what it was asked with, which is the
// point — proxy credentials that are configured but never sent are worse than
// none, because the deployment looks correct.
type connectProxy struct {
	t        *testing.T
	ln       net.Listener
	requires string // the Proxy-Authorization it demands, empty for none.
	sawAuth  atomic.Value
}

func newConnectProxy(t *testing.T, requires string) *connectProxy {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &connectProxy{t: t, ln: ln, requires: requires}
	p.sawAuth.Store("")
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *connectProxy) url() *url.URL {
	return &url.URL{Scheme: "http", Host: p.ln.Addr().String()}
}

func (p *connectProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *connectProxy) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	auth := req.Header.Get("Proxy-Authorization")
	p.sawAuth.Store(auth)

	if p.requires != "" && auth != p.requires {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n")
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

// staticResolver sends every request through one proxy.
type staticResolver struct{ u *url.URL }

func (s staticResolver) Proxy(*http.Request) (*url.URL, error) { return s.u, nil }

// Configured proxy credentials must actually reach the proxy. Every URL idunn
// fetches is https, so the proxy sees a CONNECT and never an individual request:
// the header on that CONNECT is the only place they can go.
func TestProxyCredentialsAreSentOnConnect(t *testing.T) {
	ca := newAuthority(t)
	serverCert, serverKey := ca.issue(t, "localhost", true, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("through the proxy"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	srv.Config.ErrorLog = quietLog()

	// "user:secret" base64-encoded, per RFC 7617.
	const want = "Basic dXNlcjpzZWNyZXQ="
	proxy := newConnectProxy(t, want)

	f, err := fetch.New(fetch.Options{
		ExtraCAs:      [][]byte{ca.certPEM},
		ProxyResolver: staticResolver{u: proxy.url()},
		ProxyUser:     "user",
		ProxyPassword: "secret",
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
	if saw := proxy.sawAuth.Load().(string); saw != want {
		t.Errorf("the proxy saw %q, want %q", saw, want)
	}
}

// A resolver that names no proxy means direct, which is http.Transport's own
// convention and the reason ProxyResolver has that signature rather than one of
// its own.
func TestAResolverThatNamesNoProxyGoesDirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	defer srv.Close()

	f, err := fetch.New(fetch.Options{ProxyResolver: staticResolver{u: nil}})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	got, err := f.DownloadFile(srv.URL+"/target", 64, 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if string(got) != "direct" {
		t.Errorf("got %q", got)
	}
}
