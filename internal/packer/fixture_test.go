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

package packer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
)

// refTime is the reference time every test publishes at. Expiries are derived
// from it, never from the wall clock, so a test cannot pass or fail by accident
// of when CI runs (AGENTS.md §4).
var refTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// testRoles are the top-level roles the fixture repository has keys for.
var testRoles = []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP}

// testKey derives a throwaway Ed25519 key from a label.
//
// TEST KEY ONLY. It is deterministic so that golden metadata — which contains
// key IDs and signatures — is stable across runs; that is exactly why it must
// never be anything but a fixture (AGENTS.md §5, §7).
func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("idunn packer test key: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// fixture is a throwaway repository, a build tree and a set of test keys.
type fixture struct {
	t      *testing.T
	repo   string
	build  string
	keyDir string

	env  map[string]string
	priv map[string]ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	f := &fixture{
		t:      t,
		repo:   filepath.Join(base, "repo"),
		build:  filepath.Join(base, "build"),
		keyDir: filepath.Join(base, "keys"),
		env:    map[string]string{},
		priv:   map[string]ed25519.PrivateKey{},
	}
	for _, dir := range []string{f.repo, f.build, f.keyDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range testRoles {
		f.priv[role] = testKey(role)
		f.writeKey(role, f.priv[role])
	}
	f.env[EnvTargetsKey] = f.keyPath(metadata.TARGETS)
	f.env[EnvSnapshotKey] = f.keyPath(metadata.SNAPSHOT)
	f.env[EnvTimestampKey] = f.keyPath(metadata.TIMESTAMP)
	f.writeRoot(nil)
	return f
}

func (f *fixture) keyPath(role string) string { return filepath.Join(f.keyDir, role+".pem") }

// writeKey stores a test key as unencrypted PKCS#8 PEM, the one format the
// packer accepts.
func (f *fixture) writeKey(role string, priv ed25519.PrivateKey) {
	f.t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		f.t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(f.keyPath(role), raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// writeRoot signs and writes the trust anchor. mutate may adjust the root before
// it is signed, which is how the tests build the roots a publish must refuse.
func (f *fixture) writeRoot(mutate func(*metadata.Metadata[metadata.RootType])) {
	f.t.Helper()
	root := metadata.Root(refTime.AddDate(1, 0, 0))
	root.Signed.ConsistentSnapshot = true
	for _, role := range testRoles {
		key, err := metadata.KeyFromPublicKey(f.priv[role].Public())
		if err != nil {
			f.t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			f.t.Fatal(err)
		}
	}
	if mutate != nil {
		mutate(root)
	}
	signer, err := signature.LoadSigner(f.priv[metadata.ROOT], crypto.Hash(0))
	if err != nil {
		f.t.Fatal(err)
	}
	root.ClearSignatures()
	if _, err := root.Sign(signer); err != nil {
		f.t.Fatal(err)
	}
	raw, err := root.ToBytes(true)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.repo, MetadataDir), 0o755); err != nil {
		f.t.Fatal(err)
	}
	name := filepath.Join(f.repo, MetadataDir, "1.root.json")
	if err := os.WriteFile(name, raw, 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) rootBytes() []byte {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.repo, MetadataDir, "1.root.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// writeSource puts a payload file in the build tree.
func (f *fixture) writeSource(name, content string) {
	f.t.Helper()
	path := filepath.Join(f.build, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// writeConfig writes pack.yaml into the build tree.
func (f *fixture) writeConfig(yaml string) string {
	f.t.Helper()
	path := filepath.Join(f.build, "pack.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *fixture) lookupEnv(name string) (string, bool) {
	v, ok := f.env[name]
	return v, ok
}

func (f *fixture) options(now time.Time) Options {
	return Options{
		ConfigPath: filepath.Join(f.build, "pack.yaml"),
		RepoDir:    f.repo,
		Now:        now,
		LookupEnv:  f.lookupEnv,
	}
}

func (f *fixture) publish(now time.Time) (*Result, error) {
	return Publish(f.options(now))
}

func (f *fixture) mustPublish(now time.Time) *Result {
	f.t.Helper()
	res, err := f.publish(now)
	if err != nil {
		f.t.Fatalf("publish: %v", err)
	}
	return res
}

// defaultConfig is one release of one platform: the shape most tests need.
const defaultConfig = `name: demo
version: 1.2.0
channel: stable
requirements:
  min_from_version: 1.0.0
  min_client_version: 1.1.0
targets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app,    dst: bin/app,    kind: exe }
      - { src: linux-amd64/lib.so, dst: lib/lib.so, kind: lib }
`

// seedRelease writes the sources and the config for defaultConfig.
func (f *fixture) seedRelease() {
	f.t.Helper()
	f.writeSource("linux-amd64/app", "idunn test payload: app 1.2.0\n")
	f.writeSource("linux-amd64/lib.so", "idunn test payload: lib 1.2.0\n")
	f.writeConfig(defaultConfig)
}

// resolution is what a client saw when it resolved the published repository.
type resolution struct {
	descriptor *release.Descriptor
	payloads   map[string][]byte
	// roles lists the metadata files the client ended up trusting locally,
	// which is how a test observes *which* delegations it had to load.
	roles []string
}

// resolve points the real client at the published repository over HTTP and runs
// a full resolve: TUF refresh, channel pointer, descriptor, and every payload.
//
// It uses core/trust unchanged. A repository that only this package can read
// would prove nothing: the done-criterion for a publish is that the client
// resolves it end to end.
func (f *fixture) resolve(channel, goos, goarch string, now time.Time) (*resolution, error) {
	f.t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/metadata/", http.StripPrefix("/metadata/",
		http.FileServer(http.Dir(filepath.Join(f.repo, MetadataDir)))))
	mux.Handle("/targets/", http.StripPrefix("/targets/",
		http.FileServer(http.Dir(filepath.Join(f.repo, TargetsDir)))))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	work := f.t.TempDir()
	c, err := trust.New(trust.Options{
		Root:        f.rootBytes(),
		MetadataURL: srv.URL + "/metadata/",
		TargetsURL:  srv.URL + "/targets/",
		LocalDir:    work,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		return nil, err
	}
	c.UnsafeSetRefTime(now)
	if err := c.Refresh(); err != nil {
		return nil, err
	}
	d, err := c.LatestRelease(channel, goos, goarch)
	if err != nil {
		return nil, err
	}
	out := &resolution{descriptor: d, payloads: map[string][]byte{}}
	for _, file := range d.Files {
		raw, err := c.Target(file.Target)
		if err != nil {
			return nil, err
		}
		out.payloads[file.Dst] = raw
	}

	entries, err := os.ReadDir(filepath.Join(work, "metadata"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		out.roles = append(out.roles, e.Name())
	}
	return out, nil
}
