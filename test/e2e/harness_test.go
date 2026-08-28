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

//go:build e2e

// Package e2e drives idunn end to end: the real packer publishes a real TUF
// repository, a real HTTP server hands it out, and the real installer, launcher
// and host application consume it as separate processes.
//
// It is the one suite in this tree with no seam in it. Every other test injects
// a filesystem, a clock or a trust client; here the only injected thing is the
// repository URL, because the alternative is testing a wiring that no user runs.
// That is also its cost: it builds binaries and talks over a socket, which is why
// it sits behind the `e2e` build tag rather than in `go test ./...`.
//
// TEST KEYS ONLY. The role keys below are generated per run and thrown away
// (AGENTS.md §5, §7); nothing here can reach a production key or repository.
package e2e

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/internal/packer"
)

// The roles this suite's throwaway ceremony creates. root signs itself and the
// other three; the packer is handed only the latter three, because a tool that
// runs on every release must not be able to sign the trust anchor
// (docs/packer.md §4) — and a suite that handed it the root key would be testing
// a repository nobody publishes.
var roles = []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP}

// bin holds the binaries under test, built once per run by TestMain.
var bin struct {
	packer    string
	installer string
	launcher  string

	dir string

	// apps caches one built host application per version. Building the fixture
	// is the slowest thing this suite does and the result depends only on the
	// version stamped into it.
	mu   sync.Mutex
	apps map[string]string
}

// repoRoot is the module root, resolved from this file's location so the suite
// does not depend on the working directory a runner chooses.
var repoRoot string

func TestMain(m *testing.M) {
	code, err := build()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2e: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(bin.dir) }()
	if code == 0 {
		code = m.Run()
	}
	// os.Exit skips the deferred cleanup, so do it explicitly.
	_ = os.RemoveAll(bin.dir)
	os.Exit(code)
}

// build compiles the three binaries the suite drives as processes.
func build() (int, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return 1, fmt.Errorf("cannot locate the test source")
	}
	repoRoot = filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	dir, err := os.MkdirTemp("", "idunn-e2e-bin-")
	if err != nil {
		return 1, err
	}
	bin.dir = dir
	bin.apps = map[string]string{}

	for name, pkg := range map[string]*string{
		"./cmd/packer":    &bin.packer,
		"./cmd/installer": &bin.installer,
		"./cmd/launcher":  &bin.launcher,
	} {
		out := filepath.Join(dir, exeName(filepath.Base(name)))
		var ldflags []string
		if name == "./cmd/launcher" {
			// The launcher bakes in what it starts; the suite's application
			// lives at the same install-relative path in every release.
			ldflags = []string{"-X", "main.appBinary=" + appDst()}
		}
		if err := goBuild(out, name, ldflags); err != nil {
			return 1, err
		}
		*pkg = out
	}
	return 0, nil
}

// buildTimeout bounds one compile. A hung toolchain should fail this suite with
// a name attached, not sit until the whole test binary's timeout fires.
const buildTimeout = 5 * time.Minute

// goBuild compiles one package into out.
func goBuild(out, pkg string, ldflags []string) error {
	args := []string{"build", "-o", out}
	if len(ldflags) > 0 {
		args = append(args, "-ldflags", strings.Join(ldflags, " "))
	}
	args = append(args, pkg)
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = repoRoot
	if combined, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, combined)
	}
	return nil
}

// appBinary builds the host application stamped with version, caching the result.
func appBinary(t *testing.T, version string) string {
	t.Helper()
	bin.mu.Lock()
	defer bin.mu.Unlock()
	if p, ok := bin.apps[version]; ok {
		return p
	}
	out := filepath.Join(bin.dir, exeName("app-"+version))
	if err := goBuild(out, "./test/e2e/fixtures/app", []string{"-X", "main.version=" + version}); err != nil {
		t.Fatal(err)
	}
	bin.apps[version] = out
	return out
}

// exeName adds the extension the platform needs to execute a file.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// appDst is the install-relative destination of the application in every release
// this suite publishes.
func appDst() string { return "bin/" + exeName("app") }

// ---------------------------------------------------------------------------
// The repository
// ---------------------------------------------------------------------------

// repo is one throwaway TUF repository: a root ceremony, a directory the packer
// publishes into, and an HTTP server that hands it out.
type repo struct {
	t *testing.T

	dir      string // the published repository (metadata/ + targets/)
	keyDir   string // PKCS#8 PEM role keys, this run only
	anchor   string // a copy of 1.root.json, the client's trust anchor
	srv      *server
	channel  string
	name     string
	released []string // versions published so far, in order
}

// newRepo runs the throwaway root ceremony and starts serving the result.
func newRepo(t *testing.T) *repo {
	t.Helper()
	base := t.TempDir()
	r := &repo{
		t:       t,
		dir:     filepath.Join(base, "repo"),
		keyDir:  filepath.Join(base, "keys"),
		channel: "stable",
		name:    "demo",
	}
	keys := r.ceremony()
	r.writeKeys(keys)
	r.srv = serve(t, r.dir)
	return r
}

// ceremony generates the role keys and writes the trust anchor.
//
// This is the offline, m-of-n root ceremony of docs/packer.md §4, reduced to
// what a test needs: one key per role, a threshold of one, and consistent
// snapshots on — the shape the packer refuses to publish into if it is missing.
func (r *repo) ceremony() map[string]ed25519.PrivateKey {
	r.t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	for _, role := range roles {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			r.t.Fatalf("generating the %s key: %v", role, err)
		}
		keys[role] = priv
	}

	// A year of validity: the suite runs against the real clock, because the
	// binaries under test are the real binaries and take no injected one.
	root := metadata.Root(time.Now().UTC().AddDate(1, 0, 0))
	root.Signed.ConsistentSnapshot = true
	for _, role := range roles {
		key, err := metadata.KeyFromPublicKey(keys[role].Public())
		if err != nil {
			r.t.Fatalf("public key for %s: %v", role, err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			r.t.Fatalf("adding the %s key to root: %v", role, err)
		}
	}
	signer, err := signature.LoadSigner(keys[metadata.ROOT], crypto.Hash(0))
	if err != nil {
		r.t.Fatalf("root signer: %v", err)
	}
	if _, err := root.Sign(signer); err != nil {
		r.t.Fatalf("signing root: %v", err)
	}
	raw, err := root.ToBytes(true)
	if err != nil {
		r.t.Fatalf("encoding root: %v", err)
	}

	metaDir := filepath.Join(r.dir, packer.MetadataDir)
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "1.root.json"), raw, 0o644); err != nil {
		r.t.Fatal(err)
	}
	// The anchor the client ships with is a *copy*, taken before anything is
	// published. A client that read it out of the served repository would be
	// trusting the server to tell it whom to trust.
	r.anchor = filepath.Join(filepath.Dir(r.dir), "root.json")
	if err := os.WriteFile(r.anchor, raw, 0o600); err != nil {
		r.t.Fatal(err)
	}
	return keys
}

// writeKeys stores the three publishing keys as unencrypted PKCS#8 PEM, which is
// the only form internal/packer accepts. The root key is deliberately not
// written: nothing in this suite may sign a trust anchor.
func (r *repo) writeKeys(keys map[string]ed25519.PrivateKey) {
	r.t.Helper()
	if err := os.MkdirAll(r.keyDir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	for _, role := range []string{metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		der, err := x509.MarshalPKCS8PrivateKey(keys[role])
		if err != nil {
			r.t.Fatalf("encoding the %s key: %v", role, err)
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(r.keyPath(role), block, 0o600); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *repo) keyPath(role string) string {
	return filepath.Join(r.keyDir, role+".pem")
}

// release describes what one publish contains beyond the application binary.
type release struct {
	// data maps an install-relative destination to its content. The application
	// binary is added automatically at appDst().
	data map[string]string
}

// publish builds the host application at version, writes a pack.yaml around it,
// and runs the real packer over both.
func (r *repo) publish(version string, rel release) {
	r.t.Helper()
	stage := r.t.TempDir()

	app := appBinary(r.t, version)
	raw, err := os.ReadFile(app)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "app"), raw, 0o755); err != nil {
		r.t.Fatal(err)
	}

	var files strings.Builder
	fmt.Fprintf(&files, "      - { src: app, dst: %s, kind: exe }\n", appDst())
	for i, dst := range sortedKeys(rel.data) {
		name := fmt.Sprintf("data%d", i)
		if err := os.WriteFile(filepath.Join(stage, name), []byte(rel.data[dst]), 0o644); err != nil {
			r.t.Fatal(err)
		}
		fmt.Fprintf(&files, "      - { src: %s, dst: %s, kind: data }\n", name, dst)
	}

	cfg := fmt.Sprintf(`name: %s
version: %s
channel: %s
targets:
  - os: %s
    arch: %s
    files:
%s`, r.name, version, r.channel, runtime.GOOS, runtime.GOARCH, files.String())

	cfgPath := filepath.Join(stage, "pack.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		r.t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(r.t.Context(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin.packer, "publish",
		"--config", cfgPath,
		"--repo", r.dir,
		// The reference time is the real one: this suite's binaries judge
		// expiry against the real clock, so metadata stamped in the past would
		// make every scenario a freshness test. Reproducibility of the packer's
		// output is pinned by internal/packer's golden test, not here.
		"--now", time.Now().UTC().Format(time.RFC3339),
	)
	cmd.Env = append(os.Environ(),
		packer.EnvTargetsKey+"="+r.keyPath(metadata.TARGETS),
		packer.EnvSnapshotKey+"="+r.keyPath(metadata.SNAPSHOT),
		packer.EnvTimestampKey+"="+r.keyPath(metadata.TIMESTAMP),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		r.t.Fatalf("packer publish %s: %v\n%s", version, err, out)
	}
	r.released = append(r.released, version)
}

// sortedKeys returns a map's keys in a deterministic order, so a published
// pack.yaml does not depend on Go's map iteration.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

// server hands out a published repository and counts what was asked for.
//
// The counter is not decoration: "unchanged files cross the wire only once" is a
// claim about requests, and the only honest way to check it is to watch the
// requests (docs/design.md §6.4 stage 1).
type server struct {
	*httptest.Server

	mu       sync.Mutex
	payloads int
	requests []string
}

func serve(t *testing.T, dir string) *server {
	t.Helper()
	s := &server{}
	mux := http.NewServeMux()
	mux.Handle("/metadata/", http.StripPrefix("/metadata/",
		http.FileServer(http.Dir(filepath.Join(dir, packer.MetadataDir)))))
	mux.Handle("/targets/", http.StripPrefix("/targets/",
		http.FileServer(http.Dir(filepath.Join(dir, packer.TargetsDir)))))

	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.record(req.URL.Path)
		mux.ServeHTTP(w, req)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) record(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, path)
	if strings.HasPrefix(path, "/targets/payloads/") {
		s.payloads++
	}
}

// payloadRequests is how many payload files were fetched so far. Descriptors and
// channel pointers are targets too and are deliberately not counted: they change
// with every release, so they say nothing about reuse.
func (s *server) payloadRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.payloads
}

func (s *server) resetCounts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloads = 0
	s.requests = nil
}

func (s *server) metadataURL() string { return s.URL + "/metadata/" }
func (s *server) targetsURL() string  { return s.URL + "/targets/" }
