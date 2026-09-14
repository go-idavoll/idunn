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

// Command e2etool is the plumbing of the GitHub end-to-end update test
// (test/e2e/run.sh). It does what the shell cannot do well:
//
//	init-repo       generate throwaway role keys and sign a 1.root.json
//	flatten         copy a TUF repository tree to flat release asset names
//	wait-asset      poll a URL until it serves the bytes of a local file, repeatedly
//	release-publish publish flat assets as a release, uploading only what changed
//	release-delete  delete a release and its tag
//	serve           serve flat assets locally, for a run without GitHub
//	report          turn one run's recorded cases into JSON and Markdown
//	summary         merge the reports of every job into one matrix
//
// None of it is product code. The keys it generates live for one CI job and are
// trusted by nothing but the client built in that job.
package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/internal/packer"
	"github.com/go-idavoll/idunn/test/e2e/ghfetch"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2etool: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: e2etool init-repo|flatten|wait-asset|release-publish|release-delete|serve|report|summary [flags]")
	}
	switch args[0] {
	case "init-repo":
		return initRepo(args[1:], stdout)
	case "flatten":
		return flatten(args[1:])
	case "wait-asset":
		return waitAsset(args[1:], stdout)
	case "release-publish":
		return releasePublish(args[1:], stdout, time.Sleep)
	case "release-delete":
		return releaseDelete(args[1:], stdout, time.Sleep)
	case "serve":
		return serve(args[1:])
	case "report":
		return report(args[1:], stdout)
	case "summary":
		return summary(args[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// initRepo writes one Ed25519 key per top-level role as unencrypted PKCS#8 PEM —
// the one format the packer reads — and a root that names them with threshold 1
// and consistent snapshots, which is what the packer's checkRoot demands. It
// prints the packer's key variables as NAME=VALUE lines.
func initRepo(args []string, stdout io.Writer) error {
	fl := flag.NewFlagSet("init-repo", flag.ContinueOnError)
	repo := fl.String("repo", "", "TUF repository directory to create")
	keys := fl.String("keys", "", "directory for the private role keys")
	expiry := fl.Duration("expiry", 72*time.Hour, "root lifetime")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *repo == "" || *keys == "" {
		return errors.New("init-repo: --repo and --keys are required")
	}
	for _, dir := range []string{filepath.Join(*repo, packer.MetadataDir), *keys} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	roles := []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP}
	priv := map[string]ed25519.PrivateKey{}
	paths := map[string]string{}
	for _, role := range roles {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		p, err := filepath.Abs(filepath.Join(*keys, role+".pem"))
		if err != nil {
			return err
		}
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}
		priv[role], paths[role] = k, p
	}

	root := metadata.Root(time.Now().UTC().Add(*expiry))
	root.Signed.ConsistentSnapshot = true
	for _, role := range roles {
		key, err := metadata.KeyFromPublicKey(priv[role].Public())
		if err != nil {
			return err
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			return err
		}
	}
	signer, err := signature.LoadSigner(priv[metadata.ROOT], crypto.Hash(0))
	if err != nil {
		return err
	}
	if _, err := root.Sign(signer); err != nil {
		return err
	}
	raw, err := root.ToBytes(true)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*repo, packer.MetadataDir, "1.root.json"), raw, 0o644); err != nil {
		return err
	}

	for _, kv := range []struct{ name, role string }{
		{packer.EnvTargetsKey, metadata.TARGETS},
		{packer.EnvSnapshotKey, metadata.SNAPSHOT},
		{packer.EnvTimestampKey, metadata.TIMESTAMP},
	} {
		if _, err := fmt.Fprintf(stdout, "%s=%s\n", kv.name, filepath.ToSlash(paths[kv.role])); err != nil {
			return err
		}
	}
	return nil
}

// flatten copies every file below src into dst under its flat asset name. The
// copy is complete on every run; release-publish compares it byte by byte with
// the previous publish's copy to decide what to upload.
func flatten(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: e2etool flatten <repo> <out>")
	}
	src, dst := args[0], args[1]
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	seen := map[string]string{}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !validAssetName(rel) {
			return fmt.Errorf("flatten: %s has characters GitHub would rename in an asset name", rel)
		}
		name := ghfetch.FlatName(rel)
		if prev, ok := seen[name]; ok {
			return fmt.Errorf("flatten: %s and %s both map to %s", prev, rel, name)
		}
		seen[name] = rel
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, name), data, 0o644)
	})
}

// validAssetName reports whether GitHub keeps a name as uploaded. It replaces
// anything outside this set, which would break the mapping silently.
func validAssetName(rel string) bool {
	for i := 0; i < len(rel); i++ {
		c := rel[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == '/':
		default:
			return false
		}
	}
	return rel[0] != '.' && !bytes.Contains([]byte(rel), []byte(ghfetch.Separator))
}

// waitAsset polls url until it serves exactly the bytes of file on --reads
// consecutive reads. After an asset is replaced, GitHub can keep serving the
// old one for a while, and not from every edge at once: one fresh read proves
// little. A client that refreshes in that window sees the old timestamp and
// correctly reports "up to date", which would fail the test for a reason that
// is not idunn's.
//
// Every read goes through core/fetch exactly as the client's does — no
// Cache-Control request header (the client sends none, and a cache that honours
// one would show this tool bytes the client does not get), no cache-busting
// query (GitHub does redirect with one, but it is a different cache entry from
// the URL the client asks for) — on a new connection each time, so the reads do
// not all land on one edge.
func waitAsset(args []string, stdout io.Writer) error {
	fl := flag.NewFlagSet("wait-asset", flag.ContinueOnError)
	url := fl.String("url", "", "asset download URL")
	file := fl.String("file", "", "local file the asset must match")
	timeout := fl.Duration("timeout", 5*time.Minute, "give up after (0: read until --reads reads, no waiting)")
	reads := fl.Int("reads", 3, "consecutive reads that must serve the file")
	spacing := fl.Duration("spacing", 2*time.Second, "pause between reads")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *reads < 1 {
		return errors.New("wait-asset: --reads must be at least 1")
	}
	want, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(*timeout)
	streak, total, stale := 0, 0, 0
	for {
		got, err := readAsset(*url, int64(len(want))+1<<20)
		total++
		if err == nil && bytes.Equal(got, want) {
			streak++
			if streak >= *reads {
				_, _ = fmt.Fprintf(stdout, "wait-asset: %s fresh on %d consecutive reads (%d reads, %d stale)\n", *url, streak, total, stale)
				return nil
			}
		} else {
			streak = 0
			stale++
			if time.Now().After(deadline) {
				if err == nil {
					err = fmt.Errorf("content differs: served %d bytes sha256 %s, want %d bytes sha256 %s",
						len(got), shortSum(got), len(want), shortSum(want))
				}
				return fmt.Errorf("wait-asset: %s after %s (%d reads, %d stale): %w; %s", *url, *timeout, total, stale, err, probe(*url))
			}
		}
		if streak > 0 {
			time.Sleep(*spacing)
		} else {
			time.Sleep(3 * time.Second)
		}
	}
}

// readAsset downloads url the way the client under test does, on a fresh
// transport.
func readAsset(url string, maxLength int64) ([]byte, error) {
	f, err := fetch.New(fetch.Options{UserAgent: "idunn-e2etool/wait-asset", Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	return f.DownloadFile(url, maxLength, 30*time.Second)
}

func shortSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:6])
}

// probe describes where a stale read came from: the object the redirect named
// (its path, never the signed query) and the cache headers along the way.
func probe(url string) string {
	res, err := (&http.Client{Timeout: 30 * time.Second}).Get(url)
	if err != nil {
		return "probe: " + err.Error()
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	return fmt.Sprintf("probe: HTTP %d from %s%s, %d bytes sha256 %s, last-modified %q, age %q, x-cache %q, x-served-by %q",
		res.StatusCode, res.Request.URL.Host, res.Request.URL.Path, len(body), shortSum(body),
		res.Header.Get("Last-Modified"), res.Header.Get("Age"), res.Header.Get("X-Cache"), res.Header.Get("X-Served-By"))
}

// serve stands in for a release download: it serves the flat assets of dir
// below /download, and redirects there first the way GitHub redirects to its
// object store. It reads the directory on every request, so a second flatten
// is live without a restart. It is how run.sh checks itself without GitHub.
func serve(args []string) error {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := fl.String("dir", "", "directory of flat assets")
	addr := fl.String("addr", "127.0.0.1:18765", "listen address")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("serve: --dir is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/store/"+r.URL.Path[len("/download/"):], http.StatusFound)
	})
	mux.Handle("/store/", http.StripPrefix("/store/", http.FileServer(http.Dir(*dir))))
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}
