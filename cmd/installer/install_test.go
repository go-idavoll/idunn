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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/test/redteam/harness"
)

// repo is a throwaway TUF repository served over HTTP, standing in for a real
// publisher.
//
// It is built with the red-team harness rather than a hand-written fixture
// because the harness is the one thing in this tree that already produces a
// repository the client accepts, and its keys are throwaway by construction
// (AGENTS.md §7).
type repo struct {
	srv      *harness.Server
	rootFile string
	version  string
}

func newRepo(t *testing.T, version string) *repo {
	t.Helper()
	keys, err := harness.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	return newRepoWithKeys(t, keys, version)
}

func newRepoWithKeys(t *testing.T, keys *harness.KeySet, version string) *repo {
	t.Helper()
	dir := t.TempDir()
	opts := harness.DefaultBuildOptions(keys)
	opts.Version = version
	// The metadata has to be live: expiry is judged against the real clock here,
	// because the binary under test is the real binary and does not take an
	// injected one.
	opts.Now = time.Now().UTC()
	// The installer resolves for the platform it runs on, and CI runs on three.
	opts.OS, opts.Arch = runtime.GOOS, runtime.GOARCH

	build, err := harness.BuildRepo(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := harness.Serve(dir)
	t.Cleanup(srv.Close)

	rootFile := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(rootFile, build.RootBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return &repo{srv: srv, rootFile: rootFile, version: version}
}

// installArgs is a full command line pointing at this repository.
func (r *repo) installArgs(t *testing.T, root string, extra ...string) []string {
	t.Helper()
	args := []string{
		"install",
		"--root", root,
		"--root-metadata", r.rootFile,
		"--metadata-url", r.srv.MetadataURL(),
		"--targets-url", r.srv.TargetsURL(),
		// A cache per run: two repositories built by two tests are two
		// publishers, and sharing trusted metadata between them would be a
		// rollback to the client, not a fresh start.
		"--cache", t.TempDir(),
	}
	return append(args, extra...)
}

// The end-to-end shape the whole project is built for: a published repository,
// the real binary, a real install root, and no test seam in between.
func TestInstallEndToEnd(t *testing.T) {
	r := newRepo(t, "1.2.0")
	root := filepath.Join(t.TempDir(), "app")

	var stdout, stderr bytes.Buffer
	if code := run(r.installArgs(t, root), &stdout, &stderr); code != exitOK {
		t.Fatalf("run = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, &stdout, &stderr)
	}

	installed, err := installer.InstalledVersion(root)
	if err != nil {
		t.Fatalf("InstalledVersion: %v", err)
	}
	if installed != "1.2.0" {
		t.Errorf("installed %q, want 1.2.0", installed)
	}
	// The payload has to be on disk, with the bytes the descriptor named.
	got, err := os.ReadFile(filepath.Join(root, "versions", "1.2.0", "bin", "app"))
	if err != nil {
		t.Fatalf("reading the installed payload: %v", err)
	}
	if want := "idunn test payload: app 1.2.0\n"; string(got) != want {
		t.Errorf("payload = %q, want %q", got, want)
	}
	if !strings.Contains(stdout.String(), "1.2.0") {
		t.Errorf("stdout does not report what was installed: %q", stdout.String())
	}
}

// Running the same install twice is success, not a second install: the requested
// state is already the state on disk.
func TestInstallIsIdempotent(t *testing.T) {
	r := newRepo(t, "1.2.0")
	root := filepath.Join(t.TempDir(), "app")

	var out bytes.Buffer
	if code := run(r.installArgs(t, root), &out, &out); code != exitOK {
		t.Fatalf("first run = %d: %s", code, &out)
	}
	out.Reset()
	if code := run(r.installArgs(t, root), &out, &out); code != exitOK {
		t.Fatalf("second run = %d: %s", code, &out)
	}
	if v, err := installer.InstalledVersion(root); err != nil || v != "1.2.0" {
		t.Fatalf("InstalledVersion = %q, %v", v, err)
	}
}

// The downgrade preflight is the reason this binary has an exit code of its own:
// an old but still validly signed installer that walks over a newer install is
// exactly what §14.6 exists to stop, and refusing is not a failure.
func TestInstallOverANewerInstallIsRefused(t *testing.T) {
	keys, err := harness.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	newer := newRepoWithKeys(t, keys, "1.2.0")
	older := newRepoWithKeys(t, keys, "1.1.0")
	root := filepath.Join(t.TempDir(), "app")

	var out bytes.Buffer
	if code := run(newer.installArgs(t, root), &out, &out); code != exitOK {
		t.Fatalf("installing 1.2.0 = %d: %s", code, &out)
	}

	out.Reset()
	code := run(older.installArgs(t, root), &out, &out)
	if code != exitRefused {
		t.Fatalf("installing 1.1.0 over 1.2.0 = %d, want %d\n%s", code, exitRefused, &out)
	}
	if !strings.Contains(out.String(), "use the application's own updater") {
		t.Errorf("the refusal does not say what to do instead: %q", out.String())
	}
	// And the newer install is untouched.
	if v, err := installer.InstalledVersion(root); err != nil || v != "1.2.0" {
		t.Fatalf("after the refusal InstalledVersion = %q, %v; want 1.2.0", v, err)
	}
}

// An operator may overrule the preflight, and only an operator: the flag exists,
// the descriptor cannot ask for it.
func TestAllowDowngradeInstallsTheOlderVersion(t *testing.T) {
	keys, err := harness.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	newer := newRepoWithKeys(t, keys, "1.2.0")
	older := newRepoWithKeys(t, keys, "1.1.0")
	root := filepath.Join(t.TempDir(), "app")

	var out bytes.Buffer
	if code := run(newer.installArgs(t, root), &out, &out); code != exitOK {
		t.Fatalf("installing 1.2.0 = %d: %s", code, &out)
	}
	out.Reset()
	if code := run(older.installArgs(t, root, "--allow-downgrade"), &out, &out); code != exitOK {
		t.Fatalf("allowed downgrade = %d, want %d\n%s", code, exitOK, &out)
	}
	if v, err := installer.InstalledVersion(root); err != nil || v != "1.1.0" {
		t.Fatalf("InstalledVersion = %q, %v; want 1.1.0", v, err)
	}
}

// --version resolves a named release instead of the channel head. The descriptor
// is verified either way; what is bypassed is only the publisher's statement
// about which release is current.
func TestInstallNamedVersion(t *testing.T) {
	r := newRepo(t, "1.2.0")
	root := filepath.Join(t.TempDir(), "app")

	var out bytes.Buffer
	if code := run(r.installArgs(t, root, "--version", "1.2.0"), &out, &out); code != exitOK {
		t.Fatalf("run = %d: %s", code, &out)
	}
	if v, err := installer.InstalledVersion(root); err != nil || v != "1.2.0" {
		t.Fatalf("InstalledVersion = %q, %v", v, err)
	}
}

// A version the repository does not have is a failure, and it leaves nothing
// behind: an install that cannot resolve must not create a half-built root.
func TestUnknownVersionFailsWithoutWriting(t *testing.T) {
	r := newRepo(t, "1.2.0")
	root := filepath.Join(t.TempDir(), "app")

	var out bytes.Buffer
	if code := run(r.installArgs(t, root, "--version", "9.9.9"), &out, &out); code != exitError {
		t.Fatalf("run = %d, want %d\n%s", code, exitError, &out)
	}
	if entries, err := os.ReadDir(root); err == nil && len(entries) != 0 {
		t.Errorf("a failed install left %d entries in the install root", len(entries))
	}
}

// A repository whose metadata is not signed by the root this binary carries is
// refused by go-tuf, and the installer reports it as a failure with nothing
// installed. This is the whole point of the anchor being a build-time input.
func TestForeignRepositoryIsRefused(t *testing.T) {
	real := newRepo(t, "1.2.0")
	imposter := newRepo(t, "1.2.0") // different keys, same shape.
	root := filepath.Join(t.TempDir(), "app")

	args := []string{
		"install",
		"--root", root,
		"--root-metadata", real.rootFile, // the anchor we trust ...
		"--metadata-url", imposter.srv.MetadataURL(), // ... pointed at someone else.
		"--targets-url", imposter.srv.TargetsURL(),
		"--cache", t.TempDir(),
	}
	var out bytes.Buffer
	if code := run(args, &out, &out); code != exitError {
		t.Fatalf("run = %d, want %d\n%s", code, exitError, &out)
	}
	if v, err := installer.InstalledVersion(root); err != nil || v != "" {
		t.Fatalf("something was installed from a repository signed by unknown keys: %q, %v", v, err)
	}
}
