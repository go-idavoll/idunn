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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// update rewrites the golden files instead of comparing against them:
//
//	go test ./internal/packer -run Golden -update
//
// Review the resulting diff. A golden file that changes without an intended
// change to the emitted format is the finding, not the inconvenience.
var update = flag.Bool("update", false, "rewrite the golden repository")

// goldenFiles are the emitted documents pinned byte for byte.
//
// Reproducibility is a claim that decays quietly: a map iterated in the wrong
// place, a field that picks up the wall clock, a dependency that reorders its
// output, and two builds stop matching without any test failing. These goldens
// are what makes that a red build. The test keys are deterministic, so
// signatures and key IDs are part of what is pinned.
var goldenFiles = []string{
	"metadata/1.targets.json",
	"metadata/1.stable.json",
	"metadata/1.v1.json",
	"metadata/1.snapshot.json",
	"metadata/timestamp.json",
}

func TestGoldenRepository(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	dir := filepath.Join("testdata", "golden")
	if *update {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range goldenFiles {
		got, err := os.ReadFile(filepath.Join(f.repo, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		path := filepath.Join(dir, strings.ReplaceAll(name, "/", "_"))
		if *update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run: go test ./internal/packer -run Golden -update)", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from the golden file:\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
		}
	}

	// The manifest covers what the per-file goldens cannot: which files exist
	// at all, and the hash-prefixed names the targets are stored under.
	manifest := manifestOf(t, f.repo)
	path := filepath.Join(dir, "manifest.txt")
	if *update {
		if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden files rewritten")
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("manifest: %v (run: go test ./internal/packer -run Golden -update)", err)
	}
	if manifest != string(want) {
		t.Errorf("the published tree differs from the golden manifest:\n--- want ---\n%s\n--- got ---\n%s", want, manifest)
	}
}

// manifestOf renders "sha256  path" for every file in a repository, sorted.
func manifestOf(t *testing.T, dir string) string {
	t.Helper()
	tree := snapshotTree(t, dir)
	names := make([]string, 0, len(tree))
	for name := range tree {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s  %s\n", tree[name], name)
	}
	return b.String()
}
