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

//go:build redteam

package harness_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/test/redteam/harness"
)

const (
	keysDir   = "../fixtures/keys"
	corpusDir = "../corpus"
)

func loadKeys(t *testing.T) *harness.KeySet {
	t.Helper()
	keys, err := harness.LoadKeys(keysDir)
	if err != nil {
		t.Fatalf("load test keys (run `make test-keys`): %v", err)
	}
	return keys
}

// refTime is the reference time every case is judged at. It sits inside the
// baseline's validity window, so an expiry case fails for its own reason and not
// because CI happened to run a week later.
func refTime(opts harness.BuildOptions) time.Time {
	return opts.Now.Add(time.Hour)
}

// TestBaselineIsAccepted is the control. Without it, a corpus that rejects
// everything — including a perfectly valid repository — would look green while
// proving nothing.
func TestBaselineIsAccepted(t *testing.T) {
	opts := harness.DefaultBuildOptions(loadKeys(t))

	dir := t.TempDir()
	build, err := harness.BuildRepo(filepath.Join(dir, "repo"), opts)
	if err != nil {
		t.Fatalf("build baseline: %v", err)
	}
	srv := harness.Serve(filepath.Join(dir, "repo"))
	defer srv.Close()

	res := harness.Run(srv, build.RootBytes, filepath.Join(dir, "client"), refTime(opts), opts)
	if res.Err != nil {
		t.Fatalf("baseline repository was rejected: %v", res.Err)
	}
	if res.Descriptor == nil {
		t.Fatal("baseline resolved to no descriptor")
	}
	if got, want := res.Descriptor.Version, opts.Version; got != want {
		t.Fatalf("baseline resolved version %q, want %q", got, want)
	}
}

// TestAdversarialCorpus is the ratchet: every tampered repository in the corpus
// must be rejected, for the expected reason, with nothing written to the install
// root. A mutation that is ACCEPTED is a vulnerability, not a test failure to be
// argued with (AGENTS.md §7).
func TestAdversarialCorpus(t *testing.T) {
	keys := loadKeys(t)

	cases, err := harness.LoadCases(corpusDir)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("corpus is empty: the adversarial suite would pass vacuously")
	}

	for _, c := range cases {
		t.Run(c.Class+"/"+c.Name, func(t *testing.T) {
			opts := harness.DefaultBuildOptions(keys)
			opts.Mutator = harness.Mutators[c.Mutator]

			dir := t.TempDir()
			repoDir := filepath.Join(dir, "repo")
			build, err := harness.BuildRepo(repoDir, opts)
			if err != nil {
				t.Fatalf("build mutated repo: %v", err)
			}

			// By default the client keeps the root it legitimately shipped with:
			// a served root of an already-trusted version is ignored, which is
			// precisely TUF's protection. Cases that attack the anchor itself
			// set SeedMutatedRoot and hand the client the tampered root instead.
			rootBytes := build.RootBytes
			if !opts.Mutator.SeedMutatedRoot {
				baseline, err := harness.BuildRepo(filepath.Join(dir, "baseline"), harness.DefaultBuildOptions(keys))
				if err != nil {
					t.Fatalf("build baseline root: %v", err)
				}
				rootBytes = baseline.RootBytes
			}

			srv := harness.Serve(repoDir)
			defer srv.Close()

			res := harness.Run(srv, rootBytes, filepath.Join(dir, "client"), refTime(opts), opts)
			if res.Err == nil {
				t.Fatalf("VULNERABILITY: mutation %q was ACCEPTED (resolved %v)", c.Mutator, res.Descriptor)
			}
			if res.Class != c.ErrorClass {
				t.Fatalf("rejected as %q, case expects %q: %v", res.Class, c.ErrorClass, res.Err)
			}
			if err := harness.NoOnDiskChange(res.InstallRoot); err != nil {
				t.Fatalf("fail-closed violated: %v", err)
			}
		})
	}
}
