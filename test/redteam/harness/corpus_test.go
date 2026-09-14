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

	"github.com/go-idavoll/idunn/core/release"
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

// TestDeltaBaselineTakesThePatch is the control for the delta cases. Without it
// they would all pass on a client that quietly ignored every patch it was
// offered — the strongest possible defence and a useless product.
//
// So: an honest repository with two releases and the patches between them, a
// machine installed on the older one, and an update that must arrive by patch.
// The full payload of the changed file is never fetched, which is the whole
// point of delta stage 2 and the only way to know the corpus above is testing
// something real.
func TestDeltaBaselineTakesThePatch(t *testing.T) {
	opts := harness.DefaultBuildOptions(loadKeys(t))
	opts.Previous = "1.1.0"

	dir := t.TempDir()
	repoDir := filepath.Join(dir, "repo")
	build, err := harness.BuildRepo(repoDir, opts)
	if err != nil {
		t.Fatalf("build delta baseline: %v", err)
	}
	srv := harness.Serve(repoDir)
	defer srv.Close()

	res := harness.RunPatchedUpdate(srv, build.RootBytes, filepath.Join(dir, "client"), refTime(opts), opts)
	if res.Err != nil {
		t.Fatalf("the honest delta update failed: %v", res.Err)
	}
	if res.Version != opts.Version {
		t.Fatalf("installed %q, want %q", res.Version, opts.Version)
	}

	for _, f := range build.Descriptor.Files {
		patch := build.Patches[f.Dst]
		if !srv.Fetched(patch) {
			t.Errorf("%s was not patched: %s never fetched", f.Dst, patch)
		}
		if srv.Fetched(f.Target) {
			t.Errorf("%s was downloaded in full although a patch was published", f.Dst)
		}
		got, err := harness.InstalledBytes(res.InstallRoot, f.Dst)
		if err != nil {
			t.Fatalf("reading the installed %s: %v", f.Dst, err)
		}
		if string(got) != string(build.Payloads[f.Target]) {
			t.Fatalf("the patched %s is not the signed target", f.Dst)
		}
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
			if opts.Mutator != nil {
				// An attack across releases needs the releases to exist: the
				// mutator says which older one the repository must publish.
				opts.Previous = opts.Mutator.Previous
			}

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
			if opts.Mutator == nil || !opts.Mutator.SeedMutatedRoot {
				baseline, err := harness.BuildRepo(filepath.Join(dir, "baseline"), harness.DefaultBuildOptions(keys))
				if err != nil {
					t.Fatalf("build baseline root: %v", err)
				}
				rootBytes = baseline.RootBytes
			}

			srv := harness.Serve(repoDir)
			defer srv.Close()

			if c.Clock != harness.ClockNone {
				runClockCase(t, c, srv, rootBytes, dir, opts)
				return
			}
			if c.Expect == harness.ExpectNoEffect {
				runDeltaCase(t, srv, build, rootBytes, dir, opts)
				return
			}

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

// runDeltaCase drives an attack on a patch: a machine installed on the older
// release, updated to the newer one against a repository whose patches are the
// attacker's.
//
// The assertions are deliberately not "it was refused". A patch is untrusted
// input whose result is checked against a signed hash, so the client is entitled
// to try it and discard what it produces. What must hold is that the update
// still arrives, that every installed byte is the signed one, and that nothing
// the attacker chose is anywhere on the machine — and, so that none of this can
// pass by accident, that the client really did fetch the patch it was offered.
func runDeltaCase(t *testing.T, srv *harness.Server, build *harness.Build, rootBytes []byte, dir string, opts harness.BuildOptions) {
	t.Helper()

	res := harness.RunPatchedUpdate(srv, rootBytes, filepath.Join(dir, "client"), refTime(opts), opts)
	if res.Err != nil {
		t.Fatalf("the update did not survive the attack: %v", res.Err)
	}
	if res.Version != opts.Version {
		t.Fatalf("installed %q, want %q", res.Version, opts.Version)
	}

	// The two halves of "the defence ran": the client took the attacker's patch,
	// and then went and fetched the real payload instead. Without the first this
	// case tests nothing; without the second the client would have installed
	// whatever the patch produced.
	const attacked = "bin/app"
	patch := build.Patches[attacked]
	if !srv.Fetched(patch) {
		t.Fatalf("VACUOUS: the client never fetched %s, so nothing was defended against", patch)
	}
	if full := targetOf(build.Descriptor, attacked); !srv.Fetched(full) {
		t.Fatalf("VACUOUS: the client never fell back to %s, so the patch was not applied and rejected", full)
	}

	// Every file of the release, byte for byte as the repository signed it.
	for _, f := range build.Descriptor.Files {
		got, err := harness.InstalledBytes(res.InstallRoot, f.Dst)
		if err != nil {
			t.Fatalf("reading the installed %s: %v", f.Dst, err)
		}
		if want := build.Payloads[f.Target]; string(got) != string(want) {
			t.Fatalf("VULNERABILITY: the installed %s is not the signed target", f.Dst)
		}
	}
	if len(build.AttackerPayload) > 0 {
		if err := harness.NoTraceOf(res.InstallRoot, build.AttackerPayload); err != nil {
			t.Fatalf("VULNERABILITY: %v", err)
		}
	}
	if err := harness.NoTraceOf(res.InstallRoot, harness.AttackerMarker); err != nil {
		t.Fatalf("VULNERABILITY: %v", err)
	}
}

// targetOf is the target path a descriptor installs at dst.
func targetOf(d *release.Descriptor, dst string) string {
	for i := range d.Files {
		if d.Files[i].Dst == dst {
			return d.Files[i].Target
		}
	}
	return ""
}

// runClockCase drives the clock-rollback story end to end.
//
// The repository is the honest baseline throughout: what is attacked is the
// machine. The four steps are the attack as it actually happens, and step three
// is the one that gives the case its teeth — it shows the repository alone is
// perfectly happy to be resolved at the rolled-back time, so the refusal in step
// four is the floor doing it and nothing else.
func runClockCase(t *testing.T, c harness.Case, srv *harness.Server, rootBytes []byte, dir string, opts harness.BuildOptions) {
	t.Helper()
	machine := filepath.Join(dir, "machine")

	// 1. An honest run inside the validity window. This is what records the
	//    known-good time.
	first := harness.RunInstall(srv, rootBytes, machine, refTime(opts), opts)
	if first.Err != nil {
		t.Fatalf("the honest install failed, so the case proves nothing: %v", first.Err)
	}
	installed, err := harness.InstalledVersion(first.InstallRoot)
	if err != nil || installed != opts.Version {
		t.Fatalf("installed %q (%v), want %s", installed, err, opts.Version)
	}

	// 2. Time passes and the metadata expires. The client says so, which is the
	//    freeze defence working as designed.
	expired := harness.RunInstall(srv, rootBytes, machine, opts.Now.AddDate(0, 0, 30), opts)
	if expired.Err == nil {
		t.Fatal("expired metadata was accepted a month later")
	}
	if expired.Class != harness.ClassVerify {
		t.Fatalf("expired metadata was rejected as %q, want %q: %v", expired.Class, harness.ClassVerify, expired.Err)
	}

	// 3. The attacker's move: at a clock turned back into the old window, the
	//    repository verifies again. A client with no memory of where it has been
	//    would take it, and stay frozen on that metadata forever.
	revived := opts.Now.Add(time.Minute)
	naive := harness.Run(srv, rootBytes, filepath.Join(dir, "naive"), revived, opts)
	if naive.Err != nil {
		t.Fatalf("the case is not testing what it claims: the repository is refused at the "+
			"rolled-back clock for its own reasons (%v)", naive.Err)
	}

	// 4. The same move against a machine that remembers. Nothing about the
	//    repository changed between this and step three.
	res := harness.RunInstall(srv, rootBytes, machine, revived, opts)
	if res.Err == nil {
		t.Fatal("VULNERABILITY: a clock turned back below the known-good floor was ACCEPTED")
	}
	if res.Class != c.ErrorClass {
		t.Fatalf("rejected as %q, case expects %q: %v", res.Class, c.ErrorClass, res.Err)
	}

	// And the installation is exactly as step one left it.
	after, err := harness.InstalledVersion(first.InstallRoot)
	if err != nil || after != opts.Version {
		t.Fatalf("after the refusal the install is %q (%v), want the untouched %s", after, err, opts.Version)
	}
}
