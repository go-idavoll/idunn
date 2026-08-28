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
	"os"
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
			dir := t.TempDir()

			// A history case owns both of its phases, including the build, so
			// it is dispatched before anything is published.
			if c.History != harness.HistoryNone {
				runHistoryCase(t, c, keys, dir)
				return
			}

			opts := harness.DefaultBuildOptions(keys)
			opts.Mutator = harness.Mutators[c.Mutator]

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

// runHistoryCase drives an attack that only exists against a client with a past.
//
// The shape is always the same: publish something honest, let the client come to
// trust it, then change what the server offers — and check that the client's
// memory, not its luck, is what refuses. Phase one is therefore asserted to
// *succeed*: a case whose setup silently failed would "pass" while testing
// nothing at all.
func runHistoryCase(t *testing.T, c harness.Case, keys *harness.KeySet, dir string) {
	t.Helper()
	repoDir := filepath.Join(dir, "repo")
	srv := harness.Serve(repoDir)
	defer srv.Close()

	// Phase one: an honest repository. For the rollback case it is published
	// far enough along that going back is visible; for the others it is the
	// plain baseline.
	first := harness.DefaultBuildOptions(keys)
	if c.Mutator != "" {
		first.Mutator = harness.Mutators[c.Mutator]
	}
	build := republish(t, repoDir, first)

	switch c.History {
	case harness.HistoryRollback:
		runRollbackCase(t, c, srv, build.RootBytes, dir, keys, first)
	case harness.HistoryFreeze:
		runFreezeCase(t, c, srv, build.RootBytes, dir, keys, first)
	case harness.HistoryDowngrade:
		runDowngradeCase(t, c, srv, build.RootBytes, dir, keys, first)
	default:
		t.Fatalf("unhandled history attack %q", c.History)
	}
}

// republish replaces the served repository with a fresh build of opts.
//
// The directory is cleared first so the second phase is exactly what the
// attacker offers, with no leftovers of the first to fall back on.
func republish(t *testing.T, repoDir string, opts harness.BuildOptions) *harness.Build {
	t.Helper()
	if err := os.RemoveAll(repoDir); err != nil {
		t.Fatalf("clearing the served repository: %v", err)
	}
	build, err := harness.BuildRepo(repoDir, opts)
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}
	return build
}

// runRollbackCase: the client trusts version 5; the server offers version 1.
func runRollbackCase(t *testing.T, c harness.Case, srv *harness.Server, rootBytes []byte,
	dir string, keys *harness.KeySet, first harness.BuildOptions) {
	t.Helper()
	client := filepath.Join(dir, "client")

	if res := harness.Run(srv, rootBytes, client, refTime(first), first); res.Err != nil {
		t.Fatalf("the honest publish was rejected, so the case proves nothing: %v", res.Err)
	}

	// The attacker replays an older, still perfectly signed repository. Nothing
	// about it is forged — that is the whole difficulty of the attack, and the
	// reason the defence has to be the version the client remembers.
	old := harness.DefaultBuildOptions(keys)
	republish(t, filepath.Join(dir, "repo"), old)

	// A client with no memory takes the replay without complaint, which is what
	// makes the next assertion about memory rather than about the bytes.
	if naive := harness.Run(srv, rootBytes, filepath.Join(dir, "naive"), refTime(old), old); naive.Err != nil {
		t.Fatalf("the case is not testing what it claims: the replayed repository is refused "+
			"even on first contact (%v)", naive.Err)
	}

	res := harness.Run(srv, rootBytes, client, refTime(old), old)
	if res.Err == nil {
		t.Fatal("VULNERABILITY: metadata older than what the client already trusts was ACCEPTED")
	}
	if res.Class != c.ErrorClass {
		t.Fatalf("rejected as %q, case expects %q: %v", res.Class, c.ErrorClass, res.Err)
	}
	if err := harness.NoOnDiskChange(res.InstallRoot); err != nil {
		t.Fatalf("fail-closed violated: %v", err)
	}
}

// runFreezeCase: the server stops publishing and keeps handing out what it has.
func runFreezeCase(t *testing.T, c harness.Case, srv *harness.Server, rootBytes []byte,
	dir string, keys *harness.KeySet, first harness.BuildOptions) {
	t.Helper()
	client := filepath.Join(dir, "client")

	if res := harness.Run(srv, rootBytes, client, refTime(first), first); res.Err != nil {
		t.Fatalf("the honest publish was rejected, so the case proves nothing: %v", res.Err)
	}

	// Nothing is republished. The attacker's whole power here is to withhold —
	// to pin a client to the last state it saw, so a fixed release never
	// reaches it. Expiry is what bounds how long that can work.
	later := first.Now.AddDate(0, 0, 30)
	res := harness.Run(srv, rootBytes, client, later, first)
	if res.Err == nil {
		t.Fatal("VULNERABILITY: metadata withheld past its expiry was ACCEPTED as current")
	}
	if res.Class != c.ErrorClass {
		t.Fatalf("rejected as %q, case expects %q: %v", res.Class, c.ErrorClass, res.Err)
	}

	// And the refusal is about staleness, not about the clock: a publisher that
	// did its job is accepted at exactly the same moment.
	fresh := harness.DefaultBuildOptions(keys)
	fresh.Now = later
	freshBuild := republish(t, filepath.Join(dir, "repo"), fresh)
	if ok := harness.Run(srv, freshBuild.RootBytes, filepath.Join(dir, "fresh"), refTime(fresh), fresh); ok.Err != nil {
		t.Fatalf("a freshly published repository is refused at the same clock, so the case "+
			"is testing the clock and not the freeze: %v", ok.Err)
	}
}

// runDowngradeCase: every document is current and authentic, and the channel
// head names a release older than what is installed.
func runDowngradeCase(t *testing.T, c harness.Case, srv *harness.Server, rootBytes []byte,
	dir string, keys *harness.KeySet, first harness.BuildOptions) {
	t.Helper()
	machine := filepath.Join(dir, "machine")

	installed := harness.RunInstall(srv, rootBytes, machine, refTime(first), first)
	if installed.Err != nil {
		t.Fatalf("the honest install failed, so the case proves nothing: %v", installed.Err)
	}
	if v, err := harness.InstalledVersion(installed.InstallRoot); err != nil || v != first.Version {
		t.Fatalf("installed %q (%v), want %s", v, err, first.Version)
	}

	// The channel moves backwards while the metadata moves forwards: role
	// versions rise, so this is not a rollback and TUF has no reason to object.
	// Only the app-level floor stands between the client and an older release.
	back := harness.DefaultBuildOptions(keys)
	back.Version = "1.1.0"
	back.Mutator = harness.Mutators["advanced_metadata_versions"]
	republish(t, filepath.Join(dir, "repo"), back)

	if naive := harness.Run(srv, rootBytes, filepath.Join(dir, "naive"), refTime(back), back); naive.Err != nil {
		t.Fatalf("the case is not testing what it claims: the older release is refused by the "+
			"trust layer before the version floor sees it (%v)", naive.Err)
	}

	res := harness.RunInstall(srv, rootBytes, machine, refTime(back), back)
	if res.Err == nil {
		t.Fatal("VULNERABILITY: a release older than the installed one was ACCEPTED")
	}
	if res.Class != c.ErrorClass {
		t.Fatalf("rejected as %q, case expects %q: %v", res.Class, c.ErrorClass, res.Err)
	}
	// The install root is not empty here — it holds a good installation — so
	// fail-closed means the refusal changed nothing, not that nothing is there.
	if v, err := harness.InstalledVersion(installed.InstallRoot); err != nil || v != first.Version {
		t.Fatalf("after the refusal the install is %q (%v), want the untouched %s", v, err, first.Version)
	}
}
