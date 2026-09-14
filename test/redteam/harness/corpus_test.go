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
	"bytes"
	"os"
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
			// A history case publishes twice, so it owns the build as well and
			// is dispatched before anything is written.
			if c.History != harness.HistoryNone {
				runHistoryCase(t, c, keys, t.TempDir())
				return
			}

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

// runHistoryCase drives an attack that only exists against a client with a past.
//
// The shape is always the same, and it is the attack as it happens: one URL, an
// honest publish the client comes to trust, then different bytes behind the
// same URL. The first phase is asserted to succeed — a case whose setup quietly
// broke would otherwise pass while testing nothing — and every runner also
// carries a control showing that what refuses is the client's memory and not
// something about the repository alone.
func runHistoryCase(t *testing.T, c harness.Case, keys *harness.KeySet, dir string) {
	t.Helper()
	repoDir := filepath.Join(dir, "repo")
	srv := harness.Serve(repoDir)
	defer srv.Close()

	switch c.History {
	case harness.HistoryRollback:
		runRollbackCase(t, c, srv, keys, dir)
	case harness.HistoryFreeze:
		runFreezeCase(t, c, srv, keys, dir)
	case harness.HistoryDowngrade:
		runDowngradeCase(t, c, srv, keys, dir)
	default:
		t.Fatalf("unhandled history attack %q", c.History)
	}
}

// republish replaces what the server at dir/repo answers with a fresh build of
// opts. The directory is cleared first, so the second phase is exactly what the
// attacker offers, with nothing of the first left behind to fall back on.
func republish(t *testing.T, dir string, opts harness.BuildOptions) *harness.Build {
	t.Helper()
	repoDir := filepath.Join(dir, "repo")
	if err := os.RemoveAll(repoDir); err != nil {
		t.Fatalf("clearing the served repository: %v", err)
	}
	build, err := harness.BuildRepo(repoDir, opts)
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}
	return build
}

// trustedTimestamp is the timestamp a client run in workDir currently trusts —
// the freshest thing it remembers, and what an attack on its memory must not
// overwrite.
func trustedTimestamp(t *testing.T, workDir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(workDir, "cache", "metadata", "timestamp.json"))
	if err != nil {
		t.Fatalf("reading the trusted timestamp: %v", err)
	}
	return raw
}

// refuseAndForgetNothing asserts the refusal every trust-layer history case
// ends in: the expected class, nothing installed, and the client's memory
// exactly as it was before the attack.
func refuseAndForgetNothing(t *testing.T, c harness.Case, res harness.Result, client string, remembered []byte, attack string) {
	t.Helper()
	if res.Err == nil {
		t.Fatalf("VULNERABILITY: %s was ACCEPTED (resolved %v)", attack, res.Descriptor)
	}
	if res.Class != c.ErrorClass {
		t.Fatalf("rejected as %q, case expects %q: %v", res.Class, c.ErrorClass, res.Err)
	}
	if err := harness.NoOnDiskChange(res.InstallRoot); err != nil {
		t.Fatalf("fail-closed violated: %v", err)
	}
	if !bytes.Equal(trustedTimestamp(t, client), remembered) {
		t.Fatalf("fail-closed violated: the refused run replaced the timestamp the client trusts")
	}
}

// runRollbackCase: the client trusts version 5, and the server replays version 1.
func runRollbackCase(t *testing.T, c harness.Case, srv *harness.Server, keys *harness.KeySet, dir string) {
	t.Helper()
	client := filepath.Join(dir, "client")

	// Phase one: a publisher that has been at work for a while.
	ahead := harness.DefaultBuildOptions(keys)
	ahead.Mutator = harness.AdvancedMetadataVersions
	rootBytes := republish(t, dir, ahead).RootBytes
	if res := harness.Run(srv, rootBytes, client, refTime(ahead), ahead); res.Err != nil {
		t.Fatalf("the honest publish was rejected, so the case proves nothing: %v", res.Err)
	}
	remembered := trustedTimestamp(t, client)

	// The attacker replays an older repository. Nothing in it is forged and
	// nothing in it has expired — it is exactly what the publisher once signed,
	// which is why the only defence is the version the client remembers.
	replay := harness.DefaultBuildOptions(keys)
	republish(t, dir, replay)

	// A client with no memory takes the replay without complaint. That is what
	// makes the refusal below about memory rather than about the bytes.
	if naive := harness.Run(srv, rootBytes, filepath.Join(dir, "naive"), refTime(replay), replay); naive.Err != nil {
		t.Fatalf("the case is not testing what it claims: the replayed repository is refused "+
			"even on first contact (%v)", naive.Err)
	}

	res := harness.Run(srv, rootBytes, client, refTime(replay), replay)
	refuseAndForgetNothing(t, c, res, client, remembered, "metadata older than what the client already trusts")
}

// runFreezeCase: the server stops publishing and keeps answering with what the
// client already has.
func runFreezeCase(t *testing.T, c harness.Case, srv *harness.Server, keys *harness.KeySet, dir string) {
	t.Helper()
	client := filepath.Join(dir, "client")

	first := harness.DefaultBuildOptions(keys)
	rootBytes := republish(t, dir, first).RootBytes
	if res := harness.Run(srv, rootBytes, client, refTime(first), first); res.Err != nil {
		t.Fatalf("the honest publish was rejected, so the case proves nothing: %v", res.Err)
	}
	remembered := trustedTimestamp(t, client)

	// A month later, a publisher that did its job has signed new metadata. This
	// is the clock both runs below are judged at.
	honest := harness.DefaultBuildOptions(keys)
	honest.Now = first.Now.AddDate(0, 0, 30)
	honest.Mutator = harness.AdvancedMetadataVersions
	later := refTime(honest)

	// The attacker republishes nothing. Its whole power is to withhold — to pin
	// the client to the last state it saw, so a fixed release never reaches it —
	// and expiry is what bounds how long that works.
	res := harness.Run(srv, rootBytes, client, later, first)
	refuseAndForgetNothing(t, c, res, client, remembered, "metadata withheld past its expiry")

	// The same client, at the same clock, against a publisher that kept
	// publishing, is fine. So the refusal above is staleness — not the clock in
	// disguise, and not a client the first refusal left unable to recover.
	republish(t, dir, honest)
	if ok := harness.Run(srv, rootBytes, client, later, honest); ok.Err != nil {
		t.Fatalf("the case is not testing what it claims: fresh metadata is refused at the same clock (%v)", ok.Err)
	}
}

// runDowngradeCase: every document is authentic and current, and the channel
// head names a release older than the one installed.
func runDowngradeCase(t *testing.T, c harness.Case, srv *harness.Server, keys *harness.KeySet, dir string) {
	t.Helper()
	machine := filepath.Join(dir, "machine")

	first := harness.DefaultBuildOptions(keys)
	build := republish(t, dir, first)
	rootBytes := build.RootBytes
	installed := harness.RunInstall(srv, rootBytes, machine, refTime(first), first)
	if installed.Err != nil {
		t.Fatalf("the honest install failed, so the case proves nothing: %v", installed.Err)
	}
	if v, err := harness.InstalledVersion(installed.InstallRoot); err != nil || v != first.Version {
		t.Fatalf("installed %q (%v), want %s", v, err, first.Version)
	}

	// The channel moves backwards while the metadata moves forwards: every role
	// version rises, so this is no rollback and TUF has nothing to object to.
	back := harness.DefaultBuildOptions(keys)
	back.Version = "1.1.0"
	back.Mutator = harness.AdvancedMetadataVersions
	older := republish(t, dir, back)

	// A machine with nothing installed takes that very release, all the way
	// through the real install path. The refusal below is therefore the
	// installation's version floor and nothing about the repository.
	naive := harness.RunInstall(srv, rootBytes, filepath.Join(dir, "naive"), refTime(back), back)
	if naive.Err != nil {
		t.Fatalf("the case is not testing what it claims: the older release is refused "+
			"even by a machine with nothing installed (%v)", naive.Err)
	}

	res := harness.RunUpdate(srv, rootBytes, machine, refTime(back), back)
	if res.Err == nil {
		t.Fatalf("VULNERABILITY: a release older than the installed one was ACCEPTED (installed %q)", res.Version)
	}
	if res.Class != c.ErrorClass {
		t.Fatalf("rejected as %q, case expects %q: %v", res.Class, c.ErrorClass, res.Err)
	}

	// The install root is not empty — it holds a good installation — so fail
	// closed means the refusal changed nothing, and none of the older release's
	// bytes arrived.
	if v, err := harness.InstalledVersion(installed.InstallRoot); err != nil || v != first.Version {
		t.Fatalf("after the refusal the install is %q (%v), want the untouched %s", v, err, first.Version)
	}
	for _, f := range build.Descriptor.Files {
		got, err := harness.InstalledBytes(installed.InstallRoot, f.Dst)
		if err != nil {
			t.Fatalf("reading the installed %s: %v", f.Dst, err)
		}
		if !bytes.Equal(got, build.Payloads[f.Target]) {
			t.Fatalf("fail-closed violated: the installed %s is no longer the %s payload", f.Dst, first.Version)
		}
	}
	for _, f := range older.Descriptor.Files {
		if err := harness.NoTraceOf(installed.InstallRoot, older.Payloads[f.Target]); err != nil {
			t.Fatalf("fail-closed violated: %v", err)
		}
	}
}
