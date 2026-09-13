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
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
)

// A payload worth patching: big enough that a patch is smaller than the file,
// and incompressible so that "smaller" can only come from what two builds have
// in common.
func libBytes(seed int64) string {
	out := make([]byte, 1<<16)
	rand.New(rand.NewSource(seed)).Read(out)
	return string(out)
}

// rebuiltLib is that library after a change: one stretch rewritten in place.
func rebuiltLib(base string, seed int64) string {
	out := []byte(base)
	rand.New(rand.NewSource(seed)).Read(out[len(out)/2 : len(out)/2+len(out)/64])
	return string(out)
}

// deltaFixture publishes one release holding a large library, and returns the
// fixture and the library's bytes.
func deltaFixture(t *testing.T, config string) (*fixture, string) {
	t.Helper()
	f := newFixture(t)
	lib := libBytes(1)
	f.writeSource("linux-amd64/app", "idunn test payload: app 1.2.0\n")
	f.writeSource("linux-amd64/lib.so", lib)
	f.writeConfig(config)
	f.mustPublish(refTime)
	return f, lib
}

// publishNext writes a new library and publishes it as the given version.
func publishNext(t *testing.T, f *fixture, config, version, lib string, at time.Time) *Result {
	t.Helper()
	f.writeSource("linux-amd64/lib.so", lib)
	f.writeConfig(strings.Replace(config, "version: 1.2.0", "version: "+version, 1))
	return f.mustPublish(at)
}

func payloadTargetOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return payloadTarget("1", sum)
}

// The publish that makes delta stage 2 possible: a file that changed a little
// gets a patch beside it, at a path derived from the two content hashes, so a
// client holding the old release can name it without anything referencing it.
func TestPublishEmitsAPatchForAChangedFile(t *testing.T) {
	f, lib := deltaFixture(t, defaultConfig)
	next := rebuiltLib(lib, 2)
	res := publishNext(t, f, defaultConfig, "1.3.0", next, refTime.Add(time.Hour))

	want, ok := release.PatchPath(payloadTargetOf(lib), payloadTargetOf(next))
	if !ok {
		t.Fatal("no patch path between the two payloads")
	}
	if !slices.Contains(res.AddedTargets, want) {
		t.Fatalf("no patch published; added %v", res.AddedTargets)
	}

	// The point of publishing it: the client can fetch it by the name it
	// derives, and applying it to the old payload produces the new one.
	c, _, err := f.client(refTime.Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	patch, err := c.Target(want)
	if err != nil {
		t.Fatalf("the published patch does not resolve: %v", err)
	}
	got, err := stage.ApplyPatch([]byte(lib), patch, int64(len(next)))
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	if !bytes.Equal(got, []byte(next)) {
		t.Fatal("the published patch does not reconstruct the payload it is named for")
	}
	if err := c.VerifyTarget(payloadTargetOf(next), got); err != nil {
		t.Fatalf("the reconstructed payload is not the signed target: %v", err)
	}
	if float64(len(patch)) > 0.5*float64(len(next)) {
		t.Errorf("patch is %d bytes for a %d byte payload", len(patch), len(next))
	}
}

// Patches are emitted against the last few releases, so a client that skipped
// one still has a single hop — and one that skipped more walks the chain.
func TestPublishEmitsPatchesAgainstSeveralReleases(t *testing.T) {
	f, v1 := deltaFixture(t, defaultConfig)
	v2 := rebuiltLib(v1, 2)
	publishNext(t, f, defaultConfig, "1.3.0", v2, refTime.Add(time.Hour))
	v3 := rebuiltLib(v2, 3)
	res := publishNext(t, f, defaultConfig, "1.4.0", v3, refTime.Add(2*time.Hour))

	for _, from := range []string{v1, v2} {
		want, _ := release.PatchPath(payloadTargetOf(from), payloadTargetOf(v3))
		if !slices.Contains(res.AddedTargets, want) {
			t.Errorf("no patch from that release; added %v", res.AddedTargets)
		}
	}
}

// patch_against bounds how far back a publish patches from. Beyond it a client
// walks the releases in between instead, so the repository does not have to
// hold a patch from every release that ever existed.
func TestPatchAgainstBoundsHowFarBackAPublishReaches(t *testing.T) {
	config := strings.Replace(defaultConfig, "channel: stable", "channel: stable\ndelta:\n  patch_against: 1", 1)
	f, v1 := deltaFixture(t, config)
	v2 := rebuiltLib(v1, 2)
	publishNext(t, f, config, "1.3.0", v2, refTime.Add(time.Hour))
	v3 := rebuiltLib(v2, 3)
	res := publishNext(t, f, config, "1.4.0", v3, refTime.Add(2*time.Hour))

	recent, _ := release.PatchPath(payloadTargetOf(v2), payloadTargetOf(v3))
	older, _ := release.PatchPath(payloadTargetOf(v1), payloadTargetOf(v3))
	if !slices.Contains(res.AddedTargets, recent) {
		t.Errorf("no patch from the previous release; added %v", res.AddedTargets)
	}
	if slices.Contains(res.AddedTargets, older) {
		t.Errorf("patched further back than configured; added %v", res.AddedTargets)
	}
}

// Nothing to gain, nothing published: a repository that carries patches nobody
// benefits from is just a bigger repository.
func TestPublishSkipsPatchesThatAreNotWorthIt(t *testing.T) {
	for name, tc := range map[string]struct {
		config string
		next   func(lib string) string
	}{
		"the file is rewritten from scratch": {
			config: defaultConfig,
			next:   func(string) string { return libBytes(99) },
		},
		"patches are switched off": {
			config: strings.Replace(defaultConfig, "channel: stable", "channel: stable\ndelta:\n  patch_against: 0", 1),
			next:   func(lib string) string { return rebuiltLib(lib, 2) },
		},
		"the ratio demands more than this patch achieves": {
			config: strings.Replace(defaultConfig, "channel: stable", "channel: stable\ndelta:\n  max_ratio: 0.0001", 1),
			next:   func(lib string) string { return rebuiltLib(lib, 2) },
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, lib := deltaFixture(t, tc.config)
			next := tc.next(lib)
			res := publishNext(t, f, tc.config, "1.3.0", next, refTime.Add(time.Hour))

			for _, target := range res.AddedTargets {
				if strings.HasPrefix(target, "patches/") {
					t.Errorf("published %s", target)
				}
			}
		})
	}
}

// A file that did not change is one target across both releases, so there is
// nothing to patch and nothing is published for it.
func TestPublishEmitsNoPatchForAnUnchangedFile(t *testing.T) {
	f, lib := deltaFixture(t, defaultConfig)
	// Only the executable changes; the library stays byte for byte.
	f.writeSource("linux-amd64/app", "idunn test payload: app 1.3.0\n")
	res := publishNext(t, f, defaultConfig, "1.3.0", lib, refTime.Add(time.Hour))

	for _, target := range res.AddedTargets {
		if strings.HasPrefix(target, "patches/") {
			t.Errorf("published %s for a release that changed nothing patchable", target)
		}
	}
}

// The patch belongs to the release line that produced the payload, which is the
// role a client following that line already trusts. Anything else would mean a
// second role to load for an optimisation.
func TestPatchesLiveInTheReleaseLineRole(t *testing.T) {
	f, lib := deltaFixture(t, defaultConfig)
	next := rebuiltLib(lib, 2)
	publishNext(t, f, defaultConfig, "1.3.0", next, refTime.Add(time.Hour))

	line := f.readTargets(t, "v1", 2)
	want, _ := release.PatchPath(payloadTargetOf(lib), payloadTargetOf(next))
	if _, ok := line.Signed.Targets[want]; !ok {
		t.Fatalf("the patch is not in v1: %v", sortedKeys(line.Signed.Targets))
	}
}

// Reproducibility covers the patches too: the same inputs must produce the same
// repository, or a rebuild is no longer a check on the publisher (AGENTS.md
// §1.7).
func TestPublishedPatchesAreReproducible(t *testing.T) {
	first, lib := deltaFixture(t, defaultConfig)
	next := rebuiltLib(lib, 2)
	publishNext(t, first, defaultConfig, "1.3.0", next, refTime.Add(time.Hour))

	second, _ := deltaFixture(t, defaultConfig)
	publishNext(t, second, defaultConfig, "1.3.0", next, refTime.Add(time.Hour))

	target, _ := release.PatchPath(payloadTargetOf(lib), payloadTargetOf(next))
	a, b := first.readTargets(t, "v1", 2), second.readTargets(t, "v1", 2)
	if !a.Signed.Targets[target].Equal(*b.Signed.Targets[target]) {
		t.Fatal("two publishes of the same inputs produced different patches")
	}
}

// A patch is built from what the repository holds, and what it holds is checked
// against the hash it is published under. A publish that patched away from a
// corrupted base would ship something that fails on every client.
func TestPublishSkipsAPatchFromACorruptedBase(t *testing.T) {
	f, lib := deltaFixture(t, defaultConfig)

	sum := sha256.Sum256([]byte(lib))
	f.corruptTarget(t, payloadTarget("1", sum), sum)

	next := rebuiltLib(lib, 2)
	res := publishNext(t, f, defaultConfig, "1.3.0", next, refTime.Add(time.Hour))
	for _, target := range res.AddedTargets {
		if strings.HasPrefix(target, "patches/") {
			t.Errorf("published %s from a base that does not match its hash", target)
		}
	}
}

// Retention removes old targets on purpose. A release whose descriptor is no
// longer on disk is simply not a base to patch from — it must not turn into a
// failed publish.
func TestPublishSurvivesAPrunedRelease(t *testing.T) {
	f, lib := deltaFixture(t, defaultConfig)

	line := f.readTargets(t, "v1", 1)
	target := release.DescriptorPath("linux", "amd64", "1.2.0")
	info, ok := line.Signed.Targets[target]
	if !ok {
		t.Fatalf("the first release has no descriptor: %v", sortedKeys(line.Signed.Targets))
	}
	sum, _ := sumOf(info.Hashes["sha256"])
	f.removeTarget(t, target, sum)

	next := rebuiltLib(lib, 2)
	res := publishNext(t, f, defaultConfig, "1.3.0", next, refTime.Add(time.Hour))
	for _, added := range res.AddedTargets {
		if strings.HasPrefix(added, "patches/") {
			t.Errorf("published %s from a release that is no longer on disk", added)
		}
	}
}

// The bounds on the configuration itself: a publish that would take an hour
// because of a typo is its own kind of outage.
func TestDeltaConfigIsBounded(t *testing.T) {
	for _, block := range []string{
		"delta:\n  patch_against: -1",
		fmt.Sprintf("delta:\n  patch_against: %d", MaxPatchAgainst+1),
		"delta:\n  max_ratio: 1.5",
		"delta:\n  max_ratio: -0.5",
		"delta:\n  unknown_setting: 3",
	} {
		t.Run(block, func(t *testing.T) {
			f := newFixture(t)
			f.seedRelease()
			f.writeConfig(strings.Replace(defaultConfig, "channel: stable", "channel: stable\n"+block, 1))
			if _, err := f.publish(refTime); err == nil {
				t.Fatal("published with a configuration that should be refused")
			}
		})
	}
}
