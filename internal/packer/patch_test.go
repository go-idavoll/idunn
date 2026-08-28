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
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/delta"
)

// binary is a deterministic stand-in for a compiled artifact: big enough that a
// patch against a near-copy is worth having, random enough that the matcher
// cannot get lucky.
func binary(seed int64, n int) string {
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // a fixture, not a key.
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + r.Intn(26))
	}
	return string(b)
}

// patching publishes a version with the given payload, emitting patches against
// the previous `against` releases.
func (f *fixture) patching(version, app string, against int, at time.Time) *Result {
	f.t.Helper()
	f.writeSource("linux-amd64/app", app)
	f.writeSource("linux-amd64/lib.so", "a library that never changes\n")
	f.writeConfig(`name: demo
version: ` + version + `
channel: stable
targets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app,    dst: bin/app,    kind: exe }
      - { src: linux-amd64/lib.so, dst: lib/lib.so, kind: lib }
`)
	o := f.options(at)
	o.PatchAgainst = against
	res, err := Publish(o)
	if err != nil {
		f.t.Fatalf("publishing %s: %v", version, err)
	}
	return res
}

// The reason stage 2 exists: a rebuilt binary that barely changed should not
// cross the wire again in full.
func TestAPatchIsPublishedForANearlyUnchangedPayload(t *testing.T) {
	f := newFixture(t)
	base := binary(1, 128<<10)
	next := base[:60000] + "a small change" + base[60014:]

	f.patching("1.0.0", base, 0, refTime)
	res := f.patching("1.1.0", next, 1, refTime.Add(time.Hour))

	if len(res.PatchTargets) != 1 {
		t.Fatalf("the publish emitted %v, want one patch", res.PatchTargets)
	}
	target := res.PatchTargets[0]
	if !strings.HasPrefix(target, "patches/v1/") {
		t.Errorf("the patch was published at %s, outside the release line's pattern", target)
	}

	// The path is the convention the client derives: from-hash to to-hash. A
	// client that knows what it has and what it wants must be able to name this
	// without anything pointing at it.
	from := sha256.Sum256([]byte(base))
	to := sha256.Sum256([]byte(next))
	want := release.PatchPath("1", hex.EncodeToString(from[:]), hex.EncodeToString(to[:]))
	if target != want {
		t.Errorf("the patch is at %s; a client would look for %s", target, want)
	}

	// And it does what it says: the published bytes reconstruct the new payload
	// from the old one.
	patch := f.targetBytes(t, target)
	got, err := delta.Apply([]byte(base), patch, 0)
	if err != nil {
		t.Fatalf("applying the published patch: %v", err)
	}
	if string(got) != next {
		t.Error("the published patch does not reconstruct the payload it names")
	}
	if len(patch) >= len(next)/2 {
		t.Errorf("the patch is %d bytes for a %d-byte payload; that is not worth publishing",
			len(patch), len(next))
	}
}

// Two files with nothing in common have a "patch" the size of the file. Emitting
// it would cost the repository the payload twice and save a client nothing.
func TestNoPatchIsPublishedWhenItWouldNotBeSmaller(t *testing.T) {
	f := newFixture(t)
	f.patching("1.0.0", binary(2, 64<<10), 0, refTime)
	res := f.patching("1.1.0", binary(3, 64<<10), 1, refTime.Add(time.Hour))

	if len(res.PatchTargets) != 0 {
		t.Errorf("a patch was published between two unrelated payloads: %v", res.PatchTargets)
	}
}

// Patches are an optimisation nobody gets unless they ask, because a repository
// pays for them in space.
func TestNoPatchesArePublishedByDefault(t *testing.T) {
	f := newFixture(t)
	base := binary(4, 64<<10)
	f.patching("1.0.0", base, 0, refTime)
	res := f.patching("1.1.0", base[:30000]+"edited"+base[30006:], 0, refTime.Add(time.Hour))

	if len(res.PatchTargets) != 0 {
		t.Errorf("patches were published without being asked for: %v", res.PatchTargets)
	}
}

// A patch is retired when the payload it *produces* is gone — it reconstructs
// something nobody may install any more. The payload it starts from is a
// different matter: a client can be running a version this repository has
// already retired, and the patch forward from those bytes is exactly what makes
// catching up cheap.
func TestRetentionDropsAPatchWhoseResultIsRetiredAndKeepsOneWhoseBaseIs(t *testing.T) {
	f := newFixture(t)
	v1 := binary(5, 64<<10)
	v2 := v1[:1000] + "second" + v1[1006:]
	v3 := v2[:2000] + "third" + v2[2005:]
	v4 := v3[:3000] + "fourth" + v3[3006:]

	f.patching("1.0.0", v1, 0, refTime)
	f.patching("1.1.0", v2, 1, refTime.Add(time.Hour))
	toV3 := f.patching("1.2.0", v3, 2, refTime.Add(2*time.Hour))
	if len(toV3.PatchTargets) == 0 {
		t.Fatal("no patches were published, so this test proves nothing")
	}

	// Retaining two drops 1.0.0 and 1.1.0 and their payloads. The patches into
	// 1.2.0 stay: their result is still installable, even though one of their
	// bases is gone.
	o := f.options(refTime.Add(3 * time.Hour))
	o.PatchAgainst = 1
	o.Retain = 2
	f.writeSource("linux-amd64/app", v4)
	f.writeSource("linux-amd64/lib.so", "a library that never changes\n")
	f.writeConfig(`name: demo
version: 1.3.0
channel: stable
targets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app,    dst: bin/app,    kind: exe }
      - { src: linux-amd64/lib.so, dst: lib/lib.so, kind: lib }
`)
	res, err := Publish(o)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	held := f.published(t, "v1", f.roleVersion(t, "v1"))
	for _, target := range toV3.PatchTargets {
		if !slices.Contains(held, target) {
			t.Errorf("retention dropped %s, whose result 1.2.0 is still installed", target)
		}
	}
	// And the payloads of the retired releases really are gone, so the survival
	// above is the rule and not a retention that did nothing.
	if len(res.RetiredTargets) == 0 {
		t.Error("retention removed nothing, so the patch survival proves nothing")
	}
}

// A repository that resolves is the only thing that matters in the end: patches
// are extra targets in the same delegated role, and adding them must not disturb
// what the client already reads.
func TestARepositoryWithPatchesStillResolves(t *testing.T) {
	f := newFixture(t)
	base := binary(6, 64<<10)
	f.patching("1.0.0", base, 0, refTime)
	f.patching("1.1.0", base[:500]+"edit"+base[504:], 1, refTime.Add(time.Hour))

	got, err := f.resolve("stable", "linux", "amd64", refTime.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("the client cannot resolve a repository that carries patches: %v", err)
	}
	if got.descriptor.Version != "1.1.0" {
		t.Errorf("resolved %s, want 1.1.0", got.descriptor.Version)
	}
	// The descriptor says nothing about patches: discovery is by convention.
	for _, file := range got.descriptor.Files {
		if strings.Contains(file.Target, "patches/") {
			t.Errorf("the descriptor names a patch target %q", file.Target)
		}
	}
}
