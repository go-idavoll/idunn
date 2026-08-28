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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/release"
)

// payload describes one release's content, so a test can say which bytes two
// releases share without spelling out a pack.yaml each time.
type payload struct {
	app string
	lib string
}

// release publishes one version on one channel. Returning the Result lets a test
// assert on what retention removed, which is the only visible record of it.
func (f *fixture) release(version, channel string, p payload, retain int, at time.Time) (*Result, error) {
	f.t.Helper()
	f.writeSource("linux-amd64/app", p.app)
	f.writeSource("linux-amd64/lib.so", p.lib)
	f.writeConfig(fmt.Sprintf(`name: demo
version: %s
channel: %s
targets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app,    dst: bin/app,    kind: exe }
      - { src: linux-amd64/lib.so, dst: lib/lib.so, kind: lib }
`, version, channel))
	o := f.options(at)
	o.Retain = retain
	return Publish(o)
}

func (f *fixture) mustRelease(version, channel string, p payload, retain int, at time.Time) *Result {
	f.t.Helper()
	res, err := f.release(version, channel, p, retain, at)
	if err != nil {
		f.t.Fatalf("publishing %s on %s: %v", version, channel, err)
	}
	return res
}

// content builds a distinct payload for a version.
func content(version string) payload {
	return payload{
		app: "idunn test payload: app " + version + "\n",
		lib: "idunn test payload: lib " + version + "\n",
	}
}

// published reports the target paths the given delegated role holds.
func (f *fixture) published(t *testing.T, role string, version int64) []string {
	t.Helper()
	meta := f.readTargets(t, role, version)
	out := make([]string, 0, len(meta.Signed.Targets))
	for target := range meta.Signed.Targets {
		out = append(out, target)
	}
	slices.Sort(out)
	return out
}

// roleVersion is the version of a delegated role as the repository currently
// stands, read back through the same verification loadState does for a publish.
func (f *fixture) roleVersion(t *testing.T, role string) int64 {
	t.Helper()
	st, err := loadState(f.repo)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	del, ok := st.delegated[role]
	if !ok {
		t.Fatalf("the repository holds no role %q", role)
	}
	return del.Signed.Version
}

// The window, and what falls out of it: the descriptors of retired releases and
// every payload only they named.
func TestRetentionRetiresOldReleasesAndTheirPayloads(t *testing.T) {
	f := newFixture(t)
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		f.mustRelease(v, "stable", content(v), 0, refTime.Add(time.Duration(i)*time.Hour))
	}
	before := len(f.payloadFiles(t))

	res := f.mustRelease("1.3.0", "stable", content("1.3.0"), 2, refTime.Add(3*time.Hour))

	// 1.3.0 and 1.2.0 stay; 1.1.0 and 1.0.0 go, with the two payloads each of
	// them alone named.
	wantRetired := []string{
		"releases/linux-amd64/1.0.0.json",
		"releases/linux-amd64/1.1.0.json",
	}
	for _, target := range wantRetired {
		if !slices.Contains(res.RetiredTargets, target) {
			t.Errorf("retention kept %s, which is outside the window of 2", target)
		}
	}
	for _, target := range []string{"releases/linux-amd64/1.2.0.json", "releases/linux-amd64/1.3.0.json"} {
		if slices.Contains(res.RetiredTargets, target) {
			t.Errorf("retention retired %s, which is inside the window", target)
		}
	}
	if got, want := len(res.RetiredTargets), len(wantRetired)+4; got != want {
		t.Errorf("retired %d targets (%v), want %d: two descriptors and the four payloads only they named",
			got, res.RetiredTargets, want)
	}

	// The role no longer names them ...
	held := f.published(t, "v1", f.roleVersion(t, "v1"))
	for _, target := range res.RetiredTargets {
		if slices.Contains(held, target) {
			t.Errorf("%s was reported as retired but is still in the delegation", target)
		}
	}
	// ... and neither does the disk.
	if after := len(f.payloadFiles(t)); after >= before {
		t.Errorf("payload files went from %d to %d; retention removed nothing from disk", before, after)
	}
	for _, target := range res.RetiredTargets {
		if strings.HasPrefix(target, "releases/") {
			continue
		}
		if f.targetFileExists(t, target) {
			t.Errorf("the file backing the retired target %s is still on disk", target)
		}
	}
}

// The repository has to remain a repository. Retention that leaves a client
// unable to install is worse than metadata that grows.
func TestTheRepositoryStillResolvesAfterRetention(t *testing.T) {
	f := newFixture(t)
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		f.mustRelease(v, "stable", content(v), 0, refTime.Add(time.Duration(i)*time.Hour))
	}
	f.mustRelease("1.3.0", "stable", content("1.3.0"), 2, refTime.Add(3*time.Hour))

	got, err := f.resolve("stable", "linux", "amd64", refTime.Add(4*time.Hour))
	if err != nil {
		t.Fatalf("the client cannot resolve the repository after retention: %v", err)
	}
	if got.descriptor.Version != "1.3.0" {
		t.Errorf("resolved %s, want 1.3.0", got.descriptor.Version)
	}
	if want := content("1.3.0").app; string(got.payloads["bin/app"]) != want {
		t.Errorf("bin/app = %q, want %q", got.payloads["bin/app"], want)
	}
}

// The dedup claim of §4.1 in one test: a payload two releases share survives the
// retirement of one of them. Reference counting is what makes that true, and a
// path-guessing implementation would get it wrong.
func TestASharedPayloadSurvivesTheReleaseThatFirstPublishedIt(t *testing.T) {
	f := newFixture(t)
	shared := "idunn test payload: a library that never changes\n"

	f.mustRelease("1.0.0", "stable", payload{app: "app one\n", lib: shared}, 0, refTime)
	f.mustRelease("1.1.0", "stable", payload{app: "app two\n", lib: shared}, 0, refTime.Add(time.Hour))
	f.mustRelease("1.2.0", "stable", payload{app: "app three\n", lib: shared}, 0, refTime.Add(2*time.Hour))

	sharedTarget := f.payloadTargetOf(t, "1.1.0", "lib/lib.so")
	res := f.mustRelease("1.3.0", "stable", payload{app: "app four\n", lib: shared}, 2, refTime.Add(3*time.Hour))

	if slices.Contains(res.RetiredTargets, sharedTarget) {
		t.Fatalf("retention removed %s, which releases inside the window still name", sharedTarget)
	}
	if !f.targetFileExists(t, sharedTarget) {
		t.Error("the shared payload file was deleted from disk")
	}
	// And the release that first published it is gone, so the survival is the
	// reference count and not a missed retirement.
	if !slices.Contains(res.RetiredTargets, "releases/linux-amd64/1.0.0.json") {
		t.Error("1.0.0 was not retired, so this test proves nothing about sharing")
	}
}

// A publisher must not retire the release its own channel still points at. That
// is the freeze attack with the publisher holding the knife: clients following
// that channel would resolve a descriptor whose bytes are gone.
func TestARetentionWindowNeverDropsWhatAChannelPointsAt(t *testing.T) {
	f := newFixture(t)
	f.mustRelease("1.0.0", "lts", content("1.0.0"), 0, refTime)
	for i, v := range []string{"1.1.0", "1.2.0", "1.3.0"} {
		f.mustRelease(v, "stable", content(v), 0, refTime.Add(time.Duration(i+1)*time.Hour))
	}

	res := f.mustRelease("1.4.0", "stable", content("1.4.0"), 2, refTime.Add(4*time.Hour))

	if slices.Contains(res.RetiredTargets, "releases/linux-amd64/1.0.0.json") {
		t.Fatal("retention retired the release the lts channel points at")
	}
	// The lts channel still resolves, which is the property the protection
	// exists for.
	got, err := f.resolve("lts", "linux", "amd64", refTime.Add(5*time.Hour))
	if err != nil {
		t.Fatalf("the lts channel no longer resolves after retention: %v", err)
	}
	if got.descriptor.Version != "1.0.0" {
		t.Errorf("lts resolved %s, want 1.0.0", got.descriptor.Version)
	}
}

// Another release line is not this publish's business: retiring it would need a
// signing key the operator did not offer for this release.
func TestRetentionLeavesOtherReleaseLinesAlone(t *testing.T) {
	f := newFixture(t)
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		f.mustRelease(v, "stable", content(v), 0, refTime.Add(time.Duration(i)*time.Hour))
	}
	res := f.mustRelease("2.0.0", "stable", content("2.0.0"), 2, refTime.Add(3*time.Hour))

	if len(res.RetiredTargets) != 0 {
		t.Errorf("publishing into v2 retired %v from another line", res.RetiredTargets)
	}
	held := f.published(t, "v1", f.roleVersion(t, "v1"))
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		if !slices.Contains(held, release.DescriptorPath("linux", "amd64", v)) {
			t.Errorf("the v1 line lost %s to a v2 publish", v)
		}
	}
}

// A window of one is refused, and the refusal costs nothing: it happens before a
// byte is written.
func TestARetentionWindowOfOneIsRefused(t *testing.T) {
	f := newFixture(t)
	f.mustRelease("1.0.0", "stable", content("1.0.0"), 0, refTime)
	before := snapshotTree(t, f.repo)

	_, err := f.release("1.1.0", "stable", content("1.1.0"), 1, refTime.Add(time.Hour))
	if err == nil {
		t.Fatal("a retention window of 1 was accepted")
	}
	if !errors.Is(err, ErrConfig) {
		t.Errorf("err = %v, want an ErrConfig", err)
	}
	after := snapshotTree(t, f.repo)
	if len(after) != len(before) {
		t.Fatalf("the refused publish changed the repository: %d files, was %d", len(after), len(before))
	}
	for name, sum := range before {
		if after[name] != sum {
			t.Errorf("the refused publish rewrote %s", name)
		}
	}
}

// Retention off is retention off. It is the default because deleting a published
// target is the one thing a publish cannot undo.
func TestRetentionIsOffByDefault(t *testing.T) {
	f := newFixture(t)
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"} {
		res := f.mustRelease(v, "stable", content(v), 0, refTime.Add(time.Duration(i)*time.Hour))
		if len(res.RetiredTargets) != 0 {
			t.Fatalf("publishing %s with retention off retired %v", v, res.RetiredTargets)
		}
	}
	held := f.published(t, "v1", f.roleVersion(t, "v1"))
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"} {
		if !slices.Contains(held, release.DescriptorPath("linux", "amd64", v)) {
			t.Errorf("%s is missing from the delegation although retention is off", v)
		}
	}
}

// targetFileExists reports whether the file backing a target is still on disk.
func (f *fixture) targetFileExists(t *testing.T, target string) bool {
	t.Helper()
	dir := filepath.Join(f.repo, TargetsDir, filepath.FromSlash(filepath.Dir(target)))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		t.Fatal(err)
	}
	base := filepath.Base(target)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "."+base) {
			return true
		}
	}
	return false
}

// payloadTargetOf finds the target path a given release installs to dst.
func (f *fixture) payloadTargetOf(t *testing.T, version, dst string) string {
	t.Helper()
	raw := f.targetBytes(t, release.DescriptorPath("linux", "amd64", version))
	d, err := release.ParseDescriptor(raw)
	if err != nil {
		t.Fatalf("parsing the descriptor of %s: %v", version, err)
	}
	for i := range d.Files {
		if d.Files[i].Dst == dst {
			return d.Files[i].Target
		}
	}
	t.Fatalf("%s installs nothing to %s", version, dst)
	return ""
}
