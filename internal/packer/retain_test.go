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
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
)

// retainedRelease is one release of the retention fixture: a small executable
// that changes every time, and a large library whose content the test chooses.
type retainedRelease struct {
	version string
	channel string
	lib     string
}

// retainConfig is pack.yaml for one release, with retention at keep (nil: off).
func retainConfig(version, channel string, keep *int) string {
	block := ""
	if keep != nil {
		block = fmt.Sprintf("retention:\n  keep: %d\n", *keep)
	}
	return fmt.Sprintf(`name: demo
version: %s
channel: %s
%stargets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app,    dst: bin/app,    kind: exe }
      - { src: linux-amd64/lib.so, dst: lib/lib.so, kind: lib }
`, version, channel, block)
}

func keepOf(n int) *int { return &n }

// appBytes is the executable of one version: distinct per release, so each
// release has at least one payload no other release names.
func appBytes(version string) string { return "idunn test payload: app " + version + "\n" }

// publishRetained writes one release's sources and publishes it.
func publishRetained(t *testing.T, f *fixture, r retainedRelease, keep *int, at time.Time) (*Result, error) {
	t.Helper()
	f.writeSource("linux-amd64/app", appBytes(r.version))
	f.writeSource("linux-amd64/lib.so", r.lib)
	f.writeConfig(retainConfig(r.version, r.channel, keep))
	return f.publish(at)
}

// publishSeries publishes releases in order, one hour apart, failing the test on
// any error, and returns the result of the last one.
func publishSeries(t *testing.T, f *fixture, rs []retainedRelease, keep *int) *Result {
	t.Helper()
	var res *Result
	for i, r := range rs {
		var err error
		if res, err = publishRetained(t, f, r, keep, refTime.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("publishing %s: %v", r.version, err)
		}
	}
	return res
}

// lineTargets loads the repository with the packer's own verifying loader and
// returns the targets of one delegated role.
func lineTargets(t *testing.T, f *fixture, role string) map[string]*metadata.TargetFiles {
	t.Helper()
	st, err := loadState(f.repo)
	if err != nil {
		t.Fatalf("loading the published repository: %v", err)
	}
	del, ok := st.delegated[role]
	if !ok {
		t.Fatalf("no delegated role %s", role)
	}
	return del.Signed.Targets
}

// storedFile reports whether the file backing target with content hash sum is
// on disk.
func storedFile(t *testing.T, f *fixture, target string, sum [sha256.Size]byte) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(f.repo, TargetsDir, filepath.FromSlash(hashPrefixedPath(target, sum))))
	switch {
	case err == nil:
		return true
	case os.IsNotExist(err):
		return false
	default:
		t.Fatal(err)
		return false
	}
}

func sumOfString(s string) [sha256.Size]byte { return sha256.Sum256([]byte(s)) }

// descriptorSum reads the hash a role signs for a descriptor.
func descriptorSum(t *testing.T, targets map[string]*metadata.TargetFiles, target string) [sha256.Size]byte {
	t.Helper()
	info, ok := targets[target]
	if !ok {
		t.Fatalf("%s is not published", target)
	}
	sum, ok := sumOf(info.Hashes["sha256"])
	if !ok {
		t.Fatalf("%s has no sha256", target)
	}
	return sum
}

// The window itself: the newest N releases stay, older ones leave the signed
// metadata, and the files behind them leave the disk.
func TestRetentionDropsReleasesBeyondTheWindow(t *testing.T) {
	f := newFixture(t)
	lib := libBytes(1)
	rs := []retainedRelease{
		{"1.0.0", "stable", lib}, {"1.1.0", "stable", lib}, {"1.2.0", "stable", lib},
	}
	publishSeries(t, f, rs[:2], keepOf(2))
	before := lineTargets(t, f, "v1")
	oldDesc := release.DescriptorPath("linux", "amd64", "1.0.0")
	oldSum := descriptorSum(t, before, oldDesc)

	res, err := publishRetained(t, f, rs[2], keepOf(2), refTime.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	oldApp := payloadTargetOf(appBytes("1.0.0"))
	if want := []string{oldApp, oldDesc}; !slices.Equal(res.RetiredTargets, want) {
		t.Fatalf("RetiredTargets = %v, want %v", res.RetiredTargets, want)
	}
	after := lineTargets(t, f, "v1")
	for _, gone := range res.RetiredTargets {
		if _, ok := after[gone]; ok {
			t.Errorf("%s is still in the signed metadata", gone)
		}
	}
	if storedFile(t, f, oldDesc, oldSum) || storedFile(t, f, oldApp, sumOfString(appBytes("1.0.0"))) {
		t.Error("a retired target's file is still on disk")
	}
	for _, v := range []string{"1.1.0", "1.2.0"} {
		if _, ok := after[release.DescriptorPath("linux", "amd64", v)]; !ok {
			t.Errorf("retained release %s is gone", v)
		}
	}
	if res.Delegations["v1"] != len(after) {
		t.Errorf("Result reports %d targets in v1, the role holds %d", res.Delegations["v1"], len(after))
	}
}

// Negative: a target shared between a dropped and a retained release is still
// needed, and survives. The dropped release's own executable proves that the
// release really was retired — the survival is the reference count, not a
// retirement that did not happen.
func TestRetentionKeepsATargetSharedWithARetainedRelease(t *testing.T) {
	f := newFixture(t)
	shared := libBytes(1)
	res := publishSeries(t, f, []retainedRelease{
		{"1.0.0", "stable", shared}, {"1.1.0", "stable", shared}, {"1.2.0", "stable", shared},
	}, keepOf(2))

	lib := payloadTargetOf(shared)
	after := lineTargets(t, f, "v1")
	if _, ok := after[release.DescriptorPath("linux", "amd64", "1.0.0")]; ok {
		t.Fatal("1.0.0 was not retired, so this test proves nothing")
	}
	if !slices.Contains(res.RetiredTargets, payloadTargetOf(appBytes("1.0.0"))) {
		t.Fatalf("1.0.0's own payload was not retired: %v", res.RetiredTargets)
	}
	if slices.Contains(res.RetiredTargets, lib) {
		t.Fatal("retired the library 1.1.0 and 1.2.0 still install")
	}
	if _, ok := after[lib]; !ok {
		t.Fatal("the shared library left the signed metadata")
	}
	if !storedFile(t, f, lib, sumOfString(shared)) {
		t.Fatal("the shared library's bytes were deleted")
	}
}

// Negative: a patch a client on a retained release needs to reach the head
// survives, together with every patch that ends at a retained payload. Patches
// that connect only retired payloads go.
func TestRetentionKeepsThePatchesARetainedReleaseNeeds(t *testing.T) {
	f := newFixture(t)
	libs := []string{libBytes(1)}
	for i := 1; i < 4; i++ {
		libs = append(libs, rebuiltLib(libs[i-1], int64(i+1)))
	}
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0"}
	var rs []retainedRelease
	for i, v := range versions {
		rs = append(rs, retainedRelease{v, "stable", libs[i]})
	}
	patch := func(from, to int) string {
		p, ok := release.PatchPath(payloadTargetOf(libs[from]), payloadTargetOf(libs[to]))
		if !ok {
			t.Fatal("no patch path")
		}
		return p
	}
	if res := publishSeries(t, f, rs[:2], keepOf(2)); !slices.Contains(res.AddedTargets, patch(0, 1)) {
		t.Fatalf("1.1.0 published no patch from 1.0.0, so this test proves nothing: %v", res.AddedTargets)
	}
	for i := 2; i < len(rs); i++ {
		if _, err := publishRetained(t, f, rs[i], keepOf(2), refTime.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("publishing %s: %v", rs[i].version, err)
		}
	}

	after := lineTargets(t, f, "v1")
	// 1.2.0 -> 1.3.0 is the walk a client on the oldest retained release takes.
	// 1.1.0 -> 1.3.0, 1.1.0 -> 1.2.0 and 1.0.0 -> 1.2.0 produce a retained
	// payload. 1.0.0 -> 1.1.0 starts from and produces retired payloads only.
	for _, p := range []string{patch(2, 3), patch(1, 3), patch(1, 2), patch(0, 2)} {
		info, ok := after[p]
		if !ok {
			t.Errorf("retention removed %s", p)
			continue
		}
		sum, _ := sumOf(info.Hashes["sha256"])
		if !storedFile(t, f, p, sum) {
			t.Errorf("the bytes of %s were deleted", p)
		}
	}
	if _, ok := after[patch(0, 1)]; ok {
		t.Errorf("%s connects two retired payloads and was kept", patch(0, 1))
	}
	if _, ok := after[payloadTargetOf(libs[1])]; ok {
		t.Error("1.1.0's library is named by no retained release and was kept")
	}

	// And the patch still does its job through the real client: fetched by the
	// name the client derives, verified by TUF, applied to the retained base,
	// and the result is the signed head payload.
	c, _, err := f.client(refTime.Add(10 * time.Hour))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	raw, err := c.Target(patch(2, 3))
	if err != nil {
		t.Fatalf("the needed patch does not resolve: %v", err)
	}
	got, err := stage.ApplyPatch([]byte(libs[2]), raw, int64(len(libs[3])))
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	if err := c.VerifyTarget(payloadTargetOf(libs[3]), got); err != nil || !bytes.Equal(got, []byte(libs[3])) {
		t.Fatalf("the patch no longer reconstructs the head: %v", err)
	}
}

// Negative: a client resolving a retained release after retention still verifies
// end to end with core/trust, and updates from it to the head through the real
// installer and updater. A retired release is refused rather than served.
func TestRetainedReleaseStillResolvesAndUpdates(t *testing.T) {
	f := newFixture(t)
	libs := []string{libBytes(1)}
	for i := 1; i < 4; i++ {
		libs = append(libs, rebuiltLib(libs[i-1], int64(i+1)))
	}
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0"}
	var rs []retainedRelease
	for i, v := range versions {
		rs = append(rs, retainedRelease{v, "stable", libs[i]})
	}
	publishSeries(t, f, rs, keepOf(2))
	at := refTime.Add(10 * time.Hour)

	c, _, err := f.client(at)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	d, err := c.ReleaseVersion("linux", "amd64", "1.2.0")
	if err != nil {
		t.Fatalf("retained release 1.2.0 does not resolve: %v", err)
	}
	for _, file := range d.Files {
		raw, err := c.Target(file.Target)
		if err != nil {
			t.Fatalf("retained payload %s does not resolve: %v", file.Dst, err)
		}
		if err := c.VerifyTarget(file.Target, raw); err != nil {
			t.Fatalf("retained payload %s does not verify: %v", file.Dst, err)
		}
	}
	if _, err := c.ReleaseVersion("linux", "amd64", "1.0.0"); err == nil {
		t.Fatal("a retired release still resolves")
	}
	if got, want := c.Versions("linux", "amd64"), []string{"1.2.0", "1.3.0"}; !slices.Equal(got, want) {
		t.Fatalf("Versions = %v, want %v", got, want)
	}

	installRoot := filepath.Join(t.TempDir(), "install")
	if err := updateInstall(t, f, installRoot, "1.2.0", at); err != nil {
		t.Fatalf("update from retained 1.2.0: %v", err)
	}
	if got, err := installer.InstalledVersion(installRoot); err != nil || got != "1.3.0" {
		t.Fatalf("installed %q (%v), want 1.3.0", got, err)
	}
}

// Negative: a window that would drop a channel head is refused, not quietly
// widened, and the repository is left exactly as it was.
func TestRetentionRefusesToDropAChannelHead(t *testing.T) {
	t.Run("another channel's head", func(t *testing.T) {
		f := newFixture(t)
		publishSeries(t, f, []retainedRelease{
			{"1.0.0", "stable", libBytes(1)}, {"1.1.0", "beta", libBytes(2)},
		}, keepOf(2))
		before := snapshotTree(t, f.repo)

		_, err := publishRetained(t, f, retainedRelease{"1.2.0", "beta", libBytes(3)}, keepOf(2), refTime.Add(5*time.Hour))
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "stable") {
			t.Fatalf("err = %v, want a refusal naming the stable head", err)
		}
		if !maps.Equal(before, snapshotTree(t, f.repo)) {
			t.Fatal("a refused publish changed the repository")
		}

		// A window wide enough for both heads publishes, and keeps the stable head.
		if _, err := publishRetained(t, f, retainedRelease{"1.2.0", "beta", libBytes(3)}, keepOf(3), refTime.Add(5*time.Hour)); err != nil {
			t.Fatalf("publish with a wide enough window: %v", err)
		}
		if _, err := f.resolve("stable", "linux", "amd64", refTime.Add(6*time.Hour)); err != nil {
			t.Fatalf("the stable head no longer resolves: %v", err)
		}
	})

	t.Run("the release being published", func(t *testing.T) {
		f := newFixture(t)
		publishSeries(t, f, []retainedRelease{
			{"1.5.0", "stable", libBytes(1)}, {"1.6.0", "beta", libBytes(2)},
		}, keepOf(2))
		before := snapshotTree(t, f.repo)

		_, err := publishRetained(t, f, retainedRelease{"1.4.1", "lts", libBytes(3)}, keepOf(2), refTime.Add(5*time.Hour))
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if !maps.Equal(before, snapshotTree(t, f.repo)) {
			t.Fatal("a refused publish changed the repository")
		}
	})
}

// Negative: a window below the minimum is refused before anything is read or
// written — including an explicit zero, which reads as "off" and "keep nothing"
// equally well.
func TestRetentionRefusesAWindowBelowTheMinimum(t *testing.T) {
	for _, keep := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			f := newFixture(t)
			publishSeries(t, f, []retainedRelease{{"1.0.0", "stable", libBytes(1)}, {"1.1.0", "stable", libBytes(2)}}, nil)
			before := snapshotTree(t, f.repo)

			_, err := publishRetained(t, f, retainedRelease{"1.2.0", "stable", libBytes(3)}, keepOf(keep), refTime.Add(5*time.Hour))
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("err = %v, want ErrConfig", err)
			}
			if !maps.Equal(before, snapshotTree(t, f.repo)) {
				t.Fatal("a refused publish changed the repository")
			}
		})
	}
}

// Off unless asked for: without a retention block, nothing is ever removed.
func TestRetentionIsOffByDefault(t *testing.T) {
	f := newFixture(t)
	res := publishSeries(t, f, []retainedRelease{
		{"1.0.0", "stable", libBytes(1)}, {"1.1.0", "stable", libBytes(2)}, {"1.2.0", "stable", libBytes(3)},
	}, nil)
	if len(res.RetiredTargets) != 0 {
		t.Fatalf("retired %v without retention configured", res.RetiredTargets)
	}
	if _, ok := lineTargets(t, f, "v1")[release.DescriptorPath("linux", "amd64", "1.0.0")]; !ok {
		t.Fatal("1.0.0 was removed without retention configured")
	}
}

// Retention is scoped to the release line being published. Retiring an old
// major is an end-of-life decision, not a side effect of a routine publish.
func TestRetentionLeavesOtherReleaseLinesAlone(t *testing.T) {
	f := newFixture(t)
	publishSeries(t, f, []retainedRelease{
		{"1.0.0", "stable", libBytes(1)}, {"1.1.0", "stable", libBytes(2)}, {"1.2.0", "stable", libBytes(3)},
		{"2.0.0", "stable", libBytes(4)}, {"2.1.0", "stable", libBytes(5)}, {"2.2.0", "stable", libBytes(6)},
	}, nil)
	v1 := lineTargets(t, f, "v1")

	res, err := publishRetained(t, f, retainedRelease{"2.3.0", "stable", libBytes(7)}, keepOf(2), refTime.Add(10*time.Hour))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	for _, target := range res.RetiredTargets {
		if !strings.HasPrefix(target, "releases/linux-amd64/2.") && !strings.Contains(target, "/v2/") {
			t.Errorf("retired %s outside the v2 line", target)
		}
	}
	if !maps.EqualFunc(v1, lineTargets(t, f, "v1"), func(a, b *metadata.TargetFiles) bool { return a.Equal(*b) }) {
		t.Fatal("publishing into v2 changed v1")
	}
}

// Fail closed: a retained descriptor retention cannot read back is one whose
// references it cannot count, so it refuses rather than guessing.
func TestRetentionRefusesAnUnreadableRetainedDescriptor(t *testing.T) {
	f := newFixture(t)
	publishSeries(t, f, []retainedRelease{{"1.0.0", "stable", libBytes(1)}, {"1.1.0", "stable", libBytes(2)}}, nil)
	target := release.DescriptorPath("linux", "amd64", "1.1.0")
	f.corruptTarget(t, target, descriptorSum(t, lineTargets(t, f, "v1"), target))
	before := snapshotTree(t, f.repo)

	_, err := publishRetained(t, f, retainedRelease{"1.2.0", "stable", libBytes(3)}, keepOf(2), refTime.Add(5*time.Hour))
	if !errors.Is(err, ErrRepo) {
		t.Fatalf("err = %v, want ErrRepo", err)
	}
	if !maps.Equal(before, snapshotTree(t, f.repo)) {
		t.Fatal("a refused publish changed the repository")
	}
}

// Reproducibility covers retention: the same series of publishes produces the
// same repository, byte for byte, deletions included (AGENTS.md §1.7).
func TestRetentionIsReproducible(t *testing.T) {
	series := func() map[string]string {
		f := newFixture(t)
		libs := []string{libBytes(1)}
		for i := 1; i < 4; i++ {
			libs = append(libs, rebuiltLib(libs[i-1], int64(i+1)))
		}
		var rs []retainedRelease
		for i, v := range []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0"} {
			rs = append(rs, retainedRelease{v, "stable", libs[i]})
		}
		publishSeries(t, f, rs, keepOf(2))
		return snapshotTree(t, f.repo)
	}
	if a, b := series(), series(); !maps.Equal(a, b) {
		t.Fatal("two identical publish series with retention produced different repositories")
	}
}

// The target classification retention depends on round-trips the helpers in
// core/release and refuses anything they could not have produced.
func TestRetentionTargetClassification(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	other := sha256.Sum256([]byte("y"))
	payload := release.PayloadPath("1", sum[:])
	patch, _ := release.PatchPath(release.PayloadPath("0", sum[:]), release.PayloadPath("1", other[:]))

	if _, ok := payloadHash(payload); !ok {
		t.Errorf("payloadHash refused %s", payload)
	}
	if from, to, ok := patchHashes(patch); !ok || from == to {
		t.Errorf("patchHashes refused %s", patch)
	}
	if _, _, _, ok := parseDescriptorTarget(release.DescriptorPath("linux", "amd64", "1.0.0")); !ok {
		t.Error("parseDescriptorTarget refused a descriptor path")
	}
	for _, bad := range []string{
		"payloads/v1/" + strings.ToUpper(fmt.Sprintf("%x", sum)),
		"payloads/v1/abc",
		"payloads/v01/" + fmt.Sprintf("%x", sum),
		"patches/v1/" + fmt.Sprintf("%x", sum),
		"patches/v1/" + fmt.Sprintf("%x-%x", sum, sum),
		"patches/v1/x/" + fmt.Sprintf("%x-%x", sum, other),
		"releases/linux-amd64/1.0.json",
		"releases/linux/1.0.0.json",
		"channels/stable/linux-amd64/latest.json",
	} {
		_, p := payloadHash(bad)
		_, _, q := patchHashes(bad)
		_, _, _, r := parseDescriptorTarget(bad)
		if p || q || r {
			t.Errorf("%s was classified (payload %v, patch %v, descriptor %v)", bad, p, q, r)
		}
	}
}
