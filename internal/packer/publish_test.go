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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
)

// The done-criterion of IDN-01: what the packer publishes, core/trust resolves,
// unchanged, end to end.
func TestPublishResolvesEndToEnd(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	res := f.mustPublish(refTime)

	if res.Version != "1.2.0" || res.Channel != "stable" {
		t.Fatalf("result = %+v", res)
	}

	got, err := f.resolve("stable", "linux", "amd64", refTime)
	if err != nil {
		t.Fatalf("client could not resolve the published repository: %v", err)
	}
	d := got.descriptor
	if d.Name != "demo" || d.Version != "1.2.0" || d.Channel != "stable" {
		t.Errorf("descriptor = %+v", d)
	}
	if d.Requirements.MinFromVersion != "1.0.0" || d.Requirements.MinClientVersion != "1.1.0" {
		t.Errorf("requirements = %+v", d.Requirements)
	}
	want := map[string]string{
		"bin/app":    "idunn test payload: app 1.2.0\n",
		"lib/lib.so": "idunn test payload: lib 1.2.0\n",
	}
	for dst, content := range want {
		if string(got.payloads[dst]) != content {
			t.Errorf("payload %s = %q, want %q", dst, got.payloads[dst], content)
		}
	}
	for _, file := range d.Files {
		switch file.Dst {
		case "bin/app":
			if file.Kind != release.KindExe || file.Mode != 0o755 {
				t.Errorf("bin/app: kind %q mode %#o", file.Kind, file.Mode)
			}
		case "lib/lib.so":
			if file.Kind != release.KindLib || file.Mode != 0o644 {
				t.Errorf("lib/lib.so: kind %q mode %#o", file.Kind, file.Mode)
			}
		}
	}
}

// IDN-02: the top-level targets.json carries delegations and nothing else, from
// the very first publish. Retrofitting this later would be a migration for every
// deployed client, which is why it is asserted rather than assumed.
func TestTopLevelTargetsOnlyDelegates(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	top := f.readTargets(t, metadata.TARGETS, 1)
	if len(top.Signed.Targets) != 0 {
		t.Errorf("targets.json holds %d targets, want none", len(top.Signed.Targets))
	}
	if top.Signed.Delegations == nil {
		t.Fatal("targets.json has no delegations")
	}
	var names []string
	for _, d := range top.Signed.Delegations.Roles {
		names = append(names, d.Name)
		if d.Threshold != 1 {
			t.Errorf("delegation %s: threshold %d", d.Name, d.Threshold)
		}
		if !d.Terminating {
			t.Errorf("delegation %s is not terminating: another role could answer for its paths", d.Name)
		}
		if len(d.KeyIDs) == 0 {
			t.Errorf("delegation %s names no key", d.Name)
		}
	}
	sort.Strings(names)
	if want := []string{"stable", "v1"}; !slices.Equal(names, want) {
		t.Errorf("delegations = %v, want %v", names, want)
	}

	// Every target lives in a delegated role, none in the top level.
	line := f.readTargets(t, "v1", 1)
	if len(line.Signed.Targets) != 3 { // two payloads and one descriptor
		t.Errorf("v1 holds %d targets: %v", len(line.Signed.Targets), sortedKeys(line.Signed.Targets))
	}
	pointer := f.readTargets(t, "stable", 1)
	if len(pointer.Signed.Targets) != 1 {
		t.Errorf("stable holds %d targets: %v", len(pointer.Signed.Targets), sortedKeys(pointer.Signed.Targets))
	}
	if _, ok := pointer.Signed.Targets[release.PointerPath("stable", "linux", "amd64")]; !ok {
		t.Errorf("stable does not hold the channel pointer: %v", sortedKeys(pointer.Signed.Targets))
	}
}

// IDN-02's second half: a client that follows one channel loads that channel's
// delegation and the one release line it installs — not another channel's
// pointers, and not another major's history.
func TestClientLoadsOnlyItsOwnDelegations(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	// A second release line on a second channel, in the same repository.
	f.writeSource("linux-amd64/app2", "idunn test payload: app 2.0.0\n")
	f.writeConfig(`name: demo
version: 2.0.0
channel: beta
targets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app2, dst: bin/app, kind: exe }
`)
	f.mustPublish(refTime.Add(time.Hour))

	got, err := f.resolve("stable", "linux", "amd64", refTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("resolve stable: %v", err)
	}
	if got.descriptor.Version != "1.2.0" {
		t.Errorf("stable resolved %s, want 1.2.0", got.descriptor.Version)
	}
	for _, unwanted := range []string{"beta.json", "v2.json"} {
		if slices.Contains(got.roles, unwanted) {
			t.Errorf("a stable client loaded %s; delegations exist so it does not have to (%v)",
				unwanted, got.roles)
		}
	}
	for _, wanted := range []string{"stable.json", "v1.json"} {
		if !slices.Contains(got.roles, wanted) {
			t.Errorf("a stable client did not load %s (%v)", wanted, got.roles)
		}
	}

	// And the beta client, symmetrically, resolves its own line.
	got, err = f.resolve("beta", "linux", "amd64", refTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("resolve beta: %v", err)
	}
	if got.descriptor.Version != "2.0.0" {
		t.Errorf("beta resolved %s, want 2.0.0", got.descriptor.Version)
	}
	if slices.Contains(got.roles, "v1.json") {
		t.Errorf("a beta client loaded v1.json (%v)", got.roles)
	}
}

// A publish must not disturb the roles it does not touch: their bytes, their
// version and their key stay exactly as they were.
func TestUntouchedDelegationIsNotResigned(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)
	before := f.readFile(t, "1.stable.json")

	f.writeSource("linux-amd64/app2", "idunn test payload: app 2.0.0\n")
	f.writeConfig(`name: demo
version: 2.0.0
channel: beta
targets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app2, dst: bin/app, kind: exe }
`)
	res := f.mustPublish(refTime.Add(time.Hour))

	if _, ok := res.Roles["stable"]; ok {
		t.Errorf("publishing to beta re-signed the stable delegation: %v", res.Roles)
	}
	if _, ok := res.Roles["v1"]; ok {
		t.Errorf("publishing 2.0.0 re-signed the v1 line: %v", res.Roles)
	}
	if after := f.readFile(t, "1.stable.json"); string(after) != string(before) {
		t.Error("the stable delegation was rewritten by a publish that did not touch it")
	}
}

// Reproducibility (AGENTS.md §1.7): the same inputs, including the reference
// time, produce a byte-identical repository. Without it, an independent rebuild
// proves nothing.
func TestPublishIsReproducible(t *testing.T) {
	first := newFixture(t)
	first.seedRelease()
	first.mustPublish(refTime)

	second := newFixture(t)
	second.seedRelease()
	second.mustPublish(refTime)

	diff(t, first.repo, second.repo)
}

// The same publish run twice into the same repository changes nothing: no new
// role version, no rewritten file. A no-op publish that bumped versions would
// make every client re-fetch metadata for nothing.
func TestRepublishingTheSameInputsIsANoOp(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)
	before := snapshotTree(t, f.repo)

	res := f.mustPublish(refTime)
	if len(res.Roles) != 0 {
		t.Errorf("a repeated publish re-signed %v", res.Roles)
	}
	if len(res.AddedTargets) != 0 {
		t.Errorf("a repeated publish added %v", res.AddedTargets)
	}
	after := snapshotTree(t, f.repo)
	if len(before) != len(after) {
		t.Fatalf("tree changed: %d files -> %d", len(before), len(after))
	}
	for name, sum := range before {
		if after[name] != sum {
			t.Errorf("%s changed on a repeated publish", name)
		}
	}
}

// Moving the reference time forward is a genuine metadata refresh: the roles
// this publish touches get a new expiry, a new version, and a fresh signature.
func TestNewReferenceTimeRefreshesTouchedRoles(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	later := refTime.AddDate(0, 0, 3)
	res := f.mustPublish(later)
	for _, role := range []string{metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP, "stable", "v1"} {
		if res.Roles[role] != 2 {
			t.Errorf("role %s is at version %d after a refresh, want 2", role, res.Roles[role])
		}
	}
	if _, err := f.resolve("stable", "linux", "amd64", later); err != nil {
		t.Fatalf("client cannot resolve the refreshed repository: %v", err)
	}
}

// Payload targets are content-addressed, so a file that does not change between
// two releases is the same target: metadata and server storage grow with changed
// files, not with releases × files (design §4.1).
func TestUnchangedPayloadIsOneTarget(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	// 1.3.0 changes the executable and keeps the library byte for byte.
	f.writeSource("linux-amd64/app", "idunn test payload: app 1.3.0\n")
	f.writeConfig(strings.Replace(defaultConfig, "version: 1.2.0", "version: 1.3.0", 1))
	res := f.mustPublish(refTime.Add(time.Hour))

	libSum := sha256.Sum256([]byte("idunn test payload: lib 1.2.0\n"))
	libTarget := payloadTarget("1", libSum)
	if slices.Contains(res.AddedTargets, libTarget) {
		t.Errorf("the unchanged library was published as a new target: %v", res.AddedTargets)
	}
	line := f.readTargets(t, "v1", 2)
	if _, ok := line.Signed.Targets[libTarget]; !ok {
		t.Errorf("the shared library target is gone: %v", sortedKeys(line.Signed.Targets))
	}
	// Two payloads for 1.2.0, one changed payload for 1.3.0, two descriptors.
	if got := len(line.Signed.Targets); got != 5 {
		t.Errorf("v1 holds %d targets, want 5: %v", got, sortedKeys(line.Signed.Targets))
	}
	// One file on disk per distinct content, not per release.
	if got := len(f.payloadFiles(t)); got != 3 {
		t.Errorf("%d payload files on disk, want 3", got)
	}
}

// A published payload or descriptor path is immutable. Republishing a version
// with different bytes is refused rather than silently changing what an already
// published path resolves to.
func TestRepublishingAVersionWithNewContentIsRefused(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	f.writeSource("linux-amd64/app", "idunn test payload: app 1.2.0 (rebuilt)\n")
	_, err := f.publish(refTime.Add(time.Hour))
	if !errors.Is(err, ErrRepo) {
		t.Fatalf("err = %v, want ErrRepo", err)
	}
	if !strings.Contains(err.Error(), release.DescriptorPath("linux", "amd64", "1.2.0")) {
		t.Errorf("error does not name the descriptor it refuses to change: %v", err)
	}
}

// T13: a missing role key aborts the publish before anything is written. A
// half-signed repository must not be reachable by accident.
func TestMissingKeyAbortsBeforeAnyWrite(t *testing.T) {
	for _, envVar := range []string{EnvTargetsKey, EnvSnapshotKey, EnvTimestampKey} {
		t.Run(envVar, func(t *testing.T) {
			f := newFixture(t)
			f.seedRelease()
			before := snapshotTree(t, f.repo)
			delete(f.env, envVar)

			_, err := f.publish(refTime)
			if !errors.Is(err, ErrKey) {
				t.Fatalf("err = %v, want ErrKey", err)
			}
			if !strings.Contains(err.Error(), envVar) {
				t.Errorf("error does not name the missing variable: %v", err)
			}
			after := snapshotTree(t, f.repo)
			if len(after) != len(before) {
				t.Fatalf("a refused publish wrote to the repository: %v", sortedKeys(after))
			}
		})
	}
}

// Every reason a repository cannot be published into correctly is caught before
// the publish writes, not after it has produced something no client accepts.
func TestRootIsCheckedBeforePublishing(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*metadata.Metadata[metadata.RootType])
		want   string
	}{
		{
			name:   "no consistent snapshots",
			mutate: func(r *metadata.Metadata[metadata.RootType]) { r.Signed.ConsistentSnapshot = false },
			want:   "consistent snapshots",
		},
		{
			name:   "expired root",
			mutate: func(r *metadata.Metadata[metadata.RootType]) { r.Signed.Expires = refTime.Add(-time.Hour) },
			want:   "root expired",
		},
		{
			name: "threshold this packer cannot meet",
			mutate: func(r *metadata.Metadata[metadata.RootType]) {
				r.Signed.Roles[metadata.TARGETS].Threshold = 2
			},
			want: "signing ceremony",
		},
		{
			name: "a key root does not trust",
			mutate: func(r *metadata.Metadata[metadata.RootType]) {
				r.Signed.Roles[metadata.TIMESTAMP].KeyIDs = []string{"0000000000000000000000000000000000000000000000000000000000000000"}
			},
			want: "is not one root trusts",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.seedRelease()
			f.writeRoot(tt.mutate)
			before := snapshotTree(t, f.repo)

			_, err := f.publish(refTime)
			if !errors.Is(err, ErrRepo) {
				t.Fatalf("err = %v, want ErrRepo", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
			if after := snapshotTree(t, f.repo); len(after) != len(before) {
				t.Errorf("a refused publish wrote to the repository")
			}
		})
	}
}

// A repository with no root is not one the packer bootstraps: root comes from
// the ceremony, and a tool that runs on every release must not be able to mint a
// trust anchor.
func TestPublishRefusesToCreateRoot(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	if err := os.Remove(filepath.Join(f.repo, MetadataDir, "1.root.json")); err != nil {
		t.Fatal(err)
	}
	_, err := f.publish(refTime)
	if !errors.Is(err, ErrRepo) {
		t.Fatalf("err = %v, want ErrRepo", err)
	}
	if !strings.Contains(err.Error(), "the packer never does") {
		t.Errorf("err = %v", err)
	}
}

// Publishing on top of a repository whose metadata does not hang together is
// refused: that is how a half-uploaded state gets compounded instead of noticed.
func TestPublishRefusesAnInconsistentRepository(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	// Truncate the delegated role snapshot signed for.
	path := filepath.Join(f.repo, MetadataDir, "1.v1.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.writeSource("linux-amd64/app", "idunn test payload: app 1.3.0\n")
	f.writeConfig(strings.Replace(defaultConfig, "version: 1.2.0", "version: 1.3.0", 1))

	_, err := f.publish(refTime.Add(time.Hour))
	if !errors.Is(err, ErrRepo) {
		t.Fatalf("err = %v, want ErrRepo", err)
	}
}

// The reference time is an input. Without it the output would embed "when this
// ran", which cannot be rebuilt and compared.
func TestPublishRequiresAReferenceTime(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	o := f.options(refTime)
	o.Now = time.Time{}
	if _, err := Publish(o); !errors.Is(err, ErrRepo) {
		t.Fatalf("err = %v, want ErrRepo", err)
	}
}

// A pointer may only name the descriptor path derived from the version it
// claims; the client refuses anything else. The packer emits exactly that, and
// the parsers the client runs are run here first.
func TestPointerNamesTheDerivedDescriptorPath(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	f.mustPublish(refTime)

	raw := f.targetBytes(t, release.PointerPath("stable", "linux", "amd64"))
	ptr, err := release.ParsePointer(raw)
	if err != nil {
		t.Fatalf("the published pointer does not parse: %v", err)
	}
	if want := release.DescriptorPath("linux", "amd64", ptr.Version); ptr.Descriptor != want {
		t.Errorf("pointer names %q, want %q", ptr.Descriptor, want)
	}
}

// Publishing must not depend on the working directory: src paths resolve against
// pack.yaml, which is where go:generate puts the operator.
func TestSourcePathsResolveAgainstTheConfig(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if _, err := f.publish(refTime); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

// --- helpers -------------------------------------------------------------

// readTargets reads one published targets role at the given version.
func (f *fixture) readTargets(t *testing.T, role string, version int64) *metadata.Metadata[metadata.TargetsType] {
	t.Helper()
	raw := f.readFile(t, fmt.Sprintf("%d.%s.json", version, role))
	m, err := metadata.Targets().FromBytes(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", role, err)
	}
	return m
}

func (f *fixture) readFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.repo, MetadataDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// targetBytes reads a published target back off disk by its target path.
func (f *fixture) targetBytes(t *testing.T, target string) []byte {
	t.Helper()
	dir := filepath.Join(f.repo, TargetsDir, filepath.FromSlash(filepath.Dir(target)))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(target)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "."+base) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		// The consistent-snapshot prefix is the content hash: a file that
		// does not match its own name would make the read meaningless.
		sum := sha256.Sum256(raw)
		if !strings.HasPrefix(e.Name(), hex.EncodeToString(sum[:])) {
			continue
		}
		return raw
	}
	t.Fatalf("no target file for %s in %s", target, dir)
	return nil
}

// payloadFiles lists every payload file stored in the repository.
func (f *fixture) payloadFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	root := filepath.Join(f.repo, TargetsDir, "payloads")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// snapshotTree maps every file in a directory to the hash of its content.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// diff fails if two repositories are not byte-identical.
func diff(t *testing.T, a, b string) {
	t.Helper()
	left, right := snapshotTree(t, a), snapshotTree(t, b)
	for name, sum := range left {
		other, ok := right[name]
		if !ok {
			t.Errorf("%s exists only in the first repository", name)
			continue
		}
		if other != sum {
			t.Errorf("%s differs between two runs over the same inputs", name)
		}
	}
	for name := range right {
		if _, ok := left[name]; !ok {
			t.Errorf("%s exists only in the second repository", name)
		}
	}
}
