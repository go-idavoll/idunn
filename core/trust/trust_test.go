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

// The red-team corpus proves that this package refuses tampered repositories.
// What it cannot show is the layer above that: the app-level resolution TUF does
// not model, where a channel pointer and a descriptor are each properly signed
// and simply do not agree. Both documents are authentic there, so no signature
// check can catch it — only the comparisons in LatestRelease and ReleaseVersion
// can, and these tests are what keeps them honest (backlog IDN-11).
//
// The repositories are built by the red-team harness, with throwaway keys it
// generates per test. Reusing it rather than hand-rolling a second builder keeps
// one definition of "a repository this client accepts" in the tree.
package trust_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/test/redteam/harness"
)

// The platform every repository below is built for. It is fixed rather than
// runtime.GOOS/GOARCH: what is under test is the resolution logic, and a test
// that resolved a different platform on every runner would be testing the
// runner.
const (
	testOS      = "linux"
	testArch    = "amd64"
	testChannel = "stable"
	testVersion = "1.2.0"
)

// fixture is one repository, served, with a client pointed at it.
type fixture struct {
	client  *trust.Client
	build   *harness.Build
	srv     *harness.Server
	refTime time.Time
	workDir string
}

// newFixture builds a repository, applies mutate to it, serves it, and returns a
// client whose reference time sits inside the baseline's validity window — so an
// expiry case fails for its own reason and not because CI ran a week later.
func newFixture(t *testing.T, mutate func(*harness.Build) error) *fixture {
	t.Helper()
	keys, err := harness.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	opts := harness.DefaultBuildOptions(keys)
	opts.OS, opts.Arch = testOS, testArch
	opts.Channel, opts.Version = testChannel, testVersion
	if mutate != nil {
		opts.Mutator = &harness.Mutator{Name: "test", Content: mutate}
	}

	dir := t.TempDir()
	repoDir := filepath.Join(dir, "repo")
	build, err := harness.BuildRepo(repoDir, opts)
	if err != nil {
		t.Fatalf("build repository: %v", err)
	}
	srv := harness.Serve(repoDir)
	t.Cleanup(srv.Close)

	refTime := opts.Now.Add(time.Hour)
	workDir := filepath.Join(dir, "client")
	c, err := trust.New(trust.Options{
		Root:        build.RootBytes,
		MetadataURL: srv.MetadataURL(),
		TargetsURL:  srv.TargetsURL(),
		LocalDir:    workDir,
		Now:         func() time.Time { return refTime },
	})
	if err != nil {
		t.Fatalf("trust.New: %v", err)
	}
	c.UnsafeSetRefTime(refTime)
	return &fixture{client: c, build: build, srv: srv, refTime: refTime, workDir: workDir}
}

// validRoot builds a repository only to take its trust anchor: the tests that
// exercise construction need root metadata go-tuf accepts, but no server.
func validRoot(t *testing.T) []byte {
	t.Helper()
	keys, err := harness.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	build, err := harness.BuildRepo(t.TempDir(), harness.DefaultBuildOptions(keys))
	if err != nil {
		t.Fatal(err)
	}
	return build.RootBytes
}

// refreshed returns a fixture whose client has completed the TUF workflow.
func refreshed(t *testing.T, mutate func(*harness.Build) error) *fixture {
	t.Helper()
	f := newFixture(t, mutate)
	if err := f.client.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return f
}

// reencode rewrites the published bytes from the structs a mutator changed. The
// harness keeps the two apart on purpose — a mutator may also publish bytes that
// are not a valid document at all — so a mutator that edits a struct says so.
func reencode(b *harness.Build) error {
	var err error
	if b.DescriptorRaw, err = json.MarshalIndent(b.Descriptor, "", "  "); err != nil {
		return err
	}
	b.PointerRaw, err = json.MarshalIndent(b.Pointer, "", "  ")
	return err
}

// --- construction --------------------------------------------------------

// New takes what it cannot work without. Each of these would otherwise surface
// much later, as a confusing failure in the middle of an update.
func TestNewRequiresItsInputs(t *testing.T) {
	valid := trust.Options{
		Root:        validRoot(t),
		MetadataURL: "https://example.com/metadata/",
		LocalDir:    t.TempDir(),
	}
	tests := []struct {
		name string
		mut  func(*trust.Options)
		want string
	}{
		{"no root", func(o *trust.Options) { o.Root = nil }, "no embedded root metadata"},
		{"empty root", func(o *trust.Options) { o.Root = []byte{} }, "no embedded root metadata"},
		{"no metadata URL", func(o *trust.Options) { o.MetadataURL = "" }, "no metadata URL"},
		{"no local dir", func(o *trust.Options) { o.LocalDir = "" }, "no local directory"},
		// A negative ceiling has no sensible reading: neither "no limit" nor
		// "refuse everything" is what anyone meant, so it is not guessed at.
		{"negative target ceiling", func(o *trust.Options) { o.MaxTargetBytes = -1 }, "MaxTargetBytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := valid
			tt.mut(&o)
			_, err := trust.New(o)
			if !errors.Is(err, trust.ErrTrust) {
				t.Fatalf("err = %v, want ErrTrust", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// Root metadata that is not metadata at all is refused at construction, not at
// the first fetch.
func TestNewRejectsUnusableRoot(t *testing.T) {
	_, err := trust.New(trust.Options{
		Root:        []byte("not json"),
		MetadataURL: "https://example.com/metadata/",
		LocalDir:    t.TempDir(),
	})
	if !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// The clock is injected so expiry decisions are deterministic under test, and
// callers read it through the client rather than reaching for time.Now.
func TestNowUsesTheInjectedClock(t *testing.T) {
	stamp := time.Date(2030, 5, 4, 3, 2, 1, 0, time.UTC)
	c, err := trust.New(trust.Options{
		Root:        validRoot(t),
		MetadataURL: "https://example.com/metadata/",
		LocalDir:    t.TempDir(),
		Now:         func() time.Time { return stamp },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.Now(); !got.Equal(stamp) {
		t.Errorf("Now() = %s, want %s", got, stamp)
	}
}

func TestNowDefaultsToTheWallClock(t *testing.T) {
	c, err := trust.New(trust.Options{
		Root:        validRoot(t),
		MetadataURL: "https://example.com/metadata/",
		LocalDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.Now(); time.Since(got) > time.Minute || time.Since(got) < -time.Minute {
		t.Errorf("Now() = %s, which is not the wall clock", got)
	}
}

// A local directory that cannot be created is a failure at construction: the
// client has nowhere to keep the trusted metadata it is about to verify.
func TestNewRejectsAnUnusableLocalDirectory(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := trust.New(trust.Options{
		Root:        validRoot(t),
		MetadataURL: "https://example.com/metadata/",
		LocalDir:    filepath.Join(blocker, "cache"),
	})
	if !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// --- the happy path ------------------------------------------------------

// The control: without it, a file full of rejections would look green while
// proving that nothing resolves at all.
func TestResolvesAValidRepository(t *testing.T) {
	f := refreshed(t, nil)

	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	if d.Version != testVersion || d.Channel != testChannel || d.OS != testOS || d.Arch != testArch {
		t.Fatalf("descriptor = %s/%s-%s@%s", d.Channel, d.OS, d.Arch, d.Version)
	}
	if len(d.Files) == 0 {
		t.Fatal("descriptor names no files")
	}
	for _, file := range d.Files {
		raw, err := f.client.Target(file.Target)
		if err != nil {
			t.Fatalf("Target(%s): %v", file.Target, err)
		}
		if want := f.build.Payloads[file.Target]; string(raw) != string(want) {
			t.Errorf("target %s = %q, want %q", file.Target, raw, want)
		}
	}
}

// ReleaseVersion is the installer's --version and the pinned-deployment path. It
// bypasses the publisher's statement about what is current, and nothing else.
func TestReleaseVersionResolvesANamedRelease(t *testing.T) {
	f := refreshed(t, nil)

	d, err := f.client.ReleaseVersion(testOS, testArch, testVersion)
	if err != nil {
		t.Fatalf("ReleaseVersion: %v", err)
	}
	if d.Version != testVersion {
		t.Errorf("version = %q, want %q", d.Version, testVersion)
	}
}

// --- resolution: two authentic documents that disagree -------------------

// The pointer and the descriptor are separately signed targets. If they
// disagree, one was substituted for another valid-but-wrong target, and there is
// no basis for picking a winner — so both are refused.
func TestDescriptorThatContradictsThePointerIsRefused(t *testing.T) {
	// The descriptor stays at the path the pointer legitimately names, and
	// claims to be a different release once opened.
	f := refreshed(t, func(b *harness.Build) error {
		b.Descriptor.Version = "9.9.9"
		return reencode(b)
	})

	_, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if !errors.Is(err, trust.ErrResolve) {
		t.Fatalf("err = %v, want ErrResolve", err)
	}
}

// A descriptor may not disagree with the platform it was resolved for either.
func TestDescriptorForAnotherPlatformIsRefused(t *testing.T) {
	f := refreshed(t, func(b *harness.Build) error {
		b.Descriptor.Arch = "arm64"
		return reencode(b)
	})

	_, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if !errors.Is(err, trust.ErrResolve) {
		t.Fatalf("err = %v, want ErrResolve", err)
	}
}

// The descriptor path is derivable from the version the pointer claims, so a
// pointer naming any other path is reaching for a release it is not entitled to
// name. The check runs before the fetch: never request what is already known to
// be wrong.
func TestPointerNamingAForeignDescriptorIsRefused(t *testing.T) {
	f := refreshed(t, func(b *harness.Build) error {
		b.Pointer.Descriptor = release.DescriptorPath(testOS, testArch, "0.0.1")
		return reencode(b)
	})

	_, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if !errors.Is(err, trust.ErrResolve) {
		t.Fatalf("err = %v, want ErrResolve", err)
	}
	if !strings.Contains(err.Error(), "expected") {
		t.Errorf("err = %v, want it to name the path it expected", err)
	}
}

// The same check from the other side: the pointer claims a version whose
// descriptor path is not the one it names.
func TestPointerWithADisagreeingVersionIsRefused(t *testing.T) {
	f := refreshed(t, func(b *harness.Build) error {
		b.Pointer.Version = "9.9.9"
		return reencode(b)
	})

	_, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if !errors.Is(err, trust.ErrResolve) {
		t.Fatalf("err = %v, want ErrResolve", err)
	}
}

// A pointer served at one platform's path while declaring another is a
// mix-and-match of two authentic documents.
func TestPointerForAnotherPlatformIsRefused(t *testing.T) {
	for _, tt := range []struct {
		name  string
		mut   func(*harness.Build)
		chann string
	}{
		{"other arch", func(b *harness.Build) { b.Pointer.Arch = "arm64" }, testChannel},
		{"other os", func(b *harness.Build) { b.Pointer.OS = "windows" }, testChannel},
		{"other channel", func(b *harness.Build) { b.Pointer.Channel = "beta" }, testChannel},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := refreshed(t, func(b *harness.Build) error {
				tt.mut(b)
				return reencode(b)
			})
			_, err := f.client.LatestRelease(tt.chann, testOS, testArch)
			if !errors.Is(err, trust.ErrResolve) {
				t.Fatalf("err = %v, want ErrResolve", err)
			}
		})
	}
}

// A version this client cannot order is a version it cannot make a trust
// decision about, so it is refused before it becomes a path.
func TestReleaseVersionRefusesAnUnorderableVersion(t *testing.T) {
	f := refreshed(t, nil)

	for _, v := range []string{"", "latest", "1.2", "v1.2.0", "../../etc/passwd"} {
		_, err := f.client.ReleaseVersion(testOS, testArch, v)
		if !errors.Is(err, trust.ErrResolve) {
			t.Errorf("ReleaseVersion(%q) err = %v, want ErrResolve", v, err)
		}
	}
}

// A descriptor that disagrees with its own location is a valid target
// substituted for another one. The path states what it describes, and the
// contents do not get to overrule it.
func TestReleaseVersionRefusesADescriptorThatDisagreesWithItsPath(t *testing.T) {
	f := refreshed(t, func(b *harness.Build) error {
		b.Descriptor.Version = "9.9.9"
		return reencode(b)
	})

	_, err := f.client.ReleaseVersion(testOS, testArch, testVersion)
	if !errors.Is(err, trust.ErrResolve) {
		t.Fatalf("err = %v, want ErrResolve", err)
	}
}

// A malformed document is a rejection by ingest, not by resolution: it never
// gets far enough to be compared with anything.
func TestMalformedDescriptorIsRefusedByIngest(t *testing.T) {
	f := refreshed(t, func(b *harness.Build) error {
		b.DescriptorRaw = []byte("{not json")
		return nil
	})

	_, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if !errors.Is(err, release.ErrInvalid) {
		t.Fatalf("err = %v, want release.ErrInvalid", err)
	}
	if !errors.Is(err, trust.ErrTrust) {
		t.Errorf("err = %v, want it to also carry ErrTrust for classification", err)
	}
}

func TestMalformedPointerIsRefusedByIngest(t *testing.T) {
	f := refreshed(t, func(b *harness.Build) error {
		b.PointerRaw = []byte("[]")
		return nil
	})

	_, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if !errors.Is(err, release.ErrInvalid) {
		t.Fatalf("err = %v, want release.ErrInvalid", err)
	}
}

// A channel with no pointer is an error, not "no update": an empty channel and a
// server withholding one are indistinguishable, so we fail closed.
func TestUnknownChannelFailsClosed(t *testing.T) {
	f := refreshed(t, nil)

	_, err := f.client.LatestRelease("nightly", testOS, testArch)
	if !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

func TestUnknownTargetIsRefused(t *testing.T) {
	f := refreshed(t, nil)

	if _, err := f.client.Target("payloads/1.2.0/not-a-target"); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// A version the repository never published is a rejection by the trust layer:
// there is no signed target at that path, and an installer asking for one gets
// an error rather than the channel head as a consolation.
func TestReleaseVersionOfAnUnpublishedReleaseIsRefused(t *testing.T) {
	f := refreshed(t, nil)

	if _, err := f.client.ReleaseVersion(testOS, testArch, "9.9.9"); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// The local cache is used on the second read, and only for bytes that still
// match the signed hash and length — go-tuf checks that in both paths, so a
// cached file is never trusted on name alone (AGENTS.md §1.5).
//
// Closing the server first is what makes the assertion mean something: a second
// read that still succeeds cannot have come from the network.
func TestTargetIsServedFromTheCacheOnTheSecondRead(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target

	first, err := f.client.Target(target)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	f.srv.Close()

	second, err := f.client.Target(target)
	if err != nil {
		t.Fatalf("Target from cache: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("cached read = %q, want %q", second, first)
	}
}

// --- reuse surface -------------------------------------------------------

// The signed length is what lets staging dismiss a local reuse candidate before
// reading it. It must come from the signed metadata, so it is available without
// the target ever being fetched.
func TestTargetLengthComesFromSignedMetadata(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target

	got, err := f.client.TargetLength(target)
	if err != nil {
		t.Fatalf("TargetLength: %v", err)
	}
	data, err := f.client.Target(target)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if got != int64(len(data)) {
		t.Fatalf("TargetLength = %d, want %d", got, len(data))
	}
}

func TestTargetLengthOfAnUnknownTargetIsRefused(t *testing.T) {
	f := refreshed(t, nil)

	if _, err := f.client.TargetLength("targets/nothing-here"); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// VerifyTarget is the door bytes from outside go-tuf come through — a file
// reused from an installed version today, the result of a delta patch later. It
// must accept exactly the signed content and nothing adjacent to it.
func TestVerifyTargetAcceptsOnlyTheSignedBytes(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target
	signed, err := f.client.Target(target)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("the fixture payload is empty; the tampering below would be vacuous")
	}

	if err := f.client.VerifyTarget(target, signed); err != nil {
		t.Fatalf("VerifyTarget rejected the signed bytes: %v", err)
	}

	flipped := append([]byte(nil), signed...)
	flipped[len(flipped)-1] ^= 0x01
	for name, data := range map[string][]byte{
		"one bit flipped": flipped,
		"truncated":       signed[:len(signed)-1],
		"one byte added":  append(append([]byte(nil), signed...), 0x00),
		"empty":           {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := f.client.VerifyTarget(target, data); !errors.Is(err, trust.ErrTrust) {
				t.Fatalf("err = %v, want ErrTrust", err)
			}
		})
	}
}

// There is no signed hash to compare against for a target the repository never
// published, so there is no verdict to give: an unknown target is refused, never
// waved through for want of an expectation.
func TestVerifyTargetOfAnUnknownTargetIsRefused(t *testing.T) {
	f := refreshed(t, nil)

	if err := f.client.VerifyTarget("targets/nothing-here", []byte("anything")); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// --- the published releases ----------------------------------------------

// publishing returns a fixture whose repository also publishes descriptors for
// the given versions. They are the real thing — same shape, own version, at the
// path that states it — because what is under test is that the client can learn
// which releases exist without a new document to sign for it.
func publishing(t *testing.T, versions ...string) *fixture {
	t.Helper()
	return refreshed(t, func(b *harness.Build) error {
		for _, v := range versions {
			d := *b.Descriptor
			d.Version = v
			raw, err := json.MarshalIndent(&d, "", "  ")
			if err != nil {
				return err
			}
			b.Payloads[release.DescriptorPath(b.Opts.OS, b.Opts.Arch, v)] = raw
		}
		return nil
	})
}

// Opening a line the repository does not publish adds nothing and fails
// nothing: a walk through it simply finds no releases. (What opening a line
// that *is* published does is only visible where roles are delegated per line,
// which is the packer's fixture, not this one.)
func TestOpenLineOfAnUnpublishedLineIsHarmless(t *testing.T) {
	f := publishing(t, "1.0.0")
	before := f.client.Versions(testOS, testArch)

	f.client.OpenLine(testOS, testArch, "9")

	if after := f.client.Versions(testOS, testArch); len(after) != len(before) {
		t.Fatalf("Versions = %v, want %v", after, before)
	}
}

// A client that skipped releases has to walk the ones it missed, and the walk
// needs to know they exist. That knowledge is already signed: every descriptor
// is a target, and its path states its version.
func TestVersionsListsThePublishedReleases(t *testing.T) {
	f := publishing(t, "1.0.0", "1.1.0", "1.1.0-rc.1")

	got := f.client.Versions(testOS, testArch)
	want := []string{"1.0.0", "1.1.0-rc.1", "1.1.0", testVersion}
	if len(got) != len(want) {
		t.Fatalf("Versions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Versions = %v, want %v (oldest first)", got, want)
		}
	}
}

// The platform is part of the path, so another one's releases are not this
// one's — an arm64 client must never chain through amd64 descriptors.
func TestVersionsAreScopedToThePlatform(t *testing.T) {
	f := publishing(t, "1.0.0")

	if got := f.client.Versions(testOS, "arm64"); len(got) != 0 {
		t.Fatalf("Versions for another arch = %v, want none", got)
	}
	if got := f.client.Versions("windows", testArch); len(got) != 0 {
		t.Fatalf("Versions for another OS = %v, want none", got)
	}
}

// Payloads and channel pointers are targets too. Only descriptors say which
// releases exist, and only they may be counted.
func TestVersionsCountsOnlyDescriptors(t *testing.T) {
	f := publishing(t)

	got := f.client.Versions(testOS, testArch)
	if len(got) != 1 || got[0] != testVersion {
		t.Fatalf("Versions = %v, want just the one published release", got)
	}
}

// What the two pieces are for: the versions the repository publishes, turned
// into the walk a patched update follows.
func TestVersionsFeedAChain(t *testing.T) {
	f := publishing(t, "1.0.0", "1.1.0")

	walk, err := release.Chain(f.client.Versions(testOS, testArch), "1.0.0", testVersion)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	want := []string{"1.0.0", "1.1.0", testVersion}
	for i := range want {
		if i >= len(walk) || walk[i] != want[i] {
			t.Fatalf("Chain = %v, want %v", walk, want)
		}
	}
}

// A repository the client has no metadata for yet cannot be walked. It must say
// so by listing nothing, so the caller falls back to full targets instead of
// walking a chain it invented.
func TestVersionsBeforeRefreshAreEmpty(t *testing.T) {
	f := newFixture(t, nil)

	if got := f.client.Versions(testOS, testArch); len(got) != 0 {
		t.Fatalf("Versions before Refresh = %v, want none", got)
	}
}

// --- materialization -----------------------------------------------------

func TestMaterializeTargetWritesVerifiedBytes(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}

	for _, file := range d.Files {
		// A nested destination that does not exist yet: staging hands over
		// paths inside a tree it is still building.
		dst := filepath.Join(t.TempDir(), "staged", "deep", filepath.Base(file.Dst))
		if err := f.client.MaterializeTarget(file.Target, dst); err != nil {
			t.Fatalf("MaterializeTarget(%s): %v", file.Target, err)
		}
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("reading %s: %v", dst, err)
		}
		if want := f.build.Payloads[file.Target]; string(got) != string(want) {
			t.Errorf("%s = %q, want %q", dst, got, want)
		}
	}
}

// Materializing over an existing file replaces it whole. The write goes through
// a temporary file in the destination directory, so an interrupted run can never
// leave a half-written file where a complete one is expected.
func TestMaterializeTargetReplacesAnExistingFile(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target

	dst := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(dst, []byte("stale content that is longer than the real one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.client.MaterializeTarget(target, dst); err != nil {
		t.Fatalf("MaterializeTarget: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if want := f.build.Payloads[target]; string(got) != string(want) {
		t.Errorf("%s = %q, want %q", dst, got, want)
	}
}

func TestMaterializeUnknownTargetWritesNothing(t *testing.T) {
	f := refreshed(t, nil)

	dir := t.TempDir()
	dst := filepath.Join(dir, "payload")
	if err := f.client.MaterializeTarget("payloads/1.2.0/not-a-target", dst); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("a refused materialization left %d entries behind (%v)", len(entries), err)
	}
}

// A destination that cannot be created is an error, not a silent skip.
func TestMaterializeTargetReportsAnUnusableDestination(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}

	// A regular file where a parent directory would have to be.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = f.client.MaterializeTarget(d.Files[0].Target, filepath.Join(blocker, "sub", "payload"))
	if !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// --- freshness -----------------------------------------------------------

// Expiry is refused either way; the classification exists so an operator is told
// "your clock looks wrong" instead of "update failed" (§14.7).
func TestExpiredMetadataIsClassifiedAsExpiry(t *testing.T) {
	f := newFixture(t, nil)
	// A reference time past the timestamp's one-day window: the freshness
	// anchor is stale, and nothing may be resolved from it.
	f.client.UnsafeSetRefTime(f.refTime.AddDate(0, 0, 30))

	err := f.client.Refresh()
	if !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
	if !trust.IsExpiry(err) {
		t.Errorf("IsExpiry(%v) = false, want true", err)
	}
}

// IsExpiry answers only for the thing it is about; everything else stays
// unclassified rather than being reported as a clock problem.
func TestIsExpiryIgnoresEverythingElse(t *testing.T) {
	if trust.IsExpiry(nil) {
		t.Error("IsExpiry(nil) = true")
	}
	if trust.IsExpiry(errors.New("connection refused")) {
		t.Error("IsExpiry(non-expiry error) = true")
	}
	if trust.IsExpiry(trust.ErrResolve) {
		t.Error("IsExpiry(ErrResolve) = true")
	}
}

// A repository that cannot be reached at all fails in the trust layer, with
// nothing resolved. This is the shape an offline client sees.
func TestRefreshAgainstAnUnreachableRepositoryFails(t *testing.T) {
	c, err := trust.New(trust.Options{
		Root:        validRoot(t),
		MetadataURL: "http://127.0.0.1:1/metadata/",
		LocalDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Refresh(); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// --- the target ceiling (IDN-12) ------------------------------------------

// withCeiling points a fresh client at the fixture's repository with the given
// target ceiling, over localDir, and refreshes it.
func (f *fixture) withCeiling(t *testing.T, maxTarget int64, localDir string) *trust.Client {
	t.Helper()
	c, err := trust.New(trust.Options{
		Root:           f.build.RootBytes,
		MetadataURL:    f.srv.MetadataURL(),
		TargetsURL:     f.srv.TargetsURL(),
		LocalDir:       localDir,
		MaxTargetBytes: maxTarget,
		Now:            func() time.Time { return f.refTime },
	})
	if err != nil {
		t.Fatalf("trust.New: %v", err)
	}
	c.UnsafeSetRefTime(f.refTime)
	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return c
}

// A target whose signed length is above the ceiling is refused before a byte of
// it is requested.
//
// go-tuf hands a target over as one []byte, so the signed length is also the
// allocation about to happen. A repository is untrusted input even when it is
// correctly signed, and an unbounded allocation from it is an OOM kill with no
// diagnosis. One byte under the target's length is the tightest ceiling that
// must refuse, so an off-by-one in the comparison fails here.
func TestATargetAboveTheCeilingIsRefusedBeforeItIsFetched(t *testing.T) {
	f := newFixture(t, nil)
	target := f.build.DescriptorTarget()
	size := int64(len(f.build.DescriptorRaw))
	work := t.TempDir()
	c := f.withCeiling(t, size-1, work)

	_, err := c.Target(target)
	if !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
	// The refusal has to say what to do about it, or an operator with a
	// legitimately large release has an unexplained failure.
	if !strings.Contains(err.Error(), "MaxTargetBytes") {
		t.Errorf("the refusal does not name the option to raise: %v", err)
	}
	// A refusal that downloads first has saved nothing.
	if f.srv.Fetched(target) {
		t.Error("the target was requested before it was refused")
	}
	entries, err := os.ReadDir(filepath.Join(work, "targets"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the refused target left %d files in the cache", len(entries))
	}
}

// A ceiling exactly at the signed length is not above it: the guard cannot be
// the reason an honest repository stops working. It is also what keeps the test
// above from passing vacuously — the same fixture, fetched, is observed.
func TestATargetAtTheCeilingIsFetched(t *testing.T) {
	f := newFixture(t, nil)
	target := f.build.DescriptorTarget()
	size := int64(len(f.build.DescriptorRaw))
	c := f.withCeiling(t, size, t.TempDir())

	raw, err := c.Target(target)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if int64(len(raw)) != size {
		t.Errorf("got %d bytes, want %d", len(raw), size)
	}
	if !f.srv.Fetched(target) {
		t.Error("the target was not fetched, so the refusal test proves nothing")
	}
}

// The go-tuf cache is a second way a target's bytes come in, and reading it is
// the same allocation as downloading. A target cached by a client with room for
// it is still refused by one without, over the same local directory.
func TestACachedTargetAboveTheCeilingIsRefused(t *testing.T) {
	f := refreshed(t, nil)
	target := f.build.DescriptorTarget()
	if _, err := f.client.Target(target); err != nil {
		t.Fatalf("Target: %v", err)
	}

	c := f.withCeiling(t, int64(len(f.build.DescriptorRaw))-1, f.workDir)
	if _, err := c.Target(target); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// Reuse and patching read beside go-tuf, and size those reads by TargetLength;
// their bytes are admitted by VerifyTarget. Both answer from the same ceiling,
// so neither path can be talked into an allocation a download would refuse —
// not even with the exact signed bytes in hand.
func TestTheReuseSurfaceRespectsTheCeiling(t *testing.T) {
	f := newFixture(t, nil)
	target := f.build.DescriptorTarget()
	signed := f.build.DescriptorRaw
	c := f.withCeiling(t, int64(len(signed))-1, t.TempDir())

	if _, err := c.TargetLength(target); !errors.Is(err, trust.ErrTrust) {
		t.Errorf("TargetLength: err = %v, want ErrTrust", err)
	}
	if err := c.VerifyTarget(target, signed); !errors.Is(err, trust.ErrTrust) {
		t.Errorf("VerifyTarget: err = %v, want ErrTrust", err)
	}
	if f.srv.Fetched(target) {
		t.Error("the target was requested")
	}

	// At the ceiling, both answer as they always did.
	c = f.withCeiling(t, int64(len(signed)), t.TempDir())
	if got, err := c.TargetLength(target); err != nil || got != int64(len(signed)) {
		t.Errorf("TargetLength at the ceiling = %d, %v; want %d", got, err, len(signed))
	}
	if err := c.VerifyTarget(target, signed); err != nil {
		t.Errorf("VerifyTarget at the ceiling: %v", err)
	}
}

// Resolving a release goes through the same door: a channel pointer above the
// ceiling is refused before it is requested, and nothing is resolved.
func TestLatestReleaseRespectsTheCeiling(t *testing.T) {
	f := newFixture(t, nil)
	c := f.withCeiling(t, int64(len(f.build.PointerRaw))-1, t.TempDir())

	if _, err := c.LatestRelease(testChannel, testOS, testArch); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
	if f.srv.Fetched(f.build.PointerTarget()) {
		t.Error("the channel pointer was requested before it was refused")
	}
}

// --- streaming targets ---------------------------------------------------

// Materialize is what staging consumes in place of Target, so it must hand over
// exactly the same bytes — and it must do it without the caller ever holding
// them, which is what the io.Writer in the signature is for.
func TestMaterializeStreamsTheSignedBytes(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target
	want, err := f.client.Target(target)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}

	var got bytes.Buffer
	if err := f.client.Materialize(target, &got); err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("Materialize wrote %d bytes, want the %d signed ones", got.Len(), len(want))
	}
}

// The second materialization must come off the local cache: that is the whole
// reason reuse and a re-run of a failed update are cheap. Closing the server
// first is what proves nothing went back to it.
func TestMaterializeSecondTimeComesFromTheCache(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target

	var first bytes.Buffer
	if err := f.client.Materialize(target, &first); err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	f.srv.Close()

	var second bytes.Buffer
	if err := f.client.Materialize(target, &second); err != nil {
		t.Fatalf("Materialize from cache: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("the cached materialization differs from the downloaded one")
	}
}

// The go-tuf cache is local, owner-only state, and a file planted in it is still
// untrusted input: it is verified exactly like a download, and a cache entry
// that does not verify is not a cache hit. It must also not be *read* whole
// first — Updater.FindCachedTarget does that with an unbounded os.ReadFile,
// which is why this path does not use it (T23).
func TestMaterializeRefusesATamperedCacheEntry(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target

	var want bytes.Buffer
	if err := f.client.Materialize(target, &want); err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	cached := filepath.Join(f.workDir, "targets", url.PathEscape(target))
	if _, err := os.Stat(cached); err != nil {
		t.Fatalf("the cache file is not where this test expects it: %v", err)
	}

	for name, planted := range map[string][]byte{
		"different content of the same length": bytes.Repeat([]byte{'x'}, want.Len()),
		"truncated":                            want.Bytes()[:max(want.Len()-1, 0)],
		"far larger than the signed length":    bytes.Repeat([]byte{'x'}, want.Len()+4<<20),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(cached, planted, 0o644); err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := f.client.Materialize(target, &got); err != nil {
				t.Fatalf("Materialize: %v", err)
			}
			if !bytes.Equal(got.Bytes(), want.Bytes()) {
				t.Error("a planted cache entry reached the caller")
			}
		})
	}
}

// A target above the ceiling is refused before it is requested, whichever door
// it is asked for through. Materialize and VerifyStream are two more doors.
func TestStreamingRespectsTheCeiling(t *testing.T) {
	f := newFixture(t, nil)
	target := f.build.DescriptorTarget()
	signed := f.build.DescriptorRaw
	c := f.withCeiling(t, int64(len(signed))-1, t.TempDir())

	if err := c.Materialize(target, io.Discard); !errors.Is(err, trust.ErrTrust) {
		t.Errorf("Materialize: err = %v, want ErrTrust", err)
	}
	if err := c.VerifyStream(target, bytes.NewReader(signed)); !errors.Is(err, trust.ErrTrust) {
		t.Errorf("VerifyStream: err = %v, want ErrTrust", err)
	}
	if f.srv.Fetched(target) {
		t.Error("the target was requested before it was refused")
	}

	// At the ceiling, both answer as they always did — otherwise the refusals
	// above would prove nothing.
	c = f.withCeiling(t, int64(len(signed)), t.TempDir())
	if err := c.Materialize(target, io.Discard); err != nil {
		t.Errorf("Materialize at the ceiling: %v", err)
	}
	if err := c.VerifyStream(target, bytes.NewReader(signed)); err != nil {
		t.Errorf("VerifyStream at the ceiling: %v", err)
	}
}

// VerifyStream is the door bytes from outside go-tuf come through once they are
// too big to hold: a reused file, the output of a delta patch, an installed file
// re-read after the swap. It must accept exactly the signed content and nothing
// adjacent to it — the same contract VerifyTarget has, over a reader.
func TestVerifyStreamAcceptsOnlyTheSignedBytes(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target
	signed, err := f.client.Target(target)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("the fixture payload is empty; the tampering below would be vacuous")
	}

	if err := f.client.VerifyStream(target, bytes.NewReader(signed)); err != nil {
		t.Fatalf("VerifyStream rejected the signed bytes: %v", err)
	}

	flipped := append([]byte(nil), signed...)
	flipped[len(flipped)-1] ^= 0x01
	for name, data := range map[string][]byte{
		"one bit flipped": flipped,
		"truncated":       signed[:len(signed)-1],
		"one byte added":  append(append([]byte(nil), signed...), 0x00),
		"empty":           {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := f.client.VerifyStream(target, bytes.NewReader(data)); err == nil {
				t.Fatal("accepted bytes that are not the signed ones")
			}
		})
	}
}

func TestVerifyStreamOfAnUnknownTargetIsRefused(t *testing.T) {
	f := refreshed(t, nil)

	err := f.client.VerifyStream("targets/nothing-here", strings.NewReader("anything"))
	if !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
}

// A reader that fails halfway is a refusal, not a partial success: the caller
// must never be told the stream verified because the part that arrived did.
func TestVerifyStreamReportsAReaderThatFails(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target
	signed, err := f.client.Target(target)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}

	broken := io.MultiReader(bytes.NewReader(signed[:len(signed)/2]), errorReader{})
	if err := f.client.VerifyStream(target, broken); err == nil {
		t.Fatal("a stream that could not be read whole was accepted")
	}
}

// errorReader fails every read, standing in for a file that goes away or a disk
// that stops answering mid-stream.
type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("the medium stopped answering") }

// A target that is not cached and cannot be fetched is a refusal that writes
// nothing: the caller's writer must not be left holding a prefix of a download
// that never finished.
func TestMaterializeReportsAnUnreachableRepository(t *testing.T) {
	f := refreshed(t, nil)
	d, err := f.client.LatestRelease(testChannel, testOS, testArch)
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	target := d.Files[0].Target
	f.srv.Close()

	var got bytes.Buffer
	if err := f.client.Materialize(target, &got); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("err = %v, want ErrTrust", err)
	}
	if got.Len() != 0 {
		t.Errorf("a failed materialization wrote %d bytes", got.Len())
	}
}
