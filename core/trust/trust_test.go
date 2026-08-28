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
	"encoding/json"
	"errors"
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

// clientWith points a fresh client at the fixture's repository with the given
// ceiling, and refreshes it.
func (f *fixture) clientWith(t *testing.T, maxTarget int64) (*trust.Client, string) {
	t.Helper()
	work := t.TempDir()
	c, err := trust.New(trust.Options{
		Root:           f.build.RootBytes,
		MetadataURL:    f.srv.MetadataURL(),
		TargetsURL:     f.srv.TargetsURL(),
		LocalDir:       work,
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
	return c, work
}

// A target whose signed length is above the ceiling is refused before a byte of
// it is requested (IDN-12).
//
// go-tuf hands a target over as one []byte, so the signed length is also the
// allocation about to happen. A repository is untrusted input even when it is
// correctly signed, and an unbounded allocation from it is an OOM kill with no
// diagnosis. Refusing is the fail-closed answer, and it names the knob to raise.
func TestATargetAboveTheCeilingIsRefusedBeforeItIsFetched(t *testing.T) {
	f := refreshed(t, nil)
	c, work := f.clientWith(t, 1) // one byte: everything is too big.

	_, err := c.Target(f.build.DescriptorTarget())
	if err == nil {
		t.Fatal("a target above the ceiling was accepted")
	}
	if !errors.Is(err, trust.ErrTrust) {
		t.Errorf("err = %v, want an ErrTrust", err)
	}
	// The refusal has to say what to do about it, or an operator with a
	// legitimately large release has an unexplained failure.
	if !strings.Contains(err.Error(), "MaxTargetBytes") {
		t.Errorf("the refusal does not name the option to raise: %v", err)
	}
	// And nothing was fetched: a refusal that downloads first has saved nothing.
	entries, err := os.ReadDir(filepath.Join(work, "targets"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the refused target left %d files in the cache", len(entries))
	}
}

// A ceiling above the target changes nothing, so the guard cannot be the reason
// an honest repository stops working.
func TestATargetBelowTheCeilingIsUnaffected(t *testing.T) {
	f := refreshed(t, nil)
	c, _ := f.clientWith(t, trust.DefaultMaxTargetBytes)

	raw, err := c.Target(f.build.DescriptorTarget())
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if len(raw) == 0 {
		t.Error("the descriptor resolved to no bytes")
	}
}
