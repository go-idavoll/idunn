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

package installer_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

const (
	root    = "/opt/app"
	channel = "stable"
	appName = "acme-app"
)

// The trust client must provide the explicit-version capability the installer
// asks for, or `--version` silently stops working against a real repository.
var _ installer.VersionResolver = (*trust.Client)(nil)

// fakeTrust serves already-verified descriptors, as the boundary in the design
// says: by the time the installer sees one, whether to trust it is settled.
type fakeTrust struct {
	head      *release.Descriptor
	versions  map[string]*release.Descriptor
	targets   map[string][]byte
	refreshes int
}

func (f *fakeTrust) Refresh() error { f.refreshes++; return nil }

func (f *fakeTrust) LatestRelease(string, string, string) (*release.Descriptor, error) {
	return f.head, nil
}

func (f *fakeTrust) ReleaseVersion(_, _, version string) (*release.Descriptor, error) {
	d, ok := f.versions[version]
	if !ok {
		return nil, errors.New("no such release: " + version)
	}
	return d, nil
}

func (f *fakeTrust) Target(path string) ([]byte, error) {
	data, ok := f.targets[path]
	if !ok {
		return nil, errors.New("no such target: " + path)
	}
	return data, nil
}

func (f *fakeTrust) SignedLength(path string) (int64, error) {
	data, ok := f.targets[path]
	if !ok {
		return 0, errors.New("no such target: " + path)
	}
	return int64(len(data)), nil
}

func (f *fakeTrust) Accepts(path string, data []byte) error {
	want, ok := f.targets[path]
	if !ok {
		return errors.New("no such target: " + path)
	}
	if !bytes.Equal(want, data) {
		return errors.New("bytes are not target " + path)
	}
	return nil
}

func descriptor(version string) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          appName,
		Version:       version,
		Channel:       channel,
		OS:            "linux",
		Arch:          "amd64",
		Files: []release.FileRef{
			{Target: "targets/app-" + version, Dst: "app", Kind: release.KindExe, Mode: 0o755},
		},
	}
}

type fixture struct {
	t     *testing.T
	fs    *fsx.Mem
	trust *fakeTrust
	opts  installer.Options
}

func newFixture(t *testing.T, offers string, alsoAvailable ...string) *fixture {
	t.Helper()

	m := fsx.NewMem()
	if err := m.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	tr := &fakeTrust{
		head:     descriptor(offers),
		versions: map[string]*release.Descriptor{},
		targets:  map[string][]byte{},
	}
	for _, v := range append([]string{offers}, alsoAvailable...) {
		tr.versions[v] = descriptor(v)
		tr.targets["targets/app-"+v] = []byte("binary " + v)
	}

	return &fixture{
		t:     t,
		fs:    m,
		trust: tr,
		opts: installer.Options{
			Updater: updater.Options{
				Trust:   tr,
				FS:      m,
				Root:    root,
				Channel: channel,
				OS:      "linux",
				Arch:    "amd64",
			},
		},
	}
}

// installed writes the tree a completed installation leaves behind.
func (f *fixture) installed(version string, layoutSchema int) {
	f.t.Helper()
	dir, err := layout.VersionDir(root, version)
	if err != nil {
		f.t.Fatalf("VersionDir: %v", err)
	}
	if err := f.fs.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(f.fs, fsx.Join(dir, "app"), []byte("binary "+version), 0o755); err != nil {
		f.t.Fatalf("write: %v", err)
	}
	if err := layout.SetPointer(f.fs, root, version); err != nil {
		f.t.Fatalf("SetPointer: %v", err)
	}
	if err := layout.WriteInstall(f.fs, root, layout.Install{
		Name: appName, Version: version, LayoutSchema: layoutSchema,
	}); err != nil {
		f.t.Fatalf("WriteInstall: %v", err)
	}
}

func (f *fixture) pointer() string {
	f.t.Helper()
	v, err := layout.PointerTarget(f.fs, root)
	if err != nil {
		f.t.Fatalf("PointerTarget: %v", err)
	}
	return v
}

func TestInstallOnAnEmptyRoot(t *testing.T) {
	f := newFixture(t, "1.3.0")
	if err := installer.Install(context.Background(), f.opts); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
	in, err := layout.ReadInstall(f.fs, root)
	if err != nil {
		t.Fatalf("ReadInstall: %v", err)
	}
	if in == nil || in.Version != "1.3.0" || in.Name != appName {
		t.Fatalf("recorded state = %+v", in)
	}
	b, err := fsx.ReadFile(f.fs, "/opt/app/versions/1.3.0/app", 1<<20)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(b) != "binary 1.3.0" {
		t.Fatalf("installed payload = %q", b)
	}
}

// The check that stops an old but still validly signed installer from walking
// over a newer installation (§14.6, §11.3 T19).
func TestInstallRefusesToOverwriteANewerInstall(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed string
		offers    string
	}{
		{"the installation is newer", "1.4.0", "1.3.0"},
		{"the installation is the same version", "1.3.0", "1.3.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.offers)
			f.installed(tc.installed, release.LayoutSchema)

			err := installer.Install(context.Background(), f.opts)
			if tc.installed == tc.offers {
				// Nothing to do is success: the requested state is the state on
				// disk. What matters is that nothing was touched.
				if err != nil {
					t.Fatalf("Install: %v", err)
				}
			} else if !errors.Is(err, installer.ErrRefused) {
				t.Fatalf("error = %v, want ErrRefused", err)
			}

			if got := f.pointer(); got != tc.installed {
				t.Fatalf("current = %q, want the existing installation untouched", got)
			}
			if f.trust.refreshes > 1 {
				t.Fatalf("the installer went to the network %d times for a refusal", f.trust.refreshes)
			}
		})
	}
}

// An installation whose layout this binary does not implement must not be
// touched at all — not even to look at its version. The refusal happens before
// the network, because the decision needs nothing from it.
func TestInstallRefusesANewerLayout(t *testing.T) {
	f := newFixture(t, "1.3.0")
	f.installed("1.2.0", release.LayoutSchema+1)

	err := installer.Install(context.Background(), f.opts)
	if !errors.Is(err, installer.ErrRefused) {
		t.Fatalf("error = %v, want ErrRefused", err)
	}
	if !strings.Contains(err.Error(), "updater") {
		t.Fatalf("the refusal %q does not point at the updater", err)
	}
	if f.trust.refreshes != 0 {
		t.Fatal("the installer went to the network before deciding it must not proceed")
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want the existing installation untouched", got)
	}
}

// "I could not read the state" is not permission to overwrite it.
func TestInstallRefusesAnUnreadableState(t *testing.T) {
	f := newFixture(t, "1.3.0")
	if err := f.fs.MkdirAll(layout.Meta(root), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(f.fs, layout.State(root), []byte("{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := installer.Install(context.Background(), f.opts)
	if !errors.Is(err, installer.ErrRefused) {
		t.Fatalf("error = %v, want ErrRefused", err)
	}
	if f.trust.refreshes != 0 {
		t.Fatal("the installer went to the network before deciding it must not proceed")
	}
}

// Downgrading is an operator decision, and one they have to state.
func TestInstallDowngradesOnlyWhenAsked(t *testing.T) {
	f := newFixture(t, "1.2.0")
	f.installed("1.4.0", release.LayoutSchema)
	f.opts.AllowDowngrade = true

	if err := installer.Install(context.Background(), f.opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want the requested downgrade to 1.2.0", got)
	}
}

func TestInstallAnExplicitVersion(t *testing.T) {
	f := newFixture(t, "1.3.0", "1.2.0")
	f.opts.Version = "1.2.0"

	if err := installer.Install(context.Background(), f.opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want the pinned 1.2.0 rather than the channel head", got)
	}
	// Naming a version does not skip the refresh: a pinned version resolved
	// from stale metadata is exactly the freeze attack (§11.3 T5).
	if f.trust.refreshes != 1 {
		t.Fatalf("TUF refreshed %d times, want once", f.trust.refreshes)
	}
}

func TestInstallRejectsAnUnusableRequest(t *testing.T) {
	t.Run("no filesystem", func(t *testing.T) {
		f := newFixture(t, "1.3.0")
		f.opts.Updater.FS = nil
		if err := installer.Install(context.Background(), f.opts); err == nil {
			t.Fatal("Install ran without a filesystem")
		}
	})

	t.Run("a version that is not a version", func(t *testing.T) {
		f := newFixture(t, "1.3.0")
		f.opts.Version = "latest"
		if err := installer.Install(context.Background(), f.opts); err == nil {
			t.Fatal("Install accepted a version that is not SemVer")
		}
	})

	t.Run("a version that does not exist", func(t *testing.T) {
		f := newFixture(t, "1.3.0")
		f.opts.Version = "9.9.9"
		if err := installer.Install(context.Background(), f.opts); err == nil {
			t.Fatal("Install accepted a version the repository does not have")
		}
	})

	t.Run("an unusable updater configuration", func(t *testing.T) {
		f := newFixture(t, "1.3.0")
		f.opts.Updater.Channel = ""
		if err := installer.Install(context.Background(), f.opts); !errors.Is(err, updater.ErrConfig) {
			t.Fatalf("error = %v, want ErrConfig", err)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		f := newFixture(t, "1.3.0")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := installer.Install(ctx, f.opts); err == nil {
			t.Fatal("a cancelled install went ahead")
		}
		if got, _ := layout.PointerTarget(f.fs, root); got != "" {
			t.Fatalf("a cancelled install left %q behind", got)
		}
	})
}

// InstalledVersion reads the real filesystem, because it is what an installer
// binary calls before it has built anything.
func TestInstalledVersion(t *testing.T) {
	dir := t.TempDir()

	got, err := installer.InstalledVersion(dir)
	if err != nil || got != "" {
		t.Fatalf("InstalledVersion on an empty root = %q, %v", got, err)
	}

	osFS := fsx.OS()
	root := fsx.Slash(dir)
	vdir, err := layout.VersionDir(root, "1.3.0")
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	if err := osFS.MkdirAll(vdir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := layout.SetPointer(osFS, root, "1.3.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	if err := layout.WriteInstall(osFS, root, layout.Install{
		Name: appName, Version: "1.3.0", LayoutSchema: release.LayoutSchema,
	}); err != nil {
		t.Fatalf("WriteInstall: %v", err)
	}

	got, err = installer.InstalledVersion(dir)
	if err != nil {
		t.Fatalf("InstalledVersion: %v", err)
	}
	if got != "1.3.0" {
		t.Fatalf("InstalledVersion = %q, want 1.3.0", got)
	}
}

// A pointer and a state that disagree mean a transaction was interrupted and
// recovery has not run. Reporting either version as the truth would be a guess.
func TestInstalledVersionRefusesAnInconsistentInstall(t *testing.T) {
	t.Run("pointer without state", func(t *testing.T) {
		dir := t.TempDir()
		root := fsx.Slash(dir)
		vdir, err := layout.VersionDir(root, "1.3.0")
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := fsx.OS().MkdirAll(vdir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := layout.SetPointer(fsx.OS(), root, "1.3.0"); err != nil {
			t.Fatalf("SetPointer: %v", err)
		}
		if _, err := installer.InstalledVersion(dir); err == nil {
			t.Fatal("an install with no recorded state was reported as settled")
		}
	})

	t.Run("state without pointer", func(t *testing.T) {
		dir := t.TempDir()
		if err := layout.WriteInstall(fsx.OS(), fsx.Slash(dir), layout.Install{
			Name: appName, Version: "1.3.0", LayoutSchema: release.LayoutSchema,
		}); err != nil {
			t.Fatalf("WriteInstall: %v", err)
		}
		if _, err := installer.InstalledVersion(dir); err == nil {
			t.Fatal("a recorded state with no pointer was reported as settled")
		}
	})

	t.Run("they disagree", func(t *testing.T) {
		dir := t.TempDir()
		root := fsx.Slash(dir)
		vdir, err := layout.VersionDir(root, "1.3.0")
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := fsx.OS().MkdirAll(vdir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := layout.SetPointer(fsx.OS(), root, "1.3.0"); err != nil {
			t.Fatalf("SetPointer: %v", err)
		}
		if err := layout.WriteInstall(fsx.OS(), root, layout.Install{
			Name: appName, Version: "1.2.0", LayoutSchema: release.LayoutSchema,
		}); err != nil {
			t.Fatalf("WriteInstall: %v", err)
		}
		if _, err := installer.InstalledVersion(dir); err == nil {
			t.Fatal("a pointer and a state that disagree were reported as settled")
		}
	})

	t.Run("unreadable state", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, layout.MetaName), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, layout.MetaName, layout.StateName), []byte("{"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := installer.InstalledVersion(dir); err == nil {
			t.Fatal("an unreadable state was reported as no installation")
		}
	})
}
