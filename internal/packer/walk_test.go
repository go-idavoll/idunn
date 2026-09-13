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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

// releaseConfig is one release of the fixture app, with the migration floor it
// demands of whatever is installed before it.
func releaseConfig(version, floor string) string {
	return fmt.Sprintf(`name: demo
version: %s
channel: stable
requirements:
  min_from_version: %s
targets:
  - os: linux
    arch: amd64
    files:
      - { src: linux-amd64/app,    dst: bin/app,    kind: exe }
      - { src: linux-amd64/lib.so, dst: lib/lib.so, kind: lib }
`, version, floor)
}

// publishRelease writes the sources for a version and publishes it.
func publishRelease(f *fixture, version, floor string, at time.Time) {
	f.t.Helper()
	f.writeSource("linux-amd64/app", "idunn test payload: app "+version+"\n")
	f.writeSource("linux-amd64/lib.so", "idunn test payload: lib "+version+"\n")
	f.writeConfig(releaseConfig(version, floor))
	f.mustPublish(at)
}

// updateInstall installs one version and then updates to the channel head,
// driving the real client: core/installer, core/updater, and the walk between
// them. A client is built per phase because a go-tuf workflow runs once per
// process, which is also what two runs on one machine look like.
func updateInstall(t *testing.T, f *fixture, installRoot, version string, at time.Time) error {
	t.Helper()
	opts := func(c *trust.Client) updater.Options {
		return updater.Options{
			Trust:   c,
			FS:      fsx.OS(),
			Root:    installRoot,
			Channel: "stable",
			OS:      "linux",
			Arch:    "amd64",
			Now:     func() time.Time { return at },
		}
	}

	c, _, err := f.newClient(at)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := installer.Install(context.Background(), installer.Options{
		Updater: opts(c),
		Version: version,
	}); err != nil {
		t.Fatalf("installing %s: %v", version, err)
	}

	if c, _, err = f.newClient(at); err != nil {
		t.Fatalf("client: %v", err)
	}
	u, err := updater.New(opts(c))
	if err != nil {
		t.Fatalf("updater.New: %v", err)
	}
	rel, err := u.CheckForUpdate(context.Background())
	if err != nil {
		return err
	}
	if rel == nil {
		t.Fatal("no update was offered")
	}
	return u.Apply(context.Background(), rel)
}

// The gap the walk above would fall into, stated directly: a real repository
// delegates per release line, so a client that resolved a 2.0.0 head has the
// 2.x role and no other, and cannot see the 1.x releases at all until it asks
// for the line.
func TestVersionsSeeALineOnlyOnceItIsOpened(t *testing.T) {
	f := newFixture(t)
	publishRelease(f, "1.0.0", "", refTime)
	publishRelease(f, "1.5.0", "1.0.0", refTime.Add(time.Hour))
	publishRelease(f, "2.0.0", "1.5.0", refTime.Add(2*time.Hour))

	at := refTime.Add(3 * time.Hour)
	c, _, err := f.client(at)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := c.LatestRelease("stable", "linux", "amd64"); err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}

	if got := c.Versions("linux", "amd64"); len(got) != 1 || got[0] != "2.0.0" {
		t.Fatalf("Versions = %v, want just the head's own line", got)
	}

	c.OpenLine("linux", "amd64", "1")
	got := c.Versions("linux", "amd64")
	want := []string{"1.0.0", "1.5.0", "2.0.0"}
	if len(got) != len(want) {
		t.Fatalf("Versions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Versions = %v, want %v", got, want)
		}
	}

	// A line the repository does not publish is not an error; it simply adds
	// nothing to walk through.
	c.OpenLine("linux", "amd64", "7")
	if again := c.Versions("linux", "amd64"); len(again) != len(want) {
		t.Fatalf("Versions = %v after opening a line that does not exist, want %v", again, want)
	}
}

// A migration floor is walked around by installing the releases in between —
// and finding them means seeing releases of a line the client has no other
// reason to load. A real repository delegates per release line, so the 1.x
// descriptors live in a metadata file a client resolving a 2.0.0 head never
// touches. This is the case a fake history cannot show.
func TestUpdateWalksAcrossReleaseLines(t *testing.T) {
	f := newFixture(t)
	publishRelease(f, "1.0.0", "", refTime)
	publishRelease(f, "1.5.0", "1.0.0", refTime.Add(time.Hour))
	publishRelease(f, "2.0.0", "1.5.0", refTime.Add(2*time.Hour))

	installRoot := filepath.Join(t.TempDir(), "install")
	at := refTime.Add(3 * time.Hour)
	if err := updateInstall(t, f, installRoot, "1.0.0", at); err != nil {
		t.Fatalf("update from 1.0.0 to the head: %v", err)
	}

	got, err := installer.InstalledVersion(installRoot)
	if err != nil {
		t.Fatalf("InstalledVersion: %v", err)
	}
	if got != "2.0.0" {
		t.Fatalf("installed %q, want 2.0.0", got)
	}
	// The release in between was really installed, not skipped: it is still on
	// disk as the rollback target the last step left behind.
	bridge, err := layout.VersionDir(installRoot, "1.5.0")
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	if _, err := os.Stat(bridge); err != nil {
		t.Fatalf("1.5.0 was never installed: %v", err)
	}
}
