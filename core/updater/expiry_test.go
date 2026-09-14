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

package updater_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/test/redteam/harness"
)

// Expired TUF metadata is refused through the updater, with no policy switch in
// the way (IDN-15).
//
// Policy once carried an EnforceExpiry flag that New forced to true. It was
// removed because it governed nothing: the check is go-tuf's, during Refresh.
// This test is what makes the removal safe to believe. It drives the real trust
// client against a real, signed repository — not the fake the other tests use,
// which cannot expire — and gives the updater the most permissive policy there
// is, so that if anything above go-tuf could relax expiry, this is where it would
// show.
func TestExpiredMetadataIsRefusedThroughTheUpdater(t *testing.T) {
	keys, err := harness.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	opts := harness.DefaultBuildOptions(keys)
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "repo")
	build, err := harness.BuildRepo(repoDir, opts)
	if err != nil {
		t.Fatalf("build repository: %v", err)
	}
	srv := harness.Serve(repoDir)
	t.Cleanup(srv.Close)

	check := func(t *testing.T, at time.Time) (*updater.Release, string, error) {
		t.Helper()
		work := t.TempDir()
		c, err := trust.New(trust.Options{
			Root:        build.RootBytes,
			MetadataURL: srv.MetadataURL(),
			TargetsURL:  srv.TargetsURL(),
			LocalDir:    filepath.Join(work, "cache"),
			Now:         func() time.Time { return at },
		})
		if err != nil {
			t.Fatalf("trust.New: %v", err)
		}
		// Expiry is judged against this time, never the wall clock.
		c.UnsafeSetRefTime(at)

		installRoot := filepath.Join(work, "install")
		u, err := updater.New(updater.Options{
			Trust:   c,
			FS:      fsx.OS(),
			Root:    installRoot,
			Channel: opts.Channel,
			OS:      opts.OS,
			Arch:    opts.Arch,
			Now:     func() time.Time { return at },
			Policy: updater.Policy{
				AllowDowngrade: true,
				OnBusy:         updater.BusyForce,
			},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		r, err := u.CheckForUpdate(context.Background())
		return r, installRoot, err
	}

	// The control: inside the validity window the same repository, client and
	// policy offer the release. Without it the refusal below could be for any
	// reason at all.
	t.Run("fresh", func(t *testing.T) {
		r, _, err := check(t, opts.Now.Add(time.Hour))
		if err != nil {
			t.Fatalf("CheckForUpdate inside the validity window: %v", err)
		}
		if r == nil || r.Descriptor.Version != opts.Version {
			t.Fatalf("release = %+v, want %s offered", r, opts.Version)
		}
	})

	// A month later the timestamp role has long expired.
	t.Run("expired", func(t *testing.T) {
		r, installRoot, err := check(t, opts.Now.AddDate(0, 0, 30))
		if err == nil {
			t.Fatalf("expired metadata was accepted; release = %+v", r)
		}
		if r != nil {
			t.Errorf("a release was offered alongside the error: %+v", r)
		}
		if !trust.IsExpiry(err) {
			t.Errorf("err = %v, want an expiry error from the trust layer", err)
		}
		if entries, err := os.ReadDir(installRoot); err == nil && len(entries) != 0 {
			t.Errorf("a refused check left %d entries in the install root", len(entries))
		}
	})
}
