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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/timefloor"
	"github.com/go-idavoll/idunn/internal/layout"
)

// A first install has usually never seen metadata, so the build time is the
// whole of its floor — and it is enough to catch the clock that matters here: a
// machine set back far enough to make an old, expired repository look current.
func TestInstallRefusesAClockBelowTheBuildTime(t *testing.T) {
	f := newFixture(t, "1.2.0")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.opts.Updater.Now = func() time.Time { return now }
	f.opts.Updater.BuildTime = now.AddDate(0, 1, 0)

	err := installer.Install(context.Background(), f.opts)
	if !errors.Is(err, timefloor.ErrClockRollback) {
		t.Fatalf("err = %v, want ErrClockRollback", err)
	}
	if f.trust.refreshes != 0 {
		t.Errorf("TUF was refreshed %d times although the clock was refused", f.trust.refreshes)
	}
	if entries, err := f.fs.ReadDir(root); err == nil && len(entries) != 0 {
		t.Errorf("a refused install left %d entries in the root", len(entries))
	}
}

// An install that has nothing to do still saw valid metadata, and still records
// where it has been. Otherwise a machine that is already up to date would never
// raise its floor.
func TestUpToDateInstallStillAdvancesTheFloor(t *testing.T) {
	f := newFixture(t, "1.2.0")
	f.installed("1.2.0", release.LayoutSchema)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.opts.Updater.Now = func() time.Time { return now }

	if err := installer.Install(context.Background(), f.opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := (timefloor.Floor{FS: f.fs, Root: root}).KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(now) {
		t.Errorf("floor = %s, want %s", got, now)
	}
}

// A successful install records where it has been, so the next run has a floor
// even though this one had none.
func TestInstallAdvancesTheFloor(t *testing.T) {
	f := newFixture(t, "1.2.0")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.opts.Updater.Now = func() time.Time { return now }

	if err := installer.Install(context.Background(), f.opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := (timefloor.Floor{FS: f.fs, Root: root}).KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(now) {
		t.Errorf("floor = %s, want %s", got, now)
	}
	if _, err := f.fs.Stat(layout.Clock(root)); err != nil {
		t.Errorf("the floor was not persisted: %v", err)
	}
}
