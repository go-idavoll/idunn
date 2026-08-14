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
	"errors"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/timefloor"
	"github.com/go-idavoll/idunn/internal/layout"
)

// The clock the fixture runs at, and a build stamped after it: the shape of a
// machine whose clock has been turned back.
func rolledBackFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.BuildTime = f.opts.Now().AddDate(0, 1, 0)
	return f
}

// A clock below the floor is refused before the metadata that depends on it is
// fetched. The order is the point: expiry is judged against this clock, so a
// refresh performed first would already have been judged wrongly (§14.7, T22).
func TestCheckForUpdateRefusesAClockBelowTheFloor(t *testing.T) {
	f := rolledBackFixture(t)

	_, err := f.updater().CheckForUpdate(context.Background())
	if !errors.Is(err, timefloor.ErrClockRollback) {
		t.Fatalf("err = %v, want ErrClockRollback", err)
	}
	if f.trust.refreshes != 0 {
		t.Errorf("TUF was refreshed %d times although the clock was refused", f.trust.refreshes)
	}
	if len(f.trust.asked) != 0 {
		t.Errorf("a release was resolved although the clock was refused: %v", f.trust.asked)
	}
}

// The refusal reaches the UI: a check that fails on the clock emits a failure
// event carrying the error, which is where the "your clock looks wrong" message
// comes from rather than a bare "update failed" (§14.7).
func TestClockRollbackReachesTheObserver(t *testing.T) {
	f := rolledBackFixture(t)

	r, err := f.updater().CheckForUpdate(context.Background())
	if err == nil {
		t.Fatal("CheckForUpdate reported success")
	}
	if r != nil {
		t.Fatal("a release was offered")
	}
	var reported error
	for _, e := range f.hooks.events {
		if e.Err != nil {
			reported = e.Err
		}
	}
	if !errors.Is(reported, timefloor.ErrClockRollback) {
		t.Fatalf("the observer saw %v, want the clock rollback", reported)
	}
}

// A successful refresh is what raises the floor: the machine has been at this
// local time with a repository it trusts answering.
func TestSuccessfulCheckAdvancesTheFloor(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	now := f.opts.Now()

	if _, err := f.updater().CheckForUpdate(context.Background()); err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}

	floor := timefloor.Floor{FS: f.fs, Root: root}
	got, err := floor.KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(now.UTC().Truncate(time.Second)) {
		t.Errorf("floor = %s, want %s", got, now.UTC())
	}
	if _, err := f.fs.Stat(layout.Clock(root)); err != nil {
		t.Errorf("the floor was not persisted: %v", err)
	}
}

// Apply does not refresh metadata, so it checks the clock itself. An update
// resolved honestly and applied after the clock was turned back is the same
// rollback attack with an extra step.
func TestApplyRefusesAClockBelowTheFloor(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")

	r, err := f.updater().CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}

	// The clock goes back between resolving and applying.
	rolled := f.opts.Now().AddDate(0, -1, 0)
	f.opts.Now = func() time.Time { return rolled }

	if err := f.updater().Apply(context.Background(), r); !errors.Is(err, timefloor.ErrClockRollback) {
		t.Fatalf("Apply err = %v, want ErrClockRollback", err)
	}
	// It reaches a publisher as clock_skew, not as a verification failure: it
	// is the one failure in this area a user can usually fix themselves.
	if len(f.hooks.outcomes) == 0 {
		t.Fatal("no outcome was reported")
	}
	if got := f.hooks.outcomes[0].ErrorClass; got != "clock_skew" {
		t.Errorf("error class = %q, want clock_skew", got)
	}
	// And the install is untouched: the refusal happens before the transaction
	// opens.
	installed, err := layout.PointerTarget(f.fs, root)
	if err != nil {
		t.Fatalf("PointerTarget: %v", err)
	}
	if installed != "1.2.0" {
		t.Errorf("installed %q, want the untouched 1.2.0", installed)
	}
}

// A client built without a stamp, on a root with no recorded floor, has nothing
// to check against and must not invent one. This is the ordinary first run.
func TestNoFloorDoesNotBlockAnything(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.BuildTime = time.Time{}

	if _, err := f.updater().CheckForUpdate(context.Background()); err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}
}
