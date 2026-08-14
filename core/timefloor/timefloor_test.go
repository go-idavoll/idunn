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

package timefloor_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/timefloor"
	"github.com/go-idavoll/idunn/internal/layout"
)

const root = "/opt/app"

var (
	built  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seen   = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	before = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
)

func newFS(t *testing.T) fsx.FS {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return m
}

// A fresh install of a binary that was built without a stamp has nothing to go
// on, and says so instead of inventing a floor.
func TestNoFloorYet(t *testing.T) {
	f := timefloor.Floor{FS: newFS(t), Root: root}

	got, err := f.KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.IsZero() {
		t.Errorf("KnownGood = %s, want the zero time", got)
	}
	if err := f.Check(before); err != nil {
		t.Errorf("Check with no floor = %v, want nil", err)
	}
}

// The build time is a floor on its own: a program cannot have been built after
// the moment it runs.
func TestBuildTimeIsAFloor(t *testing.T) {
	f := timefloor.Floor{FS: newFS(t), Root: root, BuildTime: built}

	got, err := f.KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(built) {
		t.Errorf("KnownGood = %s, want %s", got, built)
	}

	err = f.Check(before)
	if !errors.Is(err, timefloor.ErrClockRollback) {
		t.Fatalf("Check(before the build) = %v, want ErrClockRollback", err)
	}
	// The message has to be actionable: both times, so an operator can see what
	// to correct.
	for _, want := range []string{before.Format(time.RFC3339), built.Format(time.RFC3339)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %s", err, want)
		}
	}
	if err := f.Check(built.Add(time.Hour)); err != nil {
		t.Errorf("Check(after the build) = %v, want nil", err)
	}
}

// A clock exactly at the floor has not gone backwards.
func TestClockAtTheFloorIsAccepted(t *testing.T) {
	f := timefloor.Floor{FS: newFS(t), Root: root, BuildTime: built}
	if err := f.Check(built); err != nil {
		t.Errorf("Check(at the floor) = %v, want nil", err)
	}
}

// A refresh that succeeded is the other thing that establishes the floor, and it
// outlives the process.
func TestObservedTimePersists(t *testing.T) {
	fs := newFS(t)
	if err := (timefloor.Floor{FS: fs, Root: root}).Observe(seen); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// A second Floor value stands in for the next run of the client.
	next := timefloor.Floor{FS: fs, Root: root}
	got, err := next.KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(seen) {
		t.Errorf("KnownGood = %s, want %s", got, seen)
	}
	if err := next.Check(before); !errors.Is(err, timefloor.ErrClockRollback) {
		t.Fatalf("Check(rolled back) = %v, want ErrClockRollback", err)
	}
}

// The floor only ever rises. Recording a clock that went backwards would hand
// the attack the very thing it needs.
func TestObserveNeverLowersTheFloor(t *testing.T) {
	fs := newFS(t)
	f := timefloor.Floor{FS: fs, Root: root}

	if err := f.Observe(seen); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := f.Observe(before); err != nil {
		t.Fatalf("Observe(earlier): %v", err)
	}
	got, err := f.KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(seen) {
		t.Errorf("KnownGood = %s after observing an earlier time, want %s", got, seen)
	}
}

// The later of the two sources wins, whichever it is.
func TestBuildTimeAndObservedTimeCombine(t *testing.T) {
	fs := newFS(t)
	if err := (timefloor.Floor{FS: fs, Root: root}).Observe(seen); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// An older build with a newer observation keeps the observation ...
	got, err := (timefloor.Floor{FS: fs, Root: root, BuildTime: built}).KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(seen) {
		t.Errorf("KnownGood = %s, want %s", got, seen)
	}

	// ... and a newer build raises it, which is what a fresh binary installed
	// over an old state should do.
	newer := seen.AddDate(1, 0, 0)
	got, err = (timefloor.Floor{FS: fs, Root: root, BuildTime: newer}).KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(newer) {
		t.Errorf("KnownGood = %s, want %s", got, newer)
	}
}

// Sub-second precision is not meaningful for this and would make the file churn
// on every refresh.
func TestObservedTimeIsTruncatedToSeconds(t *testing.T) {
	fs := newFS(t)
	f := timefloor.Floor{FS: fs, Root: root}
	if err := f.Observe(seen.Add(750 * time.Millisecond)); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	got, err := f.KnownGood()
	if err != nil {
		t.Fatalf("KnownGood: %v", err)
	}
	if !got.Equal(seen) {
		t.Errorf("KnownGood = %s, want %s", got, seen)
	}
}

// The floor lives with the installation, not with the disposable TUF cache.
func TestFloorLivesInTheInstallRoot(t *testing.T) {
	fs := newFS(t)
	if err := (timefloor.Floor{FS: fs, Root: root}).Observe(seen); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if _, err := fs.Stat(layout.Clock(root)); err != nil {
		t.Fatalf("the floor is not at %s: %v", layout.Clock(root), err)
	}
}

// A floor file that cannot be understood is a refusal, not "no floor". A defence
// that disappears when its own state is damaged is not a defence.
func TestUnreadableFloorIsRefused(t *testing.T) {
	tests := []struct{ name, body string }{
		{"not json", "{"},
		{"unknown schema", `{"schema_version": 99, "known_good": "2026-06-01T12:00:00Z"}`},
		{"no known_good", `{"schema_version": 1}`},
		{"zero known_good", `{"schema_version": 1, "known_good": "0001-01-01T00:00:00Z"}`},
		{"unknown field", `{"schema_version": 1, "known_good": "2026-06-01T12:00:00Z", "override": true}`},
		{"trailing data", `{"schema_version": 1, "known_good": "2026-06-01T12:00:00Z"}{}`},
		{"not a time", `{"schema_version": 1, "known_good": "yesterday"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newFS(t)
			if err := fs.MkdirAll(layout.Meta(root), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := fsx.WriteFileAtomic(fs, layout.Clock(root), []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			f := timefloor.Floor{FS: fs, Root: root}

			if _, err := f.KnownGood(); !errors.Is(err, timefloor.ErrFloor) {
				t.Errorf("KnownGood err = %v, want ErrFloor", err)
			}
			// And the refusal propagates to both callers, so a damaged file
			// cannot be walked past by either.
			if err := f.Check(seen); !errors.Is(err, timefloor.ErrFloor) {
				t.Errorf("Check err = %v, want ErrFloor", err)
			}
			if err := f.Observe(seen); !errors.Is(err, timefloor.ErrFloor) {
				t.Errorf("Observe err = %v, want ErrFloor", err)
			}
		})
	}
}

// A floor that cannot be written is reported, not swallowed: the caller decides
// what a machine that cannot record where it has been should do.
func TestUnwritableFloorIsReported(t *testing.T) {
	fs := newFS(t)
	// A regular file where idunn's state directory belongs.
	if err := fsx.WriteFileAtomic(fs, layout.Meta(root), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (timefloor.Floor{FS: fs, Root: root}).Observe(seen); !errors.Is(err, timefloor.ErrFloor) {
		t.Fatalf("Observe err = %v, want ErrFloor", err)
	}
}

// A Floor with nowhere to persist is a configuration error, not a silently
// disabled check.
func TestNoFilesystemIsAnError(t *testing.T) {
	f := timefloor.Floor{Root: root}
	if _, err := f.KnownGood(); !errors.Is(err, timefloor.ErrFloor) {
		t.Errorf("KnownGood err = %v, want ErrFloor", err)
	}
	if err := f.Check(seen); !errors.Is(err, timefloor.ErrFloor) {
		t.Errorf("Check err = %v, want ErrFloor", err)
	}
	if err := f.Observe(seen); !errors.Is(err, timefloor.ErrFloor) {
		t.Errorf("Observe err = %v, want ErrFloor", err)
	}
}

// The whole scenario, in the order it happens: a client runs, records where it
// has been, and then the clock is turned back to make expired metadata look
// fresh again. The second run refuses before it looks at any metadata at all.
func TestClockRollbackBetweenRunsIsRefused(t *testing.T) {
	fs := newFS(t)
	f := timefloor.Floor{FS: fs, Root: root, BuildTime: built}

	if err := f.Check(seen); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := f.Observe(seen); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	rolledBack := seen.AddDate(0, -2, 0)
	err := f.Check(rolledBack)
	if !errors.Is(err, timefloor.ErrClockRollback) {
		t.Fatalf("second run with a rolled-back clock = %v, want ErrClockRollback", err)
	}
}
