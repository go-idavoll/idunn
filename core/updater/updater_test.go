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

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
)

// The trust client must satisfy the interface the updater consumes. If it stops
// doing so, the tests below go on passing against a fake that no longer resembles
// anything real.
var _ updater.Resolver = (*trust.Client)(nil)

func TestNewRejectsAnUnusableConfiguration(t *testing.T) {
	base := func() updater.Options {
		return updater.Options{
			Trust:   &fakeTrust{},
			FS:      fsx.NewMem(),
			Root:    root,
			Channel: channel,
		}
	}
	for _, tc := range []struct {
		name    string
		breakIt func(o *updater.Options)
	}{
		{"no trust client", func(o *updater.Options) { o.Trust = nil }},
		{"no filesystem", func(o *updater.Options) { o.FS = nil }},
		{"no root", func(o *updater.Options) { o.Root = "" }},
		{"no channel", func(o *updater.Options) { o.Channel = "" }},
		{"retention leaves no rollback target", func(o *updater.Options) { o.Policy.RetainVersions = 1 }},
		{"negative quiesce timeout", func(o *updater.Options) { o.Policy.QuiesceTimeout = -time.Second }},
		{"unknown busy policy", func(o *updater.Options) { o.Policy.OnBusy = updater.BusyPolicy(99) }},
		{"unknown elevation mode", func(o *updater.Options) { o.Policy.Elevation = updater.ElevationMode(99) }},
		{"elevation without an elevator", func(o *updater.Options) {
			o.Policy.Elevation = updater.ElevationService
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			tc.breakIt(&o)
			if _, err := updater.New(o); err == nil {
				t.Fatal("an unusable configuration was accepted")
			} else if !errors.Is(err, updater.ErrConfig) {
				t.Fatalf("error %v is not classified as ErrConfig", err)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	u := f.updater()
	if u.Root() != root {
		t.Fatalf("Root = %q, want %q", u.Root(), root)
	}

	// The defaults have to be the safe ones, because the zero value is what a
	// host that thinks about none of this will get.
	f.opts.Policy = updater.Policy{}
	if _, err := updater.New(f.opts); err != nil {
		t.Fatalf("the zero policy was rejected: %v", err)
	}
}

func TestCheckForUpdateFindsAnUpdate(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	r, err := f.updater().CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}
	if r == nil {
		t.Fatal("no update was offered")
	}
	if r.Descriptor.Version != "1.3.0" || r.FromVersion != "1.2.0" {
		t.Fatalf("release = %s from %s, want 1.3.0 from 1.2.0", r.Descriptor.Version, r.FromVersion)
	}
	if f.trust.refreshes != 1 {
		t.Fatalf("TUF refreshed %d times, want once before anything is resolved", f.trust.refreshes)
	}
	if len(f.trust.asked) != 1 || f.trust.asked[0] != "stable/linux-amd64" {
		t.Fatalf("resolved %v, want the configured channel and platform", f.trust.asked)
	}
}

func TestCheckForUpdateWhenUpToDate(t *testing.T) {
	f := newFixture(t, "1.3.0", "1.3.0")
	r, err := f.updater().CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}
	if r != nil {
		t.Fatalf("an update was offered although %s is installed", r.Descriptor.Version)
	}
}

func TestCheckForUpdateOnAnEmptyRoot(t *testing.T) {
	f := newFixture(t, "", "1.0.0")
	r, err := f.updater().CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}
	if r == nil || r.FromVersion != "" {
		t.Fatalf("release = %+v, want a first install", r)
	}
}

// A trust failure is a trust failure: nothing downstream may reinterpret it, and
// nothing may proceed on the strength of a refresh that did not happen.
func TestCheckForUpdatePropagatesTrustFailures(t *testing.T) {
	t.Run("refresh", func(t *testing.T) {
		f := newFixture(t, "1.2.0", "1.3.0")
		f.trust.refreshErr = errors.New("timestamp expired")
		if _, err := f.updater().CheckForUpdate(context.Background()); err == nil {
			t.Fatal("a failed refresh was reported as no update")
		}
		if len(f.trust.asked) != 0 {
			t.Fatal("a release was resolved although the refresh failed")
		}
	})

	t.Run("resolve", func(t *testing.T) {
		f := newFixture(t, "1.2.0", "1.3.0")
		f.trust.latestErr = errors.New("no such target")
		if _, err := f.updater().CheckForUpdate(context.Background()); err == nil {
			t.Fatal("an unresolvable channel was reported as no update")
		}
	})
}

// The app-level floors sit on top of TUF's rollback protection and answer a
// different question: whether THIS install may make THIS jump.
func TestCheckForUpdateEnforcesPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed string
		offers    string
		adjust    func(f *fixture)
		wantErr   bool
		wantOffer bool
	}{
		{
			name: "a downgrade is refused", installed: "1.3.0", offers: "1.2.0", wantErr: true,
		},
		{
			name:      "a downgrade is allowed when the policy says so",
			installed: "1.3.0", offers: "1.2.0",
			adjust:    func(f *fixture) { f.opts.Policy.AllowDowngrade = true },
			wantOffer: true,
		},
		{
			name:      "an install below the migration floor is refused",
			installed: "1.0.0", offers: "1.3.0",
			adjust: func(f *fixture) {
				f.trust.descriptor.Requirements.MinFromVersion = "1.2.0"
			},
			wantErr: true,
		},
		{
			name:      "an install at the migration floor is accepted",
			installed: "1.2.0", offers: "1.3.0",
			adjust: func(f *fixture) {
				f.trust.descriptor.Requirements.MinFromVersion = "1.2.0"
			},
			wantOffer: true,
		},
		{
			name:      "a client older than the release requires is refused",
			installed: "1.2.0", offers: "1.3.0",
			adjust: func(f *fixture) {
				f.trust.descriptor.Requirements.MinClientVersion = "2.0.0"
				f.opts.ClientVersion = "1.9.0"
			},
			wantErr: true,
		},
		{
			name:      "a client that does not state its version is refused when one is required",
			installed: "1.2.0", offers: "1.3.0",
			adjust: func(f *fixture) {
				f.trust.descriptor.Requirements.MinClientVersion = "2.0.0"
			},
			wantErr: true,
		},
		{
			name:      "a new enough client is accepted",
			installed: "1.2.0", offers: "1.3.0",
			adjust: func(f *fixture) {
				f.trust.descriptor.Requirements.MinClientVersion = "2.0.0"
				f.opts.ClientVersion = "2.1.0"
			},
			wantOffer: true,
		},
		{
			name:      "a descriptor for another channel is refused",
			installed: "1.2.0", offers: "1.3.0",
			adjust:  func(f *fixture) { f.trust.descriptor.Channel = "beta" },
			wantErr: true,
		},
		{
			name:      "a descriptor for another platform is refused",
			installed: "1.2.0", offers: "1.3.0",
			adjust:  func(f *fixture) { f.trust.descriptor.Arch = "arm64" },
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.installed, tc.offers)
			if tc.adjust != nil {
				tc.adjust(f)
			}
			r, err := f.updater().CheckForUpdate(context.Background())
			switch {
			case tc.wantErr && err == nil:
				t.Fatal("the release was accepted")
			case !tc.wantErr && err != nil:
				t.Fatalf("the release was refused: %v", err)
			}
			if tc.wantOffer && r == nil {
				t.Fatal("no release was offered")
			}
			if err != nil && !errors.Is(err, updater.ErrPolicy) {
				t.Fatalf("error %v is not classified as ErrPolicy", err)
			}
		})
	}
}

// A staged rollout is decided locally: the identifier never leaves the machine,
// only the bucket it lands in decides (§14.5).
func TestCheckForUpdateHonoursStagedRollout(t *testing.T) {
	// Find two identifiers that land on opposite sides of a 50% rollout, so the
	// test asserts both answers rather than whichever one this build produces.
	var inCohort, outOfCohort string
	for i := 0; i < 100 && (inCohort == "" || outOfCohort == ""); i++ {
		id := string(rune('a'+i%26)) + string(rune('0'+i/26))
		f := newFixture(t, "1.2.0", "1.3.0")
		f.trust.descriptor.Rollout = 0.5
		f.opts.ClientID = id
		r, err := f.updater().CheckForUpdate(context.Background())
		if err != nil {
			t.Fatalf("CheckForUpdate: %v", err)
		}
		if r != nil && inCohort == "" {
			inCohort = id
		}
		if r == nil && outOfCohort == "" {
			outOfCohort = id
		}
	}
	if inCohort == "" || outOfCohort == "" {
		t.Fatal("a 50% rollout put every identifier on the same side")
	}

	// The same identifier must land in the same bucket every time, or a client
	// would take a canary and then be offered it again.
	for i := 0; i < 3; i++ {
		f := newFixture(t, "1.2.0", "1.3.0")
		f.trust.descriptor.Rollout = 0.5
		f.opts.ClientID = outOfCohort
		r, err := f.updater().CheckForUpdate(context.Background())
		if err != nil {
			t.Fatalf("CheckForUpdate: %v", err)
		}
		if r != nil {
			t.Fatal("the same identifier changed cohort between checks")
		}
	}
}

func TestRolloutEdges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rollout   float64
		clientID  string
		wantOffer bool
	}{
		{"no rollout means everyone", 0, "some-client", true},
		{"a full rollout means everyone", 1, "some-client", true},
		{"a partial rollout without an identifier means nobody", 0.5, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			f.trust.descriptor.Rollout = tc.rollout
			f.opts.ClientID = tc.clientID
			r, err := f.updater().CheckForUpdate(context.Background())
			if err != nil {
				t.Fatalf("CheckForUpdate: %v", err)
			}
			if (r != nil) != tc.wantOffer {
				t.Fatalf("offered = %v, want %v", r != nil, tc.wantOffer)
			}
		})
	}
}

func TestCheckForUpdateHonoursCancellation(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := f.updater().CheckForUpdate(ctx); err == nil {
		t.Fatal("a cancelled check went ahead")
	}
	if f.trust.refreshes != 0 {
		t.Fatal("a cancelled check still went to the network")
	}
}

// The elevator is the design's privilege boundary. The updater's job is to route
// to it, not to decide anything on its behalf.
func TestApplyRoutesThroughTheElevator(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	el := &fakeElevator{}
	f.opts.Elevator = el
	f.opts.Policy.Elevation = updater.ElevationService

	// The elevated helper does the swap; here it only records the request, so
	// the pointer stays where it was and the transaction rolls back. What is
	// asserted is the delegation itself.
	_ = f.run()
	if el.calls != 1 {
		t.Fatalf("the elevator was called %d times, want once", el.calls)
	}
	if el.seen != root+"@1.3.0" {
		t.Fatalf("the elevator was asked for %q", el.seen)
	}
}

var _ elevate.Elevator = (*fakeElevator)(nil)

// Descriptors reach the updater only after core/release has accepted them, so a
// version it could not order can never get this far. The check is still here,
// because "it cannot happen" is not a reason to compute an answer.
func TestApplyRejectsNothingToApply(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	u := f.updater()

	if err := u.Apply(context.Background(), nil); err == nil {
		t.Fatal("Apply accepted a nil release")
	}
	if err := u.Apply(context.Background(), &updater.Release{}); err == nil {
		t.Fatal("Apply accepted a release with no descriptor")
	}
}

func TestReleaseCarriesTheDescriptor(t *testing.T) {
	d := descriptor("1.3.0", ref("targets/app", "app"))
	r := updater.Release{Descriptor: d, FromVersion: "1.2.0"}
	if r.Descriptor.Name != appName || r.FromVersion != "1.2.0" {
		t.Fatalf("release = %+v", r)
	}
}
