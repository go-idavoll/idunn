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
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

func (f *fixture) probation() *layout.Probation {
	f.t.Helper()
	p, err := layout.ReadProbation(f.fs, root)
	if err != nil {
		f.t.Fatalf("ReadProbation: %v", err)
	}
	return p
}

func TestProbationPolicyIsValidated(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    updater.Policy
	}{
		{"negative attempts", updater.Policy{Probation: updater.ProbationPolicy{Attempts: -1}}},
		{"too many attempts", updater.Policy{Probation: updater.ProbationPolicy{Attempts: layout.MaxProbationAttempts + 1}}},
		{"negative restarts", updater.Policy{Probation: updater.ProbationPolicy{Attempts: 3, Restarts: -1}}},
		{"too many restarts", updater.Policy{Probation: updater.ProbationPolicy{Attempts: 3, Restarts: layout.MaxProbationRestarts + 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			f.opts.Policy = tc.p
			if _, err := updater.New(f.opts); !errors.Is(err, updater.ErrConfig) {
				t.Fatalf("New = %v, want ErrConfig", err)
			}
		})
	}

	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Policy.Probation = updater.ProbationPolicy{Attempts: 3}
	f.opts.Policy.Elevation = updater.ElevationService
	f.opts.Elevator = &fakeElevator{}
	if _, err := updater.New(f.opts); !errors.Is(err, updater.ErrConfig) {
		t.Fatalf("New with probation for an elevated root = %v, want ErrConfig", err)
	}
}

func TestApplyWithoutProbationLeavesNoRecord(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if p := f.probation(); p != nil {
		t.Fatalf("probation record %+v without a probation policy", p)
	}
}

func TestApplyPutsTheNewVersionOnProbation(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Policy.Probation = updater.ProbationPolicy{Attempts: 3}
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	p := f.probation()
	want := layout.Probation{
		SchemaVersion: layout.ProbationSchema, Version: "1.3.0", Previous: "1.2.0",
		Status: layout.ProbationActive, AttemptsAllowed: 3, RestartsAllowed: updater.DefaultProbationRestarts,
	}
	if p == nil || *p != want {
		t.Fatalf("probation = %+v, want %+v", p, want)
	}
}

// A first install has nothing to return to, so nothing is put on probation.
func TestFirstInstallIsNotOnProbation(t *testing.T) {
	f := newFixture(t, "", "1.3.0")
	f.opts.Policy.Probation = updater.ProbationPolicy{Attempts: 3}
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if p := f.probation(); p != nil {
		t.Fatalf("probation record %+v after a first install", p)
	}
}

// The whole cycle: an update that never confirms is rolled back by the
// launcher, the updater does not offer it again, and the next release it does.
func TestAnUnconfirmedUpdateIsRolledBackAndNotOfferedAgain(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Policy.Probation = updater.ProbationPolicy{Attempts: 2}
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	start := func() launch.Result {
		t.Helper()
		res, err := launch.Start(context.Background(), launch.Options{FS: f.fs, Root: root, Migrate: f.hooks})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		return res
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if res := start(); res.Probation.Attempt != attempt || res.Probation.Reverted {
			t.Fatalf("start %d: probation = %+v", attempt, res.Probation)
		}
	}
	res := start()
	if !res.Probation.Reverted || res.Probation.To != "1.2.0" {
		t.Fatalf("third start: probation = %+v, want a rollback to 1.2.0", res.Probation)
	}
	if f.pointer() != "1.2.0" || f.stateVersion() != "1.2.0" {
		t.Fatalf("after the rollback current = %s, state = %s", f.pointer(), f.stateVersion())
	}
	if f.hostState() != "1.2.0" {
		t.Fatalf("host state = %q, want the migration undone", f.hostState())
	}

	u := f.updater()
	r, err := u.CheckForUpdate(context.Background())
	if err != nil || r != nil {
		t.Fatalf("CheckForUpdate after the rollback = %v, %v; want nothing offered", r, err)
	}
	// Asked for explicitly, it is refused.
	err = u.Apply(context.Background(), &updater.Release{Descriptor: f.trust.descriptor, FromVersion: "1.2.0"})
	if !errors.Is(err, updater.ErrBlocked) || !errors.Is(err, updater.ErrPolicy) {
		t.Fatalf("Apply of the rolled-back release = %v, want ErrBlocked", err)
	}

	f.trust.descriptor = descriptor("1.4.0", ref("targets/app", "app"))
	f.trust.targets["targets/app"] = []byte("binary 1.4.0")
	if err := f.run(); err != nil {
		t.Fatalf("Apply 1.4.0: %v", err)
	}
	p := f.probation()
	if p.Version != "1.4.0" || p.Previous != "1.2.0" || p.Blocked == nil || p.Blocked.Version != "1.3.0" {
		t.Fatalf("probation after 1.4.0 = %+v, want 1.4.0 on probation and 1.3.0 still blocked", p)
	}
}

// A rollback the launcher has not finished is what makes it finish; an update
// that replaced its record would turn it into a half-done one.
func TestApplyWaitsForAnUnfinishedRollback(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Policy.Probation = updater.ProbationPolicy{Attempts: 3}
	if err := layout.WriteProbation(f.fs, root, layout.Probation{
		Version: "1.2.5", Previous: "1.2.0", Status: layout.ProbationReverting, AttemptsAllowed: 3, Reason: "broken",
	}); err != nil {
		t.Fatal(err)
	}
	err := f.run()
	if !errors.Is(err, updater.ErrStale) || !strings.Contains(err.Error(), "not finished") {
		t.Fatalf("Apply = %v, want a refusal naming the unfinished rollback", err)
	}
	if f.pointer() != "1.2.0" || f.probation().Status != layout.ProbationReverting {
		t.Fatalf("the refused update changed something: current %s, probation %+v", f.pointer(), f.probation())
	}
}

func TestAnUnreadableProbationRecordFailsTheCheck(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	if err := f.fs.MkdirAll(layout.Meta(root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(f.fs, layout.ProbationFile(root), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.updater().CheckForUpdate(context.Background()); !errors.Is(err, layout.ErrLayout) {
		t.Fatalf("CheckForUpdate = %v, want the record refused", err)
	}
}

// --- the release's own policy ------------------------------------------------

func releasePolicy(version string, attempts, restarts int) *release.Policy {
	return &release.Policy{
		SchemaVersion: release.SchemaVersion, Name: appName, Version: version, OS: "linux", Arch: "amd64",
		Probation: &release.ProbationPolicy{Attempts: attempts, Restarts: restarts},
	}
}

func TestFollowingReleasesTakesTheReleasesAllowance(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		host                   updater.ProbationPolicy
		policy                 *release.Policy
		wantAttempts, restarts int // wantAttempts 0: no record at all
	}{
		{"release states it", updater.ProbationPolicy{FollowRelease: true, Attempts: 2}, releasePolicy("1.3.0", 5, 4), 5, 4},
		{"release keeps the host's restarts", updater.ProbationPolicy{FollowRelease: true, Restarts: 6}, releasePolicy("1.3.0", 5, 0), 5, 6},
		{"release turns it off", updater.ProbationPolicy{FollowRelease: true, Attempts: 2}, releasePolicy("1.3.0", 0, 0), 0, 0},
		{"release states nothing", updater.ProbationPolicy{FollowRelease: true, Attempts: 2}, nil, 2, updater.DefaultProbationRestarts},
		{"release without probation", updater.ProbationPolicy{FollowRelease: true, Attempts: 2},
			&release.Policy{SchemaVersion: 1, Name: appName, Version: "1.3.0", OS: "linux", Arch: "amd64"}, 2, updater.DefaultProbationRestarts},
		{"nothing anywhere", updater.ProbationPolicy{FollowRelease: true}, nil, 0, 0},
		// A host that does not follow releases is not put on probation by one.
		{"host does not follow", updater.ProbationPolicy{}, releasePolicy("1.3.0", 5, 4), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			f.opts.Policy.Probation = tc.host
			if tc.policy != nil {
				f.trust.policies = map[string]*release.Policy{"1.3.0": tc.policy}
			}
			if err := f.run(); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			p := f.probation()
			if tc.wantAttempts == 0 {
				if p != nil {
					t.Fatalf("probation = %+v, want no record", p)
				}
				return
			}
			if p == nil || p.AttemptsAllowed != tc.wantAttempts || p.RestartsAllowed != tc.restarts {
				t.Fatalf("probation = %+v, want %d attempts and %d restarts", p, tc.wantAttempts, tc.restarts)
			}
		})
	}
}

// A policy the release publishes and that cannot be resolved stops the update
// before anything is written: installing without the probation the publisher
// asked for would decide on less than the signed metadata says.
func TestAnUnresolvablePolicyFailsTheUpdate(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Policy.Probation = updater.ProbationPolicy{FollowRelease: true, Attempts: 2}
	f.trust.policyErr = trust.ErrTrust
	if err := f.run(); !errors.Is(err, trust.ErrTrust) {
		t.Fatalf("Apply = %v, want the policy error", err)
	}
	if f.pointer() != "1.2.0" || f.probation() != nil || journalState(t, f) != "" {
		t.Fatalf("the refused update left traces: current %s, probation %+v, journal %q", f.pointer(), f.probation(), journalState(t, f))
	}
}

type resolverWithoutPolicies struct{ updater.Resolver }

func TestFollowingReleasesNeedsAPolicyResolver(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Trust = resolverWithoutPolicies{f.trust}
	f.opts.Policy.Probation = updater.ProbationPolicy{FollowRelease: true}
	if _, err := updater.New(f.opts); !errors.Is(err, updater.ErrConfig) {
		t.Fatalf("New = %v, want ErrConfig", err)
	}
}
