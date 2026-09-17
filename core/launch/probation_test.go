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

package launch_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/internal/layout"
)

// onProbation is 1.3.0 installed over 1.2.0 and on probation with attempts.
func onProbation(t *testing.T, attempts int) *fsx.Mem {
	t.Helper()
	m := tree(t, []string{"1.2.0", "1.3.0"}, "1.3.0")
	writeProbation(t, m, layout.Probation{
		Version: "1.3.0", Previous: "1.2.0", Status: layout.ProbationActive,
		AttemptsAllowed: attempts, RestartsAllowed: 2,
	})
	return m
}

func writeProbation(t *testing.T, m fsx.FS, p layout.Probation) {
	t.Helper()
	if err := layout.WriteProbation(m, root, p); err != nil {
		t.Fatal(err)
	}
}

func readProbation(t *testing.T, m fsx.FS) *layout.Probation {
	t.Helper()
	p, err := layout.ReadProbation(m, root)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func startProbation(t *testing.T, o launch.Options) launch.Result {
	t.Helper()
	if o.Root == "" {
		o.Root = root
	}
	res, err := launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Probation.Err != nil {
		t.Fatalf("Start: probation: %v", res.Probation.Err)
	}
	return res
}

func installedState(t *testing.T, m fsx.FS) string {
	t.Helper()
	in, err := layout.ReadInstall(m, root)
	if err != nil || in == nil {
		t.Fatalf("ReadInstall = %+v, %v", in, err)
	}
	return in.Version
}

func TestAStartWithoutProbationCountsNothing(t *testing.T) {
	m := tree(t, []string{"1.2.0"}, "1.2.0")
	if res := startProbation(t, launch.Options{FS: m}); res.Probation != (launch.ProbationResult{}) {
		t.Fatalf("probation = %+v, want nothing", res.Probation)
	}
}

func TestEveryStartCountsAnAttemptAndTheOneBeyondRollsBack(t *testing.T) {
	m := onProbation(t, 2)
	mig := &migrator{fs: m}
	ev := &events{}
	o := launch.Options{FS: m, Migrate: mig, Observe: ev}

	for attempt := 1; attempt <= 2; attempt++ {
		res := startProbation(t, o)
		if res.Probation.Version != "1.3.0" || res.Probation.Attempt != attempt || res.Probation.Reverted {
			t.Fatalf("start %d: %+v", attempt, res.Probation)
		}
		if got := readProbation(t, m).Attempts; got != attempt {
			t.Fatalf("start %d recorded %d attempts", attempt, got)
		}
	}

	res := startProbation(t, o)
	pr := res.Probation
	if !pr.Reverted || pr.To != "1.2.0" || pr.Reason != "not confirmed healthy after 2 starts" {
		t.Fatalf("third start: %+v, want a rollback to 1.2.0", pr)
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Errorf("current = %s, want 1.2.0", got)
	}
	if got := installedState(t, m); got != "1.2.0" {
		t.Errorf("install state = %s, want 1.2.0", got)
	}
	if mig.rolled != 1 {
		t.Errorf("the host's rollback ran %d times, want once", mig.rolled)
	}
	if _, err := m.Stat(root + "/versions/1.3.0"); !fsx.IsNotExist(err) {
		t.Errorf("the rolled-back version is still there: %v", err)
	}
	p := readProbation(t, m)
	if p.Status != layout.ProbationReverted || p.Blocked == nil || p.Blocked.Version != "1.3.0" || p.Blocked.Reason != pr.Reason {
		t.Errorf("record after the rollback = %+v", p)
	}
	if !strings.Contains(eventText(ev), "rolled back 1.3.0 to 1.2.0") {
		t.Errorf("no rollback event among %q", eventText(ev))
	}

	// The version rolled back to is not on probation: later starts count nothing.
	if res := startProbation(t, o); res.Probation != (launch.ProbationResult{}) {
		t.Fatalf("start after the rollback: %+v", res.Probation)
	}
}

func eventText(ev *events) string {
	var b strings.Builder
	for _, e := range ev.seen {
		b.WriteString(e.Message + "\n")
	}
	return b.String()
}

func TestMarkHealthyEndsTheProbation(t *testing.T) {
	m := onProbation(t, 1)
	startProbation(t, launch.Options{FS: m})

	// Another version's confirmation is not this one's.
	if err := launch.MarkHealthy(m, root, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if got := readProbation(t, m).Status; got != layout.ProbationActive {
		t.Fatalf("status after confirming another version = %s", got)
	}

	if err := launch.MarkHealthy(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	if err := launch.MarkHealthy(m, root, "1.3.0"); err != nil {
		t.Fatalf("a second MarkHealthy: %v", err)
	}
	for i := 0; i < 3; i++ {
		if res := startProbation(t, launch.Options{FS: m}); res.Probation != (launch.ProbationResult{}) {
			t.Fatalf("start after confirming: %+v", res.Probation)
		}
	}
	if pointer(t, m) != "1.3.0" || readProbation(t, m).Status != layout.ProbationConfirmed {
		t.Fatalf("current %s, record %+v", pointer(t, m), readProbation(t, m))
	}
}

func TestMarkUnhealthyRollsBackAtTheNextStart(t *testing.T) {
	m := onProbation(t, 5)
	startProbation(t, launch.Options{FS: m})

	if err := launch.MarkUnhealthy(m, root, "1.3.0", "  database\x00 schema\nunknown  "); err != nil {
		t.Fatal(err)
	}
	// Once reported, confirming is too late for this version.
	if err := launch.MarkHealthy(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	res := startProbation(t, launch.Options{FS: m})
	if !res.Probation.Reverted || res.Probation.Reason != "database  schema unknown" {
		t.Fatalf("probation = %+v, want a rollback with the sanitized reason", res.Probation)
	}
	if pointer(t, m) != "1.2.0" {
		t.Fatalf("current = %s", pointer(t, m))
	}
}

func TestMarkUnhealthyWithoutAReasonStillSaysSomething(t *testing.T) {
	m := onProbation(t, 5)
	if err := launch.MarkUnhealthy(m, root, "1.3.0", " \t"); err != nil {
		t.Fatal(err)
	}
	if got := readProbation(t, m).Reason; got == "" {
		t.Fatal("an unhealthy version recorded no reason")
	}
}

func TestMarkIsANoOpWithoutARecord(t *testing.T) {
	m := tree(t, []string{"1.2.0"}, "1.2.0")
	if err := launch.MarkHealthy(m, root, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := launch.MarkUnhealthy(m, root, "1.2.0", "x"); err != nil {
		t.Fatal(err)
	}
	if readProbation(t, m) != nil {
		t.Fatal("marking created a record")
	}
	if err := launch.MarkHealthy(nil, root, "1.2.0"); !errors.Is(err, launch.ErrLaunch) {
		t.Fatalf("MarkHealthy without a filesystem = %v", err)
	}
	if err := launch.MarkHealthy(m, "", "1.2.0"); !errors.Is(err, launch.ErrLaunch) {
		t.Fatalf("MarkHealthy without a root = %v", err)
	}
}

func TestARequestedRestartCountsNoAttempt(t *testing.T) {
	m := onProbation(t, 1)
	p := readProbation(t, m)
	p.Restarts, p.RestartPending = 1, true
	writeProbation(t, m, *p)

	res := startProbation(t, launch.Options{FS: m})
	if !res.Probation.Restart || res.Probation.Attempt != 0 || res.Probation.Reverted {
		t.Fatalf("probation = %+v, want a restart that counted nothing", res.Probation)
	}
	if p := readProbation(t, m); p.RestartPending || p.Attempts != 0 {
		t.Fatalf("record = %+v, want the marker consumed and no attempt", p)
	}
}

func TestTooManyRequestedRestartsRollBack(t *testing.T) {
	m := onProbation(t, 5)
	p := readProbation(t, m)
	p.Restarts, p.RestartPending = p.RestartsAllowed+1, true
	writeProbation(t, m, *p)

	res := startProbation(t, launch.Options{FS: m})
	if !res.Probation.Reverted || !strings.Contains(res.Probation.Reason, "restarted more than 2 times") {
		t.Fatalf("probation = %+v", res.Probation)
	}
}

// A record for a version that is not live — an update that rolled back, or one
// still deferred — is left exactly as it is.
func TestARecordForAnotherVersionIsLeftAlone(t *testing.T) {
	m := tree(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	want := layout.Probation{
		SchemaVersion: layout.ProbationSchema, Version: "1.3.0", Previous: "1.2.0",
		Status: layout.ProbationActive, AttemptsAllowed: 1,
	}
	writeProbation(t, m, want)
	for i := 0; i < 3; i++ {
		if res := startProbation(t, launch.Options{FS: m}); res.Probation != (launch.ProbationResult{}) {
			t.Fatalf("probation = %+v", res.Probation)
		}
	}
	if got := readProbation(t, m); *got != want {
		t.Fatalf("record = %+v, want it untouched", got)
	}
}

// A deferred update applied by this start is on probation from this start on,
// and the start that holds the lock does not ask for it a second time.
func TestADeferredUpdateIsOnProbationFromItsFirstStart(t *testing.T) {
	m := deferredTree(t)
	writeProbation(t, m, layout.Probation{
		Version: "1.3.0", Previous: "1.2.0", Status: layout.ProbationActive, AttemptsAllowed: 1,
	})
	l := &lock{}
	res := startProbation(t, launch.Options{FS: m, Lock: l, Migrate: &migrator{fs: m}})
	if !res.Applied || res.Probation.Attempt != 1 {
		t.Fatalf("result = %+v", res)
	}
	if l.attempts != 1 || l.unlocked != 1 {
		t.Fatalf("lock taken %d times, released %d", l.attempts, l.unlocked)
	}

	// The next start rolls back, and takes the lock for that itself.
	l2 := &lock{}
	res = startProbation(t, launch.Options{FS: m, Lock: l2, Migrate: &migrator{fs: m}})
	if !res.Probation.Reverted || l2.attempts != 1 || l2.unlocked != 1 {
		t.Fatalf("probation = %+v, lock %+v", res.Probation, l2)
	}
}

func TestARollbackWaitsForARunningInstance(t *testing.T) {
	m := onProbation(t, 1)
	startProbation(t, launch.Options{FS: m})

	res := startProbation(t, launch.Options{FS: m, Lock: &lock{held: true}})
	if res.Probation.Reverted || pointer(t, m) != "1.3.0" {
		t.Fatalf("rolled back under a running instance: %+v", res.Probation)
	}
	if p := readProbation(t, m); p.Status != layout.ProbationActive {
		t.Fatalf("record = %+v, want it still on probation", p)
	}

	lockErr := errors.New("lock broken")
	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Lock: &lock{err: lockErr}})
	if err != nil || !errors.Is(res.Probation.Err, lockErr) {
		t.Fatalf("Start = %+v, %v; want the lock error reported, not returned", res.Probation, err)
	}

	if res := startProbation(t, launch.Options{FS: m, Lock: &lock{}}); !res.Probation.Reverted {
		t.Fatalf("the rollback did not happen once the instance was gone: %+v", res.Probation)
	}
}

// A rollback that stopped part-way is finished by the next start.
func TestAnInterruptedRollbackIsFinished(t *testing.T) {
	m := onProbation(t, 1)
	startProbation(t, launch.Options{FS: m})
	mig := &migrator{fs: m}
	failing := &failingRollback{migrator: mig, err: errors.New("database locked")}

	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Migrate: failing})
	if err != nil || res.Probation.Err == nil || res.Probation.Reverted {
		t.Fatalf("Start = %+v, %v; want the rollback reported as stopped", res.Probation, err)
	}
	if p := readProbation(t, m); p.Status != layout.ProbationReverting {
		t.Fatalf("record = %+v, want REVERTING", p)
	}

	res = startProbation(t, launch.Options{FS: m, Migrate: mig})
	if !res.Probation.Reverted || pointer(t, m) != "1.2.0" || installedState(t, m) != "1.2.0" {
		t.Fatalf("second start: %+v, current %s", res.Probation, pointer(t, m))
	}
	if readProbation(t, m).Status != layout.ProbationReverted {
		t.Fatalf("record = %+v", readProbation(t, m))
	}
}

type failingRollback struct {
	*migrator
	err error
}

func (f *failingRollback) Rollback(hook.Context) error {
	f.rolled++
	return f.err
}

func TestAVersionWithNothingToReturnToIsKept(t *testing.T) {
	m := tree(t, []string{"1.3.0"}, "1.3.0")
	writeProbation(t, m, layout.Probation{
		Version: "1.3.0", Previous: "1.2.0", Status: layout.ProbationUnhealthy, AttemptsAllowed: 1, Reason: "broken",
	})
	res := startProbation(t, launch.Options{FS: m})
	if !res.Probation.Kept || res.Probation.Reverted || !strings.Contains(res.Probation.Reason, "1.2.0 is no longer installed") {
		t.Fatalf("probation = %+v", res.Probation)
	}
	if pointer(t, m) != "1.3.0" || readProbation(t, m).Status != layout.ProbationKept {
		t.Fatalf("current %s, record %+v", pointer(t, m), readProbation(t, m))
	}
	if res := startProbation(t, launch.Options{FS: m}); res.Probation != (launch.ProbationResult{}) {
		t.Fatalf("a kept version is still acted on: %+v", res.Probation)
	}
}

// An updater that predates probation — the one in the version rolled back to —
// installs the blocked version again. The launcher does not let it stay.
func TestABlockedVersionInstalledAgainIsRolledBackAgain(t *testing.T) {
	m := tree(t, []string{"1.2.0", "1.3.0"}, "1.3.0")
	writeProbation(t, m, layout.Probation{
		Version: "1.3.0", Previous: "1.2.0", Status: layout.ProbationReverted, AttemptsAllowed: 1,
		Reason: "broken", Blocked: &layout.BlockedVersion{Version: "1.3.0", Reason: "broken"},
	})
	res := startProbation(t, launch.Options{FS: m})
	if !res.Probation.Reverted || res.Probation.Reason != "broken" || pointer(t, m) != "1.2.0" {
		t.Fatalf("probation = %+v, current %s", res.Probation, pointer(t, m))
	}
}

func TestAnUnreadableRecordIsReportedAndTheStartGoesOn(t *testing.T) {
	m := tree(t, []string{"1.2.0"}, "1.2.0")
	if err := fsx.WriteFileAtomic(m, layout.ProbationFile(root), []byte(`{"schema_version": 9}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root})
	if err != nil || !errors.Is(res.Probation.Err, layout.ErrLayout) {
		t.Fatalf("Start = %+v, %v", res.Probation, err)
	}
}
