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
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

func journalState(t *testing.T, f *fixture) txn.State {
	t.Helper()
	j, err := txn.Open(f.fs, root)
	if err != nil {
		t.Fatalf("txn.Open: %v", err)
	}
	last, ok := j.Last()
	if !ok {
		return ""
	}
	return last.State
}

func TestApplyInstallsTheRelease(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
	if got := f.stateVersion(); got != "1.3.0" {
		t.Fatalf("recorded state = %q, want 1.3.0", got)
	}
	if got := f.hostState(); got != "1.3.0" {
		t.Fatalf("host state = %q, want the migration to have run", got)
	}
	for name, want := range map[string]string{
		"/opt/app/versions/1.3.0/app":           "binary 1.3.0",
		"/opt/app/versions/1.3.0/lib/plugin.so": "library 1.3.0",
	} {
		b, err := fsx.ReadFile(f.fs, name, 1<<20)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		if string(b) != want {
			t.Fatalf("%s = %q, want %q", name, b, want)
		}
	}
	if s := journalState(t, f); s != txn.StateCommitted {
		t.Fatalf("journal ends at %s, want COMMITTED", s)
	}
	// The previous version stays as the instant rollback target (§14.1).
	if !f.exists("/opt/app/versions/1.2.0") {
		t.Fatal("the previous version was collected although it is the rollback target")
	}
	if f.exists(layout.Staging(root)) {
		t.Fatal("the staging tree survived the commit")
	}

	if len(f.hooks.outcomes) != 1 {
		t.Fatalf("%d outcomes reported, want one", len(f.hooks.outcomes))
	}
	o := f.hooks.outcomes[0]
	if o.Result != "committed" || o.ErrorClass != "" || o.FailedPhase != "" {
		t.Fatalf("outcome = %+v, want a clean commit", o)
	}
	if o.FromVersion != "1.2.0" || o.ToVersion != "1.3.0" || o.OS != "linux" || o.Arch != "amd64" {
		t.Fatalf("outcome = %+v", o)
	}
	if o.At != f.opts.Now() {
		t.Fatalf("outcome timestamp %v did not come from the injected clock", o.At)
	}
}

func TestApplyFirstInstall(t *testing.T) {
	f := newFixture(t, "", "1.0.0")
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.pointer(); got != "1.0.0" {
		t.Fatalf("current = %q, want 1.0.0", got)
	}
	if f.hooks.migrated != 1 {
		t.Fatalf("the migrator ran %d times, want once", f.hooks.migrated)
	}
	if f.hooks.lastHookCtx.FromVersion != "" {
		t.Fatalf("the migrator saw FromVersion %q on a first install", f.hooks.lastHookCtx.FromVersion)
	}
}

func TestApplyCollectsOldVersions(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	// Two older versions beyond the window; both must go, and only they.
	for _, v := range []string{"1.0.0", "1.1.0"} {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := f.fs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if f.exists("/opt/app/versions/" + v) {
			t.Fatalf("%s survived the retention window", v)
		}
	}
	for _, v := range []string{"1.2.0", "1.3.0"} {
		if !f.exists("/opt/app/versions/" + v) {
			t.Fatalf("%s was collected although it is inside the window", v)
		}
	}
}

// The hooks are the host's compiled code and the only extension points there
// are. Their order is part of the contract: a Checker that runs after the files
// are already installed has nothing left to check.
func TestApplyRunsTheHooksInOrder(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Check = f.hooks
	f.opts.Prompt = f.hooks
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if f.hooks.checked != 1 {
		t.Fatalf("the checker ran %d times, want once", f.hooks.checked)
	}
	if len(f.hooks.prompted) != 1 || !strings.Contains(f.hooks.prompted[0], "1.3.0") {
		t.Fatalf("the prompt was %v", f.hooks.prompted)
	}
	if f.hooks.migrated != 1 || f.hooks.rolled != 0 {
		t.Fatalf("migrate ran %d times and rollback %d, want 1 and 0", f.hooks.migrated, f.hooks.rolled)
	}

	// The observer sees the transaction as it happens, ending in the commit.
	phases := f.hooks.phases()
	if len(phases) == 0 || phases[len(phases)-1] != hook.PhaseCommit {
		t.Fatalf("events ended at %v, want the commit last", phases)
	}
	seen := map[hook.Phase]bool{}
	for _, p := range phases {
		seen[p] = true
	}
	for _, want := range []hook.Phase{hook.PhaseCheck, hook.PhaseDownload, hook.PhaseApply, hook.PhaseCommit} {
		if !seen[want] {
			t.Errorf("no %s event was emitted; the observer saw %v", want, phases)
		}
	}
}

func TestApplyStopsWhenThePromptDeclines(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Prompt = f.hooks
	f.hooks.confirm = false

	err := f.run()
	if !errors.Is(err, updater.ErrDeclined) {
		t.Fatalf("error = %v, want ErrDeclined", err)
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q after a declined update", got)
	}
	if f.exists("/opt/app/versions/1.3.0") {
		t.Fatal("a declined update still staged the release")
	}
	// Declining is not a failed release, and must not be reported as one: it is
	// the number a publisher watches to decide a release is bad (§14.5).
	if o := f.hooks.outcomes[0]; o.Result != "aborted" || o.ErrorClass != "declined" {
		t.Fatalf("outcome = %+v, want an aborted/declined report", o)
	}
}

// The core promise, exercised through the real Apply path: whatever fails, the
// install is left entirely on the old version, and the host state with it.
func TestApplyRollsBackEveryFailure(t *testing.T) {
	boom := errors.New("boom")

	for _, tc := range []struct {
		name       string
		arrange    func(f *fixture)
		wantClass  string
		wantPhase  hook.Phase
		wantResult string
		wantRolled int
	}{
		{
			name: "the pre-flight check refuses",
			arrange: func(f *fixture) {
				f.opts.Check = f.hooks
				f.hooks.checkErr = boom
			},
			wantClass: "check", wantPhase: hook.PhaseCheck, wantResult: "aborted", wantRolled: 0,
		},
		{
			name: "a target cannot be materialized",
			arrange: func(f *fixture) {
				f.trust.targetErr["targets/plugin.so"] = boom
			},
			wantClass: "unknown", wantPhase: hook.PhaseStage, wantResult: "rolled_back", wantRolled: 0,
		},
		{
			name: "the migration fails",
			arrange: func(f *fixture) {
				f.hooks.migrateEr = boom
			},
			wantClass: "migrate", wantPhase: hook.PhaseMigrate, wantResult: "rolled_back", wantRolled: 1,
		},
		{
			name: "the swap fails",
			arrange: func(f *fixture) {
				f.fs.Fail = func(op, name string) error {
					// Both pointer forms end in a rename onto `current`; the
					// symlink form is not the one to hook, or this would stop
					// injecting anything on Windows.
					if op == "rename" && strings.HasSuffix(name, "/"+layout.CurrentName) {
						return boom
					}
					return nil
				}
			},
			wantClass: "disk", wantPhase: hook.PhaseApply, wantResult: "rolled_back", wantRolled: 1,
		},
		{
			name: "post-apply verification finds a mismatch",
			arrange: func(f *fixture) {
				f.opts.Policy.VerifyAfterApply = true
				// Change what the file is supposed to be after it has been
				// staged, which is indistinguishable from the installed file
				// having changed underneath us — the window §11.3 T9 covers.
				f.fs.Fail = func(op, name string) error {
					if op == "rename" && strings.HasSuffix(name, "versions/1.3.0") {
						f.trust.targets["targets/app"] = []byte("something else entirely")
					}
					return nil
				}
			},
			wantClass: "verify", wantPhase: hook.PhaseVerify, wantResult: "rolled_back", wantRolled: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			tc.arrange(f)

			err := f.run()
			if err == nil {
				t.Fatal("Apply reported success")
			}
			f.fs.Fail = nil

			if got := f.pointer(); got != "1.2.0" {
				t.Fatalf("current = %q, want the old version to be live again", got)
			}
			if got := f.hostState(); got != "1.2.0" {
				t.Fatalf("host state = %q, want the migration undone", got)
			}
			if f.exists("/opt/app/versions/1.3.0") {
				t.Fatal("the abandoned version directory survived the rollback")
			}
			if f.exists(layout.Staging(root)) {
				t.Fatal("the staging tree survived the rollback")
			}
			if f.hooks.rolled != tc.wantRolled {
				t.Fatalf("Migrator.Rollback ran %d times, want %d", f.hooks.rolled, tc.wantRolled)
			}
			if s := journalState(t, f); s != txn.StateRolledBack && s != "" {
				t.Fatalf("journal ends at %s, want ROLLED_BACK", s)
			}

			if len(f.hooks.outcomes) != 1 {
				t.Fatalf("%d outcomes reported, want one", len(f.hooks.outcomes))
			}
			o := f.hooks.outcomes[0]
			if o.Result != tc.wantResult {
				t.Errorf("outcome result = %q, want %q", o.Result, tc.wantResult)
			}
			if o.ErrorClass != tc.wantClass {
				t.Errorf("error class = %q, want %q", o.ErrorClass, tc.wantClass)
			}
			if o.FailedPhase != tc.wantPhase {
				t.Errorf("failed phase = %q, want %q", o.FailedPhase, tc.wantPhase)
			}
			// Nothing identifying may reach a Reporter (§14.5).
			if strings.Contains(o.ErrorClass, "/") || strings.Contains(o.ErrorClass, boom.Error()) {
				t.Errorf("the outcome leaked detail: %q", o.ErrorClass)
			}
		})
	}
}

// A Release resolved against a tree that has since moved must not be applied:
// the plan was made for an install that no longer exists.
func TestApplyRefusesAStaleRelease(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	u := f.updater()
	r, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}

	// Someone else updated in the meantime.
	dir, err := layout.VersionDir(root, "1.2.5")
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	if err := f.fs.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := layout.SetPointer(f.fs, root, "1.2.5"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	err = u.Apply(context.Background(), r)
	if !errors.Is(err, updater.ErrStale) {
		t.Fatalf("error = %v, want ErrStale", err)
	}
	if got := f.pointer(); got != "1.2.5" {
		t.Fatalf("current = %q; the stale apply moved the pointer", got)
	}
}

// Apply settles an interrupted transaction before opening a new one: the journal
// keeps one history, and a new BEGIN replaces it.
func TestApplyRecoversAnInterruptedTransactionFirst(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")

	// Leave the root as a crash during a 1.2.0 -> 1.9.0 update would.
	j, err := txn.Open(f.fs, root)
	if err != nil {
		t.Fatalf("txn.Open: %v", err)
	}
	dir, err := layout.VersionDir(root, "1.9.0")
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	if err := f.fs.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged} {
		if err := j.Append(txn.Record{
			State: s, Name: appName, FromVersion: "1.2.0", ToVersion: "1.9.0", Phase: hook.PhaseStage,
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.exists("/opt/app/versions/1.9.0") {
		t.Fatal("the interrupted transaction was not undone before the new one started")
	}
	if f.hooks.rolled != 1 {
		t.Fatalf("Migrator.Rollback ran %d times, want once for the interrupted transaction", f.hooks.rolled)
	}
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want the new update to have completed", got)
	}
}

// Reporting is best-effort and must never change the update's result (§14.5).
func TestReportingCannotAffectTheResult(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.hooks.reportErr = errors.New("telemetry endpoint down")

	if err := f.run(); err != nil {
		t.Fatalf("a failing Reporter broke the update: %v", err)
	}
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
}

func TestHeadlessOperationNeedsNoHooks(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Migrate = nil
	f.opts.Observe = nil
	f.opts.Report = nil

	if err := f.run(); err != nil {
		t.Fatalf("Apply without hooks: %v", err)
	}
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
}

// The exclusive application lock is the ground truth that nothing is writing;
// Coordinator.RequestShutdown is only how the instances are asked (§14.3).
func TestQuiesce(t *testing.T) {
	t.Run("an idle application is locked straight away", func(t *testing.T) {
		f := newFixture(t, "1.2.0", "1.3.0")
		lock := &fakeLock{}
		f.opts.Lock = lock
		f.opts.Coordinate = f.hooks

		if err := f.run(); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if f.hooks.shutdowns != 0 {
			t.Fatal("the application was asked to quit although it was not running")
		}
		if lock.unlocked != 1 {
			t.Fatalf("the lock was released %d times, want once", lock.unlocked)
		}
	})

	t.Run("a running application is asked to stop and then waited for", func(t *testing.T) {
		f := newFixture(t, "1.2.0", "1.3.0")
		lock := &fakeLock{heldBySomeoneElse: 1}
		f.opts.Lock = lock
		f.opts.Coordinate = f.hooks
		f.opts.Policy.QuiesceTimeout = 5 * time.Second
		f.opts.Now = time.Now

		if err := f.run(); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if f.hooks.shutdowns != 1 {
			t.Fatalf("RequestShutdown ran %d times, want once", f.hooks.shutdowns)
		}
		if got := f.pointer(); got != "1.3.0" {
			t.Fatalf("current = %q, want the update to have completed", got)
		}
	})

	t.Run("an application that never stops", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			policy  updater.BusyPolicy
			wantErr error
			wantPtr string
		}{
			{"abort", updater.BusyAbort, updater.ErrBusy, "1.2.0"},
			{"defer to restart", updater.BusyDeferToRestart, updater.ErrDeferred, "1.2.0"},
			{"force", updater.BusyForce, nil, "1.3.0"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t, "1.2.0", "1.3.0")
				f.opts.Lock = &fakeLock{heldBySomeoneElse: -1}
				f.opts.Coordinate = f.hooks
				f.opts.Policy.OnBusy = tc.policy
				f.opts.Policy.QuiesceTimeout = time.Millisecond
				f.opts.Now = time.Now

				err := f.run()
				if tc.wantErr == nil {
					if err != nil {
						t.Fatalf("Apply: %v", err)
					}
				} else if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				if got := f.pointer(); got != tc.wantPtr {
					t.Fatalf("current = %q, want %q", got, tc.wantPtr)
				}
				if err != nil && !f.exists("/opt/app/versions/1.3.0") {
					return // rolled back, as it should be
				}
			})
		}
	})

	t.Run("a lock that cannot be consulted stops the update", func(t *testing.T) {
		f := newFixture(t, "1.2.0", "1.3.0")
		f.opts.Lock = &fakeLock{err: errors.New("lock file unreadable")}

		if err := f.run(); err == nil {
			t.Fatal("the update proceeded although quiescence could not be established")
		}
		if got := f.pointer(); got != "1.2.0" {
			t.Fatalf("current = %q, want 1.2.0", got)
		}
	})

	t.Run("a coordinator that fails stops the update", func(t *testing.T) {
		f := newFixture(t, "1.2.0", "1.3.0")
		f.opts.Coordinate = f.hooks
		f.hooks.shutdownErr = errors.New("ipc unavailable")

		err := f.run()
		if !errors.Is(err, updater.ErrBusy) {
			t.Fatalf("error = %v, want ErrBusy", err)
		}
		if got := f.pointer(); got != "1.2.0" {
			t.Fatalf("current = %q, want 1.2.0", got)
		}
	})
}

// A cancelled context must still leave the tree consistent: undoing is not
// optional work that a cancellation may skip.
func TestApplyRollsBackAfterCancellation(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	u := f.updater()
	r, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := u.Apply(ctx, r); err == nil {
		t.Fatal("a cancelled Apply reported success")
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
	if f.exists("/opt/app/versions/1.3.0") {
		t.Fatal("a cancelled Apply left a version directory behind")
	}
	if got := f.hooks.outcomes[0].ErrorClass; got != "cancelled" {
		t.Fatalf("error class = %q, want cancelled", got)
	}
}

// If the rollback itself fails, both failures have to reach the caller: knowing
// only that the update failed would hide that the machine is now in the state
// nobody wants.
func TestApplySurfacesAFailedRollback(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.hooks.migrateEr = errors.New("cannot migrate")
	f.hooks.rollbackE = errors.New("cannot undo either")

	err := f.run()
	if err == nil {
		t.Fatal("Apply reported success")
	}
	if !strings.Contains(err.Error(), "cannot migrate") {
		t.Fatalf("error %v does not mention the original failure", err)
	}
	if !strings.Contains(err.Error(), "cannot undo either") {
		t.Fatalf("error %v does not mention the failed rollback", err)
	}
	// The journal stays where it is, so the next start tries the rollback again.
	if s := journalState(t, f); s != txn.StateStaged {
		t.Fatalf("journal ends at %s, want it left for the next attempt", s)
	}
}
