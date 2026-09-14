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
	"errors"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

// busy prepares an update against an application that will not release its lock,
// with the policy set to defer.
func busy(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Lock = &fakeLock{heldBySomeoneElse: -1}
	f.opts.Policy.OnBusy = updater.BusyDeferToRestart
	f.opts.Policy.QuiesceTimeout = time.Millisecond
	f.opts.Now = time.Now
	return f
}

func lastRecord(t *testing.T, f *fixture) txn.Record {
	t.Helper()
	j, err := txn.Open(f.fs, root)
	if err != nil {
		t.Fatalf("Open journal: %v", err)
	}
	last, ok := j.Last()
	if !ok {
		t.Fatal("the journal holds no record")
	}
	return last
}

// Deferring keeps the verified tree and records why. Before this, the policy
// rolled back cleanly and threw the download away — correct, but it meant the
// "defer" policy and the "abort" policy did exactly the same thing at three times
// the cost.
func TestDeferKeepsTheStagedTreeAndSaysSo(t *testing.T) {
	f := busy(t)

	err := f.run()
	if !errors.Is(err, updater.ErrDeferred) {
		t.Fatalf("err = %v, want ErrDeferred", err)
	}
	if last := lastRecord(t, f); last.State != txn.StateDeferred {
		t.Fatalf("journal is at %v, want DEFERRED", last.State)
	}
	if !f.exists("/opt/app/versions/1.3.0") {
		t.Error("the staged version was removed")
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Errorf("current = %q; a deferred update must not swap", got)
	}
	if in, err := layout.ReadInstall(f.fs, root); err != nil || in == nil || in.Version != "1.2.0" {
		t.Errorf("install state = %+v (%v), want the still-live 1.2.0", in, err)
	}
}

// The migration is the reason the work waits: it runs against host state the
// application is still using, so it must not happen while that application is up.
func TestDeferDoesNotMigrate(t *testing.T) {
	f := busy(t)

	if err := f.run(); !errors.Is(err, updater.ErrDeferred) {
		t.Fatalf("err = %v, want ErrDeferred", err)
	}
	if f.hooks.migrated != 0 {
		t.Errorf("Migrate ran %d times while the application was still running", f.hooks.migrated)
	}
	if f.hooks.rolled != 0 {
		t.Errorf("Rollback ran %d times on a deferral, which undoes nothing", f.hooks.rolled)
	}
}

// A deferral is reported as its own outcome. A publisher watching the rolled_back
// rate must not see a policy working as intended as a failure.
func TestDeferIsReportedAsDeferred(t *testing.T) {
	f := busy(t)

	if err := f.run(); !errors.Is(err, updater.ErrDeferred) {
		t.Fatalf("err = %v, want ErrDeferred", err)
	}
	if len(f.hooks.outcomes) != 1 {
		t.Fatalf("%d outcomes reported, want one", len(f.hooks.outcomes))
	}
	o := f.hooks.outcomes[0]
	if o.Result != "deferred" {
		t.Errorf("result = %q, want deferred", o.Result)
	}
	if o.ErrorClass != "busy" {
		t.Errorf("error class = %q, want busy", o.ErrorClass)
	}
}

// The next check must not trip over the resting transaction, and must not undo
// it either: recovery runs at the start of every Apply.
func TestADeferredTransactionSurvivesTheNextCheck(t *testing.T) {
	f := busy(t)
	if err := f.run(); !errors.Is(err, updater.ErrDeferred) {
		t.Fatalf("err = %v, want ErrDeferred", err)
	}

	// A second cycle, still busy.
	if err := f.run(); !errors.Is(err, updater.ErrDeferred) {
		t.Fatalf("second cycle err = %v, want ErrDeferred", err)
	}
	if !f.exists("/opt/app/versions/1.3.0") {
		t.Error("the second cycle discarded the deferred tree")
	}
	if last := lastRecord(t, f); last.State != txn.StateDeferred {
		t.Errorf("journal is at %v, want DEFERRED", last.State)
	}
}

// Aborting is the other half of the contract, and it still undoes everything.
// The two policies have to stay distinguishable, or there is no point in having
// both.
func TestAbortStillUndoesTheStaging(t *testing.T) {
	f := busy(t)
	f.opts.Policy.OnBusy = updater.BusyAbort

	if err := f.run(); !errors.Is(err, updater.ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if f.exists("/opt/app/versions/1.3.0") {
		t.Error("an aborted update left its staged version behind")
	}
	if last := lastRecord(t, f); last.State != txn.StateRolledBack {
		t.Errorf("journal is at %v, want ROLLED_BACK", last.State)
	}
}

// A Policy that never mentions OnBusy aborts. It does not defer, and New does not
// promote it to deferring (IDN-21).
//
// The design recommends BusyDeferToRestart to a host whose running application
// updates itself, which makes "why is it not simply the default?" a fair
// question. The answer is that Go cannot distinguish "left unset" from
// "deliberately chosen": promoting would turn a forgotten line of host
// configuration into an update that quietly stays staged and lands at the next
// start, on a host that never asked for one. This test is what stops that from
// being introduced later as a convenience.
func TestUnsetOnBusyAbortsRatherThanDefers(t *testing.T) {
	f := busy(t)
	f.opts.Policy.OnBusy = updater.BusyPolicy(0) // as if the host never set it.

	err := f.run()
	if errors.Is(err, updater.ErrDeferred) {
		t.Fatal("an unset OnBusy deferred; the zero value must be the failing one")
	}
	if !errors.Is(err, updater.ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if f.exists("/opt/app/versions/1.3.0") {
		t.Error("the aborted update left its staged version behind")
	}
	if last := lastRecord(t, f); last.State != txn.StateRolledBack {
		t.Errorf("journal is at %v, want ROLLED_BACK", last.State)
	}
}
