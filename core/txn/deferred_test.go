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

package txn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

// deferred builds the state BusyDeferToRestart leaves behind: 1.2.0 live, 1.3.0
// staged and complete, hook scratch space in place, and a journal that says the
// transaction is resting rather than interrupted.
func deferred(t *testing.T) *fsx.Mem {
	t.Helper()
	m := installed(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	if err := m.MkdirAll(fsx.Join(layout.Staging(root), "1.3.0"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged, txn.StateDeferred)
	return m
}

// swapTo is the pointer move core/stage performs, reduced to what the journal
// needs from it.
func swapTo(m *fsx.Mem) func(string) error {
	return func(version string) error { return layout.SetPointer(m, root, version) }
}

// The defining property: recovery leaves a deferred transaction completely
// alone. Undoing it would throw away a verified tree the policy asked to keep;
// finishing it would migrate host state under a running application, which is
// the very situation that caused the deferral.
func TestRecoveryLeavesADeferredTransactionAlone(t *testing.T) {
	m := deferred(t)

	res, err := txn.RecoverResult(context.Background(), m, root, newRecorder(m))
	if err != nil {
		t.Fatalf("RecoverResult: %v", err)
	}
	if !res.Deferred {
		t.Error("recovery did not report the transaction as deferred")
	}
	if res.Completed {
		t.Error("recovery completed a deferred transaction")
	}

	if got := pointer(t, m); got != "1.2.0" {
		t.Errorf("current = %q, want the still-live 1.2.0", got)
	}
	dir, err := layout.VersionDir(root, "1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if !exists(t, m, dir) {
		t.Error("recovery removed the staged version")
	}
	// The hook scratch space survives too: a Migrator may have left something
	// there for the run that will finish this.
	if !exists(t, m, layout.Staging(root)) {
		t.Error("recovery swept up the staging tree as litter")
	}

	j := open(t, m)
	last, ok := j.Last()
	if !ok || last.State != txn.StateDeferred {
		t.Errorf("journal is at %v, want it untouched at DEFERRED", last.State)
	}
}

// Recovery runs on every start, and a deferred update may sit through several of
// them before an opportunity to apply it comes along.
func TestRepeatedRecoveryKeepsTheDeferredUpdate(t *testing.T) {
	m := deferred(t)

	for i := range 3 {
		res, err := txn.RecoverResult(context.Background(), m, root, nil)
		if err != nil {
			t.Fatalf("recovery %d: %v", i, err)
		}
		if !res.Deferred {
			t.Fatalf("recovery %d did not report the deferral", i)
		}
	}
	dir, _ := layout.VersionDir(root, "1.3.0")
	if !exists(t, m, dir) {
		t.Error("the staged version did not survive three starts")
	}
}

// The launcher's half: the migration and the swap that could not run while the
// application was writing.
func TestResumeDeferredFinishesTheTransaction(t *testing.T) {
	m := deferred(t)
	r := newRecorder(m)

	var swapped string
	res, err := txn.ResumeDeferred(context.Background(), m, root, r, func(version string) error {
		swapped = version
		return layout.SetPointer(m, root, version)
	})
	if err != nil {
		t.Fatalf("ResumeDeferred: %v", err)
	}
	if !res.Completed || res.ToVersion != "1.3.0" {
		t.Fatalf("result = %+v, want a completed 1.3.0", res)
	}
	if swapped != "1.3.0" {
		t.Errorf("swapped %q, want 1.3.0", swapped)
	}
	if r.migrated != 1 || r.rolled != 0 {
		t.Errorf("migrator: %d migrations, %d rollbacks; want 1 and 0", r.migrated, r.rolled)
	}
	// The hook was told what it is migrating between, which is what makes a
	// deferred migration meaningful at all.
	if r.seenFrom != "1.2.0" || r.seenTo != "1.3.0" {
		t.Errorf("migrator saw %s->%s, want 1.2.0->1.3.0", r.seenFrom, r.seenTo)
	}

	if got := pointer(t, m); got != "1.3.0" {
		t.Errorf("current = %q, want 1.3.0", got)
	}
	if got := stateVersion(t, m); got != "1.3.0" {
		t.Errorf("install state = %q, want 1.3.0", got)
	}
	j := open(t, m)
	if last, _ := j.Last(); last.State != txn.StateCommitted {
		t.Errorf("journal is at %v, want COMMITTED", last.State)
	}
	// The transaction is over, so its litter goes with it.
	if exists(t, m, layout.Staging(root)) {
		t.Error("the staging tree outlived the transaction")
	}
}

// Resuming twice must not migrate twice. The second call has nothing to do and
// says so, rather than replaying a transaction that already committed.
func TestResumeDeferredIsIdempotent(t *testing.T) {
	m := deferred(t)
	r := newRecorder(m)

	if _, err := txn.ResumeDeferred(context.Background(), m, root, r, swapTo(m)); err != nil {
		t.Fatalf("first resume: %v", err)
	}
	res, err := txn.ResumeDeferred(context.Background(), m, root, r, swapTo(m))
	if err != nil {
		t.Fatalf("second resume: %v", err)
	}
	if res.Recovered {
		t.Errorf("the second resume reported work: %+v", res)
	}
	if r.migrated != 1 {
		t.Errorf("Migrate ran %d times across two resumes, want once", r.migrated)
	}
}

// A migration that fails leaves the transaction deferred rather than tearing it
// down: the staged tree is still good and the next start may well succeed.
// Undoing is a decision the caller makes, not a consequence of one attempt.
func TestResumeDeferredKeepsTheTransactionWhenMigrationFails(t *testing.T) {
	m := deferred(t)
	failing := &failingMigrator{err: errors.New("the database is locked")}

	swapped := false
	if _, err := txn.ResumeDeferred(context.Background(), m, root, failing, func(string) error {
		swapped = true
		return nil
	}); err == nil {
		t.Fatal("a failed migration was reported as success")
	}
	if swapped {
		t.Error("the swap ran although the migration failed")
	}

	j := open(t, m)
	if last, _ := j.Last(); last.State != txn.StateDeferred {
		t.Errorf("journal is at %v, want it still at DEFERRED", last.State)
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Errorf("current = %q, want the untouched 1.2.0", got)
	}
	dir, _ := layout.VersionDir(root, "1.3.0")
	if !exists(t, m, dir) {
		t.Error("the staged version was removed after a failed migration")
	}
}

// Nothing deferred, nothing to do — the shape of every ordinary start.
func TestResumeDeferredOnAQuietRoot(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")

	res, err := txn.ResumeDeferred(context.Background(), m, root, nil, func(string) error {
		t.Error("swap ran with nothing deferred")
		return nil
	})
	if err != nil {
		t.Fatalf("ResumeDeferred: %v", err)
	}
	if res.Recovered || res.Completed {
		t.Errorf("result = %+v, want nothing to report", res)
	}
}

func TestResumeDeferredNeedsASwap(t *testing.T) {
	m := deferred(t)
	if _, err := txn.ResumeDeferred(context.Background(), m, root, nil, nil); !errors.Is(err, txn.ErrJournal) {
		t.Fatalf("err = %v, want ErrJournal", err)
	}
}

// A newer update may supersede one that is still waiting. Without that the
// updater would wedge permanently on a deferred transaction nobody restarts for.
func TestANewTransactionMaySupersedeADeferredOne(t *testing.T) {
	m := deferred(t)
	j := open(t, m)

	if err := j.Append(rec(txn.StateBegin, "1.2.0", "1.4.0")); err != nil {
		t.Fatalf("a new transaction could not begin over a deferred one: %v", err)
	}
	last, _ := j.Last()
	if last.State != txn.StateBegin || last.ToVersion != "1.4.0" {
		t.Errorf("journal = %+v, want a fresh BEGIN for 1.4.0", last)
	}
}

// A deferred transaction may also be abandoned outright — an operator, or an
// updater told to stop deferring, undoes it like any other.
func TestADeferredTransactionCanBeRolledBack(t *testing.T) {
	m := deferred(t)

	if err := txn.Rollback(context.Background(), m, root, newRecorder(m)); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Errorf("current = %q, want 1.2.0", got)
	}
	dir, _ := layout.VersionDir(root, "1.3.0")
	if exists(t, m, dir) {
		t.Error("the abandoned version directory is still there")
	}
	j := open(t, m)
	if last, _ := j.Last(); last.State != txn.StateRolledBack {
		t.Errorf("journal is at %v, want ROLLED_BACK", last.State)
	}
}

// failingMigrator fails the migration itself, which the recorder cannot.
type failingMigrator struct{ err error }

func (f *failingMigrator) Migrate(hook.Context) error  { return f.err }
func (f *failingMigrator) Rollback(hook.Context) error { return nil }
