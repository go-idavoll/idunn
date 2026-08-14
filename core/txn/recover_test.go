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
	"fmt"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

// recorder is the host's Migrator. It writes a marker outside the install root,
// which is what a real migration does — that is the state a rollback has to be
// able to undo, and the reason the journal exists at all.
type recorder struct {
	fs        *fsx.Mem
	migrated  int
	rolled    int
	failWith  error
	seenFrom  string
	seenTo    string
	markerDir string
}

func newRecorder(m *fsx.Mem) *recorder {
	if err := m.MkdirAll("/appdata", 0o755); err != nil {
		panic(err)
	}
	return &recorder{fs: m, markerDir: "/appdata"}
}

func (r *recorder) marker() string { return fsx.Join(r.markerDir, "schema") }

func (r *recorder) Migrate(c hook.Context) error {
	r.migrated++
	r.seenFrom, r.seenTo = c.FromVersion, c.ToVersion
	return fsx.WriteFileAtomic(r.fs, r.marker(), []byte(c.ToVersion), 0o644)
}

func (r *recorder) Rollback(c hook.Context) error {
	r.rolled++
	r.seenFrom, r.seenTo = c.FromVersion, c.ToVersion
	if r.failWith != nil {
		return r.failWith
	}
	if c.FromVersion == "" {
		return r.fs.RemoveAll(r.marker())
	}
	return fsx.WriteFileAtomic(r.fs, r.marker(), []byte(c.FromVersion), 0o644)
}

// installed builds an install root holding the given versions with `current`
// pointing at one of them, as a completed installation would look.
func installed(t *testing.T, versions []string, current string) *fsx.Mem {
	t.Helper()
	m := newRoot(t)
	for _, v := range versions {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := m.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := fsx.WriteFileAtomic(m, fsx.Join(dir, "app"), []byte(v), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if current != "" {
		if err := layout.SetPointer(m, root, current); err != nil {
			t.Fatalf("SetPointer: %v", err)
		}
		if err := layout.WriteInstall(m, root, layout.Install{
			Name: "acme-app", Version: current, LayoutSchema: 1,
		}); err != nil {
			t.Fatalf("WriteInstall: %v", err)
		}
	}
	return m
}

func pointer(t *testing.T, m *fsx.Mem) string {
	t.Helper()
	v, err := layout.PointerTarget(m, root)
	if err != nil {
		t.Fatalf("PointerTarget: %v", err)
	}
	return v
}

func stateVersion(t *testing.T, m *fsx.Mem) string {
	t.Helper()
	in, err := layout.ReadInstall(m, root)
	if err != nil {
		t.Fatalf("ReadInstall: %v", err)
	}
	if in == nil {
		return ""
	}
	return in.Version
}

func exists(t *testing.T, m *fsx.Mem, name string) bool {
	t.Helper()
	_, err := m.Stat(name)
	if err != nil && !fsx.IsNotExist(err) {
		t.Fatalf("Stat(%s): %v", name, err)
	}
	return err == nil
}

// journalAt drives an install root to a given point in a transaction, as a crash
// at that moment would leave it.
func journalAt(t *testing.T, m *fsx.Mem, from, to string, states ...txn.State) {
	t.Helper()
	j := open(t, m)
	for _, s := range states {
		if err := j.Append(rec(s, from, to)); err != nil {
			t.Fatalf("Append(%s): %v", s, err)
		}
	}
}

func stage(t *testing.T, m *fsx.Mem, version string) {
	t.Helper()
	dir, err := layout.VersionDir(root, version)
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	if err := m.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(m, fsx.Join(dir, "app"), []byte(version), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestRecoverNothingToDo(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	if err := txn.Recover(m, root, nil); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
}

// The staging tree and the scratch files of interrupted atomic writes are
// removed on every start; left behind, they are what the next recovery would
// have to interpret.
func TestRecoverCleansOrphans(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	if err := m.MkdirAll(layout.Staging(root), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(m, fsx.Join(layout.Staging(root), "app"), []byte("half"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	scratch := fsx.TempName(fsx.Join(root, "current"))
	if err := m.Symlink("versions/9.9.9", scratch); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if err := txn.Recover(m, root, nil); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if exists(t, m, layout.Staging(root)) {
		t.Fatal("the staging tree survived recovery")
	}
	if exists(t, m, scratch) {
		t.Fatal("an abandoned scratch pointer survived recovery")
	}
}

func TestRecoverTerminalStatesAreNoOps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		states  []txn.State
		current string
	}{
		{"committed", []txn.State{
			txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted,
		}, "1.3.0"},
		{"rolled back", []txn.State{txn.StateBegin, txn.StateRolledBack}, "1.2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := installed(t, []string{"1.2.0", "1.3.0"}, tc.current)
			journalAt(t, m, "1.2.0", "1.3.0", tc.states...)
			mig := newRecorder(m)

			if err := txn.Recover(m, root, mig); err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if got := pointer(t, m); got != tc.current {
				t.Fatalf("current = %q, want %q", got, tc.current)
			}
			if mig.rolled != 0 {
				t.Fatal("a terminal transaction was rolled back a second time")
			}
		})
	}
}

// Past the swap the new version is already live and the migration has already
// run. Finishing is the only answer that does not undo work the application can
// already see.
func TestRecoverCompletesAfterSwap(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	stage(t, m, "1.3.0")
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged, txn.StateMigrated)
	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateSwapped)

	mig := newRecorder(m)
	res, err := txn.RecoverResult(context.Background(), m, root, mig)
	if err != nil {
		t.Fatalf("RecoverResult: %v", err)
	}
	if !res.Recovered || !res.Completed {
		t.Fatalf("result = %+v, want a completed recovery", res)
	}
	if got := pointer(t, m); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
	if got := stateVersion(t, m); got != "1.3.0" {
		t.Fatalf("recorded state = %q, want 1.3.0", got)
	}
	if last, _ := open(t, m).Last(); last.State != txn.StateCommitted {
		t.Fatalf("journal ends at %s, want COMMITTED", last.State)
	}
	if mig.rolled != 0 {
		t.Fatal("a swapped transaction was rolled back")
	}
}

// The swap is a single rename: it either happened or it did not, and the record
// that would say so may be missing. The filesystem is the authority, not the
// journal.
func TestRecoverResolvesTheSwapAmbiguity(t *testing.T) {
	t.Run("rename completed", func(t *testing.T) {
		m := installed(t, []string{"1.2.0"}, "1.2.0")
		stage(t, m, "1.3.0")
		journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged, txn.StateMigrated)
		if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
			t.Fatalf("SetPointer: %v", err)
		}

		mig := newRecorder(m)
		if err := txn.Recover(m, root, mig); err != nil {
			t.Fatalf("Recover: %v", err)
		}
		if got := pointer(t, m); got != "1.3.0" {
			t.Fatalf("current = %q, want the completed swap to stand", got)
		}
		if last, _ := open(t, m).Last(); last.State != txn.StateCommitted {
			t.Fatalf("journal ends at %s, want COMMITTED", last.State)
		}
	})

	t.Run("rename did not happen", func(t *testing.T) {
		m := installed(t, []string{"1.2.0"}, "1.2.0")
		stage(t, m, "1.3.0")
		journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged, txn.StateMigrated)

		mig := newRecorder(m)
		if err := mig.Migrate(hook.Context{FromVersion: "1.2.0", ToVersion: "1.3.0"}); err != nil {
			t.Fatalf("Migrate: %v", err)
		}

		res, err := txn.RecoverResult(context.Background(), m, root, mig)
		if err != nil {
			t.Fatalf("RecoverResult: %v", err)
		}
		if !res.Recovered || res.Completed {
			t.Fatalf("result = %+v, want an undone transaction", res)
		}
		if got := pointer(t, m); got != "1.2.0" {
			t.Fatalf("current = %q, want 1.2.0", got)
		}
		if mig.rolled != 1 {
			t.Fatalf("Rollback ran %d times, want once", mig.rolled)
		}
		dir, _ := layout.VersionDir(root, "1.3.0")
		if exists(t, m, dir) {
			t.Fatal("the abandoned version directory survived the rollback")
		}
		if last, _ := open(t, m).Last(); last.State != txn.StateRolledBack {
			t.Fatalf("journal ends at %s, want ROLLED_BACK", last.State)
		}
	})
}

// A crash during Migrate leaves the journal at STAGED with the host's state
// half-changed. Migrator.Rollback is contractually safe after a partial Migrate,
// and this is the case it exists for.
func TestRecoverRollsBackAPartialMigration(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	stage(t, m, "1.3.0")
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged)

	mig := newRecorder(m)
	if err := txn.Recover(m, root, mig); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if mig.rolled != 1 {
		t.Fatalf("Rollback ran %d times, want once", mig.rolled)
	}
	if mig.seenFrom != "1.2.0" || mig.seenTo != "1.3.0" {
		t.Fatalf("Rollback saw %s->%s, want 1.2.0->1.3.0", mig.seenFrom, mig.seenTo)
	}
}

// At BEGIN nothing but the journal write has happened: the migration only starts
// after STAGED, so there is nothing for the host to undo.
func TestRecoverAtBeginDoesNotCallTheMigrator(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin)

	mig := newRecorder(m)
	if err := txn.Recover(m, root, mig); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if mig.rolled != 0 {
		t.Fatal("the host was asked to undo a migration that never started")
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
}

// A failed first install must leave no installation, not a dangling pointer.
func TestRecoverRollsBackAFirstInstall(t *testing.T) {
	m := newRoot(t)
	stage(t, m, "1.0.0")
	if err := layout.SetPointer(m, root, "1.0.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	journalAt(t, m, "", "1.0.0", txn.StateBegin, txn.StateStaged)

	mig := newRecorder(m)
	if err := txn.Recover(m, root, mig); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got := pointer(t, m); got != "" {
		t.Fatalf("current = %q, want no installation", got)
	}
	dir, _ := layout.VersionDir(root, "1.0.0")
	if exists(t, m, dir) {
		t.Fatal("the failed first install left its version directory behind")
	}
}

// Repointing at a version that is not on disk would produce an install that
// looks whole and cannot start. Refusing is the only honest answer.
func TestRecoverRefusesToRollBackToAMissingVersion(t *testing.T) {
	m := installed(t, []string{"1.3.0"}, "1.3.0")
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged)

	err := txn.Recover(m, root, newRecorder(m))
	if err == nil {
		t.Fatal("recovery repointed at a version that is not installed")
	}
	if !errors.Is(err, txn.ErrJournal) {
		t.Fatalf("error %v is not classified as ErrJournal", err)
	}
}

// If the host cannot undo its own migration, the journal must stay where it is
// so the next start tries again — recording a rollback that did not happen would
// mean the failure is never seen again.
func TestRecoverKeepsTheJournalWhenRollbackFails(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	stage(t, m, "1.3.0")
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged)

	mig := newRecorder(m)
	mig.failWith = errors.New("cannot undo the schema change")

	if err := txn.Recover(m, root, mig); err == nil {
		t.Fatal("a failed rollback was reported as a successful recovery")
	}
	if last, _ := open(t, m).Last(); last.State != txn.StateStaged {
		t.Fatalf("journal ends at %s, want it left at STAGED for the next attempt", last.State)
	}

	// The next start succeeds once the host can undo its change.
	mig.failWith = nil
	if err := txn.Recover(m, root, mig); err != nil {
		t.Fatalf("second Recover: %v", err)
	}
	if last, _ := open(t, m).Last(); last.State != txn.StateRolledBack {
		t.Fatalf("journal ends at %s, want ROLLED_BACK", last.State)
	}
}

// An install in a state this code did not produce is not repaired by guessing.
func TestRecoverRefusesAnInconsistentSwap(t *testing.T) {
	m := installed(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped)

	if err := txn.Recover(m, root, newRecorder(m)); err == nil {
		t.Fatal("a swap the filesystem contradicts was completed anyway")
	}
}

func TestRecoverIsIdempotent(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	stage(t, m, "1.3.0")
	journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged)
	mig := newRecorder(m)

	for i := 0; i < 3; i++ {
		if err := txn.Recover(m, root, mig); err != nil {
			t.Fatalf("Recover #%d: %v", i+1, err)
		}
		if got := pointer(t, m); got != "1.2.0" {
			t.Fatalf("after Recover #%d current = %q, want 1.2.0", i+1, got)
		}
	}
	if mig.rolled != 1 {
		t.Fatalf("Rollback ran %d times across three recoveries, want once", mig.rolled)
	}
}

func TestRecoverRejectsAnUnreadableJournal(t *testing.T) {
	m := installed(t, []string{"1.2.0"}, "1.2.0")
	if err := fsx.WriteFileAtomic(m, layout.Journal(root), []byte("{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := txn.Recover(m, root, nil); err == nil {
		t.Fatal("recovery ran against a journal it could not read")
	}
}

// The invariant the journal exists for: interrupt the transaction anywhere, and
// what remains after recovery is either entirely the old install or entirely the
// new one — including the state the migration keeps outside the install root.
func TestApplyIsAtomicAtEveryBoundary(t *testing.T) {
	const steps = 8
	for crashAt := 0; crashAt <= steps; crashAt++ {
		t.Run(fmt.Sprintf("crash-before-step-%d", crashAt), func(t *testing.T) {
			m := installed(t, []string{"1.2.0"}, "1.2.0")
			mig := newRecorder(m)
			if err := fsx.WriteFileAtomic(m, mig.marker(), []byte("1.2.0"), 0o644); err != nil {
				t.Fatalf("seed marker: %v", err)
			}
			j := open(t, m)
			hc := hook.Context{Ctx: context.Background(), FromVersion: "1.2.0", ToVersion: "1.3.0", Root: root}

			// Each step is one durable move of the transaction. Stopping before
			// step k models the process dying at that exact instant.
			transaction := []func() error{
				func() error { return j.Append(rec(txn.StateBegin, "1.2.0", "1.3.0")) },
				func() error { stage(t, m, "1.3.0"); return nil },
				func() error { return j.Append(rec(txn.StateStaged, "1.2.0", "1.3.0")) },
				func() error { return mig.Migrate(hc) },
				func() error { return j.Append(rec(txn.StateMigrated, "1.2.0", "1.3.0")) },
				func() error { return layout.SetPointer(m, root, "1.3.0") },
				func() error { return j.Append(rec(txn.StateSwapped, "1.2.0", "1.3.0")) },
				func() error {
					return layout.WriteInstall(m, root, layout.Install{
						Name: "acme-app", Version: "1.3.0", LayoutSchema: 1,
					})
				},
			}
			for i := 0; i < crashAt; i++ {
				if err := transaction[i](); err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
			}

			if err := txn.Recover(m, root, mig); err != nil {
				t.Fatalf("Recover: %v", err)
			}

			live := pointer(t, m)
			marker, err := fsx.ReadFile(m, mig.marker(), 64)
			if err != nil {
				t.Fatalf("read marker: %v", err)
			}
			switch live {
			case "1.2.0":
				if string(marker) != "1.2.0" {
					t.Fatalf("the old version is live but the host state says %q", marker)
				}
				dir, _ := layout.VersionDir(root, "1.3.0")
				if exists(t, m, dir) {
					t.Fatal("the old version is live but the new version directory is still there")
				}
			case "1.3.0":
				if string(marker) != "1.3.0" {
					t.Fatalf("the new version is live but the host state says %q", marker)
				}
				if got := stateVersion(t, m); got != "1.3.0" {
					t.Fatalf("the new version is live but the recorded state says %q", got)
				}
			default:
				t.Fatalf("current = %q: neither the old install nor the new one", live)
			}

			if exists(t, m, layout.Staging(root)) {
				t.Fatal("staging survived recovery")
			}
		})
	}
}
