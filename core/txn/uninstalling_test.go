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

	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

// An uninstall may follow any resting state, and only a resting state: an
// interrupted transaction has to be settled first, or the uninstall would record
// itself over a history recovery still needs.
func TestUninstallingFollowsOnlyARestingState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []txn.State
		ok    bool
	}{
		{"after a commit", []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted}, true},
		{"after a rollback", []txn.State{txn.StateBegin, txn.StateRolledBack}, true},
		{"after a deferral", []txn.State{txn.StateBegin, txn.StateStaged, txn.StateDeferred}, true},
		{"on an empty journal", nil, true},
		{"inside begin", []txn.State{txn.StateBegin}, false},
		{"inside staged", []txn.State{txn.StateBegin, txn.StateStaged}, false},
		{"inside migrated", []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated}, false},
		{"inside swapped", []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRoot(t)
			j := open(t, m)
			appendAll(t, j, tc.steps...)
			err := j.Append(rec(txn.StateUninstalling, "1.2.0", "1.3.0"))
			if tc.ok && err != nil {
				t.Fatalf("Append(UNINSTALLING): %v", err)
			}
			if !tc.ok && !errors.Is(err, txn.ErrJournal) {
				t.Fatalf("Append(UNINSTALLING) = %v, want a refusal", err)
			}
		})
	}
}

// Nothing follows an uninstall: not a new transaction, not a rollback, not a
// second uninstall record.
func TestNothingFollowsUninstalling(t *testing.T) {
	for _, next := range []txn.State{
		txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped,
		txn.StateCommitted, txn.StateRolledBack, txn.StateDeferred, txn.StateUninstalling,
	} {
		t.Run(string(next), func(t *testing.T) {
			m := newRoot(t)
			j := open(t, m)
			appendAll(t, j, txn.StateBegin, txn.StateRolledBack, txn.StateUninstalling)
			if err := j.Append(rec(next, "1.2.0", "1.3.0")); !errors.Is(err, txn.ErrJournal) {
				t.Fatalf("Append(%s) after UNINSTALLING = %v, want a refusal", next, err)
			}
			if last, _ := open(t, m).Last(); last.State != txn.StateUninstalling {
				t.Fatalf("the journal on disk moved on to %s", last.State)
			}
		})
	}
}

// A journal that opens with UNINSTALLING is one an uninstall wrote over an
// installation whose journal was gone. It is read back as such.
func TestAJournalMayOpenWithUninstalling(t *testing.T) {
	m := newRoot(t)
	j := open(t, m)
	if err := j.Append(rec(txn.StateUninstalling, "", "1.3.0")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	last, ok := open(t, m).Last()
	if !ok || last.State != txn.StateUninstalling || last.ToVersion != "1.3.0" {
		t.Fatalf("reopened Last = %+v, %v", last, ok)
	}
}

// Recovery, rollback and resuming a deferral all refuse a tree that is being
// uninstalled, and change nothing in it. Each of them would otherwise rebuild
// part of an installation an uninstall has begun to remove.
func TestRecoveryRefusesAnUninstallingRoot(t *testing.T) {
	m := installed(t, []string{"1.2.0", "1.3.0"}, "1.3.0")
	journalAt(t, m, "1.2.0", "1.3.0",
		txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted, txn.StateUninstalling)
	mig := newRecorder(m)

	if _, err := txn.RecoverResult(context.Background(), m, root, mig); !errors.Is(err, txn.ErrUninstalling) {
		t.Fatalf("RecoverResult = %v, want ErrUninstalling", err)
	}
	if err := txn.Recover(m, root, mig); !errors.Is(err, txn.ErrUninstalling) {
		t.Fatalf("Recover = %v, want ErrUninstalling", err)
	}
	if err := txn.Rollback(context.Background(), m, root, mig); !errors.Is(err, txn.ErrUninstalling) {
		t.Fatalf("Rollback = %v, want ErrUninstalling", err)
	}
	if !errors.Is(txn.ErrUninstalling, txn.ErrJournal) {
		t.Fatal("ErrUninstalling is not classified as a journal error")
	}
	res, err := txn.ResumeDeferred(context.Background(), m, root, mig, func(string) error {
		t.Fatal("ResumeDeferred swapped in a tree that is being uninstalled")
		return nil
	})
	if err != nil || res.Recovered {
		t.Fatalf("ResumeDeferred = %+v, %v; want nothing done", res, err)
	}

	if mig.migrated != 0 || mig.rolled != 0 {
		t.Fatalf("the migrator was called: migrate %d, rollback %d", mig.migrated, mig.rolled)
	}
	if got := pointer(t, m); got != "1.3.0" {
		t.Fatalf("pointer = %q, want it untouched at 1.3.0", got)
	}
	for _, v := range []string{"1.2.0", "1.3.0"} {
		dir, _ := layout.VersionDir(root, v)
		if !exists(t, m, dir) {
			t.Fatalf("%s was removed", dir)
		}
	}
	if last, _ := open(t, m).Last(); last.State != txn.StateUninstalling {
		t.Fatalf("journal = %s, want UNINSTALLING", last.State)
	}
}
