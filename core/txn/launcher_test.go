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
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

func appendStates(t *testing.T, m *fsx.Mem, states ...txn.State) {
	t.Helper()
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		if err := j.Append(txn.Record{State: s, Name: "acme", FromVersion: "1.2.0", ToVersion: "1.3.0"}); err != nil {
			t.Fatal(err)
		}
	}
}

func stagedLauncher(t *testing.T, m *fsx.Mem) bool {
	t.Helper()
	next, _ := layout.LauncherNext(root, "acme")
	_, err := fsx.Lstat(m, next)
	if err != nil && !fsx.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

var committed = []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted}

// Both settle paths of a committed transaction — recovery on the next start and
// Rollback called on a transaction that turned out to be committed — promote
// its launcher before they sweep the staging tree it lives in.
func TestSettlingACommitPromotesItsLauncher(t *testing.T) {
	for name, settle := range map[string]func(m *fsx.Mem) error{
		"Recover":  func(m *fsx.Mem) error { return txn.Recover(m, root, nil) },
		"Rollback": func(m *fsx.Mem) error { return txn.Rollback(context.Background(), m, root, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			m := installed(t, []string{"1.2.0", "1.3.0"}, "1.3.0")
			appendStates(t, m, committed...)
			if err := layout.WriteLauncherPending(m, root, "1.3.0", "acme", []byte("launcher")); err != nil {
				t.Fatal(err)
			}
			if err := settle(m); err != nil {
				t.Fatal(err)
			}
			if !stagedLauncher(t, m) {
				t.Error("the committed update's launcher was swept away instead of staged")
			}
			if _, err := fsx.Lstat(m, layout.Staging(root)); !fsx.IsNotExist(err) {
				t.Errorf("the staging tree survived: %v", err)
			}
		})
	}
}

// Negative: a pending launcher that staging did not write fails recovery closed.
// Neither promoted nor swept: the staging tree stays for someone to look at, and
// no launcher is offered.
func TestAMalformedPendingLauncherFailsRecoveryClosed(t *testing.T) {
	m := installed(t, []string{"1.2.0", "1.3.0"}, "1.3.0")
	appendStates(t, m, committed...)
	dir, _ := layout.LauncherPendingDir(root, "1.3.0")
	for _, name := range []string{"acme", "other"} {
		if err := m.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := fsx.WriteFileAtomic(m, fsx.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := txn.Recover(m, root, nil)
	if !errors.Is(err, txn.ErrJournal) || !errors.Is(err, layout.ErrLayout) {
		t.Fatalf("Recover = %v, want a journal/layout refusal", err)
	}
	if stagedLauncher(t, m) {
		t.Error("a malformed pending launcher was staged")
	}
	if _, err := fsx.Lstat(m, dir); err != nil {
		t.Errorf("the evidence was swept: %v", err)
	}
}
