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
	"errors"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

const root = "/opt/app"

func newRoot(t *testing.T) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return m
}

func rec(state txn.State, from, to string) txn.Record {
	return txn.Record{State: state, Name: "acme-app", FromVersion: from, ToVersion: to}
}

func open(t *testing.T, f fsx.FS) *txn.Journal {
	t.Helper()
	j, err := txn.Open(f, root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return j
}

func appendAll(t *testing.T, j *txn.Journal, states ...txn.State) {
	t.Helper()
	for _, s := range states {
		if err := j.Append(rec(s, "1.2.0", "1.3.0")); err != nil {
			t.Fatalf("Append(%s): %v", s, err)
		}
	}
}

func TestJournalRoundTrip(t *testing.T) {
	m := newRoot(t)
	j := open(t, m)

	if _, ok := j.Last(); ok {
		t.Fatal("a fresh journal reported a record")
	}
	appendAll(t, j, txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted)

	last, ok := j.Last()
	if !ok || last.State != txn.StateCommitted {
		t.Fatalf("Last = %+v, %v", last, ok)
	}
	if got := len(j.Records()); got != 5 {
		t.Fatalf("%d records, want 5", got)
	}

	// A second process must read exactly the history the first one wrote —
	// that is the whole point of the file surviving the crash.
	reopened := open(t, m)
	got, ok := reopened.Last()
	if !ok || got != last {
		t.Fatalf("reopened Last = %+v, %v; want %+v", got, ok, last)
	}
}

func TestJournalRejectsIllegalTransitions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []txn.State
	}{
		{"opens with staged", []txn.State{txn.StateStaged}},
		{"skips staging", []txn.State{txn.StateBegin, txn.StateMigrated}},
		{"swaps before migrating", []txn.State{txn.StateBegin, txn.StateStaged, txn.StateSwapped}},
		{"commits before swapping", []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateCommitted}},
		{"continues after commit", []txn.State{
			txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped,
			txn.StateCommitted, txn.StateStaged,
		}},
		{"rolls back twice", []txn.State{txn.StateBegin, txn.StateRolledBack, txn.StateRolledBack}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRoot(t)
			j := open(t, m)

			var err error
			for _, s := range tc.steps {
				err = j.Append(rec(s, "1.2.0", "1.3.0"))
				if err != nil {
					break
				}
			}
			if err == nil {
				t.Fatalf("the sequence %v was accepted", tc.steps)
			}
			if !errors.Is(err, txn.ErrJournal) {
				t.Fatalf("error %v is not classified as ErrJournal", err)
			}
		})
	}
}

func TestJournalRejectsIncompleteRecords(t *testing.T) {
	m := newRoot(t)
	j := open(t, m)

	for _, tc := range []struct {
		name string
		r    txn.Record
	}{
		{"no state", txn.Record{Name: "acme-app", ToVersion: "1.3.0"}},
		{"unknown state", txn.Record{State: "SOMETHING", Name: "acme-app", ToVersion: "1.3.0"}},
		{"no target version", txn.Record{State: txn.StateBegin, Name: "acme-app"}},
		{"no name", txn.Record{State: txn.StateBegin, ToVersion: "1.3.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := j.Append(tc.r); err == nil {
				t.Fatalf("accepted %+v", tc.r)
			}
		})
	}
}

// The identity of a transaction is fixed once it opens. A record that changes it
// mid-flight would make recovery restore a version this transaction never had.
func TestJournalRejectsIdentityChange(t *testing.T) {
	for _, tc := range []struct {
		name string
		next txn.Record
	}{
		{"other target", rec(txn.StateStaged, "1.2.0", "1.4.0")},
		{"other source", rec(txn.StateStaged, "1.1.0", "1.3.0")},
		{"other application", txn.Record{
			State: txn.StateStaged, Name: "other-app", FromVersion: "1.2.0", ToVersion: "1.3.0",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRoot(t)
			j := open(t, m)
			appendAll(t, j, txn.StateBegin)
			if err := j.Append(tc.next); err == nil {
				t.Fatal("the transaction identity was allowed to change")
			}
		})
	}
}

// A new transaction supersedes the previous history, so the file cannot grow
// without bound over the life of an installation.
func TestJournalBeginResetsHistory(t *testing.T) {
	m := newRoot(t)
	j := open(t, m)
	appendAll(t, j, txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted)

	if err := j.Append(rec(txn.StateBegin, "1.3.0", "1.4.0")); err != nil {
		t.Fatalf("Append(BEGIN): %v", err)
	}
	records := j.Records()
	if len(records) != 1 || records[0].ToVersion != "1.4.0" {
		t.Fatalf("history is %+v, want only the new BEGIN", records)
	}
	if got := open(t, m).Records(); len(got) != 1 {
		t.Fatalf("on disk the history is %+v, want only the new BEGIN", got)
	}
}

// A journal we cannot read is not one we may act on: starting a fresh one would
// silently discard the record of an interrupted transaction.
func TestOpenRejectsCorruptJournal(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not json", "{"},
		{"trailing data", `{"schema_version":1,"records":[{"state":"BEGIN","name":"a","from_version":"","to_version":"1.3.0","phase":""}]} {}`},
		{"unknown schema", `{"schema_version":2,"records":[{"state":"BEGIN","name":"a","from_version":"","to_version":"1.3.0","phase":""}]}`},
		{"unknown field", `{"schema_version":1,"records":[],"extra":1}`},
		{"no records", `{"schema_version":1,"records":[]}`},
		{"does not open with begin", `{"schema_version":1,"records":[{"state":"COMMITTED","name":"a","from_version":"","to_version":"1.3.0","phase":""}]}`},
		{"impossible history", `{"schema_version":1,"records":[
			{"state":"BEGIN","name":"a","from_version":"","to_version":"1.3.0","phase":""},
			{"state":"COMMITTED","name":"a","from_version":"","to_version":"1.3.0","phase":""}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRoot(t)
			if err := m.MkdirAll(layout.Meta(root), 0o700); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := fsx.WriteFileAtomic(m, layout.Journal(root), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := txn.Open(m, root); err == nil {
				t.Fatal("a corrupt journal was accepted")
			}
		})
	}
}

func TestOpenRejectsOversizeJournal(t *testing.T) {
	m := newRoot(t)
	if err := m.MkdirAll(layout.Meta(root), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	body := `{"schema_version":1,"records":[` + strings.Repeat(" ", 128<<10) + `]}`
	if err := fsx.WriteFileAtomic(m, layout.Journal(root), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := txn.Open(m, root); err == nil {
		t.Fatal("an oversized journal was accepted")
	}
}

func TestOpenRequiresFilesystemAndRoot(t *testing.T) {
	if _, err := txn.Open(nil, root); err == nil {
		t.Fatal("Open accepted a nil filesystem")
	}
	if _, err := txn.Open(fsx.NewMem(), ""); err == nil {
		t.Fatal("Open accepted an empty root")
	}
}

// A record is only recorded once it is durable. If the write fails, the in-memory
// history must not advance either — otherwise the process would go on believing a
// step was journalled that a crash would show it was not.
func TestAppendDoesNotAdvanceOnWriteFailure(t *testing.T) {
	m := newRoot(t)
	j := open(t, m)
	appendAll(t, j, txn.StateBegin)

	m.Fail = func(op, name string) error {
		if op == "write" && strings.Contains(name, layout.JournalName) {
			return errors.New("disk full")
		}
		return nil
	}
	if err := j.Append(rec(txn.StateStaged, "1.2.0", "1.3.0")); err == nil {
		t.Fatal("a failed write was reported as a recorded step")
	}
	m.Fail = nil

	if last, _ := j.Last(); last.State != txn.StateBegin {
		t.Fatalf("in-memory history advanced to %s despite the failure", last.State)
	}
	if last, _ := open(t, m).Last(); last.State != txn.StateBegin {
		t.Fatalf("on-disk history advanced to %s despite the failure", last.State)
	}
}

func TestJournalPath(t *testing.T) {
	m := newRoot(t)
	if got := open(t, m).Path(); got != layout.Journal(root) {
		t.Fatalf("Path = %q, want %q", got, layout.Journal(root))
	}
}

func TestRecordsIsACopy(t *testing.T) {
	m := newRoot(t)
	j := open(t, m)
	appendAll(t, j, txn.StateBegin)

	records := j.Records()
	records[0].State = txn.StateCommitted
	if last, _ := j.Last(); last.State != txn.StateBegin {
		t.Fatal("Records handed out the journal's own storage")
	}
}

func TestPhaseIsRecorded(t *testing.T) {
	m := newRoot(t)
	j := open(t, m)
	r := rec(txn.StateBegin, "1.2.0", "1.3.0")
	r.Phase = hook.PhaseApply
	if err := j.Append(r); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if last, _ := open(t, m).Last(); last.Phase != hook.PhaseApply {
		t.Fatalf("phase %q survived as %q", hook.PhaseApply, last.Phase)
	}
}
