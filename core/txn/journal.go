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

// Package txn is the transaction journal that makes an update atomic across a
// crash: after any interruption the install is either fully old or fully new,
// never half. See docs/design.md §6.2.
package txn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/internal/layout"
)

// State is a journal record. The sequence is BEGIN -> (STAGED -> MIGRATED ->
// SWAPPED)* -> COMMITTED, or ROLLED_BACK. Values are persisted, so they are
// append-only: never renumber or reuse them.
type State string

// The journal states, in the order a successful transaction passes through them.
const (
	StateBegin      State = "BEGIN"
	StateStaged     State = "STAGED"
	StateMigrated   State = "MIGRATED"
	StateSwapped    State = "SWAPPED"
	StateCommitted  State = "COMMITTED"
	StateRolledBack State = "ROLLED_BACK"
)

// Record is one durably written journal entry.
//
// Name is part of the record because recovery has to be able to finish a
// transaction on its own. Completing an interrupted update means writing the
// install state, and that state names the application; asking the caller for it
// would mean a recovery that only works when the caller already knows what was
// being installed — which is exactly what it cannot know after a crash.
type Record struct {
	State       State      `json:"state"`
	Name        string     `json:"name"`
	FromVersion string     `json:"from_version"`
	ToVersion   string     `json:"to_version"`
	Phase       hook.Phase `json:"phase"`
}

// ErrJournal is the class of every rejection here: a malformed journal, an
// impossible state transition, a recovery that cannot reach a valid state.
var ErrJournal = errors.New("journal")

// JournalSchema is the on-disk format version. Unknown means unknown semantics,
// and a journal we cannot read is not one we may act on.
const JournalSchema = 1

// MaxRecords bounds one transaction's journal. A transaction writes at most six
// records; the ceiling exists so a corrupt or hostile file cannot be replayed
// into unbounded work.
const MaxRecords = 32

// MaxJournalLen bounds the file on disk.
const MaxJournalLen = 64 << 10

// document is the on-disk form. The whole document is rewritten atomically on
// every append rather than appended to in place: a torn append at the end of a
// log is exactly the state a crash produces, and a journal that can itself be
// half-written cannot certify that nothing else is.
type document struct {
	SchemaVersion int      `json:"schema_version"`
	Records       []Record `json:"records"`
}

// allowed lists the states each state may be followed by. A transition outside
// this table is a bug in the caller, and the journal refuses it rather than
// recording a history that recovery would then have to interpret.
var allowed = map[State][]State{
	StateBegin:      {StateStaged, StateRolledBack},
	StateStaged:     {StateMigrated, StateRolledBack},
	StateMigrated:   {StateSwapped, StateRolledBack},
	StateSwapped:    {StateCommitted, StateRolledBack},
	StateCommitted:  {StateBegin},
	StateRolledBack: {StateBegin},
}

// Journal appends transaction records durably (write + fsync + atomic rename) so
// recovery can always classify an interrupted transaction.
type Journal struct {
	fs      fsx.FS
	path    string
	root    string
	records []Record
}

// Open opens or creates the journal under root.
//
// A journal that exists but cannot be parsed is an error. The alternative —
// starting a fresh one — would silently discard the record of an interrupted
// transaction and let the next update run against a half-applied install.
func Open(f fsx.FS, root string) (*Journal, error) {
	if f == nil {
		return nil, fmt.Errorf("%w: no filesystem", ErrJournal)
	}
	if root == "" {
		return nil, fmt.Errorf("%w: no install root", ErrJournal)
	}

	j := &Journal{fs: f, path: layout.Journal(root), root: root}
	raw, err := fsx.ReadFile(f, j.path, MaxJournalLen)
	if err != nil {
		if fsx.IsNotExist(err) {
			return j, nil
		}
		return nil, fmt.Errorf("%w: read: %w", ErrJournal, err)
	}

	doc, err := parse(raw)
	if err != nil {
		return nil, err
	}
	j.records = doc.Records
	return j, nil
}

// parse decodes and validates a journal document.
func parse(raw []byte) (*document, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrJournal, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: parse: trailing data", ErrJournal)
	}
	if doc.SchemaVersion != JournalSchema {
		return nil, fmt.Errorf("%w: schema_version %d is not %d", ErrJournal, doc.SchemaVersion, JournalSchema)
	}
	if len(doc.Records) == 0 {
		return nil, fmt.Errorf("%w: no records", ErrJournal)
	}
	if len(doc.Records) > MaxRecords {
		return nil, fmt.Errorf("%w: %d records exceed the ceiling of %d", ErrJournal, len(doc.Records), MaxRecords)
	}

	// A stored history that could not have been produced by a legal sequence of
	// appends is corrupt, whatever produced it. Recovery reads the last record
	// and acts on it, so the history it comes from has to be one we could have
	// written.
	if doc.Records[0].State != StateBegin {
		return nil, fmt.Errorf("%w: history starts at %q, not %q", ErrJournal, doc.Records[0].State, StateBegin)
	}
	for i := 1; i < len(doc.Records); i++ {
		if err := checkTransition(doc.Records[i-1], doc.Records[i]); err != nil {
			return nil, err
		}
	}
	return &doc, nil
}

// checkTransition reports whether next may follow prev.
func checkTransition(prev, next Record) error {
	for _, s := range allowed[prev.State] {
		if s != next.State {
			continue
		}
		// Within one transaction the identity is fixed. A record that changes it
		// mid-flight would make recovery restore a version this transaction
		// never had, or write state for an application it never installed.
		if next.State != StateBegin &&
			(next.FromVersion != prev.FromVersion || next.ToVersion != prev.ToVersion || next.Name != prev.Name) {
			return fmt.Errorf("%w: %s changes the transaction from %s %s->%s to %s %s->%s",
				ErrJournal, next.State, prev.Name, prev.FromVersion, prev.ToVersion,
				next.Name, next.FromVersion, next.ToVersion)
		}
		return nil
	}
	return fmt.Errorf("%w: %q cannot follow %q", ErrJournal, next.State, prev.State)
}

// Append durably records r. It returns only after the record has hit stable
// storage; a transaction step must not proceed before its record is durable.
//
// A BEGIN starts a new history and replaces the previous one, which is why
// Recover must run before a new transaction opens: the record it would have
// acted on is gone afterwards.
func (j *Journal) Append(r Record) error {
	if r.State == "" {
		return fmt.Errorf("%w: record without a state", ErrJournal)
	}
	if _, known := allowed[r.State]; !known {
		return fmt.Errorf("%w: unknown state %q", ErrJournal, r.State)
	}
	if r.ToVersion == "" {
		return fmt.Errorf("%w: record without a target version", ErrJournal)
	}
	if r.Name == "" {
		return fmt.Errorf("%w: record without a name", ErrJournal)
	}

	next := append([]Record(nil), j.records...)
	switch {
	case len(j.records) == 0:
		if r.State != StateBegin {
			return fmt.Errorf("%w: a transaction must open with %q, not %q", ErrJournal, StateBegin, r.State)
		}
		next = []Record{r}
	case r.State == StateBegin:
		last := j.records[len(j.records)-1]
		if err := checkTransition(last, r); err != nil {
			return err
		}
		next = []Record{r}
	default:
		if err := checkTransition(j.records[len(j.records)-1], r); err != nil {
			return err
		}
		next = append(next, r)
	}
	if len(next) > MaxRecords {
		return fmt.Errorf("%w: more than %d records in one transaction", ErrJournal, MaxRecords)
	}

	raw, err := json.MarshalIndent(document{SchemaVersion: JournalSchema, Records: next}, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode: %w", ErrJournal, err)
	}
	raw = append(raw, '\n')

	if err := j.fs.MkdirAll(layout.Meta(j.root), 0o700); err != nil {
		return fmt.Errorf("%w: %w", ErrJournal, err)
	}
	if err := fsx.WriteFileAtomic(j.fs, j.path, raw, 0o600); err != nil {
		return fmt.Errorf("%w: %w", ErrJournal, err)
	}

	// The in-memory history advances only once the write is durable, so a
	// caller that ignores the error cannot go on believing a step was recorded.
	j.records = next
	return nil
}

// Last returns the most recent record, or false if the journal is empty.
func (j *Journal) Last() (Record, bool) {
	if len(j.records) == 0 {
		return Record{}, false
	}
	return j.records[len(j.records)-1], true
}

// Records returns a copy of the current history. It exists for tests and for
// operator tooling; nothing in the apply path decides on more than Last.
func (j *Journal) Records() []Record {
	return append([]Record(nil), j.records...)
}

// Path returns the journal's location.
func (j *Journal) Path() string { return j.path }
