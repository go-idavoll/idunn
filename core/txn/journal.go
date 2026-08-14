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
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
)

// State is a journal record. The sequence is BEGIN -> (STAGED -> MIGRATED ->
// SWAPPED)* -> COMMITTED, or ROLLED_BACK. Values are persisted, so they are
// append-only: never renumber or reuse them.
type State string

const (
	StateBegin      State = "BEGIN"
	StateStaged     State = "STAGED"
	StateMigrated   State = "MIGRATED"
	StateSwapped    State = "SWAPPED"
	StateCommitted  State = "COMMITTED"
	StateRolledBack State = "ROLLED_BACK"
)

// Record is one durably written journal entry.
type Record struct {
	State       State      `json:"state"`
	FromVersion string     `json:"from_version"`
	ToVersion   string     `json:"to_version"`
	Phase       hook.Phase `json:"phase"`
}

// Journal appends transaction records durably (write + fsync + atomic rename) so
// recovery can always classify an interrupted transaction.
type Journal struct {
	// unexported: fs + path + last record.
}

// Open opens or creates the journal under root.
func Open(fs fsx.FS, root string) (*Journal, error) {
	panic("not implemented")
}

// Append durably records r. It returns only after the record has hit stable
// storage; a transaction step must not proceed before its record is durable.
func (j *Journal) Append(r Record) error {
	panic("not implemented")
}

// Last returns the most recent record, or false if the journal is empty.
func (j *Journal) Last() (Record, bool) {
	panic("not implemented")
}

// Recover inspects the journal after a crash and drives the install back to a
// valid state: a transaction past SWAPPED is completed, anything earlier is rolled
// back. It is idempotent and safe to call on every start.
func Recover(fs fsx.FS, root string, m hook.Migrator) error {
	panic("not implemented")
}
