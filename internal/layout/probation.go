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

package layout

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-idavoll/idunn/core/fsx"
)

// ProbationSchema is the format version of probation.json. Any other value is
// refused, like every other record under .updater/.
const ProbationSchema = 1

// Bounds on a probation record. They are ceilings for a file on disk, not
// defaults: a host that asks for more attempts or restarts than this is refused
// when it configures them, so a typo cannot turn probation into "never roll back".
const (
	MaxProbationAttempts = 20
	MaxProbationRestarts = 20
	MaxProbationReason   = 512
	MaxProbationLen      = 16 << 10
)

// ProbationStatus is where a version on probation stands. Values are persisted:
// never rename or reuse them.
type ProbationStatus string

const (
	// ProbationActive is a committed version that has not confirmed yet. Every
	// launcher start counts an attempt against it.
	ProbationActive ProbationStatus = "probation"

	// ProbationConfirmed is a version that reported itself healthy. Nothing
	// counts against it any more.
	ProbationConfirmed ProbationStatus = "confirmed"

	// ProbationUnhealthy is a version that reported itself unhealthy. The next
	// launcher start rolls it back without spending further attempts.
	ProbationUnhealthy ProbationStatus = "unhealthy"

	// ProbationReverting is a rollback that has started. It is the record that
	// makes the rollback crash-safe: a start that finds it finishes the rollback
	// before anything else, and every step of it can be repeated.
	ProbationReverting ProbationStatus = "reverting"

	// ProbationReverted is a version that was rolled back. Blocked names it
	// until another version is installed.
	ProbationReverted ProbationStatus = "reverted"

	// ProbationKept is a version that failed its probation and could not be
	// rolled back — its predecessor is gone. It stays live, and the reason says
	// why; nothing counts against it any more.
	ProbationKept ProbationStatus = "kept"
)

// Probation is the record of a committed version that has to show it is healthy
// (IDN-39).
//
// It is deliberately not part of the transaction journal. A rollback puts the
// previous version back, and with it that version's copy of this library, which
// may predate probation: a journal state it does not know would make its updater
// refuse the journal and never update again. This file is one it ignores.
//
// The pointer is the authority on which version runs, as everywhere else: a
// record for a version `current` does not name is stale — a transaction that
// rolled back, or a deferred one that has not been applied yet — and is left
// alone rather than acted on.
type Probation struct {
	SchemaVersion int `json:"schema_version"`

	// Version is the version on probation; Previous is the one it replaced,
	// which a rollback returns to.
	Version  string `json:"version"`
	Previous string `json:"previous"`

	Status ProbationStatus `json:"status"`

	// Attempts counts the launcher starts of Version that were not restarts the
	// application asked for; a start beyond AttemptsAllowed rolls it back.
	Attempts        int `json:"attempts"`
	AttemptsAllowed int `json:"attempts_allowed"`

	// Restarts counts the restarts the application asked for through
	// launch.Relaunch; RestartPending is set by the application before it
	// leaves and consumed by the next launcher start, which then counts no
	// attempt. A restart beyond RestartsAllowed rolls the version back too, so
	// an application that relaunches forever does not stay on probation forever.
	Restarts        int  `json:"restarts"`
	RestartsAllowed int  `json:"restarts_allowed"`
	RestartPending  bool `json:"restart_pending"`

	// Reason is why the version was reported unhealthy, rolled back or kept.
	Reason string `json:"reason,omitempty"`

	// Blocked is the last version rolled back for failing its probation. An
	// updater does not install it again; a newer release is offered as usual.
	Blocked *BlockedVersion `json:"blocked,omitempty"`
}

// BlockedVersion is a version an updater must not install again.
type BlockedVersion struct {
	Version string `json:"version"`
	Reason  string `json:"reason"`
}

// ReadProbation returns the probation record under root, or nil when there is
// none. Anything else that is not a valid record is an error, never "no
// probation": a record the launcher cannot read is not one it may silently
// forget, because forgetting it is what keeps a broken version live.
func ReadProbation(f fsx.FS, root string) (*Probation, error) {
	raw, err := fsx.ReadFile(f, ProbationFile(root), MaxProbationLen)
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: read probation: %w", ErrLayout, err)
	}
	var p Probation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: parse probation: %w", ErrLayout, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: parse probation: trailing data", ErrLayout)
	}
	if p.SchemaVersion != ProbationSchema {
		return nil, fmt.Errorf("%w: probation schema_version %d is not %d", ErrLayout, p.SchemaVersion, ProbationSchema)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// WriteProbation records p atomically.
func WriteProbation(f fsx.FS, root string, p Probation) error {
	p.SchemaVersion = ProbationSchema
	if err := p.validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode probation: %w", ErrLayout, err)
	}
	raw = append(raw, '\n')
	if err := f.MkdirAll(Meta(root), DirMode); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if err := fsx.WriteFileAtomic(f, ProbationFile(root), raw, MetaFileMode); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

func (p *Probation) validate() error {
	if err := ValidateVersion(p.Version); err != nil {
		return fmt.Errorf("%w: probation version: %w", ErrLayout, err)
	}
	if err := ValidateVersion(p.Previous); err != nil {
		return fmt.Errorf("%w: probation previous version: %w", ErrLayout, err)
	}
	if p.Version == p.Previous {
		return fmt.Errorf("%w: probation of %s replaces itself", ErrLayout, p.Version)
	}
	switch p.Status {
	case ProbationActive, ProbationConfirmed, ProbationUnhealthy, ProbationReverting, ProbationReverted, ProbationKept:
	default:
		return fmt.Errorf("%w: unknown probation status %q", ErrLayout, p.Status)
	}
	if p.AttemptsAllowed < 1 || p.AttemptsAllowed > MaxProbationAttempts {
		return fmt.Errorf("%w: probation attempts_allowed %d is not within 1..%d", ErrLayout, p.AttemptsAllowed, MaxProbationAttempts)
	}
	if p.RestartsAllowed < 0 || p.RestartsAllowed > MaxProbationRestarts {
		return fmt.Errorf("%w: probation restarts_allowed %d is not within 0..%d", ErrLayout, p.RestartsAllowed, MaxProbationRestarts)
	}
	// One past the allowance is what a start records before it rolls back.
	if p.Attempts < 0 || p.Attempts > p.AttemptsAllowed+1 {
		return fmt.Errorf("%w: probation attempts %d is not within 0..%d", ErrLayout, p.Attempts, p.AttemptsAllowed+1)
	}
	if p.Restarts < 0 || p.Restarts > p.RestartsAllowed+1 {
		return fmt.Errorf("%w: probation restarts %d is not within 0..%d", ErrLayout, p.Restarts, p.RestartsAllowed+1)
	}
	if p.Reason != SanitizeReason(p.Reason) {
		return fmt.Errorf("%w: probation reason is not a sanitized reason", ErrLayout)
	}
	if b := p.Blocked; b != nil {
		if err := ValidateVersion(b.Version); err != nil {
			return fmt.Errorf("%w: blocked version: %w", ErrLayout, err)
		}
		if b.Reason != SanitizeReason(b.Reason) {
			return fmt.Errorf("%w: blocked reason is not a sanitized reason", ErrLayout)
		}
	}
	return nil
}

// SanitizeReason makes an application's own words safe to store, log and show:
// valid UTF-8, no control characters, no surrounding space, at most
// MaxProbationReason bytes cut at a character boundary. The reason travels to
// hooks, telemetry and a UI sidecar, none of which should have to defend against
// what an application put in it.
func SanitizeReason(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= MaxProbationReason {
		return s
	}
	cut := MaxProbationReason
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}
