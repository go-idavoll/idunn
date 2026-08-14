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

// Package timefloor is the monotonic known-good time floor (docs/design.md
// §14.7, threat T22).
//
// TUF judges metadata expiry against the local clock. That makes the clock an
// input to a security decision, and an input an attacker with local access — or
// a dead CMOS battery — can move. Turning the clock back far enough makes expired
// metadata look valid again, which is the freeze attack the timestamp role exists
// to prevent, re-opened from below.
//
// The defence is a floor rather than a second opinion about the time: the client
// remembers the highest point in time it has already legitimately been at, and
// refuses to operate when the clock is below it. Two things establish that point:
//
//   - The build time of the binary. A program cannot have been built after the
//     moment it runs, so a clock below it is wrong before anything else is known.
//   - The clock at the last successful metadata refresh. Whatever the true time
//     was then, the machine has been there, and it does not go back.
//
// What this package must never become is a second expiry check. It cannot make
// anything acceptable — it has no way to say yes, only to refuse — and go-tuf
// still judges expiry exactly as it did before (AGENTS.md §1.2). The metadata's
// own `expires` is deliberately not used as a floor: it lies in the future by
// construction, so treating it as a lower bound on "now" would refuse every
// honest clock.
package timefloor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
)

// ErrClockRollback reports a local clock below the known-good floor.
//
// It is its own class because it is the one failure in this area a user can
// usually fix themselves, and it is reported as clock_skew rather than as a
// verification failure for exactly that reason (§14.7).
var ErrClockRollback = errors.New("clock rollback")

// ErrFloor is the class of every other rejection here: a floor file that cannot
// be read, parsed, or written.
var ErrFloor = errors.New("time floor")

// Schema guards the on-disk format. An unknown value is refused rather than
// guessed at, like every other schema in this project.
const Schema = 1

// MaxLen bounds the floor file. It holds one timestamp; anything larger is not
// a floor file.
const MaxLen = 4 << 10

// record is the persisted floor.
type record struct {
	SchemaVersion int       `json:"schema_version"`
	KnownGood     time.Time `json:"known_good"`
}

// Floor reads and advances the known-good time of one installation.
//
// It lives in the install root rather than beside the TUF cache: the cache is
// disposable — clearing it is the first thing anyone tries when updates
// misbehave — and a defence that a routine cleanup silently disables is not one.
type Floor struct {
	// FS is the filesystem to persist through.
	FS fsx.FS

	// Root is the install root whose known-good time this is.
	Root string

	// BuildTime is when this client was built. Zero means the build did not
	// stamp one, and then only observed refreshes establish the floor.
	BuildTime time.Time
}

// KnownGood returns the floor: the later of the build time and the persisted
// known-good time. A zero return means nothing establishes a floor yet, which is
// the honest state of a fresh install built without a stamp.
func (f Floor) KnownGood() (time.Time, error) {
	if f.FS == nil {
		return time.Time{}, fmt.Errorf("%w: no filesystem", ErrFloor)
	}
	stored, err := f.read()
	if err != nil {
		return time.Time{}, err
	}
	if stored.After(f.BuildTime) {
		return stored, nil
	}
	return f.BuildTime.UTC().Truncate(time.Second), nil
}

// Check refuses a clock below the floor.
//
// The error names both times, because the whole point of the classification is
// that the operator can act on it: "your clock says X, this machine has already
// been at Y" is a fixable statement, "update failed" is not.
func (f Floor) Check(now time.Time) error {
	floor, err := f.KnownGood()
	if err != nil {
		return err
	}
	if floor.IsZero() {
		return nil
	}
	if now.UTC().Before(floor) {
		return fmt.Errorf("%w: the system clock reads %s, which is before %s — a time this installation has already passed; "+
			"updates stay paused until the clock is corrected",
			ErrClockRollback, now.UTC().Format(time.RFC3339), floor.Format(time.RFC3339))
	}
	return nil
}

// Observe raises the floor to now and persists it. It never lowers it: a clock
// that went backwards is what this is here to notice, not to record.
//
// It is called after a successful metadata refresh — the moment the client has
// verified that a repository it trusts is answering, so wherever the true time
// is, the machine has been at this local time with everything in order.
func (f Floor) Observe(now time.Time) error {
	if f.FS == nil {
		return fmt.Errorf("%w: no filesystem", ErrFloor)
	}
	now = now.UTC().Truncate(time.Second)
	stored, err := f.read()
	if err != nil {
		return err
	}
	if !now.After(stored) {
		return nil
	}

	raw, err := json.MarshalIndent(record{SchemaVersion: Schema, KnownGood: now}, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFloor, err)
	}
	raw = append(raw, '\n')

	if err := f.FS.MkdirAll(layout.Meta(f.Root), 0o700); err != nil {
		return fmt.Errorf("%w: %w", ErrFloor, err)
	}
	if err := fsx.WriteFileAtomic(f.FS, layout.Clock(f.Root), raw, 0o600); err != nil {
		return fmt.Errorf("%w: %w", ErrFloor, err)
	}
	return nil
}

// read returns the persisted known-good time, or the zero time when none has
// been recorded.
//
// Anything else — unreadable, malformed, an unknown schema — is an error rather
// than "no floor". A defence that disappears when its own state is damaged is
// not a defence, and this file is small enough that a damaged one means
// something happened worth stopping for.
func (f Floor) read() (time.Time, error) {
	raw, err := fsx.ReadFile(f.FS, layout.Clock(f.Root), MaxLen)
	if err != nil {
		if fsx.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("%w: read: %w", ErrFloor, err)
	}

	var rec record
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return time.Time{}, fmt.Errorf("%w: parse: %w", ErrFloor, err)
	}
	if dec.More() {
		return time.Time{}, fmt.Errorf("%w: parse: trailing data", ErrFloor)
	}
	if rec.SchemaVersion != Schema {
		return time.Time{}, fmt.Errorf("%w: schema_version %d is not %d", ErrFloor, rec.SchemaVersion, Schema)
	}
	if rec.KnownGood.IsZero() {
		return time.Time{}, fmt.Errorf("%w: known_good is not set", ErrFloor)
	}
	return rec.KnownGood.UTC().Truncate(time.Second), nil
}
