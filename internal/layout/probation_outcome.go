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
	"sort"
	"strings"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
)

// ProbationOutcomesName is the directory of failed probations waiting to be
// reported (IDN-39).
const ProbationOutcomesName = "probation-outcomes"

// ProbationOutcomes is where the launcher leaves one file per failed probation
// for an updater with a Reporter to pick up.
func ProbationOutcomes(root string) string {
	return fsx.Join(root, MetaName, ProbationOutcomesName)
}

// ProbationOutcomeSchema is the format version of a pending outcome.
const ProbationOutcomeSchema = 1

// MaxProbationOutcomes bounds the pending outcomes. A host without a Reporter
// never collects them, and a machine that fails probation over and over must
// not fill its install root with the evidence: past the ceiling a new outcome
// is not written.
const MaxProbationOutcomes = 16

// maxProbationOutcomeLen bounds one file.
const maxProbationOutcomeLen = 4 << 10

// The results a failed probation is reported with. rolled_back is the
// transaction vocabulary's own word, so a publisher watching its rolled_back rate
// sees these too.
const (
	ProbationResultRolledBack = "rolled_back"
	ProbationResultKept       = "kept"
)

// The classes of a failed probation: why, as a word from a closed vocabulary.
// The application's own reason never leaves the machine — it is free text, and
// §14.5 sends none.
const (
	ProbationClassUnconfirmed = "unconfirmed" // attempts used up without MarkHealthy
	ProbationClassUnhealthy   = "unhealthy"   // MarkUnhealthy
	ProbationClassRestarts    = "restarts"    // more requested restarts than allowed
	ProbationClassReinstalled = "reinstalled" // a blocked version installed again
)

// ProbationOutcome is one failed probation waiting to be reported. It carries
// what hook.Outcome carries and nothing more.
type ProbationOutcome struct {
	SchemaVersion int       `json:"schema_version"`
	FromVersion   string    `json:"from_version"`
	ToVersion     string    `json:"to_version"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	Result        string    `json:"result"`
	Class         string    `json:"class"`
	At            time.Time `json:"at"`
}

// WriteProbationOutcome leaves o for the updater. It is named after the
// version and the class, so writing the same outcome twice — a rollback that
// is finished by a second start — reports it once, and it reports nothing when
// the ceiling is reached.
func WriteProbationOutcome(f fsx.FS, root string, o ProbationOutcome) error {
	o.SchemaVersion = ProbationOutcomeSchema
	if err := o.validate(); err != nil {
		return err
	}
	name := probationOutcomeName(o)
	pending, err := ProbationOutcomeNames(f, root)
	if err != nil {
		return err
	}
	if len(pending) >= MaxProbationOutcomes && !containsString(pending, name) {
		return fmt.Errorf("%w: %d probation outcomes are already waiting to be reported", ErrLayout, len(pending))
	}
	raw, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode probation outcome: %w", ErrLayout, err)
	}
	raw = append(raw, '\n')
	dir := ProbationOutcomes(root)
	if err := f.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if err := fsx.WriteFileAtomic(f, fsx.Join(dir, name), raw, MetaFileMode); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

// ProbationOutcomeNames lists the pending outcomes, oldest name first. Scratch
// files of an interrupted write are not outcomes.
func ProbationOutcomeNames(f fsx.FS, root string) ([]string, error) {
	entries, err := f.ReadDir(ProbationOutcomes(root))
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	var names []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".json") && !strings.Contains(n, ".idunn-") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

// ReadProbationOutcome reads one pending outcome by the name
// ProbationOutcomeNames listed.
func ReadProbationOutcome(f fsx.FS, root, name string) (*ProbationOutcome, error) {
	raw, err := fsx.ReadFile(f, fsx.Join(ProbationOutcomes(root), fsx.Base(name)), maxProbationOutcomeLen)
	if err != nil {
		return nil, fmt.Errorf("%w: read probation outcome: %w", ErrLayout, err)
	}
	var o ProbationOutcome
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("%w: parse probation outcome: %w", ErrLayout, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: parse probation outcome: trailing data", ErrLayout)
	}
	if o.SchemaVersion != ProbationOutcomeSchema {
		return nil, fmt.Errorf("%w: probation outcome schema_version %d is not %d", ErrLayout, o.SchemaVersion, ProbationOutcomeSchema)
	}
	if err := o.validate(); err != nil {
		return nil, err
	}
	return &o, nil
}

// RemoveProbationOutcome deletes one pending outcome once it was handled.
func RemoveProbationOutcome(f fsx.FS, root, name string) error {
	if err := f.RemoveAll(fsx.Join(ProbationOutcomes(root), fsx.Base(name))); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

func (o *ProbationOutcome) validate() error {
	if err := ValidateVersion(o.FromVersion); err != nil {
		return fmt.Errorf("%w: probation outcome from_version: %w", ErrLayout, err)
	}
	if err := ValidateVersion(o.ToVersion); err != nil {
		return fmt.Errorf("%w: probation outcome to_version: %w", ErrLayout, err)
	}
	if o.OS == "" || o.Arch == "" || strings.ContainsAny(o.OS+o.Arch, "/\\ ") {
		return fmt.Errorf("%w: probation outcome platform %q-%q", ErrLayout, o.OS, o.Arch)
	}
	switch o.Result {
	case ProbationResultRolledBack, ProbationResultKept:
	default:
		return fmt.Errorf("%w: unknown probation outcome result %q", ErrLayout, o.Result)
	}
	switch o.Class {
	case ProbationClassUnconfirmed, ProbationClassUnhealthy, ProbationClassRestarts, ProbationClassReinstalled:
	default:
		return fmt.Errorf("%w: unknown probation outcome class %q", ErrLayout, o.Class)
	}
	if o.At.IsZero() {
		return fmt.Errorf("%w: probation outcome has no time", ErrLayout)
	}
	return nil
}

func probationOutcomeName(o ProbationOutcome) string {
	return o.ToVersion + "_" + o.Result + "_" + o.Class + ".json"
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
