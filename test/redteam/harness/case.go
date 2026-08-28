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

package harness

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// ErrorClass is the coarse taxonomy a rejection is checked against, so a case
// cannot pass by failing for an unrelated reason (a typo'd URL is not a defense).
type ErrorClass string

const (
	// ClassVerify is a rejection by the TUF trust layer: signature, threshold,
	// expiry, freshness, or a target that does not match its signed metadata.
	ClassVerify ErrorClass = "verify"
	// ClassDescriptor is a rejection by idunn's own descriptor/pointer ingest:
	// the document is authentic but malformed or dangerous.
	ClassDescriptor ErrorClass = "descriptor"
	// ClassResolve is a rejection because two authentic documents do not agree —
	// the pointer and the descriptor describe different releases or platforms.
	ClassResolve ErrorClass = "resolve"
	// ClassClock is a rejection by the monotonic known-good time floor: the
	// local clock is below a point this installation has already passed. The
	// repository may be flawless — the attack is on the client's environment,
	// not on the bytes it is served (§14.7, T22).
	ClassClock ErrorClass = "clock"
	// ClassDowngrade is a refusal by the app-level version floor: every
	// document is authentic and current, and the release they name is older
	// than what is already installed (§14.6, T19). TUF cannot catch it — a
	// publisher is entitled to point a channel wherever it likes; what is not
	// acceptable is walking an installation backwards without being told to.
	ClassDowngrade ErrorClass = "downgrade"
)

// ClockAttack is a manipulation of the client's clock rather than of the
// repository. It is a second axis of a case: every other class mutates what the
// server sends, this one changes what the client believes the time is.
type ClockAttack string

const (
	// ClockNone leaves the clock alone, which is what every repository case
	// wants.
	ClockNone ClockAttack = ""

	// ClockRollback turns the clock back after the client has already run, to
	// bring expired metadata back inside its validity window.
	ClockRollback ClockAttack = "rollback"
)

// HistoryAttack is an attack that needs the client to have run before. It is a
// third axis of a case: a repository mutation attacks the bytes, a clock attack
// attacks the machine, and this one attacks the *memory* — what the client
// already trusts, and what is already installed.
//
// These are the attacks TUF's freshness guarantees exist for, and none of them
// is expressible against a client with no past: served version 1 metadata is
// only a rollback if the client has seen version 5, and an older release is only
// a downgrade if something newer is installed.
type HistoryAttack string

const (
	// HistoryNone is a case that needs no prior run.
	HistoryNone HistoryAttack = ""

	// HistoryRollback serves metadata older than what the client already
	// trusts.
	HistoryRollback HistoryAttack = "rollback"

	// HistoryFreeze withholds new metadata: the server keeps handing out what
	// it handed out before, until it is stale.
	HistoryFreeze HistoryAttack = "freeze"

	// HistoryDowngrade moves the channel head below the installed version.
	HistoryDowngrade HistoryAttack = "downgrade"
)

// Case is one adversarial scenario, loaded from a case.yaml.
type Case struct {
	// Class is the attack family, taken from the directory layout.
	Class string `yaml:"class"`
	// Name is the case directory name.
	Name string `yaml:"-"`
	// Dir is the absolute path of the case directory.
	Dir string `yaml:"-"`

	Description string     `yaml:"description"`
	Expect      string     `yaml:"expect"`
	ErrorClass  ErrorClass `yaml:"error_class"`
	Mutator     string     `yaml:"mutator"`
	Notes       string     `yaml:"notes"`

	// Clock names an attack on the client's clock. A case that sets it needs no
	// mutator: the repository is the honest baseline, and what is tampered with
	// is the machine the client runs on.
	Clock ClockAttack `yaml:"clock"`

	// History names an attack that needs the client to have run before. Like
	// Clock it stands in for a mutator: the runner drives the two phases, and
	// the mutator field (if set) describes only the *first*, honest one.
	History HistoryAttack `yaml:"history"`
}

// LoadCases walks root (typically test/redteam/corpus) and returns every case in
// a stable order. Directories starting with "_" are skipped: `_proposed` is the
// agent's staging area and is never a merge gate.
func LoadCases(root string) ([]Case, error) {
	classes, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("harness: reading corpus: %w", err)
	}

	var cases []Case
	for _, class := range classes {
		if !class.IsDir() || class.Name()[0] == '_' {
			continue
		}
		names, err := os.ReadDir(filepath.Join(root, class.Name()))
		if err != nil {
			return nil, fmt.Errorf("harness: reading corpus class %s: %w", class.Name(), err)
		}
		for _, name := range names {
			if !name.IsDir() || name.Name()[0] == '_' {
				continue
			}
			dir := filepath.Join(root, class.Name(), name.Name())
			c, err := loadCase(dir)
			if err != nil {
				return nil, err
			}
			c.Name = name.Name()
			c.Dir = dir
			if c.Class == "" {
				c.Class = class.Name()
			}
			if c.Class != class.Name() {
				return nil, fmt.Errorf("harness: %s declares class %q but lives under %q", dir, c.Class, class.Name())
			}
			cases = append(cases, c)
		}
	}

	sort.Slice(cases, func(i, j int) bool {
		if cases[i].Class != cases[j].Class {
			return cases[i].Class < cases[j].Class
		}
		return cases[i].Name < cases[j].Name
	})
	return cases, nil
}

func loadCase(dir string) (Case, error) {
	var c Case
	raw, err := os.ReadFile(filepath.Join(dir, "case.yaml"))
	if err != nil {
		return c, fmt.Errorf("harness: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("harness: parsing %s/case.yaml: %w", dir, err)
	}

	// A corpus case that expects anything but "reject" would be a hole in the
	// ratchet, so the loader refuses to represent one.
	if c.Expect != "reject" {
		return c, fmt.Errorf("harness: %s: expect must be \"reject\", got %q", dir, c.Expect)
	}
	switch c.ErrorClass {
	case ClassVerify, ClassDescriptor, ClassResolve, ClassClock, ClassDowngrade:
	default:
		return c, fmt.Errorf("harness: %s: unknown error_class %q", dir, c.ErrorClass)
	}
	switch c.Clock {
	case ClockNone, ClockRollback:
	default:
		return c, fmt.Errorf("harness: %s: unknown clock %q", dir, c.Clock)
	}
	switch c.History {
	case HistoryNone, HistoryRollback, HistoryFreeze, HistoryDowngrade:
	default:
		return c, fmt.Errorf("harness: %s: unknown history %q", dir, c.History)
	}
	// Two axes that both drive the whole run would each have to decide what the
	// other does. Refusing the combination is cheaper than defining it, and no
	// attack so far needs both.
	if c.Clock != ClockNone && c.History != HistoryNone {
		return c, fmt.Errorf("harness: %s: a case attacks the clock or the client's history, not both", dir)
	}
	// A case attacks the repository, the clock, or the client's history — but it
	// has to attack something, or it is a baseline dressed up as an adversary.
	if c.Mutator == "" && c.Clock == ClockNone && c.History == HistoryNone {
		return c, fmt.Errorf("harness: %s: neither a mutator, a clock attack nor a history attack", dir)
	}
	if c.Mutator != "" {
		if _, ok := Mutators[c.Mutator]; !ok {
			return c, fmt.Errorf("harness: %s: unknown mutator %q", dir, c.Mutator)
		}
	}
	return c, nil
}
