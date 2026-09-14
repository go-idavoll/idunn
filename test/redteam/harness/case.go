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
	// ClassPolicy is a rejection by the updater's app-level policy: every
	// document is authentic, signed and current, and this installation still
	// may not take the release they name — here, because it is older than what
	// is installed (Policy.AllowDowngrade, T3). TUF cannot catch that and should
	// not: a publisher may point a channel wherever it likes. What is refused is
	// walking an installation backwards without being told to.
	ClassPolicy ErrorClass = "policy"
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
// third axis of a case beside the repository and the clock: what is attacked is
// the client's memory — the metadata it already trusts, the release it already
// has installed.
//
// None of these is expressible against a client with no past. Version 1
// metadata is only a rollback to a client that has seen version 5; an older
// release is only a downgrade where something newer is installed; and a server
// that stops publishing only freezes a client that had something to be frozen
// on. So a history case runs in two phases against one served directory —
// publish honestly, let the client come to trust it, then change what the same
// URL answers — and the runner asserts that the first phase succeeded.
type HistoryAttack string

const (
	// HistoryNone is a case that needs no prior run.
	HistoryNone HistoryAttack = ""

	// HistoryRollback replays older, still validly signed metadata to a client
	// that already trusts newer.
	HistoryRollback HistoryAttack = "rollback"

	// HistoryFreeze withholds new metadata: the server keeps answering with
	// what the client already has, until that is past its expiry.
	HistoryFreeze HistoryAttack = "freeze"

	// HistoryDowngrade moves the channel head below the installed release while
	// every role version moves forward.
	HistoryDowngrade HistoryAttack = "downgrade"
)

// Expectation is what a case asserts about the client's behaviour.
type Expectation string

const (
	// ExpectReject is the ordinary one: the client refuses, with an error of the
	// declared class, and writes nothing.
	ExpectReject Expectation = "reject"

	// ExpectNoEffect is for an attack the client is not supposed to refuse —
	// only to be unaffected by. A delta patch is untrusted input with a signed
	// result: the client may fetch one, apply it, and throw the result away when
	// it does not rebuild the file it was supposed to. So the assertion is not a
	// refusal but something stricter: the update completes, every installed byte
	// is the signed target, and nothing the attacker chose is anywhere on the
	// machine. A case may only claim it where the client really did try the
	// attacker's input — the runner checks that too, or the case would pass by
	// never being exercised.
	ExpectNoEffect Expectation = "no-effect"
)

// Case is one adversarial scenario, loaded from a case.yaml.
type Case struct {
	// Class is the attack family, taken from the directory layout.
	Class string `yaml:"class"`
	// Name is the case directory name.
	Name string `yaml:"-"`
	// Dir is the absolute path of the case directory.
	Dir string `yaml:"-"`

	Description string      `yaml:"description"`
	Expect      Expectation `yaml:"expect"`
	ErrorClass  ErrorClass  `yaml:"error_class"`
	Mutator     string      `yaml:"mutator"`
	Notes       string      `yaml:"notes"`

	// Clock names an attack on the client's clock. A case that sets it needs no
	// mutator: the repository is the honest baseline, and what is tampered with
	// is the machine the client runs on.
	Clock ClockAttack `yaml:"clock"`

	// History names an attack on what the client already knows. Like Clock it
	// stands in for a mutator: the runner builds both phases itself from the
	// honest baseline, so the only difference between them is the attacker's
	// move.
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

	// Both expectations are hard assertions, and the loader refuses anything
	// that is neither: a corpus case that expects less than one of these would
	// be a hole in the ratchet.
	switch c.Expect {
	case ExpectReject:
		switch c.ErrorClass {
		case ClassVerify, ClassDescriptor, ClassResolve, ClassClock, ClassPolicy:
		default:
			return c, fmt.Errorf("harness: %s: unknown error_class %q", dir, c.ErrorClass)
		}
	case ExpectNoEffect:
		if c.ErrorClass != "" {
			return c, fmt.Errorf("harness: %s: expect %q describes an attack that is survived, not refused, so it takes no error_class",
				dir, c.Expect)
		}
		m, ok := Mutators[c.Mutator]
		if !ok || m.Previous == "" {
			return c, fmt.Errorf("harness: %s: expect %q needs a mutator that publishes a previous release to attack across",
				dir, c.Expect)
		}
	default:
		return c, fmt.Errorf("harness: %s: expect must be %q or %q, got %q", dir, ExpectReject, ExpectNoEffect, c.Expect)
	}
	switch c.Clock {
	case ClockNone, ClockRollback:
	default:
		return c, fmt.Errorf("harness: %s: unknown clock %q", dir, c.Clock)
	}
	switch c.History {
	case HistoryNone:
	case HistoryRollback, HistoryFreeze, HistoryDowngrade:
		// A history case owns both of its phases. A mutator on top would have
		// to say which phase it tampers with, a clock attack would decide the
		// time both run at, and an attack that is merely survived is not what
		// any of them promises. Refusing the combinations is cheaper than
		// defining them, and no attack so far needs one.
		if c.Mutator != "" || c.Clock != ClockNone || c.Expect != ExpectReject {
			return c, fmt.Errorf("harness: %s: history %q takes no mutator and no clock attack, and expects %q",
				dir, c.History, ExpectReject)
		}
	default:
		return c, fmt.Errorf("harness: %s: unknown history %q", dir, c.History)
	}
	// A case attacks the repository, the clock, both, or the client's history —
	// but it has to attack something, or it is a baseline dressed up as an
	// adversary.
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
