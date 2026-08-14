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
	case ClassVerify, ClassDescriptor, ClassResolve:
	default:
		return c, fmt.Errorf("harness: %s: unknown error_class %q", dir, c.ErrorClass)
	}
	if c.Mutator == "" {
		return c, fmt.Errorf("harness: %s: no mutator", dir)
	}
	if _, ok := Mutators[c.Mutator]; !ok {
		return c, fmt.Errorf("harness: %s: unknown mutator %q", dir, c.Mutator)
	}
	return c, nil
}
