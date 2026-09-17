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

package layout_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
)

func validProbation() layout.Probation {
	return layout.Probation{
		Version: "1.3.0", Previous: "1.2.0", Status: layout.ProbationActive,
		Attempts: 1, AttemptsAllowed: 3, Restarts: 1, RestartsAllowed: 2, RestartPending: true,
		Reason: "broken", Blocked: &layout.BlockedVersion{Version: "1.1.0", Reason: "older failure"},
	}
}

func TestProbationRoundTrips(t *testing.T) {
	m := newRoot(t)
	if p, err := layout.ReadProbation(m, root); p != nil || err != nil {
		t.Fatalf("ReadProbation on an empty root = %+v, %v", p, err)
	}
	want := validProbation()
	if err := layout.WriteProbation(m, root, want); err != nil {
		t.Fatalf("WriteProbation: %v", err)
	}
	got, err := layout.ReadProbation(m, root)
	if err != nil {
		t.Fatalf("ReadProbation: %v", err)
	}
	want.SchemaVersion = layout.ProbationSchema
	if got.Blocked == nil || *got.Blocked != *want.Blocked {
		t.Fatalf("blocked = %+v, want %+v", got.Blocked, want.Blocked)
	}
	got.Blocked, want.Blocked = nil, nil
	if *got != want {
		t.Fatalf("round trip = %+v, want %+v", *got, want)
	}
}

func TestWriteProbationRefusesAnInvalidRecord(t *testing.T) {
	for name, change := range map[string]func(*layout.Probation){
		"no version":          func(p *layout.Probation) { p.Version = "" },
		"path as version":     func(p *layout.Probation) { p.Version = "../1.3.0" },
		"no previous":         func(p *layout.Probation) { p.Previous = "" },
		"replaces itself":     func(p *layout.Probation) { p.Previous = p.Version },
		"unknown status":      func(p *layout.Probation) { p.Status = "healthy-ish" },
		"no attempts allowed": func(p *layout.Probation) { p.AttemptsAllowed = 0 },
		"too many attempts":   func(p *layout.Probation) { p.AttemptsAllowed = layout.MaxProbationAttempts + 1 },
		"negative restarts":   func(p *layout.Probation) { p.RestartsAllowed = -1 },
		"too many restarts":   func(p *layout.Probation) { p.RestartsAllowed = layout.MaxProbationRestarts + 1 },
		"attempts overrun":    func(p *layout.Probation) { p.Attempts = p.AttemptsAllowed + 2 },
		"negative attempts":   func(p *layout.Probation) { p.Attempts = -1 },
		"restarts overrun":    func(p *layout.Probation) { p.Restarts = p.RestartsAllowed + 2 },
		"control in reason":   func(p *layout.Probation) { p.Reason = "a\nb" },
		"blocked path":        func(p *layout.Probation) { p.Blocked.Version = "/etc" },
		"blocked control":     func(p *layout.Probation) { p.Blocked.Reason = "\x1b[31m" },
	} {
		t.Run(name, func(t *testing.T) {
			p := validProbation()
			change(&p)
			if err := layout.WriteProbation(newRoot(t), root, p); !errors.Is(err, layout.ErrLayout) {
				t.Fatalf("WriteProbation = %v, want ErrLayout", err)
			}
		})
	}
}

func TestReadProbationRefusesWhatItCannotTrust(t *testing.T) {
	for name, raw := range map[string]string{
		"malformed":      `{`,
		"unknown field":  `{"schema_version":1,"version":"1.3.0","previous":"1.2.0","status":"probation","attempts_allowed":1,"extra":true}`,
		"trailing data":  `{"schema_version":1,"version":"1.3.0","previous":"1.2.0","status":"probation","attempts_allowed":1} {}`,
		"unknown schema": `{"schema_version":2,"version":"1.3.0","previous":"1.2.0","status":"probation","attempts_allowed":1}`,
		"invalid record": `{"schema_version":1,"version":"1.3.0","previous":"1.3.0","status":"probation","attempts_allowed":1}`,
		"oversized":      strings.Repeat(" ", layout.MaxProbationLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			m := newRoot(t)
			if err := m.MkdirAll(layout.Meta(root), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := fsx.WriteFileAtomic(m, layout.ProbationFile(root), []byte(raw), 0o644); err != nil {
				t.Fatal(err)
			}
			if p, err := layout.ReadProbation(m, root); p != nil || !errors.Is(err, layout.ErrLayout) {
				t.Fatalf("ReadProbation = %+v, %v; want ErrLayout", p, err)
			}
		})
	}
}

func TestSanitizeReason(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "",
		"  plain  ":                    "plain",
		"line\nbreak\ttab\x00nul":      "line break tab nul",
		"\x1b[31mred\x1b[0m":           "[31mred [0m",
		"bad \xff utf8":                "bad � utf8",
		"schema 3 needs 1.2 or newer ": "schema 3 needs 1.2 or newer",
	} {
		if got := layout.SanitizeReason(in); got != want {
			t.Errorf("SanitizeReason(%q) = %q, want %q", in, got, want)
		}
	}

	long := strings.Repeat("ä", layout.MaxProbationReason) // two bytes each
	got := layout.SanitizeReason(long)
	if len(got) > layout.MaxProbationReason || !utf8.ValidString(got) {
		t.Fatalf("a long reason came back %d bytes, valid UTF-8 %v", len(got), utf8.ValidString(got))
	}
	if layout.SanitizeReason(got) != got {
		t.Fatal("SanitizeReason is not idempotent on a truncated reason")
	}
}

func validOutcome() layout.ProbationOutcome {
	return layout.ProbationOutcome{
		FromVersion: "1.2.0", ToVersion: "1.3.0", OS: "linux", Arch: "amd64",
		Result: layout.ProbationResultRolledBack, Class: layout.ProbationClassUnconfirmed,
		At: time.Date(2026, 9, 17, 8, 0, 0, 0, time.UTC),
	}
}

func TestProbationOutcomesRoundTrip(t *testing.T) {
	m := newRoot(t)
	if names, err := layout.ProbationOutcomeNames(m, root); names != nil || err != nil {
		t.Fatalf("names on an empty root = %v, %v", names, err)
	}
	o := validOutcome()
	// The same outcome written twice is one outcome.
	for range 2 {
		if err := layout.WriteProbationOutcome(m, root, o); err != nil {
			t.Fatalf("WriteProbationOutcome: %v", err)
		}
	}
	names, err := layout.ProbationOutcomeNames(m, root)
	if err != nil || len(names) != 1 {
		t.Fatalf("names = %v, %v", names, err)
	}
	got, err := layout.ReadProbationOutcome(m, root, names[0])
	if err != nil {
		t.Fatal(err)
	}
	o.SchemaVersion = layout.ProbationOutcomeSchema
	if *got != o {
		t.Fatalf("read %+v, want %+v", *got, o)
	}
	if err := layout.RemoveProbationOutcome(m, root, names[0]); err != nil {
		t.Fatal(err)
	}
	if names, _ := layout.ProbationOutcomeNames(m, root); len(names) != 0 {
		t.Fatalf("names after removal = %v", names)
	}
}

func TestProbationOutcomesStopAtTheCeiling(t *testing.T) {
	m := newRoot(t)
	for i := 0; i < layout.MaxProbationOutcomes; i++ {
		o := validOutcome()
		o.ToVersion = fmt.Sprintf("1.3.%d", i)
		if err := layout.WriteProbationOutcome(m, root, o); err != nil {
			t.Fatalf("outcome %d: %v", i, err)
		}
	}
	o := validOutcome()
	o.ToVersion = "2.0.0"
	if err := layout.WriteProbationOutcome(m, root, o); !errors.Is(err, layout.ErrLayout) {
		t.Fatalf("an outcome past the ceiling = %v, want ErrLayout", err)
	}
	// Rewriting one that is already waiting is not a new one.
	o.ToVersion = "1.3.0"
	if err := layout.WriteProbationOutcome(m, root, o); err != nil {
		t.Fatalf("rewriting a waiting outcome at the ceiling: %v", err)
	}
}

func TestProbationOutcomesRefuseWhatTheyCannotReport(t *testing.T) {
	for name, change := range map[string]func(*layout.ProbationOutcome){
		"bad from":       func(o *layout.ProbationOutcome) { o.FromVersion = "x" },
		"path as to":     func(o *layout.ProbationOutcome) { o.ToVersion = "../1.3.0" },
		"no os":          func(o *layout.ProbationOutcome) { o.OS = "" },
		"path in arch":   func(o *layout.ProbationOutcome) { o.Arch = "amd64/x" },
		"unknown result": func(o *layout.ProbationOutcome) { o.Result = "committed" },
		"free text":      func(o *layout.ProbationOutcome) { o.Class = "database schema 7" },
		"no time":        func(o *layout.ProbationOutcome) { o.At = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			o := validOutcome()
			change(&o)
			if err := layout.WriteProbationOutcome(newRoot(t), root, o); !errors.Is(err, layout.ErrLayout) {
				t.Fatalf("WriteProbationOutcome = %v, want ErrLayout", err)
			}
		})
	}

	m := newRoot(t)
	dir := layout.ProbationOutcomes(root)
	if err := m.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"a.json": `{"schema_version":2}`,
		"b.json": `{"schema_version":1,"from_version":"1.2.0","to_version":"1.3.0","os":"linux","arch":"amd64","result":"rolled_back","class":"unhealthy","at":"2026-09-17T08:00:00Z","reason":"x"}`,
	} {
		if err := fsx.WriteFileAtomic(m, dir+"/"+name, []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		if o, err := layout.ReadProbationOutcome(m, root, name); o != nil || !errors.Is(err, layout.ErrLayout) {
			t.Errorf("%s: ReadProbationOutcome = %+v, %v", name, o, err)
		}
	}
}
