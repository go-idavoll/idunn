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

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Case is one attested step of a scenario: what was expected, whether it held,
// and the observed state that says so.
type Case struct {
	Name        string `json:"name"`
	Expect      string `json:"expect"`
	Status      string `json:"status"` // PASS or FAIL
	Attestation string `json:"attestation"`
}

// Report is one job's result: one scenario on one platform.
type Report struct {
	Scenario string `json:"scenario"`
	Platform string `json:"platform"`
	Commit   string `json:"commit"`
	Run      string `json:"run,omitempty"`
	Passed   bool   `json:"passed"`
	Cases    []Case `json:"cases"`
}

// statusPass is the one status that counts as passing; anything else fails.
const statusPass = "PASS"

// report reads the cases run.sh recorded — one per line, tab-separated name,
// expectation, status, attestation — writes them as JSON, and prints them as a
// Markdown table. It fails when any case failed or none was recorded, so the
// report is also the verdict.
func report(args []string, stdout io.Writer) error {
	fl := flag.NewFlagSet("report", flag.ContinueOnError)
	in := fl.String("results", "", "recorded cases (TSV)")
	out := fl.String("out", "", "JSON report to write")
	r := Report{}
	fl.StringVar(&r.Scenario, "scenario", "", "scenario name")
	fl.StringVar(&r.Platform, "platform", "", "os/arch")
	fl.StringVar(&r.Commit, "commit", "", "commit under test")
	fl.StringVar(&r.Run, "run", "", "CI run URL")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" {
		return errors.New("report: --results and --out are required")
	}

	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), "\t", 4)
		if len(fields) != 4 {
			return fmt.Errorf("report: malformed line %q", sc.Text())
		}
		r.Cases = append(r.Cases, Case{Name: fields[0], Expect: fields[1], Status: fields[2], Attestation: fields[3]})
	}
	if err := sc.Err(); err != nil {
		return err
	}
	r.Passed = len(r.Cases) > 0
	for _, c := range r.Cases {
		if c.Status != statusPass {
			r.Passed = false
		}
	}

	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o644); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(stdout, "### %s %s on %s\n\n| Case | Expected | Result | Attestation |\n|---|---|---|---|\n",
		verdict(r.Passed), r.Scenario, r.Platform); err != nil {
		return err
	}
	for _, c := range r.Cases {
		if _, err := fmt.Fprintf(stdout, "| %s | %s | %s %s | `%s` |\n",
			cell(c.Name), cell(c.Expect), verdict(c.Status == statusPass), c.Status, cell(c.Attestation)); err != nil {
			return err
		}
	}
	if !r.Passed {
		return fmt.Errorf("report: %s on %s did not pass", r.Scenario, r.Platform)
	}
	return nil
}

// summary merges job reports into one matrix of case by platform. A scenario
// that some platform never reported counts as a failure there: a job that died
// before writing its report must not read as green.
func summary(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: e2etool summary <report.json> [report.json ...]")
	}
	var reports []Report
	for _, p := range args {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r Report
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("summary: %s: %w", p, err)
		}
		reports = append(reports, r)
	}

	platforms, scenarios := map[string]bool{}, map[string]bool{}
	type key struct{ scenario, platform string }
	byKey := map[key]Report{}
	for _, r := range reports {
		platforms[r.Platform], scenarios[r.Scenario] = true, true
		byKey[key{r.Scenario, r.Platform}] = r
	}
	plats, scens := sortedKeys(platforms), sortedKeys(scenarios)

	failed := false
	if _, err := fmt.Fprintf(stdout, "## E2E update matrix\n\n| Scenario | Case | %s |\n|---|---|%s\n",
		strings.Join(plats, " | "), strings.Repeat("---|", len(plats))); err != nil {
		return err
	}
	for _, s := range scens {
		// Case order comes from the first platform that reported the scenario;
		// every platform runs the same script, so the lists agree.
		var names []string
		for _, p := range plats {
			if r, ok := byKey[key{s, p}]; ok {
				for _, c := range r.Cases {
					names = append(names, c.Name)
				}
				break
			}
		}
		for _, n := range names {
			row := []string{cell(s), cell(n)}
			for _, p := range plats {
				r, ok := byKey[key{s, p}]
				mark := "❔ missing"
				if ok {
					for _, c := range r.Cases {
						if c.Name == n {
							mark = verdict(c.Status == statusPass)
						}
					}
				}
				if mark != verdict(true) {
					failed = true
				}
				row = append(row, mark)
			}
			if _, err := fmt.Fprintf(stdout, "| %s |\n", strings.Join(row, " | ")); err != nil {
				return err
			}
		}
		for _, p := range plats {
			if r, ok := byKey[key{s, p}]; !ok || !r.Passed {
				failed = true
			}
		}
	}
	if failed {
		return errors.New("summary: not every case passed on every platform")
	}
	return nil
}

func verdict(ok bool) string {
	if ok {
		return "✅"
	}
	return "❌"
}

// cell keeps a value from breaking the Markdown table it is put in.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "`", "'", "\n", " ").Replace(s)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
