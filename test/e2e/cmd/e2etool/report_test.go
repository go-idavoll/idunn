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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeResults(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "results.tsv")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runReport(t *testing.T, results, scenario, platform string) (Report, string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), scenario+"-"+strings.ReplaceAll(platform, "/", "-")+".json")
	var md bytes.Buffer
	err := report([]string{"--results", results, "--out", out, "--scenario", scenario, "--platform", platform, "--commit", "abc"}, &md)
	raw, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var r Report
	if jerr := json.Unmarshal(raw, &r); jerr != nil {
		t.Fatal(jerr)
	}
	return r, md.String(), err
}

func TestReportPassesOnlyWhenEveryCasePasses(t *testing.T) {
	ok := writeResults(t,
		"install 1.0.0\tinstalls\tPASS\trc=0 installed=1.0.0",
		"minor update 1.0.0 -> 1.1.0\tapplied\tPASS\trc=0 installed=1.1.0",
	)
	r, md, err := runReport(t, ok, "minor", "linux/amd64")
	if err != nil || !r.Passed || len(r.Cases) != 2 {
		t.Fatalf("passing results: err=%v passed=%v cases=%d", err, r.Passed, len(r.Cases))
	}
	if !strings.Contains(md, "| minor update 1.0.0 -> 1.1.0 | applied | ✅ PASS |") {
		t.Errorf("markdown lacks the case row:\n%s", md)
	}

	bad := writeResults(t,
		"install 1.0.0\tinstalls\tPASS\trc=0",
		"refuse\trefused\tFAIL\trc='0' want '3' | a|b",
	)
	r, md, err = runReport(t, bad, "floor-gap", "linux/amd64")
	if err == nil || r.Passed {
		t.Fatalf("failing results: err=%v passed=%v", err, r.Passed)
	}
	if !strings.Contains(md, `a\|b`) {
		t.Errorf("a pipe in an attestation must be escaped:\n%s", md)
	}
}

func TestReportWithNoCasesFails(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "results.tsv")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if r, _, err := runReport(t, empty, "minor", "linux/amd64"); err == nil || r.Passed {
		t.Fatalf("no cases: err=%v passed=%v", err, r.Passed)
	}
}

func writeReport(t *testing.T, r Report) string {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "r.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSummaryMatrix(t *testing.T) {
	pass := func(scenario, platform string) string {
		return writeReport(t, Report{Scenario: scenario, Platform: platform, Passed: true,
			Cases: []Case{{Name: "install 1.0.0", Status: statusPass}}})
	}

	var md bytes.Buffer
	if err := summary([]string{pass("minor", "linux/amd64"), pass("minor", "windows/amd64")}, &md); err != nil {
		t.Fatalf("all green: %v\n%s", err, md.String())
	}
	if !strings.Contains(md.String(), "| minor | install 1.0.0 | ✅ | ✅ |") {
		t.Errorf("matrix row missing:\n%s", md.String())
	}

	// A platform that reported another scenario but not this one is missing
	// there, and missing is not green.
	md.Reset()
	err := summary([]string{pass("minor", "linux/amd64"), pass("major", "windows/amd64")}, &md)
	if err == nil || !strings.Contains(md.String(), "❔ missing") {
		t.Fatalf("missing report: err=%v\n%s", err, md.String())
	}

	md.Reset()
	failed := writeReport(t, Report{Scenario: "minor", Platform: "darwin/arm64",
		Cases: []Case{{Name: "install 1.0.0", Status: "FAIL"}}})
	if err := summary([]string{pass("minor", "linux/amd64"), failed}, &md); err == nil {
		t.Fatalf("failed case passed the summary:\n%s", md.String())
	}
}
