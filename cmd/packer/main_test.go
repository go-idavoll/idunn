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
	"strings"
	"testing"
	"time"
)

// The reference time is an input. There is deliberately no fallback to the wall
// clock: silently stamping "when this ran" into signed metadata would make the
// output unreproducible without anyone noticing.
func TestReferenceTime(t *testing.T) {
	empty := func(string) (string, bool) { return "", false }

	got, err := referenceTime("2026-01-01T00:00:00Z", empty)
	if err != nil || !got.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("--now: %v (%v)", got, err)
	}

	epoch := func(name string) (string, bool) {
		if name == envSourceDateEpoch {
			return "1767225600", true
		}
		return "", false
	}
	got, err = referenceTime("", epoch)
	if err != nil || got.Unix() != 1767225600 {
		t.Errorf("%s: %v (%v)", envSourceDateEpoch, got, err)
	}

	// --now wins over the environment: the explicit input is the one the
	// operator can point at in a rebuild.
	got, err = referenceTime("2026-01-01T00:00:00Z", epoch)
	if err != nil || got.Unix() != time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("--now over env: %v (%v)", got, err)
	}

	for _, tt := range []struct {
		name, flag string
		env        func(string) (string, bool)
		want       string
	}{
		{"neither", "", empty, "no reference time"},
		{"not rfc3339", "yesterday", empty, "not RFC3339"},
		{"not a timestamp", "", func(string) (string, bool) { return "noon", true }, "not a Unix timestamp"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := referenceTime(tt.flag, tt.env); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// Exit codes are the contract with CI: a usage mistake is worth telling apart
// from a publish that was refused.
func TestRunExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, exitUsage},
		{"help", []string{"help"}, exitOK},
		{"unknown command", []string{"sign-root"}, exitUsage},
		{"no repo", []string{"publish", "--now", "2026-01-01T00:00:00Z"}, exitUsage},
		{"stray argument", []string{"publish", "--repo", "x", "extra"}, exitUsage},
		{"no reference time", []string{"publish", "--repo", "x"}, exitUsage},
		{"missing repository", []string{"publish", "--repo", "does-not-exist", "--now", "2026-01-01T00:00:00Z"}, exitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Errorf("run(%v) = %d, want %d (stderr: %s)", tt.args, got, tt.want, stderr.String())
			}
		})
	}
}

// The usage text names the key variables without ever naming a key.
func TestUsageDocumentsTheKeyEnvironment(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	for _, want := range []string{"TUF_TARGETS_KEY", "TUF_SNAPSHOT_KEY", "TUF_TIMESTAMP_KEY", "SOURCE_DATE_EPOCH"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage does not mention %s", want)
		}
	}
}
