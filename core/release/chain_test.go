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

package release_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

func TestChainWalksThePublishedReleases(t *testing.T) {
	for _, tc := range []struct {
		name      string
		available []string
		from, to  string
		want      []string
	}{
		{
			name:      "one hop",
			available: []string{"1.0.0", "1.1.0"},
			from:      "1.0.0", to: "1.1.0",
			want: []string{"1.0.0", "1.1.0"},
		},
		{
			name:      "the releases in between, in order",
			available: []string{"1.2.0", "1.0.0", "1.3.0", "1.1.0"},
			from:      "1.0.0", to: "1.3.0",
			want: []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0"},
		},
		{
			name:      "releases outside the walk are left out",
			available: []string{"0.9.0", "1.0.0", "1.1.0", "1.2.0", "2.0.0"},
			from:      "1.0.0", to: "1.1.0",
			want: []string{"1.0.0", "1.1.0"},
		},
		{
			name:      "across a major",
			available: []string{"1.9.0", "2.0.0", "2.1.0"},
			from:      "1.9.0", to: "2.1.0",
			want: []string{"1.9.0", "2.0.0", "2.1.0"},
		},
		{
			name:      "a prerelease on the way sorts where SemVer puts it",
			available: []string{"1.0.0", "1.1.0-rc.1", "1.1.0"},
			from:      "1.0.0", to: "1.1.0",
			want: []string{"1.0.0", "1.1.0-rc.1", "1.1.0"},
		},
		{
			name:      "entries that are not versions are ignored, not fatal",
			available: []string{"1.0.0", "latest", "", "v1.1.0", "1.1.0"},
			from:      "1.0.0", to: "1.1.0",
			want: []string{"1.0.0", "1.1.0"},
		},
		{
			name:      "the same version listed twice is one hop",
			available: []string{"1.0.0", "1.1.0", "1.0.0"},
			from:      "1.0.0", to: "1.1.0",
			want: []string{"1.0.0", "1.1.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := release.Chain(tc.available, tc.from, tc.to)
			if err != nil {
				t.Fatalf("Chain: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("Chain = %v, want %v", got, tc.want)
			}
		})
	}
}

// Everything a chain cannot answer unambiguously is an error, because the
// caller's fallback — fetching the full targets — is always available and always
// correct. Guessing here would be the only way to get it wrong.
func TestChainRefusesWhatItCannotWalk(t *testing.T) {
	for _, tc := range []struct {
		name      string
		available []string
		from, to  string
	}{
		{
			name:      "backwards",
			available: []string{"1.0.0", "1.1.0"},
			from:      "1.1.0", to: "1.0.0",
		},
		{
			name:      "to itself",
			available: []string{"1.0.0"},
			from:      "1.0.0", to: "1.0.0",
		},
		{
			name:      "the installed release is no longer published",
			available: []string{"1.1.0", "1.2.0"},
			from:      "1.0.0", to: "1.2.0",
		},
		{
			name:      "the target release is not published",
			available: []string{"1.0.0", "1.1.0"},
			from:      "1.0.0", to: "1.2.0",
		},
		{
			name:      "nothing is published",
			available: nil,
			from:      "1.0.0", to: "1.1.0",
		},
		{
			name:      "an end that is not a version",
			available: []string{"1.0.0", "1.1.0"},
			from:      "1.0", to: "1.1.0",
		},
		{
			name:      "a target that is not a version",
			available: []string{"1.0.0"},
			from:      "1.0.0", to: "newest",
		},
		{
			name:      "two releases of the same precedence",
			available: []string{"1.0.0", "1.1.0+build.1", "1.1.0+build.2"},
			from:      "1.0.0", to: "1.1.0+build.2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := release.Chain(tc.available, tc.from, tc.to)
			if err == nil {
				t.Fatalf("Chain returned %v for a walk it cannot make", got)
			}
			if !errors.Is(err, release.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if got != nil {
				t.Fatalf("Chain returned %v beside the error", got)
			}
		})
	}
}

// The path a descriptor lives at states which release it describes, and that is
// where the list of published versions comes from. Reading it back must accept
// exactly the paths DescriptorPath produces for this platform, and nothing that
// merely looks like one.
func TestVersionOfDescriptorPath(t *testing.T) {
	if got := release.DescriptorPath("linux", "amd64", "1.2.0"); got != "releases/linux-amd64/1.2.0.json" {
		t.Fatalf("DescriptorPath = %q; this test pins the inverse of it", got)
	}

	for path, want := range map[string]string{
		"releases/linux-amd64/1.2.0.json":       "1.2.0",
		"releases/linux-amd64/1.2.0-rc.1.json":  "1.2.0-rc.1",
		"releases/linux-amd64/10.20.30.json":    "10.20.30",
		"releases/linux-amd64/1.2.0+meta.json":  "1.2.0+meta",
		"releases/windows-amd64/1.2.0.json":     "",
		"releases/linux-arm64/1.2.0.json":       "",
		"releases/linux-amd64/1.2.0.txt":        "",
		"releases/linux-amd64/latest.json":      "",
		"releases/linux-amd64/sub/1.2.0.json":   "",
		"channels/stable/linux-amd64/1.2.0.jso": "",
		"payloads/v1/1.2.0.json":                "",
		"releases/linux-amd64/.json":            "",
		"releases/linux-amd64/1.2.0.json.bak":   "",
		"":                                      "",
	} {
		got, ok := release.VersionOfDescriptorPath(path, "linux", "amd64")
		if want == "" {
			if ok {
				t.Errorf("%q was read as version %q", path, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("%q read as (%q, %v), want %q", path, got, ok, want)
		}
	}
}
