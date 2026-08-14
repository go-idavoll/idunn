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
	"sort"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

// The order below is the precedence example from SemVer 2.0.0 §11, which is the
// specification this ordering claims to implement. A change that breaks it either
// installs an old, vulnerable build or deletes the rollback target.
func TestCompareFollowsSemVerPrecedence(t *testing.T) {
	ascending := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.1.0",
		"2.0.0",
		"2.1.0",
		"2.1.1",
		"10.0.0",
	}
	for i := 0; i < len(ascending); i++ {
		for j := 0; j < len(ascending); j++ {
			got, err := release.Compare(ascending[i], ascending[j])
			if err != nil {
				t.Fatalf("Compare(%s, %s): %v", ascending[i], ascending[j], err)
			}
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", ascending[i], ascending[j], got, want)
			}
		}
	}
}

// Build metadata does not participate in precedence (SemVer §10). Two versions
// that differ only in it are the same release, and treating one as newer would
// let a rebuild masquerade as an update.
func TestCompareIgnoresBuildMetadata(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.3.0", "1.3.0+build.1"},
		{"1.3.0+build.1", "1.3.0+build.2"},
		{"1.3.0-rc.1+a", "1.3.0-rc.1+b"},
	} {
		got, err := release.Compare(pair[0], pair[1])
		if err != nil {
			t.Fatalf("Compare(%s, %s): %v", pair[0], pair[1], err)
		}
		if got != 0 {
			t.Errorf("Compare(%s, %s) = %d, want 0", pair[0], pair[1], got)
		}
	}
}

// A leading zero makes an identifier alphanumeric: "01" must not be read as 1.
func TestComparePreReleaseIdentifierKinds(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.0-1", "1.0.0-alpha", -1}, // numeric ranks below alphanumeric
		{"1.0.0-2", "1.0.0-10", -1},    // numeric compares numerically
		{"1.0.0-01", "1.0.0-2", 1},     // "01" is alphanumeric, so it sorts after
		{"1.0.0-alpha", "1.0.0-alpha", 0},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1}, // more fields wins when equal so far
	} {
		got, err := release.Compare(tc.a, tc.b)
		if err != nil {
			t.Fatalf("Compare(%s, %s): %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// A version we cannot order is a version we cannot make a trust decision about,
// so there is no silent answer to be had.
func TestCompareRejectsNonVersions(t *testing.T) {
	for _, tc := range [][2]string{
		{"latest", "1.3.0"},
		{"1.3.0", "v1.3.0"},
		{"", "1.3.0"},
		{"1.3", "1.3.0"},
	} {
		if _, err := release.Compare(tc[0], tc[1]); err == nil {
			t.Errorf("Compare(%q, %q) returned an ordering", tc[0], tc[1])
		}
		if _, err := release.Newer(tc[0], tc[1]); err == nil {
			t.Errorf("Newer(%q, %q) returned an answer", tc[0], tc[1])
		}
	}
}

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"1.3.0", "1.2.0", true},
		{"1.2.0", "1.3.0", false},
		{"1.3.0", "1.3.0", false},
		{"1.3.0", "1.3.0-rc.1", true},
	} {
		got, err := release.Newer(tc.a, tc.b)
		if err != nil {
			t.Fatalf("Newer(%s, %s): %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Errorf("Newer(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// Sorting is how the GC picks which version directories to keep, so the ordering
// has to be usable as a sort key and not just as a pairwise answer.
func TestCompareSortsVersionDirectories(t *testing.T) {
	got := []string{"1.10.0", "1.2.0", "1.3.0-rc.1", "1.3.0", "0.9.9"}
	sort.Slice(got, func(i, j int) bool {
		c, err := release.Compare(got[i], got[j])
		if err != nil {
			t.Fatalf("Compare: %v", err)
		}
		return c < 0
	})
	want := []string{"0.9.9", "1.2.0", "1.3.0-rc.1", "1.3.0", "1.10.0"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted = %v, want %v", got, want)
		}
	}
}
