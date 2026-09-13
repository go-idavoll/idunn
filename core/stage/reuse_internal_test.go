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

package stage

import (
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
)

const testRoot = "/opt/app"

func versionRoot(t *testing.T, versions ...string) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	for _, v := range versions {
		dir, err := layout.VersionDir(testRoot, v)
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := m.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	return m
}

// The order is the whole optimisation: the live version holds the file that was
// installed last and is the likeliest match, and after it the newest predecessor
// beats an older one. Getting this wrong costs reads, not correctness — which is
// exactly why it needs asserting rather than assuming.
func TestReuseSourcesAreOrderedByLikelihood(t *testing.T) {
	for _, tc := range []struct {
		name     string
		live     string
		staging  string
		versions []string
		want     []string
	}{
		{
			name:     "the live version first, then newest to oldest",
			live:     "1.1.0",
			staging:  "2.0.0",
			versions: []string{"1.0.0", "1.5.0", "1.1.0", "1.2.0"},
			want:     []string{"1.1.0", "1.5.0", "1.2.0", "1.0.0"},
		},
		{
			name:     "nothing installed yet",
			live:     "",
			staging:  "1.0.0",
			versions: nil,
			want:     nil,
		},
		{
			name:     "no live version, e.g. an interrupted first install",
			live:     "",
			staging:  "1.0.0",
			versions: []string{"0.9.0", "0.8.0"},
			want:     []string{"0.9.0", "0.8.0"},
		},
		{
			name:     "the version being staged is never its own source",
			live:     "1.0.0",
			staging:  "1.2.0",
			versions: []string{"1.0.0", "1.2.0"},
			want:     []string{"1.0.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Stager{FS: versionRoot(t, tc.versions...), Root: testRoot}

			var want []string
			for _, v := range tc.want {
				want = append(want, fsx.Join(layout.Versions(testRoot), v))
			}
			if got := s.reuseSources(tc.live, tc.staging); !slices.Equal(got, want) {
				t.Fatalf("reuseSources = %v, want %v", got, want)
			}
		})
	}
}

// An install root whose versions/ cannot be listed yields no sources rather than
// an error: reuse has a complete fallback, and a broken directory listing must
// not be able to stop an update that could still be fetched in full.
func TestReuseSourcesSurviveAnUnlistableRoot(t *testing.T) {
	m := fsx.NewMem()
	if err := m.MkdirAll(testRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// versions/ is a file, so the listing fails with something other than
	// "does not exist".
	if err := fsx.WriteFileAtomic(m, layout.Versions(testRoot), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := &Stager{FS: m, Root: testRoot}
	if got := s.reuseSources("1.0.0", "1.1.0"); got != nil {
		t.Fatalf("reuseSources = %v, want none", got)
	}
}
