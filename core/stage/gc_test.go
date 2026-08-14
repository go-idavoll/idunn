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

package stage_test

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

// withVersions builds an install root holding the given version directories with
// `current` on live.
func withVersions(t *testing.T, live string, versions ...string) *fsx.Mem {
	t.Helper()
	m := newRoot(t)
	for _, v := range versions {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := m.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := fsx.WriteFileAtomic(m, fsx.Join(dir, "app"), []byte(v), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if live != "" {
		if err := layout.SetPointer(m, root, live); err != nil {
			t.Fatalf("SetPointer: %v", err)
		}
	}
	return m
}

func remaining(t *testing.T, m *fsx.Mem) []string {
	t.Helper()
	got, err := layout.InstalledVersions(m, root)
	if err != nil {
		t.Fatalf("InstalledVersions: %v", err)
	}
	sort.Strings(got)
	return got
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGCKeepsTheRetentionWindow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		live     string
		versions []string
		retain   int
		want     []string
	}{
		{
			name:     "keeps current and one predecessor",
			live:     "1.4.0",
			versions: []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0"},
			retain:   2,
			want:     []string{"1.3.0", "1.4.0"},
		},
		{
			name:     "a wider window keeps more",
			live:     "1.4.0",
			versions: []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0"},
			retain:   3,
			want:     []string{"1.2.0", "1.3.0", "1.4.0"},
		},
		{
			name:     "nothing to collect",
			live:     "1.4.0",
			versions: []string{"1.3.0", "1.4.0"},
			retain:   2,
			want:     []string{"1.3.0", "1.4.0"},
		},
		{
			name:     "ordering is by precedence, not by name",
			live:     "1.10.0",
			versions: []string{"1.2.0", "1.9.0", "1.10.0"},
			retain:   2,
			want:     []string{"1.9.0", "1.10.0"},
		},
		{
			// After a rollback the pointer sits below a newer tree. Deleting it
			// because it is "ahead" would remove the way forward.
			name:     "a newer version than the live one survives",
			live:     "1.3.0",
			versions: []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0"},
			retain:   2,
			want:     []string{"1.2.0", "1.3.0", "1.4.0"},
		},
		{
			name:     "pre-releases order below their release",
			live:     "1.3.0",
			versions: []string{"1.3.0-rc.1", "1.3.0-rc.2", "1.3.0"},
			retain:   2,
			want:     []string{"1.3.0-rc.2", "1.3.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := withVersions(t, tc.live, tc.versions...)
			s := &stage.Stager{FS: m, Root: root}

			if err := s.GC(tc.retain); err != nil {
				t.Fatalf("GC: %v", err)
			}
			got := remaining(t, m)
			sort.Strings(tc.want)
			if !equal(got, tc.want) {
				t.Fatalf("versions after GC = %v, want %v", got, tc.want)
			}
			// Whatever else happens, the running version must still be there.
			if live, _ := layout.PointerTarget(m, root); live != tc.live {
				t.Fatalf("current = %q after GC, want %q", live, tc.live)
			}
		})
	}
}

// A window below two would leave the running version with nothing to fall back
// to, which is the one thing the retained directories exist for.
func TestGCRefusesToLeaveNoRollbackTarget(t *testing.T) {
	m := withVersions(t, "1.3.0", "1.2.0", "1.3.0")
	s := &stage.Stager{FS: m, Root: root}

	for _, retain := range []int{-1, 0, 1} {
		if err := s.GC(retain); err == nil {
			t.Fatalf("GC(%d) was accepted", retain)
		}
	}
	if got := remaining(t, m); len(got) != 2 {
		t.Fatalf("a refused GC still deleted something: %v", got)
	}
}

// With nothing installed, the version directories present belong to an
// interrupted first install that recovery is about to undo — not to the GC.
func TestGCDoesNothingWithoutAnInstall(t *testing.T) {
	m := withVersions(t, "", "1.0.0", "1.1.0")
	s := &stage.Stager{FS: m, Root: root}

	if err := s.GC(2); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if got := remaining(t, m); len(got) != 2 {
		t.Fatalf("GC deleted %v from a root with no installation", got)
	}
}

// A directory that will not go — the Windows sharing violation on a running
// binary — is its own error class. It is not a failed update, and rolling one
// back over it would be a far worse outcome than a directory left on disk.
func TestGCReportsUndeletableDirectoriesSeparately(t *testing.T) {
	m := withVersions(t, "1.4.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0")
	m.Fail = func(op, name string) error {
		if op == "removeall" && strings.HasSuffix(name, "versions/1.1.0") {
			return errors.New("the process cannot access the file")
		}
		return nil
	}
	s := &stage.Stager{FS: m, Root: root}

	err := s.GC(2)
	if err == nil {
		t.Fatal("GC hid a directory it could not remove")
	}
	if !errors.Is(err, stage.ErrIncompleteGC) {
		t.Fatalf("error %v is not classified as ErrIncompleteGC", err)
	}
	if errors.Is(err, stage.ErrStage) {
		t.Fatal("an undeletable directory was reported as a staging failure")
	}
	m.Fail = nil

	// Everything that could go, went: one stubborn directory does not stop the
	// rest, and the next cycle retries it.
	got := remaining(t, m)
	want := []string{"1.1.0", "1.3.0", "1.4.0"}
	if !equal(got, want) {
		t.Fatalf("versions after GC = %v, want %v", got, want)
	}
}

func TestGCRejectsAnUnusableStager(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *stage.Stager
	}{
		{"no filesystem", &stage.Stager{Root: root}},
		{"no root", &stage.Stager{FS: fsx.NewMem()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.s.GC(2); err == nil {
				t.Fatal("an unusable stager was allowed to collect")
			}
		})
	}
}

// GC reads the pointer to decide what to keep. A pointer it cannot trust means
// it cannot tell the running version from a deletable one.
func TestGCRefusesAnUnreadablePointer(t *testing.T) {
	m := withVersions(t, "", "1.2.0", "1.3.0")
	if err := m.Symlink("somewhere/else", layout.Current(root)); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	s := &stage.Stager{FS: m, Root: root}

	if err := s.GC(2); err == nil {
		t.Fatal("GC ran against a pointer it could not read")
	}
	if got := remaining(t, m); len(got) != 2 {
		t.Fatalf("a refused GC still deleted something: %v", got)
	}
}

// Intra-file binary deltas are stage 2 of §6.4 and are not implemented. Until
// they are, the honest answer is an error — never a best guess at the bytes.
func TestApplyPatchIsNotImplemented(t *testing.T) {
	got, err := stage.ApplyPatch([]byte("base"), []byte("patch"))
	if err == nil {
		t.Fatal("ApplyPatch claimed to have reconstructed a target")
	}
	if got != nil {
		t.Fatal("ApplyPatch returned bytes it cannot vouch for")
	}
	if !errors.Is(err, stage.ErrStage) {
		t.Fatalf("error %v is not classified as ErrStage", err)
	}
}
