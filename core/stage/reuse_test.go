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
	"context"
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

// installed puts a version directory on disk with the given files and points
// `current` at it, which is the state every reuse case starts from.
func installed(t *testing.T, m *fsx.Mem, version string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := fsx.Join(root, "versions", version, name)
		if err := m.MkdirAll(fsx.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fsx.WriteFileAtomic(m, full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := layout.SetPointer(m, root, version); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
}

// The point of delta stage 1's second half: a file that is already installed and
// still holds the signed bytes does not cross the wire again.
func TestAnUnchangedFileIsReusedFromTheInstalledVersion(t *testing.T) {
	m := newRoot(t)
	unchanged := "a library that did not change"
	installed(t, m, "1.2.0", map[string]string{"lib/plugin.so": unchanged})

	tr := newTargets(map[string][]byte{
		"payloads/v1/app": []byte("a new binary"),
		"payloads/v1/lib": []byte(unchanged),
	})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("payloads/v1/app", "app", release.KindExe, 0o755),
		ref("payloads/v1/lib", "lib/plugin.so", release.KindLib, 0o644),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if slices.Contains(tr.asked, "payloads/v1/lib") {
		t.Error("the unchanged file was fetched although an installed copy already held its bytes")
	}
	if !slices.Contains(tr.asked, "payloads/v1/app") {
		t.Error("the changed file was not fetched")
	}
	// Reuse is not a shortcut around producing a complete tree: blue/green
	// needs the new version directory to be self-contained (§6.1).
	if got := read(t, m, "/opt/app/versions/1.3.0/lib/plugin.so"); got != unchanged {
		t.Errorf("the reused file reads %q, want %q", got, unchanged)
	}
}

// The negative test the reuse exists under (AGENTS.md §1.5, §1.6): a local file
// with the right name and the right length and the wrong bytes is not the
// target, and no amount of it sitting in the install root makes it one.
func TestALocallyTamperedFileIsNeverReused(t *testing.T) {
	m := newRoot(t)
	real := "the library the publisher signed"
	fake := "the librarv the publisher signed" // same length, one byte apart.
	installed(t, m, "1.2.0", map[string]string{"lib/plugin.so": fake})

	tr := newTargets(map[string][]byte{"payloads/v1/lib": []byte(real)})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("payloads/v1/lib", "lib/plugin.so", release.KindLib, 0o644),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if !slices.Contains(tr.asked, "payloads/v1/lib") {
		t.Fatal("VULNERABILITY: a local file that does not match the signed target was adopted")
	}
	if got := read(t, m, "/opt/app/versions/1.3.0/lib/plugin.so"); got != real {
		t.Errorf("the staged file is %q, want the signed %q", got, real)
	}
}

// A candidate of the wrong size is skipped without being read, so a file that
// merely shares a name cannot cost anything.
func TestACandidateOfTheWrongLengthIsNotReused(t *testing.T) {
	m := newRoot(t)
	installed(t, m, "1.2.0", map[string]string{"lib/plugin.so": "short"})

	tr := newTargets(map[string][]byte{"payloads/v1/lib": []byte("a considerably longer library")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("payloads/v1/lib", "lib/plugin.so", release.KindLib, 0o644),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(tr.asked, "payloads/v1/lib") {
		t.Error("a candidate of the wrong length was reused")
	}
}

// A symlink where a candidate would be is skipped rather than followed. It is
// how a local attacker points the read at something that is not a file, and the
// answer is not worth obtaining that way.
func TestASymlinkedCandidateIsNotFollowed(t *testing.T) {
	m := newRoot(t)
	content := "the library"
	installed(t, m, "1.2.0", map[string]string{"real/plugin.so": content})
	dir := fsx.Join(root, "versions", "1.2.0", "lib")
	if err := m.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.Symlink(fsx.Join(root, "versions", "1.2.0", "real", "plugin.so"),
		fsx.Join(dir, "plugin.so")); err != nil {
		t.Skipf("this filesystem cannot make symlinks: %v", err)
	}

	tr := newTargets(map[string][]byte{"payloads/v1/lib": []byte(content)})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("payloads/v1/lib", "lib/plugin.so", release.KindLib, 0o644),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(tr.asked, "payloads/v1/lib") {
		t.Error("the staging read through a symlink to decide on reuse")
	}
}

// A retained version is a reuse source too, not just the live one: that is what
// makes a rollback-then-forward cheap (§14.1's retention doubles as a relink
// source, §6.4).
func TestAFileIsReusedFromARetainedVersion(t *testing.T) {
	m := newRoot(t)
	old := "a file only the older version still has"
	installed(t, m, "1.1.0", map[string]string{"share/data": old})
	installed(t, m, "1.2.0", map[string]string{"app": "the live binary"})

	tr := newTargets(map[string][]byte{
		"payloads/v1/app":  []byte("a new binary"),
		"payloads/v1/data": []byte(old),
	})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("payloads/v1/app", "app", release.KindExe, 0o755),
		ref("payloads/v1/data", "share/data", release.KindData, 0o644),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if slices.Contains(tr.asked, "payloads/v1/data") {
		t.Error("a file present in a retained version was fetched anyway")
	}
}

// A first install has no past to reuse from, and must not trip over the absence.
func TestAFirstInstallReusesNothing(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{"payloads/v1/app": []byte("the binary")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("payloads/v1/app", "app", release.KindExe, 0o755),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(tr.asked, "payloads/v1/app") {
		t.Error("a first install claimed to reuse something")
	}
}
