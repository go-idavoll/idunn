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
	"errors"
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

// install writes a version directory holding the given install-relative files.
func install(t *testing.T, m *fsx.Mem, version string, files map[string]string) string {
	t.Helper()
	dir, err := layout.VersionDir(root, version)
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	for dst, content := range files {
		full := fsx.Join(dir, dst)
		if err := m.MkdirAll(fsx.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := fsx.WriteFileAtomic(m, full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return dir
}

// offline is the fake trust client with the network taken away: any target it is
// asked for fails. A Stage that still succeeds can only have got its bytes from
// disk, which is the whole assertion of the reuse tests below.
func offline(t *testing.T, files map[string][]byte) *targets {
	t.Helper()
	tr := newTargets(files)
	for path := range files {
		tr.fail[path] = errors.New("target " + path + " must not be fetched")
	}
	return tr
}

// The unchanged file of a previous release comes off the disk. For a release
// whose bulk is a browser runtime, this is the difference between a few
// megabytes and a few hundred on every update (docs/design.md §6.4 stage 1).
func TestStageReusesAnUnchangedFileFromTheLiveVersion(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "the runtime"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	tr := offline(t, map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got := read(t, m, "/opt/app/versions/1.3.0/lib/libcef.so"); got != "the runtime" {
		t.Errorf("staged %q", got)
	}
	if len(tr.asked) != 0 {
		t.Errorf("fetched %v although the bytes were already installed", tr.asked)
	}
}

// A retained version counts as a source too, so a file that survived unchanged
// across two releases is still reused after one that replaced it (this is also
// what makes RetainVersions a delta knob, docs/design.md §14.1).
func TestStageReusesFromARetainedVersion(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.1.0", map[string]string{"lib/libcef.so": "the runtime"})
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "a different one"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	tr := offline(t, map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(tr.asked) != 0 {
		t.Errorf("fetched %v although a retained version held the bytes", tr.asked)
	}
}

// The negative case that decides whether reuse may exist at all: a local file
// that is the right size at the right place but the wrong content must not be
// adopted. Local tampering and bit rot are the same event to us, and both end in
// the signed bytes being fetched (AGENTS.md §1.5, T21).
func TestStageRefusesALocallyTamperedFile(t *testing.T) {
	for name, local := range map[string]string{
		"same length, different content": "the r0ntime",
		"truncated":                      "the runt",
		"appended to":                    "the runtime and more",
		"emptied":                        "",
	} {
		t.Run(name, func(t *testing.T) {
			m := newRoot(t)
			install(t, m, "1.2.0", map[string]string{"lib/libcef.so": local})
			if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
				t.Fatalf("SetPointer: %v", err)
			}

			tr := newTargets(map[string][]byte{"targets/libcef.so": []byte("the runtime")})
			s := &stage.Stager{FS: m, Trust: tr, Root: root}

			if _, err := s.Stage(context.Background(), descriptor(
				ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
			), nil); err != nil {
				t.Fatalf("Stage: %v", err)
			}
			if got := read(t, m, "/opt/app/versions/1.3.0/lib/libcef.so"); got != "the runtime" {
				t.Fatalf("staged %q, want the signed bytes", got)
			}
			if !slices.Contains(tr.asked, "targets/libcef.so") {
				t.Error("the tampered local file was adopted instead of fetching the target")
			}
		})
	}
}

// A symlink where a payload file belongs is not a reuse candidate. Its content
// would be verified like any other, so this is not what stops a substitution —
// it stops a bounded read of our own tree from becoming a read of whatever the
// link was aimed at.
func TestStageDoesNotFollowASymlinkedCandidate(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.2.0", map[string]string{"lib/other.so": "the runtime"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	dir, err := layout.VersionDir(root, "1.2.0")
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	if err := m.Symlink(fsx.Join(dir, "lib/other.so"), fsx.Join(dir, "lib/libcef.so")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	tr := newTargets(map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(tr.asked, "targets/libcef.so") {
		t.Error("read through a symlink instead of fetching the target")
	}
}

// Reuse is an optimisation, so every way of not being able to decide it ends in
// a fetch — never in a failed update, and never in bytes admitted without the
// verdict.
func TestStageFetchesWhenReuseCannotBeDecided(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  string
		content string
		setup   func(*targets)
	}{
		{
			name:    "the signed length is unavailable",
			target:  "targets/libcef.so",
			content: "the runtime",
			setup: func(tr *targets) {
				tr.lenErr["targets/libcef.so"] = errors.New("no target info")
			},
		},
		{
			name:    "the target is empty",
			target:  "targets/empty",
			content: "",
			setup:   func(*targets) {},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRoot(t)
			install(t, m, "1.2.0", map[string]string{"lib/libcef.so": tc.content})
			if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
				t.Fatalf("SetPointer: %v", err)
			}

			tr := newTargets(map[string][]byte{tc.target: []byte(tc.content)})
			tc.setup(tr)
			s := &stage.Stager{FS: m, Trust: tr, Root: root}

			if _, err := s.Stage(context.Background(), descriptor(
				ref(tc.target, "lib/libcef.so", release.KindLib, 0o644),
			), nil); err != nil {
				t.Fatalf("Stage: %v", err)
			}
			if got := read(t, m, "/opt/app/versions/1.3.0/lib/libcef.so"); got != tc.content {
				t.Fatalf("staged %q, want %q", got, tc.content)
			}
			if !slices.Contains(tr.asked, tc.target) {
				t.Error("neither reused nor fetched the target")
			}
		})
	}
}

// A destination that no installed version has is simply fetched — reuse keys on
// the destination a file lands at, which is where a file's lineage lives.
func TestStageFetchesANewDestination(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "the runtime"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	tr := newTargets(map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/moved/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(tr.asked, "targets/libcef.so") {
		t.Error("did not fetch a destination no installed version holds")
	}
}

// A candidate that cannot be read is not a failed update. The file is there and
// the right size, the read fails anyway — a permission, a bad sector, a locked
// file on Windows — and the target is fetched.
func TestStageFetchesWhenACandidateCannotBeRead(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "the runtime"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	tr := newTargets(map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}
	m.Fail = func(op, name string) error {
		if op == "open" && name == "/opt/app/versions/1.2.0/lib/libcef.so" {
			return errors.New("i/o error")
		}
		return nil
	}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got := read(t, m, "/opt/app/versions/1.3.0/lib/libcef.so"); got != "the runtime" {
		t.Fatalf("staged %q", got)
	}
	if !slices.Contains(tr.asked, "targets/libcef.so") {
		t.Error("an unreadable candidate did not fall back to a fetch")
	}
}

// Between the stat that sizes a candidate and the read that takes it, a local
// attacker may swap the file. Nothing in the check order prevents that, and
// nothing has to: the bytes that were actually read are the bytes that get
// verified, so the swap ends in a fetch rather than in a substituted payload.
func TestStageRefusesACandidateSwappedAfterTheSizeCheck(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "the runtime"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	tr := newTargets(map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}
	candidate := "/opt/app/versions/1.2.0/lib/libcef.so"
	m.Fail = func(op, name string) error {
		if op == "open" && name == candidate {
			// The hook runs without the filesystem lock, so it can plant the
			// swap in exactly the window a real attacker would use.
			if err := fsx.WriteFileAtomic(m, candidate, []byte("evil payload"), 0o644); err != nil {
				t.Errorf("swap: %v", err)
			}
		}
		return nil
	}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got := read(t, m, "/opt/app/versions/1.3.0/lib/libcef.so"); got != "the runtime" {
		t.Fatalf("staged %q, want the signed bytes", got)
	}
	if !slices.Contains(tr.asked, "targets/libcef.so") {
		t.Error("the swapped candidate was adopted instead of fetching the target")
	}
}

// The trust client's target ceiling (IDN-12) is not something reuse can route
// around. A file already on disk holds exactly the signed bytes, but the signed
// length is above what the client will allocate: the candidate is not even
// opened, the fetch is refused too, and nothing is staged. Reuse degrades into a
// download, and a download of this target is refused — so the update fails.
func TestStageRefusesAReusableTargetAboveTheCeiling(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "the runtime"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	tr := newTargets(map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	tr.ceiling = int64(len("the runtime")) - 1
	candidate := "/opt/app/versions/1.2.0/lib/libcef.so"
	opened := false
	m.Fail = func(op, name string) error {
		if op == "open" && name == candidate {
			opened = true
		}
		return nil
	}
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err == nil {
		t.Fatal("staged a target above the ceiling")
	}
	if opened {
		t.Error("the candidate was read although its signed length is refused")
	}
	if _, err := fsx.Lstat(m, "/opt/app/versions/1.3.0"); !fsx.IsNotExist(err) {
		t.Errorf("a version directory exists after the refusal: %v", err)
	}
}
