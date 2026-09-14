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
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math/rand"
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/delta"
	"github.com/go-idavoll/idunn/internal/layout"
)

// A payload target is content-addressed, so a test that wants a realistic route
// has to name its targets the way the repository does — the patch path the
// client asks for is derived from exactly these two names.
func payload(data []byte) string {
	sum := sha256.Sum256(data)
	return release.PayloadPath("1", sum[:])
}

// runtimeBytes is a stand-in for the big shared library a release is mostly
// made of: incompressible, so a small patch can only come from what two
// versions have in common.
func runtimeBytes(seed int64, size int) []byte {
	out := make([]byte, size)
	rand.New(rand.NewSource(seed)).Read(out)
	return out
}

// rebuilt is that library after a change: a stretch rewritten in place.
func rebuilt(base []byte, seed int64) []byte {
	out := append([]byte(nil), base...)
	rand.New(rand.NewSource(seed)).Read(out[len(out)/2 : len(out)/2+len(out)/64])
	return out
}

// repo is the fake trust client plus the patches the repository publishes
// between the payloads it holds.
type repo struct {
	*targets
	t *testing.T
}

func newRepo(t *testing.T, payloads ...[]byte) *repo {
	t.Helper()
	files := map[string][]byte{}
	for _, p := range payloads {
		files[payload(p)] = p
	}
	return &repo{targets: newTargets(files), t: t}
}

// publishPatch adds the patch from one payload to another, as the packer would.
func (r *repo) publishPatch(from, to []byte) string {
	r.t.Helper()
	path, ok := release.PatchPath(payload(from), payload(to))
	if !ok {
		r.t.Fatalf("no patch path between these payloads")
	}
	patch, err := delta.Diff(from, to)
	if err != nil {
		r.t.Fatalf("Diff: %v", err)
	}
	r.files[path] = patch
	return path
}

// installed writes a version directory holding one file and points current at
// it, which is what gives a patch its base.
func installedWith(t *testing.T, version, dst string, data []byte) *fsx.Mem {
	t.Helper()
	m := newRoot(t)
	dir, err := layout.VersionDir(root, version)
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	full := fsx.Join(dir, dst)
	if err := m.MkdirAll(fsx.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(m, full, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := layout.SetPointer(m, root, version); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	return m
}

// The case delta stage 2 exists for: the file changed, so reuse cannot have it,
// but it changed little, and the repository publishes the patch. The full
// target is made unfetchable, so a Stage that succeeds can only have patched.
func TestStagePatchesAChangedFile(t *testing.T) {
	const dst = "lib/libcef.so"
	old := runtimeBytes(1, 1<<16)
	newer := rebuilt(old, 2)

	r := newRepo(t, old, newer)
	r.publishPatch(old, newer)
	r.fail[payload(newer)] = errors.New("the full target must not be fetched")

	m := installedWith(t, "1.2.0", dst, old)
	s := &stage.Stager{FS: m, Trust: r, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(payload(newer), dst, release.KindLib, 0o644),
	), stage.Route{dst: {payload(old), payload(newer)}}); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	got, err := fsx.ReadFile(m, "/opt/app/versions/1.3.0/"+dst, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, newer) {
		t.Fatal("the staged file is not the target")
	}
}

// A client that skipped a release cannot jump: there is no patch from where it
// is to where it is going, only the ones between the releases it missed. So it
// walks them, and every intermediate result is verified before it becomes the
// base of the next hop.
func TestStageWalksAChainOfPatches(t *testing.T) {
	const dst = "lib/libcef.so"
	v1 := runtimeBytes(11, 1<<16)
	v2 := rebuilt(v1, 12)
	v3 := rebuilt(v2, 13)

	r := newRepo(t, v1, v2, v3)
	r.publishPatch(v1, v2)
	r.publishPatch(v2, v3)
	r.fail[payload(v3)] = errors.New("the full target must not be fetched")

	m := installedWith(t, "1.1.0", dst, v1)
	s := &stage.Stager{FS: m, Trust: r, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(payload(v3), dst, release.KindLib, 0o644),
	), stage.Route{dst: {payload(v1), payload(v2), payload(v3)}}); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	got, err := fsx.ReadFile(m, "/opt/app/versions/1.3.0/"+dst, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, v3) {
		t.Fatal("the walk did not arrive at the target")
	}
}

// When the repository publishes both the hops and the shortcut, the cheaper one
// wins — and cheaper is a question with an answer, because the size of every
// patch is in the signed metadata before any of it is fetched. Here the release
// in between rewrote half the file and put it back, so walking it costs far
// more than jumping over it.
func TestStagePrefersTheCheaperRoute(t *testing.T) {
	const dst = "lib/libcef.so"
	v1 := runtimeBytes(21, 1<<16)
	churned := runtimeBytes(22, 1<<16) // v2: unrelated bytes, an expensive hop
	v3 := rebuilt(v1, 23)              // v3: v1 again, with a small change

	r := newRepo(t, v1, churned, v3)
	viaV2a := r.publishPatch(v1, churned)
	viaV2b := r.publishPatch(churned, v3)
	direct := r.publishPatch(v1, v3)

	m := installedWith(t, "1.1.0", dst, v1)
	s := &stage.Stager{FS: m, Trust: r, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(payload(v3), dst, release.KindLib, 0o644),
	), stage.Route{dst: {payload(v1), payload(churned), payload(v3)}}); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(r.asked, direct) {
		t.Errorf("did not take the direct patch; fetched %v", r.asked)
	}
	if slices.Contains(r.asked, viaV2a) || slices.Contains(r.asked, viaV2b) {
		t.Errorf("walked the expensive route anyway; fetched %v", r.asked)
	}
}

// Patching is an optimisation, and every way it can fall short ends in the
// download it was trying to avoid — with the right bytes on disk either way.
func TestStageFallsBackToTheFullTarget(t *testing.T) {
	const dst = "lib/libcef.so"
	old := runtimeBytes(31, 1<<15)
	newer := rebuilt(old, 32)

	for name, setup := range map[string]func(*repo) stage.Route{
		"no patch is published": func(*repo) stage.Route {
			return stage.Route{dst: {payload(old), payload(newer)}}
		},
		"the patch reconstructs the wrong bytes": func(r *repo) stage.Route {
			// A patch that applies cleanly and produces something else: the
			// attack the signed hash of the result is there to catch (T21).
			path, _ := release.PatchPath(payload(old), payload(newer))
			poison, err := delta.Diff(old, rebuilt(old, 999))
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			r.files[path] = poison
			return stage.Route{dst: {payload(old), payload(newer)}}
		},
		"the patch is not a patch at all": func(r *repo) stage.Route {
			path, _ := release.PatchPath(payload(old), payload(newer))
			r.files[path] = []byte("not a patch")
			return stage.Route{dst: {payload(old), payload(newer)}}
		},
		"the patch costs more than the file": func(r *repo) stage.Route {
			path, _ := release.PatchPath(payload(old), payload(newer))
			// A "patch" that is a whole unrelated file's worth of literals.
			bloated, err := delta.Diff(nil, newer)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			r.files[path] = bloated
			return stage.Route{dst: {payload(old), payload(newer)}}
		},
		"the base is not on disk any more": func(r *repo) stage.Route {
			r.publishPatch(old, newer)
			return stage.Route{dst: {payload(runtimeBytes(33, 1<<15)), payload(newer)}}
		},
		"the route does not end at the file being staged": func(r *repo) stage.Route {
			r.publishPatch(old, newer)
			return stage.Route{dst: {payload(old), payload(runtimeBytes(34, 1<<15))}}
		},
		"there is no route for this destination": func(r *repo) stage.Route {
			r.publishPatch(old, newer)
			return stage.Route{"some/other/file": {payload(old), payload(newer)}}
		},
		"the patch cannot be fetched": func(r *repo) stage.Route {
			path := r.publishPatch(old, newer)
			r.fail[path] = errors.New("the patch target is gone")
			return stage.Route{dst: {payload(old), payload(newer)}}
		},
		"the published patch is empty": func(r *repo) stage.Route {
			path, _ := release.PatchPath(payload(old), payload(newer))
			r.files[path] = nil
			return stage.Route{dst: {payload(old), payload(newer)}}
		},
		"the size of the file being staged is unknown": func(r *repo) stage.Route {
			r.publishPatch(old, newer)
			r.lenErr[payload(newer)] = errors.New("no target info")
			return stage.Route{dst: {payload(old), payload(newer)}}
		},
		"a hop leads nowhere the metadata knows": func(r *repo) stage.Route {
			// The middle release has no patch leading into it, so no route
			// spans the walk even though its second half is published.
			middle := runtimeBytes(35, 1<<15)
			r.files[payload(middle)] = middle
			r.publishPatch(middle, newer)
			return stage.Route{dst: {payload(old), payload(middle), payload(newer)}}
		},
		"the base is published but not installed here": func(r *repo) stage.Route {
			// The walk starts from a release this machine never had: its
			// payload exists in the repository, so the patch is found, but
			// nothing on disk holds the bytes to apply it to.
			absent := rebuilt(newer, 36)
			r.files[payload(absent)] = absent
			r.publishPatch(absent, newer)
			return stage.Route{dst: {payload(absent), payload(newer)}}
		},
		"a hop lands on a payload of unknown size": func(r *repo) stage.Route {
			middle := rebuilt(old, 37)
			r.files[payload(middle)] = middle
			r.publishPatch(old, middle)
			r.publishPatch(middle, newer)
			r.lenErr[payload(middle)] = errors.New("no target info")
			return stage.Route{dst: {payload(old), payload(middle), payload(newer)}}
		},
		"the route names something that is not a payload": func(r *repo) stage.Route {
			r.files["targets/legacy-name"] = old
			return stage.Route{dst: {"targets/legacy-name", payload(newer)}}
		},
		"the route is a single release": func(r *repo) stage.Route {
			r.publishPatch(old, newer)
			return stage.Route{dst: {payload(newer)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRepo(t, old, newer)
			route := setup(r)

			m := installedWith(t, "1.2.0", dst, old)
			s := &stage.Stager{FS: m, Trust: r, Root: root}

			if _, err := s.Stage(context.Background(), descriptor(
				ref(payload(newer), dst, release.KindLib, 0o644),
			), route); err != nil {
				t.Fatalf("Stage: %v", err)
			}
			got, err := fsx.ReadFile(m, "/opt/app/versions/1.3.0/"+dst, 1<<20)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if !bytes.Equal(got, newer) {
				t.Fatal("the staged file is not the target")
			}
			if !slices.Contains(r.asked, payload(newer)) {
				t.Error("did not fall back to fetching the full target")
			}
		})
	}
}

// A file that did not change between two releases has the same
// content-addressed target at both, and there is no patch from a payload to
// itself. The walk has to see through that rather than give up on it.
func TestStageWalksPastAReleaseThatDidNotTouchTheFile(t *testing.T) {
	const dst = "lib/libcef.so"
	v1 := runtimeBytes(41, 1<<16)
	v3 := rebuilt(v1, 42)

	r := newRepo(t, v1, v3)
	r.publishPatch(v1, v3)
	r.fail[payload(v3)] = errors.New("the full target must not be fetched")

	m := installedWith(t, "1.1.0", dst, v1)
	s := &stage.Stager{FS: m, Trust: r, Root: root}

	// 1.2.0 shipped the same bytes as 1.1.0 for this file.
	if _, err := s.Stage(context.Background(), descriptor(
		ref(payload(v3), dst, release.KindLib, 0o644),
	), stage.Route{dst: {payload(v1), payload(v1), payload(v3)}}); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	got, err := fsx.ReadFile(m, "/opt/app/versions/1.3.0/"+dst, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, v3) {
		t.Fatal("the staged file is not the target")
	}
}

// An unchanged file is reused from disk and never patched: reuse is checked
// first because it is free, and a patch for it would not exist anyway.
func TestStagePrefersReuseOverPatching(t *testing.T) {
	const dst = "lib/libcef.so"
	same := runtimeBytes(51, 1<<15)

	r := newRepo(t, same)
	r.fail[payload(same)] = errors.New("nothing about this file needs the network")

	m := installedWith(t, "1.2.0", dst, same)
	s := &stage.Stager{FS: m, Trust: r, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(payload(same), dst, release.KindLib, 0o644),
	), stage.Route{dst: {payload(same), payload(same)}}); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(r.asked) != 0 {
		t.Errorf("fetched %v for a file that did not change", r.asked)
	}
}

// Patching cannot route around the target ceiling either (IDN-12). The patch
// itself is small, but what it would build is above what the trust client will
// allocate: the patch is never fetched, its base never read, and the full
// target is refused as well.
func TestStageDoesNotPatchTowardsATargetAboveTheCeiling(t *testing.T) {
	const dst = "lib/libcef.so"
	old := runtimeBytes(61, 1<<16)
	newer := rebuilt(old, 62)

	r := newRepo(t, old, newer)
	patch := r.publishPatch(old, newer)
	r.ceiling = int64(len(newer)) - 1
	if int64(len(r.files[patch])) > r.ceiling {
		t.Fatal("the patch is above the ceiling itself; the case would be vacuous")
	}

	m := installedWith(t, "1.2.0", dst, old)
	base := "/opt/app/versions/1.2.0/" + dst
	opened := false
	m.Fail = func(op, name string) error {
		if op == "open" && name == base {
			opened = true
		}
		return nil
	}
	s := &stage.Stager{FS: m, Trust: r, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(payload(newer), dst, release.KindLib, 0o644),
	), stage.Route{dst: {payload(old), payload(newer)}}); err == nil {
		t.Fatal("staged a target above the ceiling")
	}
	if slices.Contains(r.asked, patch) {
		t.Error("fetched a patch towards a target above the ceiling")
	}
	if opened {
		t.Error("read a patch base for a target above the ceiling")
	}
}
