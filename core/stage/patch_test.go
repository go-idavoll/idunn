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
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/delta"
)

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Delta stage 2 from the client's side: an installed file that is *not* the
// target may still be most of it, and the patch that connects them is named by
// convention rather than pointed at by the descriptor.
func TestAPublishedPatchIsUsedInsteadOfTheFullTarget(t *testing.T) {
	m := newRoot(t)
	old := []byte("the application, version one, with a great deal of unchanged content")
	next := []byte("the application, version two, with a great deal of unchanged content")
	installed(t, m, "1.2.0", map[string]string{"app": string(old)})

	target := "payloads/v1/" + sha(next)
	tr := newTargets(map[string][]byte{
		target: next,
		release.PatchPath("1", sha(old), sha(next)): delta.Diff(old, next),
	})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(target, "app", release.KindExe, 0o755),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if slices.Contains(tr.asked, target) {
		t.Error("the full payload was fetched although a patch to it was published")
	}
	if got := read(t, m, "/opt/app/versions/1.3.0/app"); got != string(next) {
		t.Errorf("the reconstructed file reads %q, want the target", got)
	}
}

// A patch that reconstructs something else is not a fallback and not a fault to
// work around: it is discarded, and the full target is fetched instead.
func TestAPatchThatReconstructsTheWrongBytesIsDiscarded(t *testing.T) {
	m := newRoot(t)
	old := []byte("the application, version one, with a great deal of unchanged content")
	next := []byte("the application, version two, with a great deal of unchanged content")
	evil := []byte("the application, version EVIL, with a great deal of unchanged content")
	installed(t, m, "1.2.0", map[string]string{"app": string(old)})

	target := "payloads/v1/" + sha(next)
	tr := newTargets(map[string][]byte{
		target: next,
		// Published at the path that promises `next`, reconstructing `evil`.
		release.PatchPath("1", sha(old), sha(next)): delta.Diff(old, evil),
	})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(target, "app", release.KindExe, 0o755),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if !slices.Contains(tr.asked, target) {
		t.Fatal("VULNERABILITY: a patch reconstructing the wrong bytes was installed")
	}
	if got := read(t, m, "/opt/app/versions/1.3.0/app"); got != string(next) {
		t.Errorf("the staged file reads %q, want the signed target", got)
	}
}

// Garbage where a patch should be costs a fallback and nothing else. There is no
// input here that turns into an install, which is why the apply side is allowed
// to be as simple as it is.
func TestAGarbagePatchFallsBackToTheFullTarget(t *testing.T) {
	m := newRoot(t)
	old := []byte("version one")
	next := []byte("version two")
	installed(t, m, "1.2.0", map[string]string{"app": string(old)})

	target := "payloads/v1/" + sha(next)
	tr := newTargets(map[string][]byte{
		target: next,
		release.PatchPath("1", sha(old), sha(next)): []byte("not a patch at all"),
	})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(target, "app", release.KindExe, 0o755),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(tr.asked, target) {
		t.Error("a garbage patch did not fall back to the full target")
	}
}

// A repository that published no patch is the ordinary case, and it must cost
// nothing beyond the download that would have happened anyway.
func TestNoPublishedPatchMeansAPlainDownload(t *testing.T) {
	m := newRoot(t)
	installed(t, m, "1.2.0", map[string]string{"app": "version one"})

	target := "payloads/v1/" + sha([]byte("version two"))
	tr := newTargets(map[string][]byte{target: []byte("version two")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref(target, "app", release.KindExe, 0o755),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !slices.Contains(tr.asked, target) {
		t.Error("the target was not fetched although no patch to it exists")
	}
}
