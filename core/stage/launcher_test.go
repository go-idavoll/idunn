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
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

var hostLauncher = stage.Launcher{Source: "bin/launcher", Name: "acme"}

func pendingLauncher(t *testing.T, m *fsx.Mem, version string) (string, bool) {
	t.Helper()
	dir, err := layout.LauncherPendingDir(root, version)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fsx.ReadFile(m, fsx.Join(dir, hostLauncher.Name), 1<<20)
	if fsx.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), true
}

// Staging keeps the launcher's verified bytes for the transaction, under the
// host's launcher name — and nothing is staged for the launcher itself yet.
func TestStageKeepsTheLauncherPending(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{
		"t/app":      []byte("the application"),
		"t/launcher": []byte("the launcher"),
	})
	s := &stage.Stager{FS: m, Trust: tr, Root: root, Launcher: hostLauncher}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("t/app", "bin/app", release.KindExe, 0o755),
		ref("t/launcher", "bin/launcher", release.KindExe, 0o755),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got, ok := pendingLauncher(t, m, "1.3.0"); !ok || got != "the launcher" {
		t.Fatalf("pending launcher = %q (%v), want the verified bytes", got, ok)
	}
	if _, err := fsx.Lstat(m, layout.LauncherNextDir(root)); !fsx.IsNotExist(err) {
		t.Errorf("staging offered a launcher before any commit: %v", err)
	}
}

// A release that does not carry the launcher leaves none pending — including one
// an abandoned earlier attempt at the same version left behind.
func TestStageWithoutTheLauncherLeavesNonePending(t *testing.T) {
	m := newRoot(t)
	if err := layout.WriteLauncherPending(m, root, "1.3.0", hostLauncher.Name, []byte("stale")); err != nil {
		t.Fatal(err)
	}
	tr := newTargets(map[string][]byte{"t/app": []byte("the application")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root, Launcher: hostLauncher}

	if _, err := s.Stage(context.Background(), descriptor(ref("t/app", "bin/app", release.KindExe, 0o755)), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got, ok := pendingLauncher(t, m, "1.3.0"); ok {
		t.Errorf("pending launcher %q survived a release that does not carry one", got)
	}
}

// Negative: bytes the trust layer refuses are never kept as a launcher, and a
// file at another destination is never taken for it.
func TestStageKeepsOnlyTheVerifiedLauncher(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		m := newRoot(t)
		tr := newTargets(map[string][]byte{"t/launcher": []byte("tampered")})
		tr.fail["t/launcher"] = errors.New("hash mismatch")
		s := &stage.Stager{FS: m, Trust: tr, Root: root, Launcher: hostLauncher}
		if _, err := s.Stage(context.Background(), descriptor(ref("t/launcher", "bin/launcher", release.KindExe, 0o755)), nil); err == nil {
			t.Fatal("Stage succeeded with a refused target")
		}
		if got, ok := pendingLauncher(t, m, "1.3.0"); ok {
			t.Errorf("refused bytes %q were kept as the launcher", got)
		}
	})
	t.Run("another destination", func(t *testing.T) {
		m := newRoot(t)
		tr := newTargets(map[string][]byte{"t/x": []byte("not the launcher")})
		s := &stage.Stager{FS: m, Trust: tr, Root: root, Launcher: hostLauncher}
		for _, dst := range []string{"bin/launcher2", "launcher", "bin/sub/launcher", "Bin/launcher"} {
			if err := m.RemoveAll(layout.Staging(root)); err != nil {
				t.Fatal(err)
			}
			if err := m.RemoveAll(fsx.Join(root, "versions")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Stage(context.Background(), descriptor(ref("t/x", dst, release.KindExe, 0o755)), nil); err != nil {
				t.Fatalf("Stage(%s): %v", dst, err)
			}
			if got, ok := pendingLauncher(t, m, "1.3.0"); ok {
				t.Errorf("%s was taken for the launcher: %q", dst, got)
			}
		}
	})
}

// Negative: a launcher configuration that could address anything but one file of
// a release and one name directly in the root is refused before anything is
// written.
func TestStageRefusesAnUnsafeLauncherConfiguration(t *testing.T) {
	for name, l := range map[string]stage.Launcher{
		"source escapes":     {Source: "../../launcher", Name: "acme"},
		"absolute source":    {Source: "/bin/launcher", Name: "acme"},
		"name escapes":       {Source: "bin/launcher", Name: "../acme"},
		"name is a path":     {Source: "bin/launcher", Name: "bin/acme"},
		"name is layout":     {Source: "bin/launcher", Name: layout.MetaName},
		"incomplete":         {Source: "bin/launcher"},
		"source not clean":   {Source: "./bin/launcher", Name: "acme"},
		"name is a leftover": {Source: "bin/launcher", Name: "acme.idunn-new.tmp"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newRoot(t)
			tr := newTargets(map[string][]byte{"t/launcher": []byte("the launcher")})
			s := &stage.Stager{FS: m, Trust: tr, Root: root, Launcher: l}
			if _, err := s.Stage(context.Background(), descriptor(ref("t/launcher", "bin/launcher", release.KindExe, 0o755)), nil); !errors.Is(err, stage.ErrStage) {
				t.Fatalf("Stage = %v, want ErrStage", err)
			}
			if _, err := fsx.Lstat(m, layout.Staging(root)); !fsx.IsNotExist(err) {
				t.Errorf("something was written before the refusal: %v", err)
			}
			if len(tr.asked) != 0 {
				t.Errorf("targets were fetched before the refusal: %v", tr.asked)
			}
		})
	}
}

// The launcher is recorded whichever of the three ways it was produced.
//
// Streaming made that a property to defend rather than one that holds by
// construction: there is no longer a single buffer every source ends in, so a
// source that returns early is a source whose launcher is silently never
// recorded — an update that then starts the *old* launcher against a new
// version directory. Reuse is the case that got it wrong, so it is the case
// that is pinned.
func TestStageKeepsThePendingLauncherWhateverProducedIt(t *testing.T) {
	const launcherBytes = "the launcher"

	for name, setup := range map[string]func(*fsx.Mem) *targets{
		"downloaded": func(*fsx.Mem) *targets {
			return newTargets(map[string][]byte{
				"t/app":      []byte("the application"),
				"t/launcher": []byte(launcherBytes),
			})
		},
		"reused from the live version": func(m *fsx.Mem) *targets {
			install(t, m, "1.2.0", map[string]string{"bin/launcher": launcherBytes})
			if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
				t.Fatalf("SetPointer: %v", err)
			}
			// Offline for the launcher: a Stage that still records it can only
			// have taken the bytes off the disk.
			tr := newTargets(map[string][]byte{
				"t/app":      []byte("the application"),
				"t/launcher": []byte(launcherBytes),
			})
			tr.fail["t/launcher"] = errors.New("the launcher must not be fetched")
			return tr
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newRoot(t)
			tr := setup(m)
			s := &stage.Stager{FS: m, Trust: tr, Root: root, Launcher: hostLauncher}

			if _, err := s.Stage(context.Background(), descriptor(
				ref("t/app", "bin/app", release.KindExe, 0o755),
				ref("t/launcher", "bin/launcher", release.KindExe, 0o755),
			), nil); err != nil {
				t.Fatalf("Stage: %v", err)
			}
			if got, ok := pendingLauncher(t, m, "1.3.0"); !ok || got != launcherBytes {
				t.Fatalf("pending launcher = %q (%v), want the verified bytes", got, ok)
			}
		})
	}
}
