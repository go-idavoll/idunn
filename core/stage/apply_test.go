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
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

const root = "/opt/app"

// targets stands in for the trust client. It returns bytes as if go-tuf had
// already verified them, which is exactly the boundary: by the time staging sees
// a target, whether to trust it is settled, and only where it goes is left.
type targets struct {
	files map[string][]byte
	fail  map[string]error
	asked []string
}

func newTargets(files map[string][]byte) *targets {
	return &targets{files: files, fail: map[string]error{}}
}

func (t *targets) Target(path string) ([]byte, error) {
	t.asked = append(t.asked, path)
	if err := t.fail[path]; err != nil {
		return nil, err
	}
	data, ok := t.files[path]
	if !ok {
		return nil, errors.New("no such target: " + path)
	}
	return data, nil
}

// SignedLength and Accepts stand in for what the trust layer knows about a
// target: how long it is, and whether given bytes are it. The fake answers both
// from the same map Target serves, so a reused file is accepted exactly when it
// is byte-identical to what a download would have produced.
func (t *targets) SignedLength(path string) (int64, error) {
	data, ok := t.files[path]
	if !ok {
		return 0, errors.New("no such target: " + path)
	}
	return int64(len(data)), nil
}

func (t *targets) Accepts(path string, data []byte) error {
	want, ok := t.files[path]
	if !ok {
		return errors.New("no such target: " + path)
	}
	if !bytes.Equal(want, data) {
		return errors.New("bytes are not target " + path)
	}
	return nil
}

func newRoot(t *testing.T) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return m
}

func descriptor(files ...release.FileRef) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "acme-app",
		Version:       "1.3.0",
		Channel:       "stable",
		OS:            "linux",
		Arch:          "amd64",
		Files:         files,
	}
}

func ref(target, dst string, kind release.FileKind, mode uint32) release.FileRef {
	return release.FileRef{Target: target, Dst: dst, Kind: kind, Mode: mode}
}

func read(t *testing.T, f fsx.FS, name string) string {
	t.Helper()
	b, err := fsx.ReadFile(f, name, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(b)
}

func TestStageWritesAVersionDirectory(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{
		"targets/app":       []byte("the binary"),
		"targets/plugin.so": []byte("the library"),
		"targets/icon.png":  []byte("the icon"),
	})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	dir, err := s.Stage(context.Background(), descriptor(
		ref("targets/app", "app", release.KindExe, 0o755),
		ref("targets/plugin.so", "lib/plugin.so", release.KindLib, 0o644),
		ref("targets/icon.png", "assets/icon.png", release.KindData, 0),
	))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if dir != "/opt/app/versions/1.3.0" {
		t.Fatalf("Stage returned %q", dir)
	}

	for name, want := range map[string]string{
		"/opt/app/versions/1.3.0/app":             "the binary",
		"/opt/app/versions/1.3.0/lib/plugin.so":   "the library",
		"/opt/app/versions/1.3.0/assets/icon.png": "the icon",
	} {
		if got := read(t, m, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	// Nothing is left under staging: what was assembled there has moved.
	if _, err := m.Stat(fsx.Join(layout.Staging(root), "1.3.0")); !fsx.IsNotExist(err) {
		t.Fatalf("the staging tree survived promotion: %v", err)
	}
	// Staging is not the install: `current` is untouched until Swap runs.
	if got, _ := layout.PointerTarget(m, root); got != "" {
		t.Fatalf("Stage moved the pointer to %q", got)
	}
}

func TestStageAppliesFileModes(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{"targets/app": []byte("x"), "targets/data": []byte("y")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/app", "app", release.KindExe, 0),
		ref("targets/data", "data", release.KindData, 0o640),
	)); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	for name, want := range map[string]fs.FileMode{
		"/opt/app/versions/1.3.0/app":  0o755, // an executable with no mode still runs
		"/opt/app/versions/1.3.0/data": 0o640,
	} {
		info, err := m.Stat(name)
		if err != nil {
			t.Fatalf("Stat(%s): %v", name, err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", name, info.Mode().Perm(), want)
		}
	}
}

// A destination that leaves the install root must be refused, and nothing may be
// written before the refusal. These are the Zip-Slip cases of §11.3 T7.
func TestStageRefusesEscapingDestinations(t *testing.T) {
	for _, dst := range []string{
		"../evil",
		"../../etc/cron.d/evil",
		"/etc/passwd",
		"lib/../../evil",
		"C:/windows/system32/evil.dll",
		`lib\..\..\evil`,
		"nul",
	} {
		t.Run(dst, func(t *testing.T) {
			m := newRoot(t)
			tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
			s := &stage.Stager{FS: m, Trust: tr, Root: root}

			_, err := s.Stage(context.Background(), descriptor(ref("targets/app", dst, release.KindData, 0o644)))
			if err == nil {
				t.Fatalf("destination %q was accepted", dst)
			}
			if !errors.Is(err, stage.ErrStage) {
				t.Fatalf("error %v is not classified as ErrStage", err)
			}
			if _, err := m.Stat(layout.Versions(root)); err == nil {
				t.Fatal("a refused descriptor still produced a version directory")
			}
		})
	}
}

// SanitizeDst judges the path text. This is the other half: a symlink planted in
// the staging tree must not redirect a write, however clean the text was.
func TestStageRefusesToWriteThroughASymlink(t *testing.T) {
	t.Run("as the destination", func(t *testing.T) {
		m := newRoot(t)
		tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
		s := &stage.Stager{FS: m, Trust: tr, Root: root}

		// Plant the link the instant staging creates the directory it lives in.
		stageDir := fsx.Join(layout.Staging(root), "1.3.0")
		m.Fail = func(op, name string) error {
			if op == "mkdirall" && name == fsx.Join(stageDir, "lib") {
				return nil
			}
			return nil
		}
		if err := m.MkdirAll(fsx.Join(stageDir, "lib"), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := m.MkdirAll("/outside", 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := m.Symlink("/outside/planted", fsx.Join(stageDir, "lib", "plugin.so")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		// Staging clears its own tree first, so the planted link is gone by the
		// time the write happens — which is itself the defence being asserted.
		if _, err := s.Stage(context.Background(), descriptor(
			ref("targets/app", "lib/plugin.so", release.KindLib, 0o644),
		)); err != nil {
			t.Fatalf("Stage: %v", err)
		}
		if _, err := m.Stat("/outside/planted"); err == nil {
			t.Fatal("the write followed a planted symlink out of the install root")
		}
	})

	t.Run("as a parent directory", func(t *testing.T) {
		m := newRoot(t)
		tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
		s := &stage.Stager{FS: m, Trust: tr, Root: root}
		stageDir := fsx.Join(layout.Staging(root), "1.3.0")

		// Win the race the clearing step would otherwise close: plant the link
		// after staging has created its tree, just before the file is written.
		var planted bool
		m.Fail = func(op, name string) error {
			if op == "mkdirall" && name == stageDir && !planted {
				planted = true
				m.Fail = nil
				if err := m.MkdirAll(stageDir, 0o700); err != nil {
					return err
				}
				if err := m.MkdirAll("/outside", 0o755); err != nil {
					return err
				}
				if err := m.Symlink("/outside", fsx.Join(stageDir, "lib")); err != nil {
					return err
				}
			}
			return nil
		}

		_, err := s.Stage(context.Background(), descriptor(
			ref("targets/app", "lib/plugin.so", release.KindLib, 0o644),
		))
		if err == nil {
			t.Fatal("staging descended through a symlinked directory")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("error %v does not name the symlink it refused", err)
		}
		if _, err := m.Stat("/outside/plugin.so"); err == nil {
			t.Fatal("the write escaped the install root")
		}
	})
}

// Staging over the running version would write into the tree the current process
// is executing from — the one case blue/green exists to avoid.
func TestStageRefusesTheLiveVersion(t *testing.T) {
	m := newRoot(t)
	if err := m.MkdirAll("/opt/app/versions/1.3.0", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(ref("targets/app", "app", release.KindExe, 0o755))); err == nil {
		t.Fatal("staging overwrote the running version")
	}
}

// A version directory left by an earlier transaction belongs to the recovery that
// owns it. Replacing it here would delete a tree something may still point at.
func TestStageRefusesAnExistingVersionDirectory(t *testing.T) {
	m := newRoot(t)
	if err := m.MkdirAll("/opt/app/versions/1.3.0", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(ref("targets/app", "app", release.KindExe, 0o755))); err == nil {
		t.Fatal("staging replaced an existing version directory")
	}
}

// An abandoned staging tree may hold files this descriptor no longer lists, so it
// is cleared rather than built on.
func TestStageClearsAnAbandonedStagingTree(t *testing.T) {
	m := newRoot(t)
	stageDir := fsx.Join(layout.Staging(root), "1.3.0")
	if err := m.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(m, fsx.Join(stageDir, "stale.dll"), []byte("old"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}
	if _, err := s.Stage(context.Background(), descriptor(ref("targets/app", "app", release.KindExe, 0o755))); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if _, err := m.Stat("/opt/app/versions/1.3.0/stale.dll"); err == nil {
		t.Fatal("a file from an abandoned attempt was promoted into the new version")
	}
}

func TestStageStopsAtTheFirstUnavailableTarget(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
	tr.fail["targets/plugin.so"] = errors.New("verification failed")
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	_, err := s.Stage(context.Background(), descriptor(
		ref("targets/app", "app", release.KindExe, 0o755),
		ref("targets/plugin.so", "lib/plugin.so", release.KindLib, 0o644),
	))
	if err == nil {
		t.Fatal("staging completed although a target could not be materialized")
	}
	if _, err := m.Stat(layout.Versions(root)); err == nil {
		t.Fatal("a failed staging still produced a version directory")
	}
}

func TestStageHonoursCancellation(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Stage(ctx, descriptor(ref("targets/app", "app", release.KindExe, 0o755))); err == nil {
		t.Fatal("staging ignored a cancelled context")
	}
	if len(tr.asked) != 0 {
		t.Fatalf("a cancelled staging still fetched %v", tr.asked)
	}
}

func TestStageRejectsAnUnusableStager(t *testing.T) {
	d := descriptor(ref("targets/app", "app", release.KindExe, 0o755))
	tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})

	for _, tc := range []struct {
		name string
		s    *stage.Stager
	}{
		{"no filesystem", &stage.Stager{Trust: tr, Root: root}},
		{"no root", &stage.Stager{FS: fsx.NewMem(), Trust: tr}},
		{"no trust client", &stage.Stager{FS: fsx.NewMem(), Root: root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.s.Stage(context.Background(), d); err == nil {
				t.Fatal("an unusable stager was allowed to run")
			}
		})
	}

	s := &stage.Stager{FS: newRoot(t), Trust: tr, Root: root}
	if _, err := s.Stage(context.Background(), nil); err == nil {
		t.Fatal("Stage accepted a nil descriptor")
	}
}

func TestSwap(t *testing.T) {
	m := newRoot(t)
	for _, v := range []string{"1.2.0", "1.3.0"} {
		if err := m.MkdirAll(fsx.Join(layout.Versions(root), v), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	s := &stage.Stager{FS: m, Root: root}

	if err := s.Swap("/opt/app/versions/1.2.0"); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if got, _ := layout.PointerTarget(m, root); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
	if err := s.Swap("/opt/app/versions/1.3.0"); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if got, _ := layout.PointerTarget(m, root); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
}

// A dangling `current` is an install that looks whole and cannot start.
func TestSwapRefusesAMissingVersionDirectory(t *testing.T) {
	m := newRoot(t)
	s := &stage.Stager{FS: m, Root: root}

	if err := s.Swap("/opt/app/versions/9.9.9"); err == nil {
		t.Fatal("Swap pointed at a directory that does not exist")
	}
	if err := s.Swap("/opt/app/versions/latest"); err == nil {
		t.Fatal("Swap accepted a directory that is not a version")
	}
	if got, _ := layout.PointerTarget(m, root); got != "" {
		t.Fatalf("a refused Swap still moved the pointer to %q", got)
	}
}
