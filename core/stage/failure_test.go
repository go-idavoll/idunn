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
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Staging touches the disk at every step, and a disk that fails must not produce
// a version directory anyway. Each case below breaks one operation and asserts
// that the failure surfaces instead of being staged around.
func TestStageReportsFilesystemFailures(t *testing.T) {
	disk := errors.New("i/o error")
	stageDir := fsx.Join(layout.Staging(root), "1.3.0")

	for _, tc := range []struct {
		name string
		fail func(op, name string) bool
	}{
		{
			name: "cannot clear an abandoned staging tree",
			fail: func(op, name string) bool { return op == "removeall" && name == stageDir },
		},
		{
			name: "cannot create the staging tree",
			fail: func(op, name string) bool { return op == "mkdirall" && name == stageDir },
		},
		{
			name: "cannot create a destination directory",
			fail: func(op, name string) bool {
				return op == "mkdirall" && name == fsx.Join(stageDir, "lib")
			},
		},
		{
			name: "cannot write a payload file",
			fail: func(op, name string) bool {
				return op == "write" && strings.Contains(name, "plugin.so")
			},
		},
		{
			name: "cannot create the versions directory",
			fail: func(op, name string) bool { return op == "mkdirall" && name == layout.Versions(root) },
		},
		{
			name: "cannot promote the staging tree",
			fail: func(op, name string) bool {
				return op == "rename" && name == "/opt/app/versions/1.3.0"
			},
		},
		{
			name: "cannot flush the versions directory",
			fail: func(op, name string) bool { return op == "sync" && name == layout.Versions(root) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRoot(t)
			tr := newTargets(map[string][]byte{
				"targets/app":       []byte("the binary"),
				"targets/plugin.so": []byte("the library"),
			})
			s := &stage.Stager{FS: m, Trust: tr, Root: root}
			m.Fail = func(op, name string) error {
				if tc.fail(op, name) {
					return disk
				}
				return nil
			}

			_, err := s.Stage(context.Background(), descriptor(
				ref("targets/app", "app", release.KindExe, 0o755),
				ref("targets/plugin.so", "lib/plugin.so", release.KindLib, 0o644),
			))
			if err == nil {
				t.Fatal("staging reported success although the filesystem failed")
			}
			m.Fail = nil

			// The one thing that must never be true after a failed staging:
			// a version directory that other code would take for a real one.
			if _, err := m.Stat("/opt/app/versions/1.3.0"); err == nil {
				t.Fatal("a failed staging left a version directory behind")
			}
		})
	}
}

// A destination that cannot even be inspected is not a destination we may write
// to: the check that would have caught a planted symlink did not run.
func TestStageRefusesAnUninspectableDestination(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{"targets/app": []byte("payload")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	// A symlink cycle makes Lstat on anything below it fail with neither a
	// success nor a not-exist answer.
	stageDir := fsx.Join(layout.Staging(root), "1.3.0")
	var planted bool
	m.Fail = func(op, name string) error {
		if op == "mkdirall" && name == stageDir && !planted {
			planted = true
			m.Fail = nil
			if err := m.MkdirAll(stageDir, 0o700); err != nil {
				return err
			}
			if err := m.Symlink("b", fsx.Join(stageDir, "a")); err != nil {
				return err
			}
			return m.Symlink("a", fsx.Join(stageDir, "b"))
		}
		return nil
	}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/app", "a/app", release.KindExe, 0o755),
	)); err == nil {
		t.Fatal("staging wrote to a destination it could not inspect")
	}
}

// Swap is the commit point. If the rename cannot be made, the pointer has to
// stay exactly where it was.
func TestSwapReportsFailureWithoutMovingThePointer(t *testing.T) {
	m := withVersions(t, "1.2.0", "1.2.0", "1.3.0")
	s := &stage.Stager{FS: m, Root: root}

	m.Fail = func(op, name string) error {
		if op == "rename" && strings.HasSuffix(name, layout.CurrentName) {
			return errors.New("i/o error")
		}
		return nil
	}
	if err := s.Swap("/opt/app/versions/1.3.0"); err == nil {
		t.Fatal("Swap reported success although the rename failed")
	}
	m.Fail = nil

	if got, _ := layout.PointerTarget(m, root); got != "1.2.0" {
		t.Fatalf("current = %q after a failed swap, want 1.2.0", got)
	}
	// The scratch link the failed swap created must not be left behind, or the
	// next recovery would find a pointer-shaped object it did not write.
	entries, err := m.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".idunn-") {
			t.Fatalf("a failed swap left the scratch link %q behind", e.Name())
		}
	}
}
