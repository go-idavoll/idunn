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

package layout

import (
	"runtime"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
)

// Both pointer forms are exercised on every platform, not just the one the build
// selects, and against the real filesystem as well as the double.
//
// That combination is deliberate. The Windows form exists because the symlink
// swap fails there, and no Linux run could have caught its absence: a swap that
// is not atomic looks exactly like one that is until the machine loses power at
// the wrong moment. Running the file form against a real disk on Linux is what
// proves it works at all; running it against the double proves the double models
// what the rest of the suite assumes.

const memRoot = "/opt/app"

// filesystem is one place a pointer can live.
type filesystem struct {
	name string
	open func(t *testing.T) (fsx.FS, string)
}

func filesystems() []filesystem {
	return []filesystem{
		{"mem", func(t *testing.T) (fsx.FS, string) {
			m := fsx.NewMem()
			if err := m.MkdirAll(memRoot, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			return m, memRoot
		}},
		{"os", func(t *testing.T) (fsx.FS, string) {
			return fsx.OS(), fsx.Slash(t.TempDir())
		}},
	}
}

func forms() []pointerForm { return []pointerForm{symlinkPointer{}, filePointer{}} }

// eachForm runs fn for every (form, filesystem) pair that the running platform
// can actually perform.
func eachForm(t *testing.T, fn func(t *testing.T, form pointerForm, f fsx.FS, root string)) {
	t.Helper()
	for _, form := range forms() {
		for _, sys := range filesystems() {
			t.Run(form.describe()+"/"+sys.name, func(t *testing.T) {
				if _, isSymlink := form.(symlinkPointer); isSymlink &&
					sys.name == "os" && runtime.GOOS == "windows" {
					t.Skip("Windows cannot rename over an existing directory symlink, " +
						"which is the whole reason the pointer-file form exists")
				}
				f, root := sys.open(t)
				fn(t, form, f, root)
			})
		}
	}
}

func mustRead(t *testing.T, form pointerForm, f fsx.FS, root string) string {
	t.Helper()
	got, err := form.read(f, root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

func TestPointerFormsRoundTrip(t *testing.T) {
	eachForm(t, func(t *testing.T, form pointerForm, f fsx.FS, root string) {
		if got := mustRead(t, form, f, root); got != "" {
			t.Fatalf("read on an empty root = %q", got)
		}

		if err := form.write(f, root, "versions/1.2.0"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := mustRead(t, form, f, root); got != "versions/1.2.0" {
			t.Fatalf("read = %q, want versions/1.2.0", got)
		}

		// Repointing replaces what is there. This is the swap itself, and the
		// operation the Windows form exists to make possible at all.
		if err := form.write(f, root, "versions/1.3.0"); err != nil {
			t.Fatalf("repoint: %v", err)
		}
		if got := mustRead(t, form, f, root); got != "versions/1.3.0" {
			t.Fatalf("after repointing read = %q, want versions/1.3.0", got)
		}

		// The stored target is relative, so the install tree stays movable and a
		// copied installation cannot be made to point outside itself.
		if fsx.IsAbs(mustRead(t, form, f, root)) {
			t.Fatal("the target was stored as an absolute path")
		}

		// Nothing is left beside the pointer: a scratch file that survived would
		// be read back by recovery as state.
		entries, err := f.ReadDir(root)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		for _, e := range entries {
			if e.Name() != CurrentName {
				t.Fatalf("the swap left %q behind", e.Name())
			}
		}
	})
}

// Each form accepts only itself. Reading whichever spelling happens to be present
// would mean two representations of the same state, and an installation carrying
// both would have to be resolved by guessing.
func TestPointerFormsRejectTheOtherForm(t *testing.T) {
	eachForm(t, func(t *testing.T, form pointerForm, f fsx.FS, root string) {
		var other pointerForm = filePointer{}
		if form.describe() == other.describe() {
			other = symlinkPointer{}
			if runtime.GOOS == "windows" {
				t.Skip("writing the symlink form needs privileges this platform reserves")
			}
		}
		if err := other.write(f, root, "versions/1.3.0"); err != nil {
			t.Fatalf("write the other form: %v", err)
		}
		if _, err := form.read(f, root); err == nil {
			t.Fatal("a pointer written in the other form was accepted")
		}
	})
}

// A directory where the pointer belongs is neither form. On Windows that is
// exactly what a directory symlink looks like, which is what makes this the
// check that catches an install written by a client that got the form wrong.
func TestPointerFormsRejectADirectory(t *testing.T) {
	eachForm(t, func(t *testing.T, form pointerForm, f fsx.FS, root string) {
		if err := f.MkdirAll(Current(root), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if _, err := form.read(f, root); err == nil {
			t.Fatal("a directory was accepted as the current pointer")
		}
	})
}

// A pointer file is one line naming a version directory. Anything else is a file
// some other program is using for something, not ours.
func TestPointerFileRejectsMalformedContent(t *testing.T) {
	for _, body := range []string{"", "   \n", "versions/1.3.0\nextra\n", "/etc/passwd", "versions"} {
		t.Run(body, func(t *testing.T) {
			m := fsx.NewMem()
			if err := m.MkdirAll(memRoot, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := fsx.WriteFileAtomic(m, Current(memRoot), []byte(body), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}

			target, err := filePointer{}.read(m, memRoot)
			if err != nil {
				return // refused as content, which is the point
			}
			if _, err := versionFromTarget(target); err == nil {
				t.Fatalf("the pointer file %q was accepted", body)
			}
		})
	}
}

// The exported API has to agree with whichever form this build selected, or the
// platform split would be invisible until an installation was already written.
func TestActivePointerMatchesThePlatform(t *testing.T) {
	want := "symlink"
	if runtime.GOOS == "windows" {
		want = "pointer file"
	}
	if got := activePointer().describe(); got != want {
		t.Fatalf("this build uses the %s pointer form, want %s", got, want)
	}

	// Drive it through the exported API on a real filesystem: SetPointer,
	// repoint, read back, remove. This is the sequence an update performs, and
	// on Windows it is the sequence that used to fail.
	root := fsx.Slash(t.TempDir())
	f := fsx.OS()

	for _, v := range []string{"1.2.0", "1.3.0"} {
		if err := SetPointer(f, root, v); err != nil {
			t.Fatalf("SetPointer(%s): %v", v, err)
		}
		got, err := PointerTarget(f, root)
		if err != nil {
			t.Fatalf("PointerTarget: %v", err)
		}
		if got != v {
			t.Fatalf("PointerTarget = %q, want %q", got, v)
		}
	}

	if err := RemovePointer(f, root); err != nil {
		t.Fatalf("RemovePointer: %v", err)
	}
	if got, err := PointerTarget(f, root); err != nil || got != "" {
		t.Fatalf("after removal PointerTarget = %q, %v", got, err)
	}
}
