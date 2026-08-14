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

package fsx_test

import (
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
)

// The in-memory filesystem only has value if it behaves like the real one where
// the transaction depends on it. Every test below therefore runs against both,
// and a divergence fails the suite rather than quietly weakening every test that
// uses the double.
type impl struct {
	name string
	open func(t *testing.T) (fsx.FS, string)
}

func impls() []impl {
	return []impl{
		{"os", func(t *testing.T) (fsx.FS, string) {
			return fsx.OS(), fsx.Slash(t.TempDir())
		}},
		{"mem", func(t *testing.T) (fsx.FS, string) {
			m := fsx.NewMem()
			if err := m.MkdirAll("/root", 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			return m, "/root"
		}},
	}
}

func each(t *testing.T, fn func(t *testing.T, f fsx.FS, root string)) {
	t.Helper()
	for _, i := range impls() {
		t.Run(i.name, func(t *testing.T) {
			f, root := i.open(t)
			fn(t, f, root)
		})
	}
}

func write(t *testing.T, f fsx.FS, name, data string) {
	t.Helper()
	if err := fsx.WriteFileAtomic(f, name, []byte(data), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic(%s): %v", name, err)
	}
}

func read(t *testing.T, f fsx.FS, name string) string {
	t.Helper()
	b, err := fsx.ReadFile(f, name, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(b)
}

func TestWriteAtomicRoundTrip(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		name := fsx.Join(root, "state.json")
		write(t, f, name, "first")
		if got := read(t, f, name); got != "first" {
			t.Fatalf("read %q, want %q", got, "first")
		}

		// The second write replaces the first with no intermediate state a
		// reader could observe; that is the property the journal relies on.
		write(t, f, name, "second")
		if got := read(t, f, name); got != "second" {
			t.Fatalf("read %q, want %q", got, "second")
		}
	})
}

// A failed write must not leave the scratch file behind: recovery scans the
// install root, and litter there is indistinguishable from state.
func TestWriteAtomicRemovesScratchOnFailure(t *testing.T) {
	m := fsx.NewMem()
	if err := m.MkdirAll("/root", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	m.Fail = func(op, name string) error {
		if op == "write" {
			return errors.New("disk full")
		}
		return nil
	}

	err := fsx.WriteFileAtomic(m, "/root/state.json", []byte("payload"), 0o644)
	if err == nil {
		t.Fatal("write succeeded although the filesystem reported a failure")
	}

	entries, err := m.ReadDir("/root")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		t.Fatalf("left %q behind after a failed write", e.Name())
	}
}

func TestReadFileRejectsOversize(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		name := fsx.Join(root, "big")
		write(t, f, name, strings.Repeat("x", 64))

		if _, err := fsx.ReadFile(f, name, 63); err == nil {
			t.Fatal("a file above the limit was accepted")
		}
		if _, err := fsx.ReadFile(f, name, 64); err != nil {
			t.Fatalf("a file at the limit was rejected: %v", err)
		}
		if _, err := fsx.ReadFile(f, name, 0); err == nil {
			t.Fatal("a non-positive limit was accepted")
		}
	})
}

func TestReadFileMissing(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		_, err := fsx.ReadFile(f, fsx.Join(root, "absent"), 16)
		if !fsx.IsNotExist(err) {
			t.Fatalf("error is %v, want a not-exist error", err)
		}
	})
}

func TestMkdirAllAndReadDir(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		if err := f.MkdirAll(fsx.Join(root, "versions/1.3.0/lib"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		write(t, f, fsx.Join(root, "versions/1.3.0/app"), "binary")

		entries, err := f.ReadDir(fsx.Join(root, "versions/1.3.0"))
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if len(names) != 2 || names[0] != "app" || names[1] != "lib" {
			t.Fatalf("entries %v, want [app lib] in name order", names)
		}
		if !entries[1].IsDir() {
			t.Fatal("lib is not reported as a directory")
		}
	})
}

func TestCreateRequiresParent(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		_, err := f.Create(fsx.Join(root, "missing/file"), 0o644)
		if err == nil {
			t.Fatal("created a file under a directory that does not exist")
		}
	})
}

// Repointing `current` is the commit of an update: a rename over an existing
// symlink must replace the link itself, never write through it.
func TestRenameReplacesSymlink(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		for _, v := range []string{"1.2.0", "1.3.0"} {
			if err := f.MkdirAll(fsx.Join(root, "versions", v), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			write(t, f, fsx.Join(root, "versions", v, "app"), v)
		}

		current := fsx.Join(root, "current")
		if err := f.Symlink("versions/1.2.0", current); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if got := read(t, f, fsx.Join(root, "current/app")); got != "1.2.0" {
			t.Fatalf("current points at %q, want 1.2.0", got)
		}

		next := fsx.Join(root, "current.next")
		if err := f.Symlink("versions/1.3.0", next); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := f.Rename(next, current); err != nil {
			t.Fatalf("Rename: %v", err)
		}

		if got := read(t, f, fsx.Join(root, "current/app")); got != "1.3.0" {
			t.Fatalf("after the swap current points at %q, want 1.3.0", got)
		}
		// The old version directory must still be intact — it is the rollback
		// target, and a swap that wrote through the link would have clobbered it.
		if got := read(t, f, fsx.Join(root, "versions/1.2.0/app")); got != "1.2.0" {
			t.Fatalf("the previous version now contains %q; the swap wrote through the link", got)
		}
		if target, err := f.Readlink(current); err != nil || target != "versions/1.3.0" {
			t.Fatalf("Readlink = %q, %v; want versions/1.3.0", target, err)
		}
	})
}

func TestLstatDistinguishesLinkFromTarget(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		write(t, f, fsx.Join(root, "real"), "payload")
		if err := f.Symlink("real", fsx.Join(root, "link")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		st, err := f.Stat(fsx.Join(root, "link"))
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			t.Fatal("Stat did not follow the link")
		}

		lst, err := fsx.Lstat(f, fsx.Join(root, "link"))
		if err != nil {
			t.Fatalf("Lstat: %v", err)
		}
		if lst.Mode()&fs.ModeSymlink == 0 {
			t.Fatal("Lstat followed the link; a planted symlink would be invisible")
		}
	})
}

func TestRemoveSemantics(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		dir := fsx.Join(root, "versions/1.3.0")
		if err := f.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		write(t, f, fsx.Join(dir, "app"), "binary")

		if err := f.Remove(dir); err == nil {
			t.Fatal("removed a non-empty directory")
		}
		if err := f.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}
		// Idempotence is what lets recovery re-run an abort it already finished.
		if err := f.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll on a missing path: %v", err)
		}
		if _, err := f.Stat(dir); !fsx.IsNotExist(err) {
			t.Fatalf("Stat after RemoveAll = %v, want a not-exist error", err)
		}
	})
}

// Removing a link must remove the link, not the version directory it points at.
func TestRemoveDoesNotFollowSymlink(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		if err := f.MkdirAll(fsx.Join(root, "versions/1.3.0"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		write(t, f, fsx.Join(root, "versions/1.3.0/app"), "binary")
		if err := f.Symlink("versions/1.3.0", fsx.Join(root, "current")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		if err := f.Remove(fsx.Join(root, "current")); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if got := read(t, f, fsx.Join(root, "versions/1.3.0/app")); got != "binary" {
			t.Fatalf("the version directory was damaged: %q", got)
		}
	})
}

func TestSymlinkCycleTerminates(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		if err := f.Symlink("b", fsx.Join(root, "a")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := f.Symlink("a", fsx.Join(root, "b")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if _, err := f.Stat(fsx.Join(root, "a")); err == nil {
			t.Fatal("a symlink cycle resolved instead of failing")
		}
	})
}

func TestSymlinkRefusesExisting(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		write(t, f, fsx.Join(root, "taken"), "payload")
		if err := f.Symlink("elsewhere", fsx.Join(root, "taken")); err == nil {
			t.Fatal("a symlink overwrote an existing file")
		}
	})
}

func TestReadlinkRejectsRegularFile(t *testing.T) {
	each(t, func(t *testing.T, f fsx.FS, root string) {
		write(t, f, fsx.Join(root, "plain"), "payload")
		if _, err := f.Readlink(fsx.Join(root, "plain")); err == nil {
			t.Fatal("Readlink succeeded on a regular file")
		}
	})
}

func TestTempNameIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n := fsx.TempName("/root/state.json")
		if seen[n] {
			t.Fatalf("TempName repeated %q; two concurrent writes would collide", n)
		}
		if !strings.HasPrefix(n, "/root/state.json.") || !strings.HasSuffix(n, ".tmp") {
			t.Fatalf("TempName produced %q, which recovery cannot recognise as scratch", n)
		}
		seen[n] = true
	}
}

func TestLstatUnsupportedFails(t *testing.T) {
	// A filesystem that cannot answer "is this a link?" must produce an error,
	// never the answer Stat would have given.
	_, err := fsx.Lstat(noLstat{fsx.NewMem()}, "/anything")
	if !errors.Is(err, fsx.ErrNotSupported) {
		t.Fatalf("error is %v, want ErrNotSupported", err)
	}
}

// noLstat hides the Lstat method of the filesystem it wraps.
type noLstat struct{ inner *fsx.Mem }

func (n noLstat) Open(name string) (fs.File, error)          { return n.inner.Open(name) }
func (n noLstat) Stat(name string) (fs.FileInfo, error)      { return n.inner.Stat(name) }
func (n noLstat) ReadDir(name string) ([]fs.DirEntry, error) { return n.inner.ReadDir(name) }
func (n noLstat) MkdirAll(name string, m fs.FileMode) error  { return n.inner.MkdirAll(name, m) }
func (n noLstat) Remove(name string) error                   { return n.inner.Remove(name) }
func (n noLstat) RemoveAll(name string) error                { return n.inner.RemoveAll(name) }
func (n noLstat) Rename(o, w string) error                   { return n.inner.Rename(o, w) }
func (n noLstat) Symlink(t, l string) error                  { return n.inner.Symlink(t, l) }
func (n noLstat) Readlink(name string) (string, error)       { return n.inner.Readlink(name) }

func (n noLstat) Create(name string, m fs.FileMode) (io.WriteCloser, error) {
	return n.inner.Create(name, m)
}

func TestPathHelpers(t *testing.T) {
	if got := fsx.Join("/opt/app", "", "versions", "1.3.0"); got != "/opt/app/versions/1.3.0" {
		t.Fatalf("Join = %q", got)
	}
	if got := fsx.Dir("/opt/app/current"); got != "/opt/app" {
		t.Fatalf("Dir = %q", got)
	}
	if got := fsx.Base("/opt/app/current"); got != "current" {
		t.Fatalf("Base = %q", got)
	}
	if got := fsx.Clean("/opt/app/./versions/../current"); got != "/opt/app/current" {
		t.Fatalf("Clean = %q", got)
	}
	for _, abs := range []string{"/opt/app", `C:\Program Files\app`, "C:/app"} {
		if !fsx.IsAbs(abs) {
			t.Fatalf("IsAbs(%q) = false", abs)
		}
	}
	if fsx.IsAbs("versions/1.3.0") {
		t.Fatal("IsAbs accepted a relative path")
	}
}
