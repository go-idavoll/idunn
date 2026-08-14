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
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
)

// The in-memory filesystem is the instrument the rest of the suite measures with.
// These tests check the instrument itself: its error paths, and the injected
// failures the transaction tests use to simulate a crash.

func newMem(t *testing.T) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll("/root", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return m
}

func TestMemRejectsEmptyNames(t *testing.T) {
	m := newMem(t)
	if _, err := m.Open(""); err == nil {
		t.Fatal("Open accepted an empty name")
	}
	if _, err := m.Create("", 0o644); err == nil {
		t.Fatal("Create accepted an empty name")
	}
	if err := m.MkdirAll("", 0o755); err == nil {
		t.Fatal("MkdirAll accepted an empty name")
	}
	if err := m.RemoveAll(""); err == nil {
		t.Fatal("RemoveAll accepted an empty name")
	}
	if err := m.Symlink("target", ""); err == nil {
		t.Fatal("Symlink accepted an empty link name")
	}
	if err := m.Symlink("", "/root/link"); err == nil {
		t.Fatal("Symlink accepted an empty target")
	}
	if err := m.Rename("/root", ""); err == nil {
		t.Fatal("Rename accepted an empty destination")
	}
}

func TestMemTypeConfusion(t *testing.T) {
	m := newMem(t)
	if err := m.MkdirAll("/root/dir", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	write(t, m, "/root/file", "payload")

	if _, err := m.Create("/root/dir", 0o644); err == nil {
		t.Fatal("Create overwrote a directory")
	}
	if err := m.MkdirAll("/root/file/sub", 0o755); err == nil {
		t.Fatal("MkdirAll descended into a regular file")
	}
	if err := m.MkdirAll("/root/file", 0o755); err == nil {
		t.Fatal("MkdirAll turned a regular file into a directory")
	}
	if _, err := m.Create("/root/file/child", 0o644); err == nil {
		t.Fatal("Create placed a file under a regular file")
	}
	if _, err := m.ReadDir("/root/file"); err == nil {
		t.Fatal("ReadDir listed a regular file")
	}
	if err := m.Rename("/root/file", "/root/dir"); err == nil {
		t.Fatal("Rename replaced a directory with a file")
	}
	if err := m.Rename("/root/dir", "/root/file"); err == nil {
		t.Fatal("Rename replaced a file with a directory")
	}
	if err := m.Rename("/root/file", "/root/missing/dst"); err == nil {
		t.Fatal("Rename accepted a destination whose parent does not exist")
	}
	if err := m.Symlink("elsewhere", "/root/missing/link"); err == nil {
		t.Fatal("Symlink accepted a parent that does not exist")
	}
}

func TestMemRenameDirectories(t *testing.T) {
	m := newMem(t)
	if err := m.MkdirAll("/root/staging/lib", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	write(t, m, "/root/staging/app", "binary")
	write(t, m, "/root/staging/lib/plugin.so", "library")

	// Staging is promoted to a version directory by renaming the whole tree.
	if err := m.Rename("/root/staging", "/root/versions"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if got := read(t, m, "/root/versions/lib/plugin.so"); got != "library" {
		t.Fatalf("the subtree did not move: %q", got)
	}
	if _, err := m.Stat("/root/staging"); !fsx.IsNotExist(err) {
		t.Fatalf("the source survived the rename: %v", err)
	}

	// Renaming onto itself is a no-op rather than a way to lose the tree.
	if err := m.Rename("/root/versions", "/root/versions"); err != nil {
		t.Fatalf("self-rename: %v", err)
	}
	if got := read(t, m, "/root/versions/app"); got != "binary" {
		t.Fatalf("a self-rename damaged the tree: %q", got)
	}
	if err := m.Rename("/root/versions", "/root/versions/inner"); err == nil {
		t.Fatal("Rename moved a directory inside itself")
	}

	if err := m.MkdirAll("/root/occupied/child", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := m.Rename("/root/versions", "/root/occupied"); err == nil {
		t.Fatal("Rename replaced a non-empty directory")
	}
	if err := m.Remove("/root/occupied"); err == nil {
		t.Fatal("Remove deleted a non-empty directory")
	}
}

func TestMemRelativeRoot(t *testing.T) {
	// A relative install root has to work too: the OS filesystem accepts one,
	// and a double that silently required absolute paths would hide a bug.
	m := fsx.NewMem()
	if err := m.MkdirAll("app/versions/1.3.0", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	write(t, m, "app/versions/1.3.0/app", "binary")
	if err := m.Symlink("versions/1.3.0", "app/current"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if got := read(t, m, "app/current/app"); got != "binary" {
		t.Fatalf("relative root resolution failed: %q", got)
	}
}

func TestMemSymlinkToAbsoluteAndParent(t *testing.T) {
	m := newMem(t)
	if err := m.MkdirAll("/root/versions/1.3.0", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	write(t, m, "/root/versions/1.3.0/app", "binary")

	if err := m.Symlink("/root/versions/1.3.0", "/root/abs"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if got := read(t, m, "/root/abs/app"); got != "binary" {
		t.Fatalf("absolute link target: %q", got)
	}

	if err := m.MkdirAll("/root/nested", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := m.Symlink("../versions/1.3.0", "/root/nested/rel"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if got := read(t, m, "/root/nested/rel/app"); got != "binary" {
		t.Fatalf("relative link target: %q", got)
	}
}

func TestMemFileInfo(t *testing.T) {
	m := newMem(t)
	write(t, m, "/root/app", "seven!!")

	f, err := m.Open("/root/app")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Name() != "app" || info.Size() != 7 || info.IsDir() {
		t.Fatalf("info = %s size=%d dir=%v", info.Name(), info.Size(), info.IsDir())
	}
	if !info.ModTime().IsZero() && info.ModTime().Unix() != 0 {
		t.Fatalf("ModTime = %v, want the fixed epoch", info.ModTime())
	}
	if info.Sys() != nil {
		t.Fatal("Sys leaked an implementation detail")
	}

	entries, err := m.ReadDir("/root")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	e := entries[0]
	if e.Type()&fs.ModeType != 0 {
		t.Fatalf("Type = %v, want a regular file", e.Type())
	}
	if _, err := e.Info(); err != nil {
		t.Fatalf("Info: %v", err)
	}
	if s, ok := e.(interface{ String() string }); ok && s.String() == "" {
		t.Fatal("String rendered nothing, which makes a failure message useless")
	}
}

func TestMemDirectoryIsNotReadable(t *testing.T) {
	m := newMem(t)
	d, err := m.Open("/root")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = d.Close() }()
	if _, err := io.ReadAll(d); err == nil {
		t.Fatal("read a directory as if it were a file")
	}
}

func TestMemWriterAfterClose(t *testing.T) {
	m := newMem(t)
	w, err := m.Create("/root/app", 0o644)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("late")); err == nil {
		t.Fatal("wrote through a closed file")
	}
	if err := w.Close(); err == nil {
		t.Fatal("closed a file twice without an error")
	}
	if s, ok := w.(fsx.Syncer); ok {
		if err := s.Sync(); err == nil {
			t.Fatal("synced a closed file")
		}
	}
}

func TestMemSyncDirMissing(t *testing.T) {
	m := newMem(t)
	if err := fsx.SyncDir(m, "/root/absent"); !fsx.IsNotExist(err) {
		t.Fatalf("SyncDir on a missing directory = %v, want a not-exist error", err)
	}
}

// Every step of WriteFileAtomic can fail on a real disk. None of them may leave
// the destination half-written or the scratch file behind.
func TestWriteFileAtomicFailurePaths(t *testing.T) {
	boom := errors.New("boom")
	for _, op := range []string{"create", "write", "sync", "rename"} {
		t.Run(op, func(t *testing.T) {
			m := newMem(t)
			write(t, m, "/root/state.json", "original")

			m.Fail = func(gotOp, _ string) error {
				if gotOp == op {
					return boom
				}
				return nil
			}
			err := fsx.WriteFileAtomic(m, "/root/state.json", []byte("replacement"), 0o644)
			if err == nil {
				t.Fatalf("write succeeded although %q failed", op)
			}
			m.Fail = nil

			if got := read(t, m, "/root/state.json"); got != "original" {
				t.Fatalf("destination is %q; a failed write must leave the previous contents", got)
			}
			entries, err := m.ReadDir("/root")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("%d entries under the root, want only state.json", len(entries))
			}
		})
	}
}

// The scratch file is removed even when the directory sync fails, because by then
// the rename has already succeeded and the destination is correct.
func TestWriteFileAtomicReportsSyncDirFailure(t *testing.T) {
	m := newMem(t)
	m.Fail = func(op, name string) error {
		if op == "sync" && name == "/root" {
			return errors.New("boom")
		}
		return nil
	}
	if err := fsx.WriteFileAtomic(m, "/root/state.json", []byte("payload"), 0o644); err == nil {
		t.Fatal("a failed directory sync was reported as success")
	}
	m.Fail = nil
	if got := read(t, m, "/root/state.json"); got != "payload" {
		t.Fatalf("destination is %q, want the new contents", got)
	}
}
