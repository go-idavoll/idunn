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

// --- streaming -----------------------------------------------------------

// WriteStreamAtomic is WriteFileAtomic for a payload that is produced rather
// than held. The guarantee is the same one, and it now has to survive a producer
// that fails halfway — which is not an error case but the normal way staging
// rejects a source whose bytes did not verify.
func TestWriteStreamAtomicLeavesNothingWhenTheProducerFails(t *testing.T) {
	m := newMem(t)
	write(t, m, "/root/payload.bin", "original")
	refused := errors.New("these are not the signed bytes")

	err := fsx.WriteStreamAtomic(m, "/root/payload.bin", 0o644, func(w io.Writer) error {
		if _, err := w.Write([]byte("half of something else")); err != nil {
			return err
		}
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v, want the producer's own error", err)
	}
	if got := read(t, m, "/root/payload.bin"); got != "original" {
		t.Errorf("destination is %q; a refused stream must leave the previous contents", got)
	}
	entries, err := m.ReadDir("/root")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d entries under the root, want only payload.bin — the scratch file was left behind", len(entries))
	}
}

// The successful path has to be indistinguishable from WriteFileAtomic's, mode
// included: a staged executable produced by a stream is still an executable.
func TestWriteStreamAtomicWritesTheStream(t *testing.T) {
	m := newMem(t)
	err := fsx.WriteStreamAtomic(m, "/root/app", 0o755, func(w io.Writer) error {
		for _, part := range []string{"one ", "two ", "three"} {
			if _, err := io.WriteString(w, part); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WriteStreamAtomic: %v", err)
	}
	if got := read(t, m, "/root/app"); got != "one two three" {
		t.Errorf("content = %q", got)
	}
	info, err := m.Stat("/root/app")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755", info.Mode().Perm())
	}
}

// Every step can fail on a real disk, exactly as in WriteFileAtomic. None of
// them may leave the destination half-written or the scratch file behind.
func TestWriteStreamAtomicFailurePaths(t *testing.T) {
	boom := errors.New("boom")
	for _, op := range []string{"create", "write", "sync", "rename"} {
		t.Run(op, func(t *testing.T) {
			m := newMem(t)
			write(t, m, "/root/payload.bin", "original")

			m.Fail = func(gotOp, _ string) error {
				if gotOp == op {
					return boom
				}
				return nil
			}
			err := fsx.WriteStreamAtomic(m, "/root/payload.bin", 0o644, func(w io.Writer) error {
				_, err := io.WriteString(w, "replacement")
				return err
			})
			if err == nil {
				t.Fatalf("write succeeded although %q failed", op)
			}
			m.Fail = nil

			if got := read(t, m, "/root/payload.bin"); got != "original" {
				t.Fatalf("destination is %q; a failed write must leave the previous contents", got)
			}
			entries, err := m.ReadDir("/root")
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("%d entries under the root, want only payload.bin", len(entries))
			}
		})
	}
}

// A delta reads its base and its patch at offsets, so the in-memory filesystem
// has to answer ReadAt — otherwise the streaming paths would be exercised only
// against a real disk, which is the half of the suite that cannot inject
// failures.
func TestOpenReaderAt(t *testing.T) {
	m := newMem(t)
	write(t, m, "/root/payload.bin", "0123456789")

	r, size, err := fsx.OpenReaderAt(m, "/root/payload.bin")
	if err != nil {
		t.Fatalf("OpenReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()
	if size != 10 {
		t.Errorf("size = %d, want 10", size)
	}
	buf := make([]byte, 3)
	if _, err := r.ReadAt(buf, 7); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "789" {
		t.Errorf("ReadAt(7) = %q, want %q", buf, "789")
	}
	// Backwards, which is what a delta does as often as forwards.
	if _, err := r.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "012" {
		t.Errorf("ReadAt(0) = %q, want %q", buf, "012")
	}
}

// A name that is not a regular file has no offsets to read at, and neither a
// directory nor a missing file may be answered with an empty reader that a
// patch would then happily apply against.
func TestOpenReaderAtRefusesWhatItCannotRead(t *testing.T) {
	m := newMem(t)

	if _, _, err := fsx.OpenReaderAt(m, "/root/missing.bin"); err == nil {
		t.Error("a missing file was opened for random access")
	}
	if _, _, err := fsx.OpenReaderAt(m, "/root"); err == nil {
		t.Error("a directory was opened for random access")
	}
}

// Copy is bounded on purpose: every stream in the apply path has a signed
// length, and a source that produces more than that is one to refuse rather
// than to truncate into something that still looks right.
func TestCopyIsBounded(t *testing.T) {
	var got strings.Builder
	n, err := fsx.Copy(&got, strings.NewReader("exactly ten"), 11)
	if err != nil || n != 11 {
		t.Fatalf("Copy of an exact-length source: %d, %v", n, err)
	}

	got.Reset()
	if _, err := fsx.Copy(&got, strings.NewReader("one byte too many"), 16); err == nil {
		t.Error("a source longer than the limit was accepted")
	}
	if _, err := fsx.Copy(io.Discard, strings.NewReader(""), -1); err == nil {
		t.Error("a negative limit was accepted")
	}
}

// A filesystem whose files cannot be read at an offset is an error, never a
// silent fallback that reads the file whole: the callers use OpenReaderAt
// precisely to keep a multi-hundred-megabyte base out of memory, and quietly
// buffering it would undo the property they asked for.
func TestOpenReaderAtRefusesAFilesystemWithoutIt(t *testing.T) {
	seq := sequentialFS{newMem(t)}
	write(t, seq.Mem, "/root/payload.bin", "0123456789")

	_, _, err := fsx.OpenReaderAt(seq, "/root/payload.bin")
	if !errors.Is(err, fsx.ErrNotSupported) {
		t.Fatalf("err = %v, want ErrNotSupported", err)
	}
}

// A file that opens and then cannot be described is not one to read at offsets
// either: without its size, a patch has no bound to check its seeks against.
func TestOpenReaderAtReportsAFileItCannotStat(t *testing.T) {
	m := newMem(t)
	write(t, m, "/root/payload.bin", "0123456789")

	if _, _, err := fsx.OpenReaderAt(undescribableFS{m}, "/root/payload.bin"); err == nil {
		t.Fatal("a file that cannot be stat'ed was opened for random access")
	}
}

// sequentialFS is a filesystem whose files can only be read forwards. It exists
// to prove the refusal above, which no real implementation in the tree triggers.
type sequentialFS struct{ *fsx.Mem }

func (s sequentialFS) Open(name string) (fs.File, error) {
	f, err := s.Mem.Open(name)
	if err != nil {
		return nil, err
	}
	return forwardOnly{f}, nil
}

type forwardOnly struct{ fs.File }

// undescribableFS opens files that cannot say how long they are.
type undescribableFS struct{ *fsx.Mem }

func (u undescribableFS) Open(name string) (fs.File, error) {
	f, err := u.Mem.Open(name)
	if err != nil {
		return nil, err
	}
	return sizeless{f}, nil
}

type sizeless struct{ fs.File }

func (sizeless) Stat() (fs.FileInfo, error) { return nil, errors.New("this file has no description") }

// ReadAt keeps sizeless a ReaderAtCloser, so OpenReaderAt gets past the first
// refusal and reaches the one under test.
func (s sizeless) ReadAt(p []byte, off int64) (int, error) {
	return s.File.(io.ReaderAt).ReadAt(p, off)
}

// The scratch file is removed even when the directory sync fails, because by
// then the rename has already succeeded and the destination is correct.
func TestWriteStreamAtomicReportsSyncDirFailure(t *testing.T) {
	m := newMem(t)
	m.Fail = func(op, name string) error {
		if op == "sync" && name == "/root" {
			return errors.New("boom")
		}
		return nil
	}
	err := fsx.WriteStreamAtomic(m, "/root/payload.bin", 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, "payload")
		return err
	})
	if err == nil {
		t.Fatal("a failed directory sync was reported as success")
	}
	m.Fail = nil
	if got := read(t, m, "/root/payload.bin"); got != "payload" {
		t.Errorf("destination is %q; the rename had already succeeded", got)
	}
	entries, err := m.ReadDir("/root")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d entries under the root, want only payload.bin", len(entries))
	}
}

// A source that stops answering mid-stream is a failure, not a short read that
// the caller then treats as the whole file.
func TestCopyReportsAReaderThatFails(t *testing.T) {
	boom := errors.New("the medium stopped answering")
	src := io.MultiReader(strings.NewReader("the first half"), failingReader{boom})

	n, err := fsx.Copy(io.Discard, src, 1<<20)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the reader's own error", err)
	}
	if n != int64(len("the first half")) {
		t.Errorf("copied %d bytes, want the prefix that did arrive", n)
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }
