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

// Package fsx is the filesystem abstraction every other package writes through.
//
// It exists so no code in core touches the OS filesystem directly: every path in
// the apply flow stays deterministically testable (in-memory FS) and every write
// goes through one auditable surface. See docs/design.md §2, §12.
//
// # Path namespace
//
// Unlike io/fs, names here are NOT restricted to fs.ValidPath: an install root is
// an absolute path (`/opt/app`, `C:\Program Files\app`), and the whole point of
// this abstraction is that the same code addresses it under both OS and in-memory
// filesystems. Names are slash-separated or OS-native; each implementation
// translates. Callers still never build a name from untrusted input directly —
// destinations pass through internal/safepath first.
package fsx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync/atomic"
)

// FS is the write-capable filesystem contract used by stage, txn and installer.
//
// Rename replaces a FILE atomically within a directory on every supported
// platform, and that is the guarantee the durable writes here rest on.
//
// It is deliberately NOT promised for a directory. On Windows os.Rename is
// MoveFileEx with MOVEFILE_REPLACE_EXISTING, which refuses to replace an
// existing directory — and a directory symlink counts as one, so a symlink to a
// version directory cannot be swapped that way. internal/layout is where that
// difference lives: the install pointer is a symlink on POSIX and a pointer file
// on Windows, so the commit point stays atomic on both (docs/design.md §13).
type FS interface {
	fs.StatFS
	fs.ReadDirFS

	Open(name string) (fs.File, error)
	Create(name string, mode fs.FileMode) (io.WriteCloser, error)
	MkdirAll(name string, mode fs.FileMode) error
	Remove(name string) error
	RemoveAll(name string) error

	// Rename moves oldname to newname, replacing newname if it exists. See the
	// note above on what is and is not atomic for directories.
	Rename(oldname, newname string) error

	// Symlink creates a symlink at linkname pointing to target.
	//
	// Nothing in core calls this on Windows: creating a symlink there needs
	// administrator rights or Developer Mode, which a per-user install does not
	// have, so the install pointer takes its file form instead.
	Symlink(target, linkname string) error

	// Readlink returns the destination of the link at name.
	Readlink(name string) (string, error)
}

// ErrNotSupported reports a capability the concrete filesystem does not provide.
// Callers treat it as a hard failure, never as "assume the safe answer": a check
// we cannot perform is a check we cannot claim (AGENTS.md §1.1).
var ErrNotSupported = errors.New("fsx: operation not supported by this filesystem")

// Syncer is implemented by the writers Create returns when their bytes can be
// forced to stable storage. The journal depends on it: a record that is only in
// the page cache does not survive the crash it exists to describe.
type Syncer interface {
	Sync() error
}

// LstatFS is implemented by filesystems that can inspect a name without
// following a final symlink.
//
// The apply path needs this distinction: `current` is a symlink by design, while
// a symlink where a regular file is expected is how a local attacker redirects a
// write out of the install root. Stat alone cannot tell those apart.
type LstatFS interface {
	FS
	Lstat(name string) (fs.FileInfo, error)
}

// SyncDirFS is implemented by filesystems whose directory entries can be forced
// to stable storage. On POSIX a rename is only durable once the containing
// directory is fsynced.
type SyncDirFS interface {
	FS
	SyncDir(name string) error
}

// Lstat stats name without following a final symlink. A filesystem that cannot
// answer the question is an error rather than a silent fallback to Stat: the
// callers use Lstat precisely to detect a link, and answering with the link's
// target would invert the result they act on.
func Lstat(f FS, name string) (fs.FileInfo, error) {
	l, ok := f.(LstatFS)
	if !ok {
		return nil, fmt.Errorf("%w: Lstat", ErrNotSupported)
	}
	return l.Lstat(name)
}

// SyncDir flushes the directory entry of name to stable storage where that is a
// meaningful operation. A filesystem without a dirty directory entry to flush
// (the in-memory one) reports success, because for it the rename already is as
// durable as the medium gets.
func SyncDir(f FS, name string) error {
	s, ok := f.(SyncDirFS)
	if !ok {
		return nil
	}
	return s.SyncDir(name)
}

// IsNotExist reports whether err means "the name does not exist". It exists so
// callers do not spread errors.Is(err, fs.ErrNotExist) plus os-specific variants
// across the apply path.
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// ReadFile reads at most limit bytes from name and fails if the file is longer.
//
// The limit is mandatory and per call site: every file this project reads
// (journal, install state, staged payload) has a known ceiling, and a hostile or
// corrupt file must not be able to turn a read into an allocation attack.
func ReadFile(f FS, name string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("fsx: read %s: limit must be positive", name)
	}
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	// Read one byte past the limit so an oversized file is detected rather than
	// silently truncated into something that still parses.
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("fsx: read %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("fsx: read %s: larger than %d bytes", name, limit)
	}
	return data, nil
}

// tmpSeq makes temporary names unique within a process; the pid separates
// processes. No randomness is involved, so nothing here can leak entropy into a
// reproducible artifact (AGENTS.md §1.7).
var tmpSeq atomic.Uint64

// TempName returns the scratch name WriteFileAtomic writes through. It is
// exported so recovery can recognise and remove abandoned scratch files.
func TempName(name string) string {
	return fmt.Sprintf("%s.idunn-%d-%d.tmp", name, os.Getpid(), tmpSeq.Add(1))
}

// WriteFileAtomic writes data to name so that a reader sees either the previous
// contents or the complete new ones, never a prefix.
//
// It writes a scratch file beside the destination, fsyncs it, renames it over the
// destination, and fsyncs the containing directory. Every durable write in idunn
// goes through here — the journal above all, whose whole value is being readable
// after the crash that interrupted it (docs/design.md §6.2).
func WriteFileAtomic(f FS, name string, data []byte, mode fs.FileMode) error {
	dir := Dir(name)
	tmp := TempName(name)

	w, err := f.Create(tmp, mode)
	if err != nil {
		return fmt.Errorf("fsx: create %s: %w", tmp, err)
	}
	// From here on the scratch file exists; every failure path must remove it,
	// or a crashed write would leave litter that later looks like state.
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		_ = f.Remove(tmp)
		return fmt.Errorf("fsx: write %s: %w", tmp, err)
	}
	if s, ok := w.(Syncer); ok {
		if err := s.Sync(); err != nil {
			_ = w.Close()
			_ = f.Remove(tmp)
			return fmt.Errorf("fsx: sync %s: %w", tmp, err)
		}
	}
	if err := w.Close(); err != nil {
		_ = f.Remove(tmp)
		return fmt.Errorf("fsx: close %s: %w", tmp, err)
	}
	if err := f.Rename(tmp, name); err != nil {
		_ = f.Remove(tmp)
		return fmt.Errorf("fsx: rename %s -> %s: %w", tmp, name, err)
	}
	if err := SyncDir(f, dir); err != nil {
		return fmt.Errorf("fsx: sync dir %s: %w", dir, err)
	}
	return nil
}
