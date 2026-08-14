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
package fsx

import (
	"io"
	"io/fs"
)

// FS is the write-capable filesystem contract used by stage, txn and installer.
//
// Rename must be atomic within the same directory on every supported platform;
// the atomic swap of `current` depends on it (docs/design.md §6.1).
type FS interface {
	fs.StatFS
	fs.ReadDirFS

	Open(name string) (fs.File, error)
	Create(name string, mode fs.FileMode) (io.WriteCloser, error)
	MkdirAll(name string, mode fs.FileMode) error
	Remove(name string) error
	RemoveAll(name string) error

	// Rename atomically replaces newname with oldname.
	Rename(oldname, newname string) error

	// Symlink creates a symlink (junction on Windows) at linkname pointing to
	// target. Used for `current` and for content-addressed delta relinks.
	Symlink(target, linkname string) error

	// Readlink returns the destination of the link at name.
	Readlink(name string) (string, error)
}
