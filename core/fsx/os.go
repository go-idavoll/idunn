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

package fsx

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// osFS is the real filesystem. It is stateless, so it carries no configuration
// that could differ between two callers looking at the same install root.
type osFS struct{}

// OS returns the filesystem backed by the operating system.
func OS() FS { return osFS{} }

// native converts a slash-separated name into the platform spelling. Callers may
// also pass an already-native name; ToSlash/FromSlash round-trips it unchanged.
func native(name string) string { return filepath.FromSlash(name) }

func (osFS) Open(name string) (fs.File, error) {
	f, err := os.Open(native(name))
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(native(name)) }

// Lstat does not follow a final symlink, which is how the apply path tells a
// deliberate `current` link from a planted one.
func (osFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(native(name)) }

func (osFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(native(name)) }

// Create truncates or creates name with the given permissions. Files land with
// exactly the mode requested — the descriptor's Mode is already restricted to
// permission bits on ingest (core/release), so no type or setuid bit can arrive
// here. The process umask still applies, and that is deliberate: it can only
// remove permissions, never add them.
func (osFS) Create(name string, mode fs.FileMode) (io.WriteCloser, error) {
	f, err := os.OpenFile(native(name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) MkdirAll(name string, mode fs.FileMode) error {
	return os.MkdirAll(native(name), mode.Perm())
}

func (osFS) Remove(name string) error    { return os.Remove(native(name)) }
func (osFS) RemoveAll(name string) error { return os.RemoveAll(native(name)) }

// Rename is the commit point of the whole system: the swap of `current` is one
// call to it (docs/design.md §6.1).
//
// It replaces an existing FILE atomically everywhere. It does NOT replace an
// existing directory on Windows, where os.Rename is MoveFileEx with
// MOVEFILE_REPLACE_EXISTING — see the FS interface comment, and internal/layout
// for how the pointer stays atomic there anyway.
func (osFS) Rename(oldname, newname string) error {
	return os.Rename(native(oldname), native(newname))
}

func (osFS) Symlink(target, linkname string) error {
	return os.Symlink(native(target), native(linkname))
}

// Readlink returns the link target in slash form, so a Windows junction and a
// POSIX symlink compare equal to the same stored value.
func (osFS) Readlink(name string) (string, error) {
	t, err := os.Readlink(native(name))
	if err != nil {
		return "", err
	}
	return Slash(t), nil
}
