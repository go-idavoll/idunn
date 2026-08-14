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
	"fmt"
	"io/fs"
	"strings"

	"github.com/go-idavoll/idunn/core/fsx"
)

// `current` is the single commit point of an update: repointing it is what makes
// a new version live, and repointing it back is the whole of a rollback. The one
// property it must have is that a reader sees either the old version or the new
// one — never nothing, never something half-written.
//
// How that is achieved is not the same on every platform, and pretending it is
// would produce a swap that silently is not atomic:
//
//   - POSIX: `current` is a symlink to versions/<v>. rename(2) replaces an
//     existing symlink atomically, so a scratch link beside it is renamed on top.
//
//   - Windows: `current` is a small pointer file naming versions/<v>. A directory
//     symlink there carries FILE_ATTRIBUTE_DIRECTORY, and MoveFileEx with
//     MOVEFILE_REPLACE_EXISTING — which is what os.Rename is — cannot replace an
//     existing directory. The swap fails with "Access is denied". Creating the
//     link is a problem of its own: Windows requires administrator rights or
//     Developer Mode for symlinks, which a per-user install does not have.
//     Replacing a FILE is atomic there, so the pointer becomes a file, and the
//     launcher reads it instead of walking through it (docs/design.md §13).
//
// The form is chosen at build time and is the only form accepted on that
// platform. Reading whichever one happens to be present would mean two spellings
// of the same state, and an installation that had both would have to be resolved
// by guessing (AGENTS.md §1.1).

// MaxPointerLen bounds the pointer file. It is far above any legitimate content.
const MaxPointerLen = 4 << 10

// pointerForm is how `current` is represented on disk.
type pointerForm interface {
	// describe names the form for error messages.
	describe() string

	// read returns the stored target ("versions/<v>"), or "" when there is no
	// pointer at all.
	read(f fsx.FS, root string) (string, error)

	// write puts target in place so that a concurrent reader sees either the
	// previous target or this one.
	write(f fsx.FS, root, target string) error
}

// relVersionTarget is what `current` contains: a root-relative target, never an
// absolute path. A relative pointer keeps the install tree movable and means a
// copied or restored installation cannot be made to point outside itself.
func relVersionTarget(version string) string {
	return VersionsName + "/" + version
}

// PointerTarget returns the version `current` names, or "" when there is no
// installation yet.
//
// A `current` that exists but is not the platform's pointer form is an error,
// not an empty answer: something replaced the pointer, and continuing would mean
// writing an update around whatever it now is.
func PointerTarget(f fsx.FS, root string) (string, error) {
	target, err := activePointer().read(f, root)
	if err != nil || target == "" {
		return "", err
	}
	return versionFromTarget(target)
}

// SetPointer atomically repoints `current` at version.
//
// This is the commit point of an update and the whole of a rollback. There is no
// window in which `current` is missing or names something that is not a version.
func SetPointer(f fsx.FS, root, version string) error {
	if err := ValidateVersion(version); err != nil {
		return err
	}
	return activePointer().write(f, root, relVersionTarget(version))
}

// RemovePointer deletes `current`. It is used only when a first install is rolled
// back, where there is no previous version to point at. A missing pointer is not
// an error, so the rollback can be re-run.
func RemovePointer(f fsx.FS, root string) error {
	if err := f.Remove(Current(root)); err != nil && !fsx.IsNotExist(err) {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

// versionFromTarget parses `versions/<v>` back into <v>, refusing anything else.
// The pointer is the one piece of install state that decides which code runs, so
// a target that is not exactly the shape we write is refused rather than
// interpreted.
func versionFromTarget(target string) (string, error) {
	clean := fsx.Clean(target)
	prefix := VersionsName + "/"
	if len(clean) <= len(prefix) || clean[:len(prefix)] != prefix {
		return "", fmt.Errorf("%w: current points at %q, not at a version directory", ErrLayout, target)
	}
	version := clean[len(prefix):]
	if err := ValidateVersion(version); err != nil {
		return "", err
	}
	return version, nil
}

// symlinkPointer stores the target as a symlink. It is the POSIX form.
type symlinkPointer struct{}

func (symlinkPointer) describe() string { return "symlink" }

func (symlinkPointer) read(f fsx.FS, root string) (string, error) {
	link := Current(root)
	info, err := fsx.Lstat(f, link)
	if err != nil {
		if fsx.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		return "", fmt.Errorf("%w: %s is not a symlink (mode %s)", ErrLayout, link, info.Mode())
	}
	target, err := f.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return target, nil
}

// write creates a scratch link beside the pointer and renames it on top. The
// rename is the atomic step; nothing before it is visible under `current`.
func (symlinkPointer) write(f fsx.FS, root, target string) error {
	link := Current(root)
	tmp := fsx.TempName(link)

	if err := f.Symlink(target, tmp); err != nil {
		return fmt.Errorf("%w: stage pointer: %w", ErrLayout, err)
	}
	if err := f.Rename(tmp, link); err != nil {
		_ = f.Remove(tmp)
		return fmt.Errorf("%w: swap pointer: %w", ErrLayout, err)
	}
	if err := fsx.SyncDir(f, root); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

// filePointer stores the target as a one-line file. It is the Windows form.
type filePointer struct{}

func (filePointer) describe() string { return "pointer file" }

func (filePointer) read(f fsx.FS, root string) (string, error) {
	name := Current(root)
	info, err := fsx.Lstat(f, name)
	if err != nil {
		if fsx.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("%w: %w", ErrLayout, err)
	}
	// A symlink or a directory here is not this form. Following it would mean
	// accepting a pointer this code did not write.
	if info.Mode().Type() != 0 {
		return "", fmt.Errorf("%w: %s is not a regular pointer file (mode %s)", ErrLayout, name, info.Mode())
	}

	raw, err := fsx.ReadFile(f, name, MaxPointerLen)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLayout, err)
	}
	target := strings.TrimSpace(string(raw))
	if target == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrLayout, name)
	}
	// One line, nothing else. A pointer file with more in it is a file some
	// other program is using for something, not ours.
	if strings.ContainsAny(target, "\r\n") {
		return "", fmt.Errorf("%w: %s holds more than one line", ErrLayout, name)
	}
	return target, nil
}

// write replaces the pointer file atomically. fsx.WriteFileAtomic writes a
// scratch file, fsyncs it, renames it over the destination and fsyncs the
// directory — and replacing a file by rename is atomic on Windows too, which is
// the whole reason this form exists.
func (filePointer) write(f fsx.FS, root, target string) error {
	if err := fsx.WriteFileAtomic(f, Current(root), []byte(target+"\n"), 0o644); err != nil {
		return fmt.Errorf("%w: swap pointer: %w", ErrLayout, err)
	}
	return nil
}
