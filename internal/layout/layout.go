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

// Package layout is the single description of what an idunn installation looks
// like on disk.
//
// It exists because four packages have to agree on it exactly: stage writes the
// version directories, txn recovers them after a crash, installer decides whether
// one already exists, and updater prunes them. If any two of those computed a
// path differently, a crash would be recovered against a tree nobody else can
// see. See docs/design.md §6.1.
//
//	<root>/
//	  launcher(.exe)        # tiny, stable; execs current/app
//	  current -> versions/1.3.0
//	  versions/
//	    1.2.0/              # previous, kept for instant rollback
//	    1.3.0/              # active
//	  .updater/
//	    journal.json        # in-progress transaction record
//	    state.json          # installed name/version/layout_schema
//	    staging/            # verified new files, pre-swap
package layout

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
)

// fsModeSymlink is spelled out once so the pointer check below reads as the
// question it asks rather than as a bit fiddle.
const fsModeSymlink = fs.ModeSymlink

// The fixed names of the layout. They are on-disk contract: an installed tree
// written by one version of idunn is read by the next, so these are not free to
// change without a LayoutSchema bump (release.LayoutSchema).
const (
	CurrentName  = "current"
	VersionsName = "versions"
	MetaName     = ".updater"
	JournalName  = "journal.json"
	StateName    = "state.json"
	StagingName  = "staging"
)

// ErrLayout is the class of every rejection in this package: a root that is not
// an install, a version string that must not become a path, a `current` that is
// not the pointer it should be.
var ErrLayout = errors.New("install layout")

// Root paths. Each takes the install root and returns a slash-space path.

// Current is the pointer that names the active version directory.
func Current(root string) string { return fsx.Join(root, CurrentName) }

// Versions is the directory holding one directory per installed version.
func Versions(root string) string { return fsx.Join(root, VersionsName) }

// Meta is idunn's own state directory inside the install.
func Meta(root string) string { return fsx.Join(root, MetaName) }

// Journal is the transaction journal.
func Journal(root string) string { return fsx.Join(root, MetaName, JournalName) }

// State is the install state the installer's downgrade preflight reads (§14.6).
func State(root string) string { return fsx.Join(root, MetaName, StateName) }

// Staging is where verified files are assembled before the swap.
func Staging(root string) string { return fsx.Join(root, MetaName, StagingName) }

// VersionDir returns the directory of one version.
//
// The version is validated before it becomes a path. It reaches here from a
// descriptor or from the journal, and while both are protected — one by TUF, the
// other by the filesystem permissions of the install root — neither is a reason
// to let an arbitrary string address the filesystem.
func VersionDir(root, version string) (string, error) {
	if err := ValidateVersion(version); err != nil {
		return "", err
	}
	return fsx.Join(root, VersionsName, version), nil
}

// ValidateVersion rejects any version string that must not become a path
// element. SemVer is already the only accepted spelling on ingest, so this is a
// second, local gate rather than a new rule.
func ValidateVersion(version string) error {
	if version == "" {
		return fmt.Errorf("%w: empty version", ErrLayout)
	}
	if !release.ValidVersion(version) {
		return fmt.Errorf("%w: version %q is not SemVer", ErrLayout, version)
	}
	return nil
}

// relVersionTarget is what `current` contains: a root-relative link, never an
// absolute path. A relative pointer keeps the install tree movable and means a
// copied or restored installation cannot be made to point outside itself.
func relVersionTarget(version string) string {
	return VersionsName + "/" + version
}

// PointerTarget returns the version `current` names, or "" when there is no
// installation yet.
//
// A `current` that exists but is not a symlink is an error, not an empty answer:
// something replaced the pointer, and continuing would mean writing an update
// around whatever it now is.
func PointerTarget(f fsx.FS, root string) (string, error) {
	link := Current(root)
	info, err := fsx.Lstat(f, link)
	if err != nil {
		if fsx.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if info.Mode()&fsModeSymlink == 0 {
		return "", fmt.Errorf("%w: %s is not a symlink (mode %s)", ErrLayout, link, info.Mode())
	}

	target, err := f.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLayout, err)
	}
	version, err := versionFromTarget(target)
	if err != nil {
		return "", err
	}
	return version, nil
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

// SetPointer atomically repoints `current` at version.
//
// This is the commit point of an update and the whole of a rollback: a symlink is
// created beside the pointer and renamed onto it, so a reader sees either the old
// version or the new one. There is no window in which `current` is missing.
func SetPointer(f fsx.FS, root, version string) error {
	if err := ValidateVersion(version); err != nil {
		return err
	}
	link := Current(root)
	tmp := fsx.TempName(link)

	if err := f.Symlink(relVersionTarget(version), tmp); err != nil {
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

// RemovePointer deletes `current`. It is used only when a first install is rolled
// back, where there is no previous version to point at. A missing pointer is not
// an error, so the rollback can be re-run.
func RemovePointer(f fsx.FS, root string) error {
	if err := f.Remove(Current(root)); err != nil && !fsx.IsNotExist(err) {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

// InstalledVersions lists the versions present under versions/, in no particular
// order. Entries that are not version directories are ignored rather than
// reported: an operator's stray file must not make the GC or the installer fail.
func InstalledVersions(f fsx.FS, root string) ([]string, error) {
	entries, err := f.ReadDir(Versions(root))
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if release.ValidVersion(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
