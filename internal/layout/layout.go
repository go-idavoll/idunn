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
// The pointer is not spelled the same everywhere: on POSIX `current` is a
// symlink, on Windows a one-line file naming the same target. See pointer.go for
// why, and docs/design.md §13. Nothing in core reads THROUGH `current`, so the
// difference is confined to this package; the launcher is what resolves it.
//
//	<root>/
//	  launcher(.exe)        # tiny, stable; runs the version `current` names
//	  current -> versions/1.3.0     # symlink (POSIX) / pointer file (Windows)
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

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
)

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
