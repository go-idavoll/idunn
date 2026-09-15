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
	"io"
	"io/fs"
	"strings"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// The launcher sits at the top of the install root, above versions/, so the
// blue/green swap never replaces it (docs/design.md §6.1, §13, IDN-17). A release
// that carries a new one gets it there in two hands:
//
//  1. The updater, while staging, writes the launcher's verified bytes — the ones
//     go-tuf just accepted — to a pending file that belongs to the transaction:
//
//     .updater/staging/<version>.launcher/<name>
//
//     It lives under staging/, so everything that removes an uncommitted
//     transaction's litter (rollback, recovery) removes it too.
//
//  2. Once the transaction has COMMITTED, the pending file is promoted:
//
//     .updater/launcher.next/<name>
//
//     That is the only file the launcher ever swaps in, at its next start. It
//     never exists for a version that did not commit, because nothing but
//     PromoteLauncher creates it and PromoteLauncher runs only after a COMMITTED
//     record for exactly that version.
//
// <name> is the launcher's own file name in the install root. Keying the staged
// file by it means a launcher only ever takes the file staged for its own name:
// a second binary in the same root cannot swap another launcher over itself.
//
// Nothing here checks bytes. The pending file holds what the trust layer verified
// and the staged file is a rename of it; both are protected by the filesystem
// permissions of the install root, exactly like the launcher they replace.
const (
	// LauncherNextName is the directory under MetaName holding the staged
	// launcher, keyed by the launcher's file name.
	LauncherNextName = "launcher.next"

	// launcherPendingSuffix marks the pending launcher of one transaction
	// beside that transaction's staging tree.
	launcherPendingSuffix = ".launcher"
)

// ValidateLauncherName rejects a launcher file name that must not become a path
// element directly in the install root: anything with a separator or traversal,
// a Windows device name, a name the layout itself uses, or one that collides with
// the scratch and leftover files idunn writes beside the launcher.
func ValidateLauncherName(name string) error {
	clean, err := safepath.Clean(name)
	if err != nil {
		return fmt.Errorf("%w: launcher name %q: %w", ErrLayout, name, err)
	}
	if clean != name || strings.Contains(name, "/") {
		return fmt.Errorf("%w: launcher name %q is not a single file name", ErrLayout, name)
	}
	for _, reserved := range []string{CurrentName, VersionsName, MetaName} {
		if strings.EqualFold(name, reserved) {
			return fmt.Errorf("%w: launcher name %q is part of the layout", ErrLayout, name)
		}
	}
	if strings.Contains(name, ".idunn-") {
		return fmt.Errorf("%w: launcher name %q collides with idunn's scratch names", ErrLayout, name)
	}
	return nil
}

// LauncherNextDir is the directory holding the staged launcher.
func LauncherNextDir(root string) string { return fsx.Join(root, MetaName, LauncherNextName) }

// LauncherNext is the staged launcher for the launcher called name.
func LauncherNext(root, name string) (string, error) {
	if err := ValidateLauncherName(name); err != nil {
		return "", err
	}
	return fsx.Join(LauncherNextDir(root), name), nil
}

// LauncherPendingDir is where one transaction keeps its launcher until it commits.
func LauncherPendingDir(root, version string) (string, error) {
	if err := ValidateVersion(version); err != nil {
		return "", err
	}
	return fsx.Join(Staging(root), version+launcherPendingSuffix), nil
}

// WriteLauncherPending records data as the launcher called name that the
// transaction installing version carries. It is written atomically (scratch
// file, fsync, rename) with MetaFileMode.
//
// The caller is staging, and data are bytes the trust layer has just accepted:
// this function is where they go, not a judgement on them.
func WriteLauncherPending(f fsx.FS, root, version, name string, data []byte) error {
	return WriteLauncherPendingStream(f, root, version, name, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// WriteLauncherPendingStream is WriteLauncherPending for a launcher that is
// produced rather than held.
//
// Staging streams every file it writes, so it no longer has the launcher's bytes
// to hand one it has just staged; produce copies them from where they landed,
// past the same signed-hash verdict (IDN-12). Either form leaves nothing behind
// if produce fails: fsx.WriteStreamAtomic removes its scratch file, and an empty
// pending directory is what "no pending launcher" already looks like.
func WriteLauncherPendingStream(f fsx.FS, root, version, name string, produce func(w io.Writer) error) error {
	if err := ValidateLauncherName(name); err != nil {
		return err
	}
	dir, err := LauncherPendingDir(root, version)
	if err != nil {
		return err
	}
	// One pending launcher per transaction: whatever an abandoned attempt left
	// here is not a base to build on.
	if err := f.RemoveAll(dir); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if err := f.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if err := fsx.WriteStreamAtomic(f, fsx.Join(dir, name), MetaFileMode, produce); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

// RemoveLauncherPending removes the pending launcher of version, if any.
func RemoveLauncherPending(f fsx.FS, root, version string) error {
	dir, err := LauncherPendingDir(root, version)
	if err != nil {
		return err
	}
	if err := f.RemoveAll(dir); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}

// PromoteLauncher turns the pending launcher of a committed transaction into the
// staged launcher the next start swaps in. The caller must only call it after the
// COMMITTED record for version is durable, and only while `current` names
// version: that is the whole guarantee that a staged launcher belongs to an
// update that happened.
//
// No pending launcher is the ordinary case — most releases do not ship one, and
// most hosts do not configure one — and is not an error. A pending entry that is
// not exactly one regular file with a valid launcher name is refused and left
// where it is: staging never writes anything else there.
//
// It is idempotent. A crash after the rename leaves nothing pending, and a
// crash before it leaves the pending file for the next recovery to promote.
func PromoteLauncher(f fsx.FS, root, version string) error {
	dir, err := LauncherPendingDir(root, version)
	if err != nil {
		return err
	}
	info, err := fsx.Lstat(f, dir)
	switch {
	case fsx.IsNotExist(err):
		return nil
	case err != nil:
		return fmt.Errorf("%w: %w", ErrLayout, err)
	case !info.IsDir() || info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%w: pending launcher %s is not a directory", ErrLayout, dir)
	}
	entries, err := f.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if len(entries) == 0 {
		// A write that died before its rename leaves an empty directory (its
		// scratch file is swept by recovery). Nothing was pending.
		return removeIfEmpty(f, dir)
	}
	if len(entries) != 1 {
		return fmt.Errorf("%w: %s holds %d entries, not one launcher", ErrLayout, dir, len(entries))
	}
	name := entries[0].Name()
	if err := ValidateLauncherName(name); err != nil {
		return err
	}
	src := fsx.Join(dir, name)
	if info, err := fsx.Lstat(f, src); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: pending launcher %s is not a regular file", ErrLayout, src)
	}

	next := LauncherNextDir(root)
	if info, err := fsx.Lstat(f, next); err == nil {
		if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is not a directory", ErrLayout, next)
		}
	} else if !fsx.IsNotExist(err) {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if err := f.MkdirAll(next, DirMode); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	// A launcher staged under another name by an earlier update is superseded:
	// the host renamed its launcher, and the old name is not the one to refresh.
	if old, err := f.ReadDir(next); err == nil {
		for _, e := range old {
			if e.Name() != name {
				if err := f.RemoveAll(fsx.Join(next, e.Name())); err != nil {
					return fmt.Errorf("%w: %w", ErrLayout, err)
				}
			}
		}
	}
	if err := f.Rename(src, fsx.Join(next, name)); err != nil {
		return fmt.Errorf("%w: promote the staged launcher: %w", ErrLayout, err)
	}
	if err := fsx.SyncDir(f, next); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return removeIfEmpty(f, dir)
}

// removeIfEmpty removes a directory that is expected to be empty.
func removeIfEmpty(f fsx.FS, dir string) error {
	if err := f.Remove(dir); err != nil && !fsx.IsNotExist(err) {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}
