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

// Package launcherfile replaces the launcher binary at the top of an install root
// and repairs a replacement that was interrupted (docs/design.md §13, IDN-17).
//
// It is file placement and nothing else. Which bytes go in is decided before this
// package is reached: the updater stages the launcher a committed update carries
// (internal/layout), and core/launch hands those bytes over. The part that is
// platform-specific is replacing a file that is currently executing. POSIX renames
// over it and the running image keeps its inode. Windows holds an image section
// on the file and refuses to replace or delete it, but it does allow the running
// executable to be *renamed* — which is the whole trick (ReplaceAside).
//
// Two packages use it: core/launch, which swaps at the start and repairs before
// it, and core/updater and launch.Relaunch, which repair from the application's
// side — so a launcher whose name an interruption left empty does not depend on
// that very launcher to come back.
package launcherfile

import (
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/go-idavoll/idunn/core/fsx"
)

const (
	// AsideSuffix marks an old launcher moved aside on a platform that will
	// not replace a running binary. A decimal counter follows it.
	AsideSuffix = ".idunn-old-"

	// NewSuffix is the scratch name the replacement is written to before
	// anything else changes. It matches the pattern recovery already sweeps as
	// abandoned scratch (".idunn-" … ".tmp").
	NewSuffix = ".idunn-new.tmp"

	// Mode is what a replaced launcher is written with: readable and executable
	// by everyone, writable only by whoever owns the install root.
	Mode fs.FileMode = 0o755
)

// Func swaps the launcher at path for data.
type Func func(f fsx.FS, path string, data []byte) error

// Replace is the platform's strategy: ReplaceByRename on POSIX, ReplaceAside on
// Windows.
var Replace Func = replaceOS

// ReplaceByRename writes the new launcher beside the old one and renames it over
// the name.
//
// On POSIX this needs no ceremony. A running program holds its image by inode,
// and a rename over the name it was started from leaves that inode alone — the
// process keeps executing what it started with and the next start picks up the
// new file. The rename is atomic, so an interruption at any point leaves either
// the old launcher or the new one at the name, never a prefix of either.
func ReplaceByRename(f fsx.FS, path string, data []byte) error {
	return fsx.WriteFileAtomic(f, path, data, Mode)
}

// ReplaceAside replaces a launcher that is currently executing, on a platform
// that will rename a running image but not replace or delete it.
//
//	<new bytes>   ->  launcher.exe.idunn-new.tmp     (written and flushed first)
//	launcher.exe  ->  launcher.exe.idunn-old-<n>     (allowed while running)
//	launcher.exe.idunn-new.tmp -> launcher.exe       (the name is free now)
//
// The new launcher is complete on disk before the running one is touched, so a
// root this process cannot write fails at the first step with nothing changed.
// If the final rename fails, the old launcher is renamed back.
//
// The window in which the name is empty is the two adjacent renames. Windows has
// no atomic replace of a mapped image, so that window cannot be closed, only
// repaired: whatever runs Repair next — the next start, the application's
// updater, launch.Relaunch — finds the name empty and an old launcher beside it,
// and puts that one back.
//
// The leftover cannot be deleted yet, because this process is executing from it.
// Repair removes it later; if even removal now fails, cleanup is asked to
// schedule a delete at reboot (MOVEFILE_DELAY_UNTIL_REBOOT on Windows) as the
// backstop, not the plan.
func ReplaceAside(cleanup func(string)) Func {
	return func(f fsx.FS, path string, data []byte) error {
		tmp := path + NewSuffix
		if err := writeSynced(f, tmp, data); err != nil {
			return fmt.Errorf("writing the new launcher: %w", err)
		}

		aside := ""
		if _, err := fsx.Lstat(f, path); err == nil {
			aside = nextAside(f, path)
			if err := f.Rename(path, aside); err != nil {
				_ = f.Remove(tmp)
				return fmt.Errorf("moving the running launcher aside: %w", err)
			}
		} else if !fsx.IsNotExist(err) {
			_ = f.Remove(tmp)
			return err
		}

		if err := f.Rename(tmp, path); err != nil {
			// Put the old one back. Failing to update the launcher is a
			// disappointment; leaving the install without one is a broken
			// machine.
			if aside != "" {
				if rerr := f.Rename(aside, path); rerr != nil {
					return fmt.Errorf("the launcher could not be replaced and the old one could not be "+
						"restored from %s (%w): %w", aside, rerr, err)
				}
			}
			_ = f.Remove(tmp)
			return fmt.Errorf("replacing the launcher: %w", err)
		}
		if err := fsx.SyncDir(f, fsx.Dir(path)); err != nil {
			return fmt.Errorf("the launcher was replaced but not flushed: %w", err)
		}

		if aside != "" {
			if err := f.Remove(aside); err != nil && cleanup != nil {
				cleanup(aside)
			}
		}
		return nil
	}
}

// writeSynced writes data to name and flushes it, removing it again on failure.
func writeSynced(f fsx.FS, name string, data []byte) error {
	w, err := f.Create(name, Mode)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		_ = f.Remove(name)
		return err
	}
	if s, ok := w.(fsx.Syncer); ok {
		if err := s.Sync(); err != nil {
			_ = w.Close()
			_ = f.Remove(name)
			return err
		}
	}
	if err := w.Close(); err != nil {
		_ = f.Remove(name)
		return err
	}
	return nil
}

// asides lists the numbered old launchers beside path, highest number first.
func asides(f fsx.FS, path string) []string {
	entries, err := f.ReadDir(fsx.Dir(path))
	if err != nil {
		return nil
	}
	prefix := fsx.Base(path) + AsideSuffix
	type aside struct {
		n    int
		name string
	}
	var found []aside
	for _, e := range entries {
		s, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok || e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || strconv.Itoa(n) != s {
			continue
		}
		found = append(found, aside{n: n, name: fsx.Join(fsx.Dir(path), e.Name())})
	}
	slices.SortFunc(found, func(a, b aside) int { return b.n - a.n })
	out := make([]string, 0, len(found))
	for _, a := range found {
		out = append(out, a.name)
	}
	return out
}

// nextAside picks the next unused numbered name beside path. A counter rather
// than a clock or a pid keeps "newest" well defined for Repair.
func nextAside(f fsx.FS, path string) string {
	n := 1
	if existing := asides(f, path); len(existing) > 0 {
		last := strings.TrimPrefix(fsx.Base(existing[0]), fsx.Base(path)+AsideSuffix)
		if i, err := strconv.Atoi(last); err == nil {
			n = i + 1
		}
	}
	return path + AsideSuffix + strconv.Itoa(n)
}

// Repair tidies up after earlier replacements of the launcher at path, and
// reports whether it had to put a launcher back.
//
// A launcher at path means the leftovers are just that: old images, removable
// once nothing runs from them. On Windows one of them may be the image a running
// launcher executes from, so a failure to remove is expected and silent — a
// later Repair succeeds.
//
// No launcher at path, with an old one beside it, is the one state an
// interrupted ReplaceAside leaves: between its two renames. The newest old
// launcher is renamed back, because a runnable old launcher at the name is worth
// strictly more than none. The error reports only that this rename failed, or
// that the name could not be inspected: those leave the install without a
// launcher, and the caller has to be able to say so.
//
// Something at path that is not a regular file — a link, a directory — is not
// touched: whatever put it there knows something this code does not.
func Repair(f fsx.FS, path string) (restored bool, err error) {
	old := asides(f, path)
	info, err := fsx.Lstat(f, path)
	switch {
	case fsx.IsNotExist(err):
		if len(old) == 0 {
			return false, nil
		}
		if err := f.Rename(old[0], path); err != nil {
			return false, fmt.Errorf("restoring the launcher from %s: %w", old[0], err)
		}
		return true, fsx.SyncDir(f, fsx.Dir(path))
	case err != nil:
		return false, err
	case !info.Mode().IsRegular():
		return false, nil
	}
	for _, name := range old {
		_ = f.Remove(name)
	}
	if _, err := fsx.Lstat(f, path+NewSuffix); err == nil {
		_ = f.Remove(path + NewSuffix)
	}
	return false, nil
}
