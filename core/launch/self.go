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

package launch

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/launcherfile"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Updating the launcher itself is a step of its own, and the layout is why: the
// launcher lives at the top of the install root, beside `current` and `versions/`,
// and a release's files land *inside* a version directory, so the blue/green swap
// never touches it (docs/design.md §13, IDN-17).
//
// The work is split along the line AGENTS.md §1.2 draws. The updater holds the
// bytes go-tuf has just verified, so it is the updater that stages the new
// launcher, and only once its update has committed:
// .updater/launcher.next/<name> (internal/layout). The launcher has no TUF client
// and makes no trust decision: at its next start, the one moment a program may
// replace the file it is executing from, it swaps that file in. Nothing is hashed
// here. The staged file is protected by the filesystem permissions of the install
// root, exactly like the launcher binary it replaces.
//
// What the launcher does refuse is anything that is not plainly "a file staged
// for me, in the root I serve": a link or other non-regular file as the staged
// file or at its own name, a staged file too large or empty to be a launcher, and
// a launcher that does not sit directly in the root it serves.
//
// Nothing here can fail a start. The installation that is live is complete and
// runnable whether or not its launcher is current; the outcome is reported in
// Result.SelfErr and the hand-over goes ahead.

// ErrSelfRefused reports a staged launcher, or a launcher, that is not something
// to swap: a link, a directory or another non-regular file, an implausible size,
// or a launcher outside the root it serves. The old launcher stays.
var ErrSelfRefused = fmt.Errorf("%w: the staged launcher is not swapped in", ErrLaunch)

// ErrSelfNotWritable reports an install root this process may not write, which
// is what a system-wide install looks like to the unprivileged user who starts
// it. The launcher is left as it is; replacing it needs the elevated side, which
// nothing starts from a launcher yet (backlog IDN-23).
var ErrSelfNotWritable = fmt.Errorf("%w: the launcher is in a root this process cannot write (IDN-23)", ErrLaunch)

// maxLauncherBytes bounds the read of the staged launcher. A launcher is a shim —
// no network, no keys, no TUF client — so a large one is a sign something else is
// going on, and a swap is not the place to find that out by allocating.
const maxLauncherBytes = 64 << 20 // 64 MiB

// replaceSelf is the platform's swap (launcherfile.Replace), a variable so the
// tests can run both strategies everywhere.
var replaceSelf = launcherfile.Replace

// updateSelf swaps the launcher staged for this launcher's name over it, when
// there is one. It reports whether it replaced anything.
func (o Options) updateSelf(replace launcherfile.Func) (bool, error) {
	if o.SelfPath == "" {
		return false, nil // the host did not ask for it.
	}
	self := fsx.Clean(o.SelfPath)
	next, err := layout.LauncherNext(o.Root, fsx.Base(self))
	if err != nil {
		// No update can stage a launcher under a name the layout refuses, so
		// there is nothing for this one to take. Not an error: it is a
		// binary that was never going to be replaced.
		return false, nil //nolint:nilerr // an unstageable name means nothing staged, by construction.
	}

	// The staged file: its directory and the file itself must be what the
	// updater creates — a real directory and a regular file — and not a link
	// to be followed somewhere else.
	//
	// These are if chains rather than switches on purpose: the mutation run
	// (docs/status.md) attributes a condition in a case clause to no covered
	// block, so every refusal below would count as untested.
	dirInfo, err := fsx.Lstat(o.FS, layout.LauncherNextDir(o.Root))
	if fsx.IsNotExist(err) {
		return false, nil // nothing staged: the ordinary case.
	}
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&fs.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: %s is not a directory", ErrSelfRefused, layout.LauncherNextDir(o.Root))
	}
	info, err := fsx.Lstat(o.FS, next)
	if fsx.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: %s is not a regular file", ErrSelfRefused, next)
	}
	if info.Size() <= 0 || info.Size() > maxLauncherBytes {
		return false, fmt.Errorf("%w: %s is %d bytes, which is no launcher", ErrSelfRefused, next, info.Size())
	}

	// The launcher that is replaced must be the one in the root being served.
	// A launcher pointed at some other root (--root) would otherwise copy that
	// root's staged file over itself — and a launcher in an administrators-only
	// directory, run by an administrator against a root a user controls, would
	// be writing that user's bytes to where everyone clicks.
	if fsx.Dir(self) != fsx.Clean(o.Root) {
		return false, fmt.Errorf("%w: the launcher %s is not in the install root %s", ErrSelfRefused, o.SelfPath, o.Root)
	}

	data, err := readExactly(o.FS, next, info.Size())
	if err != nil {
		return false, err
	}

	current, err := fsx.Lstat(o.FS, self)
	if err != nil && !fsx.IsNotExist(err) {
		return false, fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	if err == nil {
		if !current.Mode().IsRegular() {
			// A link or a directory where the launcher should be is not
			// something to follow or to replace: whatever put it there knows
			// something this code does not.
			return false, fmt.Errorf("%w: %s is not a regular file; the launcher is not replaced", ErrSelfRefused, o.SelfPath)
		}
		// A different length is a different launcher; no need to read it.
		if current.Size() == int64(len(data)) {
			have, err := readExactly(o.FS, self, current.Size())
			if err != nil {
				return false, err
			}
			if bytes.Equal(have, data) {
				// Already swapped — a start that died before it could remove
				// the staged file. Finish that and nothing else.
				o.dropStaged(next)
				return false, nil
			}
		}
	}

	if err := replace(o.FS, self, data); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return false, fmt.Errorf("%w: %w", ErrSelfNotWritable, err)
		}
		return false, fmt.Errorf("%w: replacing the launcher: %w", ErrLaunch, err)
	}
	// The swap is done; the staged file has served its purpose. If it cannot be
	// removed now, the next start finds it identical to the launcher and
	// removes it then.
	o.dropStaged(next)
	return true, nil
}

// dropStaged removes a staged launcher that has been swapped in.
func (o Options) dropStaged(next string) {
	// Best effort, both: a staged file left behind is found identical to the
	// launcher on the next start and removed then.
	_ = o.FS.Remove(next)
	_ = fsx.SyncDir(o.FS, layout.LauncherNextDir(o.Root))
}

// readExactly reads name, which must be exactly size bytes long. A file that has
// changed size since it was stat'ed fails the read rather than being truncated
// into something that compares equal.
func readExactly(f fsx.FS, name string, size int64) ([]byte, error) {
	data, err := fsx.ReadFile(f, name, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("%w: %s changed while it was read", ErrLaunch, name)
	}
	return data, nil
}
