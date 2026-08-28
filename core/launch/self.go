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
	"fmt"
	"io/fs"
	"strings"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// Updating the launcher itself is a step of its own, and the layout is why: the
// shim lives at the top of the install root, beside `current` and `versions/`,
// and a release's files land *inside* a version directory. The blue/green swap
// therefore never touches it. Something has to carry the new launcher the last
// few centimetres, and that something is the launcher, at the one moment it is
// allowed to — the start, before it hands over (docs/design.md §13, IDN-17).
//
// Trust does not enter into it. The file being copied was verified against its
// signed target hash when it was staged, and copying an already-verified byte
// somewhere else is not a new trust decision. That is the same argument the rest
// of this package rests on: the launcher has no network, no keys and no TUF
// client, because everything it moves was checked before it arrived.
//
// What *is* platform-specific is replacing a file that is currently executing.
// POSIX renames over it and the running image keeps its inode. Windows holds an
// image section on the file and refuses to replace it, but it does allow the
// running executable to be *renamed* — which is the whole trick, and the reason
// this needs a mechanism on that platform rather than a rename (see
// replaceSelf).

// selfSuffix marks the old launcher moved aside on a platform that will not
// replace a running binary. A start that finds one and can remove it does; one
// that cannot leaves it for the next start.
const selfSuffix = ".idunn-old"

// maxLauncherBytes bounds the two reads that decide whether the shim is stale.
// A launcher is a shim — no network, no keys, no TUF client — so a large one is
// a sign something else is going on, and the comparison is not the place to find
// that out by allocating.
const maxLauncherBytes = 64 << 20 // 64 MiB

// updateSelf replaces the launcher in the install root with the one the live
// version ships, when the two differ.
//
// It reports whether it replaced anything. Nothing here is fatal to a start: the
// installation that is live is complete and runnable either way, and refusing to
// launch an application because its *launcher* could not be refreshed would be
// the worse outcome by a wide margin — the same judgement Start already makes
// about a deferred update it could not finish.
func (o Options) updateSelf() (bool, error) {
	if o.SelfSource == "" || o.SelfPath == "" {
		return false, nil // the host did not ask for it.
	}
	rel, err := safepath.Clean(o.SelfSource)
	if err != nil {
		return false, fmt.Errorf("%w: SelfSource: %w", ErrLaunch, err)
	}

	version, err := layout.PointerTarget(o.FS, o.Root)
	if err != nil {
		return false, err
	}
	if version == "" {
		return false, nil // nothing is installed, so nothing ships a launcher.
	}
	dir, err := layout.VersionDir(o.Root, version)
	if err != nil {
		return false, err
	}
	src := fsx.Join(dir, rel)

	// A release that ships no launcher is the ordinary case, not an error: most
	// releases change the application and leave the shim alone.
	next, err := readIfRegular(o.FS, src)
	if err != nil || next == nil {
		return false, err
	}
	current, err := readIfRegular(o.FS, o.SelfPath)
	if err != nil {
		return false, err
	}
	if current != nil && bytes.Equal(current, next) {
		return false, nil
	}

	if err := replaceSelf(o.FS, o.SelfPath, next); err != nil {
		return false, err
	}
	return true, nil
}

// readIfRegular reads name, or returns nil if it is absent or is not a plain
// file.
//
// A symlink or a directory where a launcher is expected is not something to
// follow: the shim's location is the one path in this layout that a user is
// invited to click, and what sits there is replaced by this code, not resolved
// by it.
func readIfRegular(f fsx.FS, name string) ([]byte, error) {
	info, err := fsx.Lstat(f, name)
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	if info.Size() > maxLauncherBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrLaunch, name, maxLauncherBytes)
	}
	data, err := fsx.ReadFile(f, name, maxLauncherBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	return data, nil
}

// sweepSelfLeftovers removes launchers a previous start moved aside once they
// are no longer running.
//
// It is best-effort by design. The file it is trying to remove is, on the start
// that created it, the image this very process is executing from — so the first
// attempt is expected to fail, and the one after the next restart is expected to
// succeed. Reporting that as an error would make every second start noisy about
// something that is working exactly as intended.
func sweepSelfLeftovers(f fsx.FS, dir string) {
	entries, err := f.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.Contains(e.Name(), selfSuffix) {
			continue
		}
		_ = f.Remove(fsx.Join(dir, e.Name()))
	}
}

// launcherMode is what a replaced launcher is written with. It is the mode a
// shim needs and no more: readable and executable by everyone, writable only by
// whoever owns the install root.
const launcherMode fs.FileMode = 0o755
