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

package elevate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-idavoll/idunn/internal/layout"
)

// ErrUnsafeRoot reports an install root that someone other than an administrator
// could change while a privileged process works in it.
//
// The root is one of the three scalars of a request, and the caller chooses it.
// A helper running as administrator that writes into a directory an ordinary
// user can modify can be redirected — a junction swapped in between two of its
// operations turns a routine write into a write anywhere on the machine. The
// helper therefore refuses such a root before it writes anything (backlog
// IDN-22, threat T16).
var ErrUnsafeRoot = errors.New("elevate: install root is not administrators-only")

// AcceptRequest is what a privileged helper calls first with the arguments it
// was started with: ParseRequest's grammar, then CheckPrivilegedRoot.
//
// It exists so a host cannot validate the text of a request and forget where it
// points. Both refusals come before the helper has read a trust anchor, touched
// the network, or created a directory.
func AcceptRequest(root, channel, version string) (Request, error) {
	req, err := ParseRequest(root, channel, version)
	if err != nil {
		return Request{}, err
	}
	if err := CheckPrivilegedRoot(req.Root); err != nil {
		return Request{}, err
	}
	return req, nil
}

// CheckPrivilegedRoot refuses an install root that is not protected against
// everyone but administrators.
//
// What it demands, by object:
//
//   - Every directory above the nearest existing one: owned by an administrator
//     principal, not a link, and granting nobody else the right to delete or
//     rename it, or to change its permissions. Creating entries next to the
//     install is allowed — ordinary users may create folders in C:\ and /opt may
//     be group-writable elsewhere — because that cannot move the install.
//   - The nearest existing directory (the root itself, or the directory the
//     root will be created in) and, if the root exists, the parts of it a helper
//     writes to (its top level, the metadata directory, the version
//     directories): owned by an administrator principal, not links, and
//     granting nobody else any right to create, delete, or change permissions —
//     including rights they would only inherit into what the helper creates.
//
// "Administrator principal" is SYSTEM, the Administrators group and
// TrustedInstaller on Windows, uid 0 (and gid 0 for group rights) on POSIX. A
// root whose ACL names any other group, even a domain group of operators, is
// refused: the helper cannot tell a trusted group from an untrusted one, and
// failing closed here means an install that asks for its ACL to be fixed rather
// than an elevation that trusts it.
//
// It is a refusal, not a prediction. NeedsElevation still decides by probing
// whether this process may write; this answers whether anyone *else* may, which
// no probe from here can establish. Once every object above holds, a
// non-administrator cannot change any of them between this check and the
// helper's writes, so the check does not race.
//
// The contents of version directories below their top level are not examined:
// the helper verifies every byte it reuses from them against its signed hash
// (§6.4) and never writes into an existing one.
func CheckPrivilegedRoot(root string) error {
	if err := checkInstallRoot(root); err != nil {
		return err
	}
	if isUNC(root) {
		return fmt.Errorf("%w: %q is a network path", ErrUnsafeRoot, root)
	}
	// The request grammar is the same on every OS, so it accepts `C:\app` on
	// Linux and `/opt/app` on Windows. Here the path meets this machine's
	// filesystem, where each of those is relative — resolved against whatever
	// working directory the privileged process has — and is refused.
	if !filepath.IsAbs(root) {
		return fmt.Errorf("%w: %q is not an absolute path on this system", ErrUnsafeRoot, root)
	}
	root = filepath.Clean(root)

	existing, err := nearestExistingDir(root)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeRoot, err)
	}
	if err := checkVolume(existing); err != nil {
		return err
	}

	for _, dir := range ancestors(existing) {
		if err := checkObject(dir, roleAncestor); err != nil {
			return err
		}
	}
	if existing != root {
		// The root will be created here: what this directory lets others do,
		// and what it passes on to a new directory, is what the root will be.
		return checkObject(existing, roleParentOfNewRoot)
	}
	objects, err := writeSet(root)
	if err != nil {
		return err
	}
	for _, p := range objects {
		if err := checkObject(p, roleContainer); err != nil {
			return err
		}
	}
	return nil
}

// role says which rights of a non-administrator make an object unsafe.
type role int

const (
	// roleAncestor is a directory above the install: others may add entries,
	// but not delete, rename, or re-permission it.
	roleAncestor role = iota
	// roleContainer is part of the install: others may only read.
	roleContainer
	// roleParentOfNewRoot is the directory the root will be created in: others
	// may add entries next to it, but must not be able to delete, rename or
	// re-permission it, nor inherit anything into the new root beyond reading.
	roleParentOfNewRoot
)

// ancestors lists the directories strictly above dir, from the volume root down.
func ancestors(dir string) []string {
	var out []string
	for p := dir; filepath.Dir(p) != p; {
		p = filepath.Dir(p)
		out = append([]string{p}, out...)
	}
	return out
}

// writeSet is the existing part of an install a helper writes to or removes
// from: the root, its top-level entries, everything in the metadata directory
// (journal, state, clock, staging, its own TUF cache), and each version
// directory itself. A directory that cannot be listed is an error, not an empty
// one: what could not be listed could not be checked.
func writeSet(root string) ([]string, error) {
	out := []string{root}
	list := func(dir string) error {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: cannot list %q: %w", ErrUnsafeRoot, dir, err)
		}
		for _, e := range entries {
			out = append(out, filepath.Join(dir, e.Name()))
		}
		return nil
	}
	if err := list(root); err != nil {
		return nil, err
	}
	if err := list(filepath.Join(root, layout.VersionsName)); err != nil {
		return nil, err
	}
	meta := filepath.Join(root, layout.MetaName)
	err := filepath.WalkDir(meta, func(p string, _ fs.DirEntry, err error) error {
		switch {
		case p == meta && errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return fmt.Errorf("%w: cannot list %q: %w", ErrUnsafeRoot, p, err)
		case p != meta:
			// The metadata directory itself is already a top-level entry.
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
