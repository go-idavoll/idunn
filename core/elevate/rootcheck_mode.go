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
	"fmt"
	"io/fs"
)

// The POSIX owner-and-mode judgement carries no build constraint: it is pure
// arithmetic on a mode and two ids, and keeping it portable lets every CI
// platform run its tests. The stat that feeds it is per platform
// (rootcheck_unix.go, interactive_linux.go).

// judgeMode is the install-root decision, apart from the stat that feeds it.
func judgeMode(path string, mode fs.FileMode, uid, gid uint64, r role) error {
	if err := modeProblem(path, mode, uid, gid, r); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeRoot, err)
	}
	return nil
}

// judgePointer is judgeMode for the install's `current` entry. On POSIX that
// entry is a symlink (internal/layout's pointer form), the one link an install
// contains, and it passes if root owns it: a symlink's own mode bits mean
// nothing, and replacing it takes write access to the root directory, which is
// judged as a container. Where it points is not this check's question —
// layout.PointerTarget refuses a pointer that does not name a version directory
// before anything follows it. Anything that is not a symlink is judged like every
// other entry of the install.
func judgePointer(path string, mode fs.FileMode, uid, gid uint64) error {
	if mode&fs.ModeSymlink == 0 {
		return judgeMode(path, mode, uid, gid, roleContainer)
	}
	if uid != 0 {
		return fmt.Errorf("%w: %q is owned by uid %d", ErrUnsafeRoot, path, uid)
	}
	return nil
}

// modeProblem says why an object with this owner and mode is not one only root
// controls in role r, or nil. It carries no error class; each caller adds the
// one that fits what the object is to it (an install root, a helper binary).
func modeProblem(path string, mode fs.FileMode, uid, gid uint64, r role) error {
	if mode&fs.ModeSymlink != 0 {
		return fmt.Errorf("%q is a symbolic link", path)
	}
	if uid != 0 {
		return fmt.Errorf("%q is owned by uid %d", path, uid)
	}
	groupWrite := mode.Perm()&0o020 != 0 && gid != 0
	otherWrite := mode.Perm()&0o002 != 0
	switch r {
	case roleAncestor, roleParentOfNewRoot:
		// Write access to a directory is the right to rename its entries, and
		// the sticky bit is what restricts that to their owners.
		if (groupWrite || otherWrite) && mode&fs.ModeSticky == 0 {
			return fmt.Errorf("%q is writable by others without the sticky bit (%s)", path, mode)
		}
	case roleContainer:
		if groupWrite || otherWrite {
			return fmt.Errorf("%q is writable by others (%s)", path, mode)
		}
	}
	return nil
}
