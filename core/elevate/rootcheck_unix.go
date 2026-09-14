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

//go:build unix

package elevate

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkVolume has nothing to refuse on POSIX: a mount is a directory like any
// other, and its owner and mode are judged as one.
func checkVolume(string) error { return nil }

// checkObject judges one object by its owner and mode bits, without following a
// final symlink.
//
// POSIX ACLs are not read. A root that carries an extended ACL granting a
// non-root user write access passes this check; the mode bits of such a
// directory show the ACL mask in the group bits, which is refused unless the
// group is root's.
func checkObject(path string, r role) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: cannot inspect %q: %w", ErrUnsafeRoot, path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot read the owner of %q", ErrUnsafeRoot, path)
	}
	return judgeMode(path, st.Mode(), uint64(sys.Uid), uint64(sys.Gid), r)
}

// judgeMode is the decision, apart from the stat that feeds it.
func judgeMode(path string, mode fs.FileMode, uid, gid uint64, r role) error {
	if mode&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %q is a symbolic link", ErrUnsafeRoot, path)
	}
	if uid != 0 {
		return fmt.Errorf("%w: %q is owned by uid %d", ErrUnsafeRoot, path, uid)
	}
	groupWrite := mode.Perm()&0o020 != 0 && gid != 0
	otherWrite := mode.Perm()&0o002 != 0
	switch r {
	case roleAncestor, roleParentOfNewRoot:
		// Write access to a directory is the right to rename its entries, and
		// the sticky bit is what restricts that to their owners.
		if (groupWrite || otherWrite) && mode&fs.ModeSticky == 0 {
			return fmt.Errorf("%w: %q is writable by others without the sticky bit (%s)", ErrUnsafeRoot, path, mode)
		}
	case roleContainer:
		if groupWrite || otherWrite {
			return fmt.Errorf("%w: %q is writable by others (%s)", ErrUnsafeRoot, path, mode)
		}
	}
	return nil
}
