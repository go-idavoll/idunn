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
	"io/fs"
	"testing"
)

// The `current` symlink is the one link an installed POSIX root contains; every
// install after the first meets it, so refusing it refuses every update.
func TestJudgePointer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mode fs.FileMode
		uid  uint64
		gid  uint64
		ok   bool
	}{
		{"root-owned symlink", fs.ModeSymlink | 0o777, 0, 0, true},
		{"root-owned symlink, another group", fs.ModeSymlink | 0o777, 0, 100, true},
		{"root-owned regular file (the Windows form)", 0o644, 0, 0, true},
		{"user-owned symlink", fs.ModeSymlink | 0o777, 1000, 1000, false},
		{"user-owned file", 0o644, 1000, 1000, false},
		{"world-writable file", 0o666, 0, 0, false},
		{"a directory others may write", fs.ModeDir | 0o777, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := judgePointer("/x/current", tc.mode, tc.uid, tc.gid)
			if tc.ok && err != nil {
				t.Fatalf("judgePointer = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrUnsafeRoot) {
				t.Fatalf("judgePointer = %v, want ErrUnsafeRoot", err)
			}
		})
	}
	// Only `current` gets this: a root-owned symlink anywhere else in the
	// install is still refused.
	if err := judgeMode("/x/.updater", fs.ModeSymlink|0o777, 0, 0, roleContainer); !errors.Is(err, ErrUnsafeRoot) {
		t.Fatalf("judgeMode(symlink, container) = %v, want ErrUnsafeRoot", err)
	}
}

func TestJudgeMode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mode fs.FileMode
		uid  uint64
		gid  uint64
		role role
		ok   bool
	}{
		{"root-owned 0755 install", fs.ModeDir | 0o755, 0, 0, roleContainer, true},
		{"root group may write", fs.ModeDir | 0o775, 0, 0, roleContainer, true},
		{"/tmp as an ancestor: sticky", fs.ModeDir | fs.ModeSticky | 0o777, 0, 0, roleAncestor, true},
		{"/tmp as the parent of a new root: sticky", fs.ModeDir | fs.ModeSticky | 0o777, 0, 0, roleParentOfNewRoot, true},
		{"user-owned", fs.ModeDir | 0o755, 1000, 1000, roleAncestor, false},
		{"a symlink", fs.ModeSymlink | 0o777, 0, 0, roleAncestor, false},
		{"world-writable install", fs.ModeDir | 0o757, 0, 0, roleContainer, false},
		{"sticky does not make an install safe", fs.ModeDir | fs.ModeSticky | 0o777, 0, 0, roleContainer, false},
		{"a non-root group may write the install", fs.ModeDir | 0o775, 0, 100, roleContainer, false},
		{"a non-root group may rename in an ancestor", fs.ModeDir | 0o775, 0, 100, roleAncestor, false},
		{"world-writable ancestor without sticky", fs.ModeDir | 0o777, 0, 0, roleAncestor, false},
		{"world-writable file in the metadata", 0o666, 0, 0, roleContainer, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := judgeMode("/x", tc.mode, tc.uid, tc.gid, tc.role)
			if tc.ok && err != nil {
				t.Fatalf("judgeMode = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrUnsafeRoot) {
				t.Fatalf("judgeMode = %v, want ErrUnsafeRoot", err)
			}
		})
	}
}
