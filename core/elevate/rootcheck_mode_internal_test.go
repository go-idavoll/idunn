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
