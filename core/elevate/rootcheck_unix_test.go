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
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCheckObjectDoesNotFollowASymlink(t *testing.T) {
	t.Parallel()

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("/", link); err != nil {
		t.Skip(err)
	}
	if err := checkObject(link, roleAncestor); !errors.Is(err, ErrUnsafeRoot) {
		t.Fatalf("checkObject(symlink to /) = %v, want ErrUnsafeRoot", err)
	}
}

// The machine root a system-wide install gets on Linux is /opt/<app> (IDN-24),
// and on a stock system everything above it is root-owned and not writable by
// anyone else: the helper must accept it. A root under a user's home is the
// other half and is refused (TestAcceptRequestRefusesAnUnsafeRoot).
func TestCheckPrivilegedRootAcceptsARootOwnedParent(t *testing.T) {
	t.Parallel()

	for _, parent := range []string{"/", "/opt"} {
		st, err := os.Lstat(parent)
		if err != nil {
			t.Logf("%s: %v", parent, err)
			return
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 || !st.IsDir() {
			// Everything below an unusual directory is judged with it, so stop.
			t.Logf("%s is not a stock root-owned directory here (%s); not judged", parent, st.Mode())
			return
		}
		root := filepath.Join(parent, "idunn-test-does-not-exist", "app")
		if err := CheckPrivilegedRoot(root); err != nil {
			t.Errorf("CheckPrivilegedRoot(%q) = %v, want nil", root, err)
		}
	}
}
