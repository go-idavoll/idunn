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

package txn_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Recovery runs on a machine that has just crashed, which is exactly where the
// disk is most likely to keep failing. Every filesystem error along the way has
// to surface: a recovery that reports success it did not achieve would let the
// next transaction start from a state nobody has checked.
func TestRecoverReportsFilesystemFailures(t *testing.T) {
	disk := errors.New("i/o error")

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) *fsx.Mem
		fail  func(op, name string) bool
	}{
		{
			name: "cannot remove the abandoned version directory",
			setup: func(t *testing.T) *fsx.Mem {
				m := installed(t, []string{"1.2.0"}, "1.2.0")
				stage(t, m, "1.3.0")
				journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged)
				return m
			},
			fail: func(op, name string) bool {
				return op == "removeall" && strings.HasSuffix(name, "versions/1.3.0")
			},
		},
		{
			name: "cannot repoint current",
			setup: func(t *testing.T) *fsx.Mem {
				m := installed(t, []string{"1.2.0", "1.3.0"}, "1.3.0")
				journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged)
				return m
			},
			fail: func(op, name string) bool {
				// The rename onto `current` is what both pointer forms do; the
				// symlink is only the POSIX form's way of getting there.
				return op == "rename" && strings.HasSuffix(name, "/"+layout.CurrentName)
			},
		},
		{
			name: "cannot remove the pointer of a failed first install",
			setup: func(t *testing.T) *fsx.Mem {
				m := newRoot(t)
				stage(t, m, "1.0.0")
				if err := layout.SetPointer(m, root, "1.0.0"); err != nil {
					t.Fatalf("SetPointer: %v", err)
				}
				journalAt(t, m, "", "1.0.0", txn.StateBegin)
				return m
			},
			fail: func(op, name string) bool {
				return op == "remove" && strings.HasSuffix(name, "/"+layout.CurrentName)
			},
		},
		{
			name: "cannot record the rollback",
			setup: func(t *testing.T) *fsx.Mem {
				m := installed(t, []string{"1.2.0"}, "1.2.0")
				stage(t, m, "1.3.0")
				journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged)
				return m
			},
			fail: func(op, name string) bool {
				return op == "write" && strings.Contains(name, layout.JournalName)
			},
		},
		{
			name: "cannot record the completed install state",
			setup: func(t *testing.T) *fsx.Mem {
				m := installed(t, []string{"1.2.0"}, "1.2.0")
				stage(t, m, "1.3.0")
				journalAt(t, m, "1.2.0", "1.3.0", txn.StateBegin, txn.StateStaged, txn.StateMigrated)
				if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
					t.Fatalf("SetPointer: %v", err)
				}
				journalAt(t, m, "1.2.0", "1.3.0", txn.StateSwapped)
				return m
			},
			fail: func(op, name string) bool {
				return op == "write" && strings.Contains(name, layout.StateName)
			},
		},
		{
			name: "cannot remove the staging tree",
			setup: func(t *testing.T) *fsx.Mem {
				m := installed(t, []string{"1.2.0"}, "1.2.0")
				if err := m.MkdirAll(layout.Staging(root), 0o700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				return m
			},
			fail: func(op, name string) bool {
				return op == "removeall" && strings.HasSuffix(name, layout.StagingName)
			},
		},
		{
			name: "cannot remove an abandoned scratch file",
			setup: func(t *testing.T) *fsx.Mem {
				m := installed(t, []string{"1.2.0"}, "1.2.0")
				if err := m.Symlink("versions/9.9.9", fsx.TempName(layout.Current(root))); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
				return m
			},
			fail: func(op, name string) bool {
				return op == "removeall" && strings.Contains(name, ".idunn-")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.setup(t)
			mig := newRecorder(m)
			m.Fail = func(op, name string) error {
				if tc.fail(op, name) {
					return disk
				}
				return nil
			}
			if err := txn.Recover(m, root, mig); err == nil {
				t.Fatal("recovery reported success although the filesystem failed")
			}
		})
	}
}

// The staging directory is scanned for scratch files too, and a directory that
// cannot be listed is a failure rather than an empty listing.
func TestRecoverReportsAnUnreadableDirectory(t *testing.T) {
	m := newRoot(t)
	// A regular file where the versions directory belongs cannot be listed.
	if err := fsx.WriteFileAtomic(m, layout.Versions(root), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := txn.Recover(m, root, nil); err == nil {
		t.Fatal("recovery ignored a directory it could not read")
	}
}
