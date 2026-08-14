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

//go:build !windows

package fsx

import (
	"fmt"
	"os"
)

// SyncDir fsyncs a directory so that a rename inside it survives a power loss.
//
// On POSIX, renaming a file durably is two steps: the file's own fsync, and an
// fsync of the directory that now names it. Without the second, a crash can leave
// the directory entry unwritten and the journal record we just "committed" gone.
// A failure here is therefore a real durability failure and is reported.
func (osFS) SyncDir(name string) error {
	d, err := os.Open(native(name))
	if err != nil {
		return fmt.Errorf("fsx: open dir %s: %w", name, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsx: fsync dir %s: %w", name, err)
	}
	return nil
}
