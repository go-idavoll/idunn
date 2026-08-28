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

package launch

import (
	"fmt"

	"github.com/go-idavoll/idunn/core/fsx"
)

// replaceSelf writes the new launcher over the old one.
//
// On POSIX this needs no ceremony at all. A running program holds its image by
// inode, and a rename over the name it was started from leaves that inode alone
// — the process keeps executing what it started with and the next start picks up
// the new file. WriteFileAtomic is therefore the whole implementation, and a
// reader who expects something more elaborate here is thinking of Windows.
func replaceSelf(f fsx.FS, path string, data []byte) error {
	if err := fsx.WriteFileAtomic(f, path, data, launcherMode); err != nil {
		return fmt.Errorf("%w: replacing the launcher: %w", ErrLaunch, err)
	}
	return nil
}
