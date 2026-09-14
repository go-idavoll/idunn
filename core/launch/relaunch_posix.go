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
	"os"
	"syscall"
)

// startLauncherOS replaces this process with the launcher. It returns only if the
// exec failed.
func startLauncherOS(path string, argv []string) (int, error) {
	// The path is the host's own launcher, validated by relaunchArgv.
	//nolint:gosec // G204: starting the launcher is the whole purpose of this call.
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		return 0, fmt.Errorf("%w: exec %s: %w", ErrLaunch, path, err)
	}
	return 0, nil
}
