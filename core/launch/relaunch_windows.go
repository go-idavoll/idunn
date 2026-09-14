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

//go:build windows

package launch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// startLauncherOS starts the launcher as a new process with this process's
// standard streams and returns 0 for the caller to exit with. The launcher does
// not wait for this process: it takes the application lock, if the host has one,
// before it finishes the update, and that is what proves this process is gone.
func startLauncherOS(path string, argv []string) (int, error) {
	// The path is the host's own launcher, validated by relaunchArgv. The
	// context is Background on purpose: the new launcher must outlive this call.
	//nolint:gosec // G204: starting the launcher is the whole purpose of this call.
	cmd := exec.CommandContext(context.Background(), path, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("%w: start %s: %w", ErrLaunch, path, err)
	}
	// The child is not waited for; releasing it lets this process exit at once.
	_ = cmd.Process.Release()
	return 0, nil
}
