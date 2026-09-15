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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/go-idavoll/idunn/core/launch"
)

// execApp starts the application and waits for it.
//
// Windows has no execve: a process cannot replace itself. The launcher therefore
// stays alive as the parent, forwards the standard streams, and exits with the
// application's own exit code — so that whatever started the launcher sees what
// it would have seen had it started the application directly.
//
// The cost is a supervisor process in the tree for the lifetime of the
// application, and it is the reason self-replacement of the launcher itself needs
// its own mechanism on this platform (rename aside, then MoveFileEx with
// MOVEFILE_DELAY_UNTIL_REBOOT for the leftover; internal/launcherfile,
// docs/design.md §13, backlog IDN-17).
func execApp(path string, args []string) (int, error) {
	// The path is the pointer's target joined with a validated, install-relative
	// name (see appPath), not caller-supplied input.
	//nolint:gosec // G204: the binary to start is the whole purpose of this program.
	// Background: the application runs for as long as it runs, and the launcher
	// waits for it; there is nothing to cancel it on.
	cmd := exec.CommandContext(context.Background(), path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Tells the application that this launcher stays its parent and will act on
	// launch.RelaunchExitCode (IDN-29).
	cmd.Env = append(os.Environ(), launch.SupervisedEnv+"=1")

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// The application ran and decided to fail. That is its answer, not
			// ours: pass the code through untouched.
			return exitErr.ExitCode(), nil
		}
		return 0, fmt.Errorf("%w: %w", errNotStarted, err)
	}
	return 0, nil
}
