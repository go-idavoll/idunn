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
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
)

// pollInterval is how often a POSIX wait checks whether the process still exists.
const pollInterval = 100 * time.Millisecond

// waitForExit polls with signal 0: POSIX offers no way to wait for a process that
// is not one's child. Relaunch on POSIX replaces the process instead and never
// passes --after-pid, so this path exists for completeness, not for the common
// case.
func waitForExit(ctx context.Context, pid int) error {
	for {
		err := syscall.Kill(pid, 0)
		switch {
		case errors.Is(err, syscall.ESRCH):
			return nil
		case err != nil && !errors.Is(err, syscall.EPERM):
			return fmt.Errorf("%w: waiting for pid %d: %w", ErrLaunch, pid, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (pid %d)", ErrStillRunning, pid)
		case <-time.After(pollInterval):
		}
	}
}
