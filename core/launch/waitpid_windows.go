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
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// waitSliceMs is how long one wait blocks before ctx is checked again.
const waitSliceMs = 200

func waitForExit(ctx context.Context, pid int) error {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)) //nolint:gosec // G115: a pid from our own flag, checked positive.
	if err != nil {
		// No such process (any more): it has exited.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil
		}
		return fmt.Errorf("%w: waiting for pid %d: %w", ErrLaunch, pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	for {
		event, err := windows.WaitForSingleObject(h, waitSliceMs)
		switch event {
		case windows.WAIT_OBJECT_0:
			return nil
		case uint32(windows.WAIT_TIMEOUT):
			if ctx.Err() != nil {
				return fmt.Errorf("%w (pid %d)", ErrStillRunning, pid)
			}
		default:
			return fmt.Errorf("%w: waiting for pid %d: %w", ErrLaunch, pid, err)
		}
	}
}
