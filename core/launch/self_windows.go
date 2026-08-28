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

package launch

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"

	"github.com/go-idavoll/idunn/core/fsx"
)

// replaceSelf replaces a launcher that is currently executing.
//
// Windows keeps an image section on a running executable and refuses to replace
// or delete the file — but it does allow it to be *renamed*, and that is the
// whole mechanism. Move the running launcher aside, write the new one at the
// name that is clicked, and deal with the leftover afterwards:
//
//	launcher.exe  ->  launcher.exe.idunn-old-<stamp>   (allowed while running)
//	<new bytes>   ->  launcher.exe                     (the name is free now)
//
// The leftover cannot be deleted yet, because this process is executing from it.
// Two things clean it up, in this order: the next start sweeps it (by then it is
// not running any more), and if even that fails, MoveFileEx with
// MOVEFILE_DELAY_UNTIL_REBOOT has the kernel remove it at the next boot. The
// scheduling is the backstop, not the plan — most machines will have swept it
// long before they reboot.
//
// If the rename fails, nothing is written. A half-replaced launcher is the one
// outcome that would leave a machine unable to start its application at all, and
// it is worth strictly more than an update of the shim.
func replaceSelf(f fsx.FS, path string, data []byte) error {
	aside := path + selfSuffix + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := f.Rename(path, aside); err != nil {
		return fmt.Errorf("%w: moving the running launcher aside: %w", ErrLaunch, err)
	}

	if err := fsx.WriteFileAtomic(f, path, data, launcherMode); err != nil {
		// Put the old one back. Failing to update the launcher is a
		// disappointment; leaving the install without one is a broken machine.
		if rerr := f.Rename(aside, path); rerr != nil {
			return fmt.Errorf("%w: the launcher could not be replaced and the old one could not be "+
				"restored from %s: %w", ErrLaunch, aside, err)
		}
		return fmt.Errorf("%w: replacing the launcher: %w", ErrLaunch, err)
	}

	// Best effort, in the order that costs least. Remove is expected to fail —
	// this process is running from that file — and the reboot scheduling is the
	// backstop for a machine that somehow never sweeps it.
	if err := f.Remove(aside); err != nil {
		scheduleDeleteOnReboot(aside)
	}
	return nil
}

// scheduleDeleteOnReboot asks the kernel to remove name at the next boot.
//
// It is deliberately silent about failure. This is the third fallback behind
// "remove it now" and "let the next start sweep it", the file it concerns is a
// few megabytes of dead launcher, and MOVEFILE_DELAY_UNTIL_REBOOT needs
// administrator rights that a per-user install does not have. Reporting it would
// turn an ordinary per-user start into a warning about nothing.
func scheduleDeleteOnReboot(name string) {
	native, err := windows.UTF16PtrFromString(filepath.FromSlash(name))
	if err != nil {
		return
	}
	_ = windows.MoveFileEx(native, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
