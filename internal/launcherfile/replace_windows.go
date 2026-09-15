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

package launcherfile

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// replaceOS on Windows renames the running launcher aside and puts the new one at
// its name (ReplaceAside), because an executing image cannot be replaced or
// deleted but can be renamed. MoveFileEx semantics throughout: os.Rename is
// MoveFileEx with MOVEFILE_REPLACE_EXISTING, and the leftover is scheduled with
// MOVEFILE_DELAY_UNTIL_REBOOT when it cannot be removed at once.
var replaceOS = ReplaceAside(scheduleDeleteOnReboot)

// scheduleDeleteOnReboot asks the kernel to remove name at the next boot.
//
// It is deliberately silent about failure. It is the fallback behind "remove it
// now" and "let the next Repair sweep it", the file it concerns is a few
// megabytes of dead launcher, and MOVEFILE_DELAY_UNTIL_REBOOT needs administrator
// rights that a per-user install does not have. Reporting it would turn an
// ordinary per-user start into a warning about nothing.
func scheduleDeleteOnReboot(name string) {
	native, err := windows.UTF16PtrFromString(filepath.FromSlash(name))
	if err != nil {
		return
	}
	_ = windows.MoveFileEx(native, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
