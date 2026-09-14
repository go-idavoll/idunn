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

package updater

import (
	"fmt"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/internal/launcherfile"
)

// RepairLauncher undoes an interrupted replacement of the host's launcher
// (Options.Launcher.Name, directly in the install root), and reports whether it
// had to put a launcher back.
//
// On Windows the launcher replaces itself by renaming its running image aside and
// the new file in, and a crash between those two renames leaves no launcher under
// the name users start (docs/design.md §13, IDN-17). The launcher repairs that at
// its next start — which is exactly what cannot happen while it is missing. So
// the application's side repairs it too: Apply and ApplyRequested call this, and
// a host may call it on its own start. It moves only files idunn itself put
// beside the launcher; it decides nothing about trust.
//
// Without a configured launcher, or for an install root this process does not
// write (Policy.Elevation), it does nothing.
func (u *Updater) RepairLauncher() (bool, error) {
	if u.stager.Launcher.Name == "" || u.policy.Elevation != ElevationNone {
		return false, nil
	}
	restored, err := launcherfile.Repair(u.fs, fsx.Join(u.root, u.stager.Launcher.Name))
	if err != nil {
		return restored, fmt.Errorf("repairing the launcher: %w", err)
	}
	return restored, nil
}

// repairLauncher is RepairLauncher on the way into an update, reported through
// the Observer and never allowed to stop it.
func (u *Updater) repairLauncher() {
	restored, err := u.RepairLauncher()
	switch {
	case err != nil:
		u.emit(hook.PhaseCheck, "an interrupted launcher replacement could not be undone", err)
	case restored:
		u.emit(hook.PhaseCheck, "an interrupted launcher replacement was undone", nil)
	}
}
