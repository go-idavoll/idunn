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

package uninstall

import (
	"fmt"
	"path/filepath"

	"github.com/go-idavoll/idunn/core/elevate"
)

// FinishArg is the first argument a launcher is started with when it is the copy
// that removes the launcher it was copied from (Windows only, see Finish). A
// launcher checks for it before it parses anything else and hands the remaining
// arguments to Finish.
const FinishArg = "--idunn-uninstall-finish"

// removeSelf and checkRoot are the platform's, variables so the tests can run
// the uninstall on an in-memory filesystem and stand in for a launcher that is
// executing.
var (
	removeSelf = removeSelfOS
	checkRoot  = checkRootOS
)

// checkRootOS refuses a root this process may not remove from.
//
// Without administrator rights the question is only whether the root can be
// written, answered by elevate.NeedsElevation's real probe rather than by
// reading permissions. With them it is the question the privileged helper asks
// before it writes a root: whether anyone but an administrator could change the
// tree (elevate.CheckPrivilegedRoot, IDN-22). A delete running as administrator
// in a tree a user controls is how that user deletes something else, through a
// link planted between two of its operations — the walk here never follows a
// link, but it cannot close the window between looking at a directory and
// removing what is in it.
func checkRootOS(root string) error {
	native := filepath.FromSlash(root)
	if privileged() {
		if err := elevate.CheckPrivilegedRoot(native); err != nil {
			return fmt.Errorf("%w: %w; run the uninstall as the user who installed it", ErrUnsafeRoot, err)
		}
		return nil
	}
	need, err := elevate.NeedsElevation(native)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUninstall, err)
	}
	if need {
		return ErrNotWritable
	}
	return nil
}
