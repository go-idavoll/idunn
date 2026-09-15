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

package uninstall

import (
	"fmt"
	"os"

	"github.com/go-idavoll/idunn/core/fsx"
)

// privileged is running as root.
func privileged() bool { return os.Geteuid() == 0 }

// removeSelfOS deletes the launcher at once: POSIX unlinks a running executable,
// and the process keeps its image until it exits. It reports false: nothing is
// left for a later step, and the caller removes the root.
func removeSelfOS(f fsx.FS, self, _ string, _ bool) (bool, error) {
	if err := f.Remove(self); err != nil && !fsx.IsNotExist(err) {
		return false, err
	}
	return false, nil
}

// Finish is Windows-only; see the Windows implementation.
func Finish([]string) error {
	return fmt.Errorf("%w: %s is used only on Windows", ErrUninstall, FinishArg)
}
