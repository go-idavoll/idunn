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

package elevate

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// programFiles asks the shell for the Program Files folder rather than reading
// %ProgramFiles%: an environment variable is the caller's to set, and the state
// directory it would name is where a privileged helper reads who may ask.
func programFiles() (string, error) {
	p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("%w: cannot locate Program Files: %w", ErrHelper, err)
	}
	return p, nil
}
