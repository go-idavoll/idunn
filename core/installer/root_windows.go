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

package installer

import "golang.org/x/sys/windows"

// knownUserProgramFiles is %LocalAppData%\Programs as the shell knows it, not as
// the environment claims it. The folder does not exist until something installs
// there, so its existence is not verified.
func knownUserProgramFiles() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_UserProgramFiles, windows.KF_FLAG_DONT_VERIFY)
}

// knownProgramFiles is Program Files as the shell knows it. A 32-bit process on
// 64-bit Windows is given Program Files (x86), which is where it belongs.
func knownProgramFiles() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
}
