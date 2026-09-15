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

//go:build e2e && windows

package e2elocal

import "golang.org/x/sys/windows"

// elevated reports whether this process runs with an elevated token. The GitHub
// Windows runner does, and an elevated process is refused a user-owned install
// root by design (elevate.CheckPrivilegedRoot, §14.8): the per-user uninstall
// path cannot be exercised there.
func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
