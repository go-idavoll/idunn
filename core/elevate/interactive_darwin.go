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

package elevate

import "fmt"

// newInteractive fails closed on macOS, by decision rather than by omission.
//
// macOS gets no one-shot prompt. Its privileged apply is a launchd daemon
// registered with SMAppService, which the user approves once under Login Items —
// the service mode (NewService, backlog IDN-07). The one-shot alternatives are
// not taken: AuthorizationExecuteWithPrivileges is deprecated and unsafe, and a
// run-once job via SMJobSubmit is deprecated too (backlog IDN-08).
//
// An updater configured for interactive elevation on macOS therefore refuses
// to start, before any apply, like every other unbuilt path in this package.
func newInteractive(InteractiveOptions) (Elevator, error) {
	return nil, fmt.Errorf("%w: macOS has no interactive elevation; a system-wide install there uses the "+
		"service mode, a launchd daemon registered with SMAppService (IDN-07, IDN-08)", ErrNotImplemented)
}
