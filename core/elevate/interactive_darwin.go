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

// newInteractive fails closed on macOS, and the reason is worth stating rather
// than leaving as a gap.
//
// The counterpart of "runas" and pkexec here is Authorization Services
// (AuthorizationExecuteWithPrivileges, deprecated since 10.7 and not a route to
// take) or, properly, a launchd helper registered with SMAppService and reached
// over XPC. Both are Objective-C frameworks with no pure-Go bindings, so the
// honest options are a cgo dependency in core or a helper written outside it.
// Which of those to take is a maintainer decision with consequences beyond this
// package — cgo changes how the whole module cross-compiles — so it is not made
// here by default (IDN-08).
//
// Until it is made, an updater configured for interactive elevation on macOS
// refuses to start. That is the same rule every other unbuilt path in this
// package follows: fail before the apply, never in the middle of it.
func newInteractive(InteractiveOptions) (Elevator, error) {
	return nil, fmt.Errorf("%w: interactive elevation on macOS needs Authorization Services or an "+
		"SMAppService helper, neither of which has a pure-Go binding (IDN-08)", ErrNotImplemented)
}
