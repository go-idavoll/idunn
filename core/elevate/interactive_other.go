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

//go:build !windows && !linux && !darwin

package elevate

import "fmt"

// newInteractive fails closed everywhere the prompt is not built yet.
//
// Windows has ShellExecuteEx "runas", Linux has pkexec, and macOS has
// Authorization Services; this file is everything else. An updater configured for
// interactive elevation on such a platform must refuse to start rather than fall
// back to an unprivileged apply that would die halfway through the swap.
func newInteractive(InteractiveOptions) (Elevator, error) {
	return nil, fmt.Errorf("%w: interactive elevation on this platform", ErrNotImplemented)
}
