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

// Package elevate performs the privileged apply for system-wide installs.
//
// The privilege boundary is the trust boundary (AGENTS.md §1.4): the elevated step
// re-verifies via TUF the exact bytes it installs and never trusts a
// caller-supplied path, URL, or "already verified" claim. Only re-verify and swap
// run elevated; download and staging stay unprivileged. See docs/design.md §14.2,
// §14.8.
package elevate

import (
	"context"

	"github.com/go-idavoll/idunn/core/release"
)

// Elevator applies a release with the privileges the install root requires.
type Elevator interface {
	// Apply re-verifies d against TUF inside the privileged context and performs
	// the swap. The descriptor is treated as untrusted input from the caller.
	Apply(ctx context.Context, root string, d *release.Descriptor) error
}

// NeedsElevation reports whether the install root requires privileges the current
// process does not have. It errs towards true: an ambiguous answer means we take
// the elevated path rather than half-writing an install.
func NeedsElevation(root string) (bool, error) {
	panic("not implemented")
}

// NewInteractive returns an Elevator that requests an on-demand privilege prompt
// (UAC on Windows, polkit/authorization services elsewhere).
func NewInteractive() (Elevator, error) {
	panic("not implemented")
}

// NewService returns an Elevator that hands the apply to an already privileged
// helper over local IPC. The helper authenticates the caller and re-verifies
// everything it installs.
func NewService() (Elevator, error) {
	panic("not implemented")
}
