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
	"errors"
	"fmt"

	"github.com/go-idavoll/idunn/core/release"
)

// ErrNotImplemented reports that a privileged apply strategy is not built yet.
//
// It is an error and not a panic: an updater configured for elevation must fail
// closed on a platform where the helper does not exist, the same way it fails on
// any other unmet precondition. A panic in the apply path would take the host
// application down with it (AGENTS.md §1.1).
var ErrNotImplemented = errors.New("elevate: not implemented")

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
	// TODO(elevate): probe writability of root per platform. Until then the
	// answer is the conservative one — "I cannot tell" — reported as an error
	// rather than as the false that would send a system-wide install down the
	// unprivileged path and have it fail halfway through.
	return true, fmt.Errorf("%w: cannot determine whether %q needs elevation", ErrNotImplemented, root)
}

// NewInteractive returns an Elevator that requests an on-demand privilege prompt
// (UAC on Windows, polkit/authorization services elsewhere).
func NewInteractive() (Elevator, error) {
	// TODO(elevate): ShellExecute "runas" (Windows), pkexec (Linux),
	// Authorization Services (macOS). See docs/design.md §14.2.
	return nil, fmt.Errorf("%w: interactive elevation", ErrNotImplemented)
}

// NewService returns an Elevator that hands the apply to an already privileged
// helper over local IPC. The helper authenticates the caller and re-verifies
// everything it installs.
func NewService() (Elevator, error) {
	// TODO(elevate): the privileged helper and its authenticated IPC. It is the
	// largest remaining piece of §14.2/§14.8 and the one with the most attack
	// surface: peer-credential authentication, a full TUF re-verification on the
	// privileged side, and the read-only fd hand-off that avoids both a second
	// download and path-based TOCTOU. It is deliberately not sketched here —
	// half a privilege boundary is worse than none.
	return nil, fmt.Errorf("%w: privileged helper service", ErrNotImplemented)
}
