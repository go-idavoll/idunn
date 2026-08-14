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
//
// Nothing here ever hands the privileged side a file to install. An Elevator
// transports a *request* — "install channel C at version V into root R" — and the
// helper on the other side answers it with its own TUF refresh and verification.
// That is why the request is reduced to three validated scalars (see Request) and
// why a descriptor's file list, hashes, and staged paths deliberately do not cross
// the boundary.
package elevate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-idavoll/idunn/core/release"
)

// The error classes this package reports. They exist so a caller can classify a
// failure without matching on strings (AGENTS.md §3): a declined prompt is a user
// decision, a rejected request is a defect or an attack, and a helper failure is
// an operational problem.
var (
	// ErrNotImplemented reports that a privileged apply strategy is not built yet.
	//
	// It is an error and not a panic: an updater configured for elevation must fail
	// closed on a platform where the helper does not exist, the same way it fails on
	// any other unmet precondition. A panic in the apply path would take the host
	// application down with it (AGENTS.md §1.1).
	ErrNotImplemented = errors.New("elevate: not implemented")

	// ErrRequest reports that the apply request was refused before any privileged
	// process was started. Everything crossing the boundary is untrusted input, so
	// a malformed root, channel, or version is rejected here rather than escaped
	// and forwarded.
	ErrRequest = errors.New("elevate: invalid request")

	// ErrDeclined reports that the elevation prompt was dismissed or denied. The
	// update did not happen and nothing on disk changed; retrying is the caller's
	// decision, not ours.
	ErrDeclined = errors.New("elevate: elevation declined")

	// ErrHelper reports that the privileged helper could not be started, or exited
	// non-zero. The exit status is carried in the wrapped error text.
	ErrHelper = errors.New("elevate: privileged helper failed")
)

// Elevator applies a release with the privileges the install root requires.
type Elevator interface {
	// Apply re-verifies d against TUF inside the privileged context and performs
	// the swap. The descriptor is treated as untrusted input from the caller.
	Apply(ctx context.Context, root string, d *release.Descriptor) error
}

// InteractiveOptions configures the on-demand elevation prompt.
//
// The zero value is usable: it elevates the running executable, which is the
// common shape for an app that ships its own `apply` subcommand.
type InteractiveOptions struct {
	// HelperPath is the binary to run elevated. Empty means the running
	// executable (os.Executable).
	//
	// SECURITY: whatever stands here is executed with full administrator rights.
	// It must live in a directory that only administrators can write, or a local
	// user can plant a binary and have it run for them — the classic elevation
	// LPE. idunn cannot establish that property at update time (the ACL can be
	// changed between the check and the launch), so it is an install-time
	// guarantee. What is enforced here is the cheap half: an absolute, local,
	// existing, regular file (see checkHelperPath).
	HelperPath string

	// ShowWindow shows the helper's own window. The default hides it; the UAC
	// consent dialog is shown by Windows either way and is not suppressed by this.
	ShowWindow bool
}

// NeedsElevation reports whether the install root requires privileges the current
// process does not have. It errs towards true: an ambiguous answer means we take
// the elevated path rather than half-writing an install.
//
// The probe is a real create-and-delete in the deepest existing directory of root,
// because that is the only answer that matches what the apply will actually do.
// Reading an ACL (Windows) or a mode bit (Unix) and predicting the outcome is a
// second implementation of the kernel's access check, and a wrong prediction here
// means an update that dies halfway through a swap.
//
// A root that does not exist yet is answered for the directory that would have to
// be created: if the parent cannot be written, neither can the root.
func NeedsElevation(root string) (bool, error) {
	if err := checkInstallRoot(root); err != nil {
		return true, err
	}
	dir, err := nearestExistingDir(root)
	if err != nil {
		return true, err
	}
	f, err := os.CreateTemp(dir, ".idunn-elevate-probe-*")
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return true, nil
		}
		return true, fmt.Errorf("elevate: cannot determine whether %q needs elevation: %w", root, err)
	}
	name := f.Name()
	// The probe file is the whole point; failing to close or remove it is not a
	// reason to report a wrong answer, but it must not be left behind silently
	// either — hence the error is reported once the answer is known to be "no".
	cerr := f.Close()
	rerr := os.Remove(name)
	if err := errors.Join(cerr, rerr); err != nil {
		return false, fmt.Errorf("elevate: probe file %q: %w", name, err)
	}
	return false, nil
}

// nearestExistingDir walks up from p to the first directory that exists.
func nearestExistingDir(p string) (string, error) {
	for {
		st, err := os.Stat(p)
		switch {
		case err == nil && st.IsDir():
			return p, nil
		case err == nil:
			return "", fmt.Errorf("elevate: %q is not a directory", p)
		case errors.Is(err, fs.ErrNotExist):
			// Keep walking: the root may legitimately not exist yet.
		case errors.Is(err, fs.ErrPermission):
			// Not even readable, so certainly not writable. Answering "needs
			// elevation" is left to the caller; here it is an error either way.
			return "", fmt.Errorf("elevate: cannot inspect %q: %w", p, err)
		default:
			return "", fmt.Errorf("elevate: cannot inspect %q: %w", p, err)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", fmt.Errorf("elevate: no existing directory above %q", p)
		}
		p = parent
	}
}

// NewInteractive returns an Elevator that requests an on-demand privilege prompt
// (UAC on Windows, polkit/authorization services elsewhere).
//
// The returned Elevator starts the helper and waits for it. It does not report
// progress: the privileged process owns the apply from the moment it starts, and
// a running elevated swap is not something the unprivileged side may cancel.
func NewInteractive(opts InteractiveOptions) (Elevator, error) {
	return newInteractive(opts)
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
