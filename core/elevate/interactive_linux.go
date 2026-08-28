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

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-idavoll/idunn/core/release"
)

// Interactive elevation on Linux is pkexec: polkit asks the session for the
// administrator's authentication and, on success, execs the target as root. It
// is the counterpart of the Windows "runas" verb, and it keeps the same two
// properties that path has (docs/design.md §14.2):
//
//   - The elevated process is the trust boundary, not a delegate. It is handed a
//     Request, it verifies everything itself, and once it is running we neither
//     can nor should stop it mid-swap. Cancelling the context abandons the
//     *wait*; it does not terminate the apply.
//   - A dismissed prompt is a user decision, not a failure. It is ErrDeclined,
//     and nothing above may turn it into a retry loop that puts a password
//     dialog on the screen every few minutes.
//
// What differs from Windows is the argument path, and it differs in our favour:
// pkexec is exec'd with an argument vector, so the request's three scalars are
// never rendered into a string anyone has to re-split. The character rules in
// newRequest still apply — they are about what may be *asked for*, not about
// quoting.
const (
	// pkexecPaths are the absolute locations pkexec is looked for, in order.
	//
	// It is deliberately not resolved through PATH. PATH belongs to the calling
	// user, and the program found through it is the one that will show an
	// authentication dialog with the system's face on it. Planting a binary
	// there does not by itself grant an attacker anything they do not already
	// have — but it does let them borrow the prompt, and a user who types their
	// password into it has been robbed by us.
	pkexecPrimary  = "/usr/bin/pkexec"
	pkexecFallback = "/usr/local/bin/pkexec"

	// pkexec's own exit codes, from pkexec(1). 126 is "the authorization could
	// not be obtained" — which includes the user closing the dialog — and 127 is
	// "the program could not be executed".
	//
	// They collide with what the helper itself may exit with, and there is no
	// way around that: pkexec has one exit status to say both things with. The
	// collision is resolved in the safe direction — a 126 is read as declined
	// and therefore *not* retried automatically, and a 127 as a helper failure.
	// Reading them the other way round would be an update system that reacts to
	// "the user said no" by asking again.
	pkexecNotAuthorized = 126
	pkexecNotRun        = 127
)

// interactive is the Linux on-demand elevator.
type interactive struct {
	elevator string // absolute path to pkexec; overridden in tests.
	helper   string // absolute path to the privileged apply helper.
	dir      string // working directory handed to the helper.
}

var _ Elevator = (*interactive)(nil)

// newInteractive validates the helper and locates pkexec.
//
// Both happen at construction so a misconfigured updater fails when it is built
// rather than in the middle of an apply — the same rule the updater applies to
// its own options, and the reason ErrNotImplemented was an error and not a panic
// on the platforms where this did not exist.
func newInteractive(opts InteractiveOptions) (Elevator, error) {
	helper := opts.HelperPath
	if helper == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("%w: cannot locate the running executable: %w", ErrRequest, err)
		}
		helper = exe
	}
	if err := checkHelperPath(helper); err != nil {
		return nil, err
	}
	elevator, err := findPkexec()
	if err != nil {
		return nil, err
	}
	return &interactive{
		elevator: elevator,
		helper:   helper,
		// The elevated process inherits a working directory, and ours is
		// whatever the host application happened to set. Pinning it to the
		// helper's own directory keeps it inside the administrator-owned tree
		// the helper already has to live in.
		dir: filepath.Dir(helper),
	}, nil
}

// findPkexec returns the first absolute pkexec that exists.
func findPkexec() (string, error) {
	for _, p := range []string{pkexecPrimary, pkexecFallback} {
		st, err := os.Stat(p)
		if err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: pkexec is not installed at %s or %s; interactive elevation needs polkit",
		ErrNotImplemented, pkexecPrimary, pkexecFallback)
}

// Apply requests the elevated apply and waits for the helper to finish.
func (e *interactive) Apply(ctx context.Context, root string, d *release.Descriptor) error {
	req, err := newRequest(root, d)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// G204: every element of the vector is either a constant or a value
	// newRequest has validated, and there is no shell between here and execve.
	// Naming a program to run *is* what this function does.
	//
	// noctx: CommandContext would kill the child when the context is cancelled,
	// and killing a helper that may be mid-swap is the half-written install this
	// package exists to prevent. The context governs the wait; see waitForHelper.
	//
	//nolint:gosec,noctx // both argued above.
	cmd := exec.Command(e.elevator, append([]string{e.helper}, req.args()...)...)
	cmd.Dir = e.dir
	// pkexec sanitizes the environment it hands on, but what it sanitizes is
	// *this* environment. Handing it an empty one means there is nothing to
	// sanitize and nothing carried across the boundary by accident.
	cmd.Env = []string{}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: starting %s: %w", ErrHelper, e.elevator, err)
	}
	return waitForHelper(ctx, cmd)
}

// waitForHelper blocks until the helper exits or ctx is done.
//
// Cancelling ctx abandons the wait; it does not terminate the elevated process.
// That is why exec.CommandContext is not used here — it would kill the child,
// and killing a helper that may be mid-swap is precisely the half-written install
// the journal and this whole package exist to prevent (AGENTS.md §1.1). An
// unprivileged process could not reliably kill a root process anyway, so the
// alternative is not even available: it is only a choice about what to report.
func waitForHelper(ctx context.Context, cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return helperExitStatus(err)
	case <-ctx.Done():
		return fmt.Errorf("%w (the elevated apply keeps running)", ctx.Err())
	}
}

// helperExitStatus turns the process result into this package's error taxonomy.
func helperExitStatus(err error) error {
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return fmt.Errorf("%w: waiting for the helper: %w", ErrHelper, err)
	}
	switch exit.ExitCode() {
	case pkexecNotAuthorized:
		return fmt.Errorf("%w: the authentication dialog was dismissed or not authorized", ErrDeclined)
	case pkexecNotRun:
		return fmt.Errorf("%w: pkexec could not run the helper", ErrHelper)
	default:
		return fmt.Errorf("%w: helper exited with status %d", ErrHelper, exit.ExitCode())
	}
}
