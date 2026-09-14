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
	"io/fs"
	"path"
	"strings"

	"github.com/go-idavoll/idunn/core/release"
)

// Interactive elevation on Linux is pkexec: polkit asks the session's
// authentication agent for an administrator's password and, on success, pkexec
// runs the target as root. It is the counterpart of the Windows "runas" verb and
// keeps the two properties that path has (docs/design.md §14.2):
//
//   - The elevated process is the trust boundary, not a delegate. It is handed a
//     Request, verifies everything itself, and once it runs we neither can nor
//     should stop it mid-swap. Cancelling the context abandons the *wait*; it
//     does not terminate the apply.
//   - A dismissed prompt is a user decision. It is ErrDeclined, never a failure
//     something above may retry into a password dialog every few minutes.
//
// The decisions live in this file, which carries no build constraint, so their
// tests run on every CI platform; interactive_linux.go supplies the three system
// calls (pkexecSystem) and is the only file that elevates anything.
const (
	// pkexec is looked for at these absolute paths and nowhere else. PATH belongs
	// to the calling user, and the program found through it would show an
	// authentication dialog with the system's face on it: a planted "pkexec"
	// collects the administrator's password. /usr/local/bin is deliberately not
	// a candidate — on several distributions a non-root group may write it.
	pkexecUsrBin = "/usr/bin/pkexec"
	pkexecBin    = "/bin/pkexec"

	// pkexec(1): 126 means the authentication dialog was dismissed; 127 means
	// authorization could not be obtained (no agent for the session, failed
	// authentication, a policy that says no) or the program could not be run.
	// On success pkexec exits with the program's own status, so a helper that
	// itself exits 126 or 127 is read as pkexec speaking. Helpers must not use
	// either status; cmd/installer and e2eapp do not.
	pkexecDismissed = 126
	pkexecFailed    = 127
)

// posixStat is the part of a stat result the ownership judgement reads.
type posixStat struct {
	mode fs.FileMode
	uid  uint64
	gid  uint64
}

// pkexecSystem is what the pkexec elevator needs from the operating system.
type pkexecSystem struct {
	// lstat stats a path without following a final symlink. An absent path is
	// reported as an error that matches fs.ErrNotExist.
	lstat func(name string) (posixStat, error)
	// resolve returns name with every symbolic link resolved.
	resolve func(name string) (string, error)
	// start runs argv (argv[0] is an absolute program path; no shell, no PATH
	// lookup) in dir, with an empty environment and no controlling terminal,
	// and returns a function that waits for it. That function reports the exit
	// status, negative if the process did not exit normally, and an error only
	// if the wait itself failed. There is deliberately no way to kill it.
	start func(argv []string, dir string) (wait func() (int, error), err error)
}

// pkexecElevator is the Linux on-demand elevator.
type pkexecElevator struct {
	pkexec string // resolved absolute path of a root-owned, setuid pkexec.
	helper string // resolved absolute path of a helper only root can change.
	start  func(argv []string, dir string) (func() (int, error), error)
}

var _ Elevator = (*pkexecElevator)(nil)

// newPkexec locates pkexec and vets the helper, both before anything runs, so a
// misconfigured updater fails when it is built rather than after a prompt.
func newPkexec(helper string, sys pkexecSystem) (*pkexecElevator, error) {
	pk, err := findPkexec(sys)
	if err != nil {
		return nil, err
	}
	h, err := checkPkexecHelper(helper, sys)
	if err != nil {
		return nil, err
	}
	return &pkexecElevator{pkexec: pk, helper: h, start: sys.start}, nil
}

// findPkexec returns the first fixed pkexec path that exists, once it is shown
// to be a root-owned setuid program nobody else can replace.
//
// A candidate that exists but fails the check is refused outright rather than
// skipped for the next one: a tampered /usr/bin/pkexec is a machine to stop on,
// not one to work around.
func findPkexec(sys pkexecSystem) (string, error) {
	for _, p := range []string{pkexecUsrBin, pkexecBin} {
		if _, err := sys.lstat(p); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		resolved, st, err := checkRootOnlyFile(p, sys)
		if err != nil {
			return "", fmt.Errorf("%w: refusing %s: %w", ErrHelper, p, err)
		}
		if st.mode&fs.ModeSetuid == 0 {
			// pkexec cannot work without it, so a pkexec without it is not the
			// one polkit installed.
			return "", fmt.Errorf("%w: refusing %s: %q is not setuid", ErrHelper, p, resolved)
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%w: interactive elevation needs polkit, and pkexec is not installed at %s or %s",
		ErrNotImplemented, pkexecUsrBin, pkexecBin)
}

// checkPkexecHelper vets the binary pkexec will run as root and returns the path
// to hand pkexec: the helper with every symlink resolved.
//
// Beyond checkHelperPath's rules, the resolved file and every directory above it
// must be owned by root and writable by nobody but root (and root's group). On
// Windows that half is an install-time guarantee because an ACL can change
// between check and launch. Here it cannot change: once root owns the file and
// every directory above it and nobody else may write them, only root can alter
// what the path names — so the check does not race. The sticky bit does not
// help a directory on this path; a helper under /tmp is refused.
//
// The resolved path, not the one given, is what runs. What was checked is then
// what pkexec executes, whatever a link along the given path points at later.
// It also means a polkit policy's org.freedesktop.policykit.exec.path must name
// the resolved file (docs/examples/org.idunn.apply.policy).
func checkPkexecHelper(helper string, sys pkexecSystem) (string, error) {
	if err := checkPosixPathText(helper, "helper path"); err != nil {
		return "", err
	}
	resolved, _, err := checkRootOnlyFile(helper, sys)
	if err != nil {
		return "", fmt.Errorf("%w: helper %q: %w", ErrRequest, helper, err)
	}
	return resolved, nil
}

// checkPosixPathText applies checkHelperPathText and additionally demands a
// POSIX absolute path: "C:\x" satisfies the portable grammar and is a relative
// name on Linux.
func checkPosixPathText(p, what string) error {
	if err := checkHelperPathText(p); err != nil {
		return err
	}
	if !strings.HasPrefix(p, "/") || strings.Contains(p, `\`) {
		return fmt.Errorf("%w: %s %q is not a POSIX absolute path", ErrRequest, what, p)
	}
	return nil
}

// checkRootOnlyFile resolves p and demands that the result is a regular file,
// and that it and every directory above it is owned by root and writable by no
// one else. It returns the resolved path and its stat. The error carries no
// class; callers add theirs.
func checkRootOnlyFile(p string, sys pkexecSystem) (string, posixStat, error) {
	resolved, err := sys.resolve(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", posixStat{}, errors.New("does not exist")
		}
		return "", posixStat{}, fmt.Errorf("cannot resolve: %w", err)
	}
	if err := checkPosixPathText(resolved, "resolved path"); err != nil {
		return "", posixStat{}, err
	}
	st, err := sys.lstat(resolved)
	if err != nil {
		return "", posixStat{}, fmt.Errorf("cannot inspect %q: %w", resolved, err)
	}
	if !st.mode.IsRegular() {
		return "", posixStat{}, fmt.Errorf("%q is not a regular file", resolved)
	}
	if err := modeProblem(resolved, st.mode, st.uid, st.gid, roleContainer); err != nil {
		return "", posixStat{}, err
	}
	for dir := path.Dir(resolved); ; dir = path.Dir(dir) {
		dst, err := sys.lstat(dir)
		if err != nil {
			return "", posixStat{}, fmt.Errorf("cannot inspect %q: %w", dir, err)
		}
		if !dst.mode.IsDir() {
			return "", posixStat{}, fmt.Errorf("%q is not a directory", dir)
		}
		if err := modeProblem(dir, dst.mode, dst.uid, dst.gid, roleContainer); err != nil {
			return "", posixStat{}, err
		}
		if dir == "/" {
			return resolved, st, nil
		}
	}
}

// Apply asks pkexec to run the helper with the request, and waits for it.
func (e *pkexecElevator) Apply(ctx context.Context, root string, d *release.Descriptor) error {
	req, err := newRequest(root, d)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(req.Root, "/") || strings.Contains(req.Root, `\`) {
		return fmt.Errorf("%w: install root %q is not a POSIX absolute path", ErrRequest, req.Root)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// An argument vector, never a command line: the three scalars reach the
	// helper exactly as validated, with no quoting and nothing to re-split.
	argv := append([]string{e.pkexec, e.helper}, req.args()...)
	wait, err := e.start(argv, path.Dir(e.helper))
	if err != nil {
		return fmt.Errorf("%w: starting %s: %w", ErrHelper, e.pkexec, err)
	}

	done := make(chan error, 1)
	go func() { done <- pkexecStatus(wait()) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// A helper that finished in the same instant is reported, not abandoned.
		select {
		case err := <-done:
			return err
		default:
		}
		// The goroutine keeps waiting and reaps the process; nothing kills it.
		// Killing a helper that may be mid-swap is the half-written install the
		// journal exists to prevent (AGENTS.md §1.1), and an unprivileged process
		// cannot signal a root one anyway.
		return fmt.Errorf("%w (the elevated apply keeps running)", ctx.Err())
	}
}

// pkexecStatus maps what pkexec exited with to this package's error taxonomy.
func pkexecStatus(code int, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("%w: waiting for pkexec: %w", ErrHelper, err)
	case code == 0:
		return nil
	case code == pkexecDismissed:
		return fmt.Errorf("%w: the authentication dialog was dismissed (pkexec status %d)", ErrDeclined, code)
	case code == pkexecFailed:
		return fmt.Errorf("%w: pkexec status %d: no polkit authentication agent for this session, "+
			"authentication failed or was refused by policy, or the helper could not be executed", ErrHelper, code)
	case code < 0:
		return fmt.Errorf("%w: pkexec did not exit normally", ErrHelper)
	default:
		return fmt.Errorf("%w: helper exited with status %d", ErrHelper, code)
	}
}
