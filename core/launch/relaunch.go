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

package launch

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// RelaunchExitCode is the exit code with which an application asks the launcher
// that started it to finish a pending update and start it again (IDN-29).
//
// It is 42 rather than something more distinctive because POSIX exit statuses are
// eight bits wide: a larger number would arrive as whatever it is modulo 256. 42 is
// not a code the C runtime, a shell, a signal (128+n) or `exit(-1)` produces, so an
// application does not exit with it by accident.
const RelaunchExitCode = 42

// SupervisedEnv is set to "1" in the environment of an application whose launcher
// stays its parent and will act on RelaunchExitCode — cmd/launcher on Windows,
// where a process cannot replace itself. Relaunch reads it to pick the mechanism;
// nothing decides trust on it.
const SupervisedEnv = "IDUNN_LAUNCHER_SUPERVISED"

// RelaunchOptions says how to reach the launcher again.
type RelaunchOptions struct {
	// Launcher is the absolute path of the launcher binary the application was
	// installed with. It is the host's own layout knowledge — typically the
	// launcher at the top of the install root — never input from outside.
	Launcher string

	// Root is passed to the launcher as --root. Empty leaves the launcher to use
	// the directory it lives in, which is its default.
	Root string

	// Args are the application's arguments for the new start.
	Args []string
}

// Relaunch starts the application again through its launcher, so that an update
// the application just deferred — or applied while running — is what runs next.
//
// The caller exits right after, with the code Relaunch returns:
//
//   - Under a launcher that stays the parent (SupervisedEnv set), nothing is
//     started here: the code is RelaunchExitCode, and the launcher finishes the
//     pending update and starts the application again when this process exits.
//   - On POSIX, this process is replaced by the launcher (execve). Relaunch does
//     not return on success; the launcher then finishes the update and replaces
//     itself with the new version, keeping the process id a service manager
//     watches.
//   - On Windows without a supervising launcher, the launcher is started as a new
//     process with --after-pid naming this one, and the code is 0. The launcher
//     waits for this process to exit before it finishes anything: a migration
//     must not run while the application that owns the state is still up.
//
// Relaunch never applies anything itself: finishing an update is the launcher's
// job, at a moment when this process is gone and cannot be writing.
func Relaunch(o RelaunchOptions) (int, error) {
	if getenv(SupervisedEnv) == "1" {
		return RelaunchExitCode, nil
	}
	argv, err := relaunchArgv(o)
	if err != nil {
		return 0, err
	}
	return startLauncher(o.Launcher, argv)
}

// relaunchArgv validates the options and renders the launcher's argument vector:
// the launcher, --root if given, then "--" and the application's arguments, so
// that no application argument can be read as a launcher flag.
func relaunchArgv(o RelaunchOptions) ([]string, error) {
	if !filepath.IsAbs(o.Launcher) {
		return nil, fmt.Errorf("%w: launcher path %q is not absolute", ErrLaunch, o.Launcher)
	}
	st, err := os.Stat(o.Launcher)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: launcher %q does not exist", ErrLaunch, o.Launcher)
		}
		return nil, fmt.Errorf("%w: launcher %q: %w", ErrLaunch, o.Launcher, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: launcher %q is not a regular file", ErrLaunch, o.Launcher)
	}
	argv := []string{o.Launcher}
	if o.Root != "" {
		if !filepath.IsAbs(o.Root) {
			return nil, fmt.Errorf("%w: install root %q is not absolute", ErrLaunch, o.Root)
		}
		argv = append(argv, "--root", o.Root)
	}
	if waitForCaller {
		argv = append(argv, "--after-pid", strconv.Itoa(os.Getpid()))
	}
	argv = append(argv, "--")
	return append(argv, o.Args...), nil
}

// The system seams, replaced in tests.
var (
	getenv        = os.Getenv
	startLauncher = startLauncherOS
	// waitForCaller is whether the new launcher runs beside this process rather
	// than in place of it, and so has to wait for it: everywhere a process cannot
	// replace itself.
	waitForCaller = runtime.GOOS == "windows"
)
