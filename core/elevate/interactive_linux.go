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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// newInteractive returns the pkexec elevator (pkexec.go). InteractiveOptions.
// ShowWindow has no meaning here: polkit's agent shows the dialog, and the
// helper has no window of its own.
func newInteractive(opts InteractiveOptions) (Elevator, error) {
	helper := opts.HelperPath
	if helper == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("%w: cannot locate the running executable: %w", ErrRequest, err)
		}
		helper = exe
	}
	e, err := newPkexec(helper, linuxSystem())
	if err != nil {
		return nil, err
	}
	return e, nil
}

// linuxSystem is the real pkexecSystem.
func linuxSystem() pkexecSystem {
	return pkexecSystem{lstat: lstatOwner, resolve: filepath.EvalSymlinks, start: startDetached}
}

// lstatOwner reads mode, owner and group without following a final symlink.
func lstatOwner(name string) (posixStat, error) {
	st, err := os.Lstat(name)
	if err != nil {
		return posixStat{}, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return posixStat{}, fmt.Errorf("cannot read the owner of %q", name)
	}
	return posixStat{mode: st.Mode(), uid: uint64(sys.Uid), gid: uint64(sys.Gid)}, nil
}

// startDetached starts argv without a shell, a PATH lookup, an environment or a
// controlling terminal.
//
//   - The environment is empty. pkexec replaces it with a minimal one of its
//     own, but what it filters is ours, and the smallest thing to filter is
//     nothing. A helper therefore sees no proxy variables either.
//   - Setsid detaches pkexec from our terminal. Without a graphical polkit agent
//     pkexec would otherwise fall back to prompting on the terminal, which from
//     a GUI or a background process is a hang — or a stopped process — rather
//     than an answer. Detached, it has no terminal to fall back to and exits 127,
//     which fails closed with a message. Standard input, output and error are
//     /dev/null for the same reason.
//   - The command is an exec.Cmd, not exec.CommandContext: CommandContext kills
//     the child when the context ends, and a helper that may be mid-swap is not
//     ours to kill. The returned wait function is the only handle.
func startDetached(argv []string, dir string) (func() (int, error), error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return nil, fmt.Errorf("program %q is not an absolute path", argv)
	}
	// G204 does not apply in substance: argv[0] is a fixed, vetted pkexec path,
	// argv[1] a vetted helper, and the rest the validated request.
	cmd := &exec.Cmd{
		Path:        argv[0],
		Args:        argv,
		Dir:         dir,
		Env:         []string{},
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() (int, error) {
		err := cmd.Wait()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil // -1 when a signal ended it.
		}
		if err != nil {
			return -1, err
		}
		return 0, nil
	}, nil
}
