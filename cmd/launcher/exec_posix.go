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

//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// execApp replaces this process with the application.
//
// execve rather than fork-and-wait, because everything about the launcher should
// disappear once it has done its job: the application keeps the process id its
// service manager is watching, signals reach it directly, and there is no
// supervisor left behind whose own failure could look like the application's.
//
// It returns only if the exec failed — on success there is nothing left to return
// to.
func execApp(path string, args []string) (int, error) {
	argv := append([]string{path}, args...)
	// The path is the pointer's target joined with a validated, install-relative
	// name (see appPath), not caller-supplied input.
	//nolint:gosec // G204: the binary to start is the whole purpose of this program.
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		return 0, fmt.Errorf("%w: %w", errNotStarted, err)
	}
	return 0, nil
}
