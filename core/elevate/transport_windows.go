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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// The Windows transport is a named pipe, and its access control is the pipe's
// own security descriptor rather than a check this package makes after the fact.
//
// That is not a concession — it is the stronger arrangement. The kernel evaluates
// the descriptor when a client opens the pipe, so a caller who may not ask never
// reaches any of our code, not even the parser. On POSIX the equivalent does not
// exist (a socket's mode cannot express "these users may connect, and I want to
// know which one"), which is why that side reads SO_PEERCRED instead. The two
// platforms answer the same question with the mechanism each of them actually
// has; neither is emulated on top of the other.
//
// go-winio is a dependency in core, which AGENTS.md §3 asks to be justified. The
// alternative was several hundred lines of hand-written overlapped I/O
// implementing net.Listener and net.Conn over CreateNamedPipe — at a privilege
// boundary, on a platform this project's CI can build but the change could not be
// exercised on. A reviewed, widely deployed implementation of exactly this
// (containerd and Docker use it for the same purpose) is the smaller risk of the
// two, and it is confined to this file.

// pipePrefix is the namespace every endpoint must live in. A path outside it is
// not a named pipe at all, and accepting one would mean this helper listening on
// something whose access rules nobody has reasoned about.
const pipePrefix = `\\.\pipe\`

// listenLocal creates the named pipe the helper answers on.
//
// It takes the whole option set rather than a path, because on this platform the
// access decision travels with the listen: the descriptor is what the kernel
// evaluates when a client opens the pipe, and separating the two would leave a
// window in which the pipe exists with a DACL nobody chose.
func listenLocal(o HelperOptions) (net.Listener, error) {
	if !strings.HasPrefix(o.Endpoint, pipePrefix) {
		return nil, fmt.Errorf(`%w: %q is not a named pipe path (it must start with \\.\pipe\)`, ErrRequest, o.Endpoint)
	}
	if o.SecurityDescriptor == "" {
		return nil, fmt.Errorf("%w: no security descriptor for the helper pipe", ErrRequest)
	}
	ln, err := winio.ListenPipe(o.Endpoint, &winio.PipeConfig{SecurityDescriptor: o.SecurityDescriptor})
	if err != nil {
		return nil, fmt.Errorf("%w: listening on %s: %w", ErrHelper, o.Endpoint, err)
	}
	return ln, nil
}

// dialLocal opens the helper's pipe.
func dialLocal(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return winio.DialPipeContext(dialCtx, endpoint)
}
