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

//go:build !unix && !windows

package elevate

import (
	"context"
	"fmt"
	"net"
	"time"
)

// The helper service exists on POSIX (a Unix socket) and Windows (a named pipe).
// Anywhere else — js/wasm, plan9, wasip1 — there is neither a transport nor a way
// to learn who is on the other end of one, so both sides fail closed here rather
// than listen or dial anything.

func checkPrincipals(HelperOptions) ([]string, error) {
	return nil, fmt.Errorf("%w: the privileged helper service on this platform (IDN-07)", ErrNotImplemented)
}

func listenLocal(string, []string) (net.Listener, error) {
	return nil, fmt.Errorf("%w: the privileged helper service on this platform (IDN-07)", ErrNotImplemented)
}

func dialLocal(context.Context, string, time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("%w: the privileged helper service on this platform (IDN-07)", ErrNotImplemented)
}

func authorizeConn(*Helper, net.Conn) (string, error) {
	return "", fmt.Errorf("%w: no peer authentication on this platform", ErrDenied)
}

func checkServiceEndpoint(string) error {
	return fmt.Errorf("%w: the privileged helper service on this platform (IDN-07)", ErrNotImplemented)
}
