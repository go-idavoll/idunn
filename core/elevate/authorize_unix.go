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

//go:build unix

package elevate

import (
	"fmt"
	"net"
	"slices"
)

// On POSIX the socket's mode cannot express "these users may connect, and I want
// to know which one", so the decision is made here from credentials the kernel
// attached to the connection. They are the kernel's answer about the process at
// the other end, not a claim the caller made, which is what makes them worth
// deciding on at all.
func authorizeConn(h *Helper, conn net.Conn) (string, error) {
	p, err := peerOf(conn)
	if err != nil {
		return "", err
	}
	if !h.permits(p) {
		return "", fmt.Errorf("%w: uid %d may not ask this helper", ErrDenied, p.uid)
	}
	return fmt.Sprintf("uid %d (pid %d)", p.uid, p.pid), nil
}

// permits reports whether this peer may ask at all.
//
// An empty list reads as "the superuser and nobody else". "Not configured" must
// never read as "everyone": a helper deployed without its allowlist filled in is
// a mistake, and the shape of that mistake should be a helper that answers no one
// rather than one that answers anyone.
func (h *Helper) permits(p peer) bool {
	if len(h.uids) == 0 {
		return p.uid == 0
	}
	return slices.Contains(h.uids, p.uid)
}

// checkPlatformOptions validates the POSIX-only half of HelperOptions.
func checkPlatformOptions(o HelperOptions) error {
	if o.SecurityDescriptor != "" {
		return fmt.Errorf("%w: SecurityDescriptor is a Windows named-pipe setting; on this platform use AllowedUIDs", ErrRequest)
	}
	return nil
}
