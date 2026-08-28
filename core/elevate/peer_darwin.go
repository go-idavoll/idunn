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
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerOf reads the connected process's credentials with LOCAL_PEERCRED.
//
// It answers the question the helper actually asks — which local user is on the
// other end — and the kernel answers it about this connection, so it cannot be
// forged. The audit token (LOCAL_PEERTOKEN), which additionally identifies the
// signed application rather than only the user, is the stronger statement macOS
// can make and is IDN-07c; it refines this check rather than replacing it.
func peerOf(conn net.Conn) (peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return peer{}, fmt.Errorf("%w: not a unix connection", ErrDenied)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peer{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	var cred *unix.Xucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return peer{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	if sockErr != nil {
		return peer{}, fmt.Errorf("%w: %w", ErrDenied, sockErr)
	}
	// Xucred carries no pid; the log simply has none to show.
	return peer{uid: cred.Uid}, nil
}
