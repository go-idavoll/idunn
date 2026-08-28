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

// peerOf reads the connected process's credentials with SO_PEERCRED.
//
// The kernel fills them in at connect time from the peer's own process, so they
// cannot be forged by the peer and cannot be reused by a third process that gets
// hold of the socket path: they describe this connection.
func peerOf(conn net.Conn) (peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return peer{}, fmt.Errorf("%w: not a unix connection", ErrDenied)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peer{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peer{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	if sockErr != nil {
		return peer{}, fmt.Errorf("%w: %w", ErrDenied, sockErr)
	}
	return peer{uid: cred.Uid, pid: int(cred.Pid)}, nil
}
