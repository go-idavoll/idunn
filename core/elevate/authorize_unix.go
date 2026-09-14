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
)

// checkPrincipals refuses the Windows half of the caller allow-list here.
//
// A setting for the other platform is a refusal, not a value quietly ignored: an
// operator who wrote AllowedSIDs believed it restricted who may ask, and a helper
// that started anyway would be answering a set of callers nobody chose.
func checkPrincipals(o HelperOptions) ([]string, error) {
	if len(o.AllowedSIDs) != 0 {
		return nil, fmt.Errorf("%w: AllowedSIDs is a Windows setting; on this platform the helper decides on AllowedUIDs", ErrRequest)
	}
	return nil, nil
}

// On POSIX the socket's mode cannot express "these users may connect, and I want
// to know which one", so the decision is made here from credentials the kernel
// attached to the connection. They are the kernel's answer about the process at
// the other end, not a claim the caller made, which is what makes them worth
// deciding on at all.
//
// The decision itself is admitPeer: the uid, and — where a PeerRequirement is
// configured, which only a darwin cgo build accepts — the peer's code signature
// as well.
func authorizeConn(h *Helper, conn net.Conn) (string, error) {
	p, err := peerOf(conn)
	if err != nil {
		return "", err
	}
	if err := admitPeer(p.uid, h.uids, h.peerRequirement, func() error {
		return h.checkPeerCode(conn, h.peerRequirement)
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("uid %d (pid %d)", p.uid, p.pid), nil
}
