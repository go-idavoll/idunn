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

//go:build !darwin || !cgo

package elevate

import (
	"fmt"
	"net"
)

// A code-signing requirement on the peer is a macOS concept checked through
// Security.framework, so only a darwin build with cgo can honour one. Anywhere
// else a helper configured with one refuses to start: silently ignoring the
// requirement would be a helper weaker than its configuration says, which is
// the one kind of misconfiguration that must never be quiet.

func checkPeerRequirement(string) error {
	return fmt.Errorf("%w: HelperOptions.PeerRequirement needs macOS and a build with cgo (IDN-08)", ErrNotImplemented)
}

func peerCodeCheck(net.Conn, string) error {
	return fmt.Errorf("%w: no code-signing check on this platform", ErrDenied)
}
