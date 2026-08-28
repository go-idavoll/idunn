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

//go:build !linux && !darwin

package elevate

import (
	"fmt"
	"net"
)

// peerOf fails closed where the peer's identity cannot be established.
//
// A helper that cannot tell who is asking must not answer. Guessing — trusting
// the endpoint's access rules alone, or believing something the caller said —
// would make the privilege boundary decorative, and half a privilege boundary is
// worse than none.
func peerOf(net.Conn) (peer, error) {
	return peer{}, fmt.Errorf("%w: peer credentials on this platform (IDN-07b, IDN-07c)", ErrNotImplemented)
}
