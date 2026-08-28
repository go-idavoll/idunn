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
	"time"
)

// The Windows transport is a named pipe with a security descriptor, and the
// peer's identity comes from the client token on that pipe rather than from a
// socket option. Neither exists in the standard library, so it is its own piece
// of work (IDN-07b) and fails closed until it is done.
//
// Failing closed here is not a formality: the alternative would be a helper that
// listens on something with weaker access rules than a named pipe, which is
// exactly the "half a privilege boundary" this package refuses to build.
func listenLocal(string) (net.Listener, error) {
	return nil, fmt.Errorf("%w: the privileged helper's named-pipe transport (IDN-07b)", ErrNotImplemented)
}

func dialLocal(context.Context, string, time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("%w: the privileged helper's named-pipe transport (IDN-07b)", ErrNotImplemented)
}
