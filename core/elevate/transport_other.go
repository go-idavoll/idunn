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

//go:build !unix

package elevate

import (
	"context"
	"fmt"
	"net"
	"time"
)

// The helper service exists on POSIX only for now. On Windows its transport is a
// named pipe whose ACL decides who may ask (IDN-07); until that is built, both
// sides fail closed here rather than listen or dial anything.

func listenLocal(string) (net.Listener, error) {
	return nil, fmt.Errorf("%w: the privileged helper service on this platform (IDN-07)", ErrNotImplemented)
}

func dialLocal(context.Context, string, time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("%w: the privileged helper service on this platform (IDN-07)", ErrNotImplemented)
}

func authorizeConn(*Helper, net.Conn) (string, error) {
	return "", fmt.Errorf("%w: no peer authentication on this platform", ErrDenied)
}

func checkServicePlatform() error {
	return fmt.Errorf("%w: the privileged helper service on this platform (IDN-07)", ErrNotImplemented)
}
