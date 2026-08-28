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

	"github.com/Microsoft/go-winio"
)

// On Windows the caller was authorized before this code ran: the pipe's security
// descriptor is evaluated by the kernel when the client opens it, so a connection
// that exists at all is one the descriptor permits.
//
// There is deliberately no second check here. Re-deriving the caller's identity
// from the connection and comparing it against a list of our own would be a
// second access-control implementation next to the operating system's, and the
// interesting failure mode is not that it disagrees — it is that a reader can no
// longer tell which of the two actually decides.
func authorizeConn(_ *Helper, _ net.Conn) (string, error) {
	return "authorized by the pipe security descriptor", nil
}

// checkPlatformOptions validates the Windows-only half of HelperOptions.
//
// The descriptor is mandatory. A named pipe created without one inherits a
// default DACL, and "whatever the default turns out to be" is not a decision
// anybody made about who may ask a privileged process to install software.
func checkPlatformOptions(o HelperOptions) error {
	if o.SecurityDescriptor == "" {
		return fmt.Errorf("%w: the helper pipe needs a SecurityDescriptor (SDDL); "+
			"a pipe without one inherits a default DACL, which is not an access decision", ErrRequest)
	}
	if _, err := winio.SddlToSecurityDescriptor(o.SecurityDescriptor); err != nil {
		return fmt.Errorf("%w: SecurityDescriptor is not valid SDDL: %w", ErrRequest, err)
	}
	if len(o.AllowedUIDs) != 0 {
		return fmt.Errorf("%w: AllowedUIDs has no meaning on Windows; express who may connect in the SecurityDescriptor", ErrRequest)
	}
	return nil
}
