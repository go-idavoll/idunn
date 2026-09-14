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

import "fmt"

// DaemonState is what SMAppService reports about a helper daemon.
//
// The zero value is DaemonStateUnknown, so a state nobody set can never read as
// DaemonEnabled.
type DaemonState int

// The states of a daemon registered through SMAppService. They mirror
// SMAppServiceStatus; a value macOS adds later maps to DaemonStateUnknown and
// an error, never to one of these.
const (
	// DaemonStateUnknown is a status this package does not know.
	DaemonStateUnknown DaemonState = iota
	// DaemonNotRegistered: SMAppServiceStatusNotRegistered.
	DaemonNotRegistered
	// DaemonEnabled: SMAppServiceStatusEnabled — registered and approved; launchd
	// may run it.
	DaemonEnabled
	// DaemonRequiresApproval: SMAppServiceStatusRequiresApproval — registered,
	// but the user has not allowed it under System Settings > Login Items. It
	// does not run until they do; OpenLoginItemsSettings takes them there.
	DaemonRequiresApproval
	// DaemonNotFound: SMAppServiceStatusNotFound — the bundle carries no such
	// plist, or the running process is not the bundle that does.
	DaemonNotFound
)

func (s DaemonState) String() string {
	switch s {
	case DaemonNotRegistered:
		return "not registered"
	case DaemonEnabled:
		return "enabled"
	case DaemonRequiresApproval:
		return "requires approval"
	case DaemonNotFound:
		return "not found"
	default:
		return "unknown"
	}
}

// The raw SMAppServiceStatus values (ServiceManagement/SMAppService.h, macOS 13).
const (
	smStatusNotRegistered    = 0
	smStatusEnabled          = 1
	smStatusRequiresApproval = 2
	smStatusNotFound         = 3
)

// daemonStateFromStatus maps the framework's integer to a DaemonState, failing
// closed on anything unrecognised.
func daemonStateFromStatus(raw int64) (DaemonState, error) {
	switch raw {
	case smStatusNotRegistered:
		return DaemonNotRegistered, nil
	case smStatusEnabled:
		return DaemonEnabled, nil
	case smStatusRequiresApproval:
		return DaemonRequiresApproval, nil
	case smStatusNotFound:
		return DaemonNotFound, nil
	default:
		return DaemonStateUnknown, fmt.Errorf("%w: SMAppService reported unknown status %d", ErrHelper, raw)
	}
}

// DaemonStatus reports the state of the helper daemon whose plist is
// Contents/Library/LaunchDaemons/<plistName> in the running application's
// bundle (SMAppService daemonServiceWithPlistName:, status).
//
// It exists on macOS 13 and later, in a build with cgo; everywhere else it
// returns ErrNotImplemented. It must be called from the application bundle that
// carries the plist — a bare executable has no bundle for SMAppService to look
// in.
func DaemonStatus(plistName string) (DaemonState, error) {
	if err := checkPlistName(plistName); err != nil {
		return DaemonStateUnknown, err
	}
	raw, err := smDaemonStatus(plistName)
	if err != nil {
		return DaemonStateUnknown, err
	}
	return daemonStateFromStatus(raw)
}

// RegisterDaemon registers the helper daemon with launchd
// (registerAndReturnError:).
//
// Registration is not approval. The first registration leaves the daemon in
// DaemonRequiresApproval until the user allows it under Login Items; a host
// calls DaemonStatus afterwards and, if approval is outstanding, explains why
// and offers OpenLoginItemsSettings. Nothing here — or anywhere — clicks that
// switch for the user.
func RegisterDaemon(plistName string) error {
	if err := checkPlistName(plistName); err != nil {
		return err
	}
	return smRegisterDaemon(plistName)
}

// UnregisterDaemon removes the registration (unregisterAndReturnError:);
// launchd stops the daemon if it is running.
func UnregisterDaemon(plistName string) error {
	if err := checkPlistName(plistName); err != nil {
		return err
	}
	return smUnregisterDaemon(plistName)
}

// OpenLoginItemsSettings opens System Settings at Login Items
// (openSystemSettingsLoginItems), where the user approves the daemon. It is for
// a process in a user's GUI session, never for the daemon itself.
func OpenLoginItemsSettings() error { return smOpenLoginItemsSettings() }
