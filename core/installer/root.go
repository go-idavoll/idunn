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

package installer

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// ErrApp is the class of every refusal of an application identity or scope that
// a default install root cannot be derived from.
var ErrApp = errors.New("installer: unusable application identity")

// Scope is who an install is for, and so where it lives by default
// (docs/design.md §5, backlog IDN-24).
type Scope int

const (
	// ScopeUser installs for the current user, in a location that user owns.
	// It is the zero value because it matches updater.ElevationNone: an install
	// that never needs privileges.
	ScopeUser Scope = iota
	// ScopeMachine installs for every user of the machine, in a location only
	// administrators control — which is what the elevated helper demands of a
	// root before it writes one (IDN-22).
	ScopeMachine
)

// String returns the spelling ParseScope accepts.
func (s Scope) String() string {
	switch s {
	case ScopeUser:
		return "user"
	case ScopeMachine:
		return "machine"
	default:
		return fmt.Sprintf("Scope(%d)", int(s))
	}
}

// ParseScope reads "user" or "machine". Nothing else is a scope: not an empty
// string, not a different case.
func ParseScope(s string) (Scope, error) {
	switch s {
	case "user":
		return ScopeUser, nil
	case "machine":
		return ScopeMachine, nil
	default:
		return 0, fmt.Errorf("%w: scope %q is neither user nor machine", ErrApp, s)
	}
}

// App names the application an install root is derived for. It comes from the
// build — a host's installer is compiled for one application — never from a
// caller at runtime.
type App struct {
	// Name is the directory name on Windows and Linux: `Programs\<Name>`,
	// `/opt/<Name>`. One plain path component.
	Name string
	// BundleID is the reverse-DNS bundle identifier, the directory name on
	// macOS: `Application Support/<BundleID>`. Required there only.
	BundleID string
}

// maxAppNameLen keeps a derived root well inside every platform's path limits.
const maxAppNameLen = 64

// DefaultRoot returns where an install of app for scope lives on this platform
// by that platform's conventions:
//
//	OS       user                                    machine
//	Windows  FOLDERID_UserProgramFiles\<Name>        FOLDERID_ProgramFiles\<Name>
//	Linux    $XDG_DATA_HOME/<Name>                   /opt/<Name>
//	         (~/.local/share/<Name>)
//	macOS    ~/Library/Application Support/<BundleID> /Library/Application Support/<BundleID>
//
// Windows known folders come from SHGetKnownFolderPath, never from environment
// variables: a machine root is what the elevated helper vets, and a process
// environment is its caller's to choose. The machine roots on Linux and macOS are
// fixed paths for the same reason. The user roots may follow the user's own
// environment ($XDG_DATA_HOME, $HOME), since whoever sets it already owns what it
// points at.
//
// On macOS this is where the versions live, not the bundle a user starts; that
// path, and the swap into it, are IDN-26's. On Linux nothing is made
// discoverable: a `.desktop` entry or a link on $PATH is the host's to create.
//
// The directory is not created.
func DefaultRoot(scope Scope, app App) (string, error) {
	return defaultRoot(runtime.GOOS, scope, app, osDirs{})
}

// dirs is what defaultRoot needs from the machine it runs on, so every platform's
// derivation is testable on every platform.
type dirs interface {
	home() (string, error)
	getenv(key string) string
	userProgramFiles() (string, error)
	programFiles() (string, error)
}

// osDirs is this machine's dirs.
type osDirs struct{}

func (osDirs) home() (string, error)             { return os.UserHomeDir() }
func (osDirs) getenv(key string) string          { return os.Getenv(key) }
func (osDirs) userProgramFiles() (string, error) { return knownUserProgramFiles() }
func (osDirs) programFiles() (string, error)     { return knownProgramFiles() }

func defaultRoot(goos string, scope Scope, app App, d dirs) (string, error) {
	if scope != ScopeUser && scope != ScopeMachine {
		return "", fmt.Errorf("%w: %v", ErrApp, scope)
	}
	switch goos {
	case "windows":
		if err := checkAppName(app.Name); err != nil {
			return "", err
		}
		folder, get := "FOLDERID_UserProgramFiles", d.userProgramFiles
		if scope == ScopeMachine {
			folder, get = "FOLDERID_ProgramFiles", d.programFiles
		}
		base, err := get()
		if err != nil {
			return "", fmt.Errorf("installer: cannot locate %s: %w", folder, err)
		}
		return join(goos, folder, base, app.Name)
	case "linux":
		if err := checkAppName(app.Name); err != nil {
			return "", err
		}
		if scope == ScopeMachine {
			return "/opt/" + app.Name, nil
		}
		// A relative $XDG_DATA_HOME is invalid by the specification and is
		// ignored, as it requires.
		if xdg := d.getenv("XDG_DATA_HOME"); strings.HasPrefix(xdg, "/") {
			return join(goos, "$XDG_DATA_HOME", xdg, app.Name)
		}
		home, err := d.home()
		if err != nil {
			return "", fmt.Errorf("installer: no home directory: %w", err)
		}
		return join(goos, "the home directory", home, ".local/share/"+app.Name)
	case "darwin":
		if err := checkBundleID(app.BundleID); err != nil {
			return "", err
		}
		if scope == ScopeMachine {
			return "/Library/Application Support/" + app.BundleID, nil
		}
		home, err := d.home()
		if err != nil {
			return "", fmt.Errorf("installer: no home directory: %w", err)
		}
		return join(goos, "the home directory", home, "Library/Application Support/"+app.BundleID)
	default:
		return "", fmt.Errorf("%w: no default install root on %s; pass one explicitly", ErrApp, goos)
	}
}

// join appends rel to base, refusing a base that is not absolute: a root derived
// from it would be resolved against a working directory.
func join(goos, what, base, rel string) (string, error) {
	abs := strings.HasPrefix(base, "/")
	if goos == "windows" {
		// A drive-absolute path. `\\server\share` is a network location, which
		// no install convention names and CheckPrivilegedRoot refuses anyway.
		abs = len(base) >= 3 && isASCIILetter(base[0]) && base[1] == ':' && (base[2] == '\\' || base[2] == '/')
	}
	if !abs {
		return "", fmt.Errorf("%w: %s %q is not an absolute path", ErrApp, what, base)
	}
	if goos == "windows" {
		return strings.TrimRight(base, `\/`) + `\` + rel, nil
	}
	return strings.TrimRight(base, "/") + "/" + rel, nil
}

// checkAppName accepts one directory name that means the same thing on every
// filesystem: letters, digits, space, '.', '_', '-'; no leading or trailing
// space or dot; not a Windows device name. Anything else is refused rather than
// escaped — a build that names its application with a separator has a defect,
// and a root built from it must not land somewhere else.
func checkAppName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: no application name", ErrApp)
	}
	if len(name) > maxAppNameLen {
		return fmt.Errorf("%w: application name %q is longer than %d bytes", ErrApp, name, maxAppNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isASCIILetter(c) && !isDigit(c) && c != ' ' && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: application name %q contains %q", ErrApp, name, c)
		}
	}
	if first, last := name[0], name[len(name)-1]; first == ' ' || first == '.' || last == ' ' || last == '.' {
		return fmt.Errorf("%w: application name %q starts or ends with a space or dot", ErrApp, name)
	}
	stem, _, _ := strings.Cut(name, ".")
	if isWindowsDeviceName(stem) {
		return fmt.Errorf("%w: application name %q is a Windows device name", ErrApp, name)
	}
	return nil
}

// checkBundleID accepts a reverse-DNS identifier: at least two dot-separated
// components of ASCII letters, digits and '-', none empty or hyphen-edged.
func checkBundleID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: no bundle identifier", ErrApp)
	}
	if len(id) > maxAppNameLen {
		return fmt.Errorf("%w: bundle identifier %q is longer than %d bytes", ErrApp, id, maxAppNameLen)
	}
	parts := strings.Split(id, ".")
	if len(parts) < 2 {
		return fmt.Errorf("%w: bundle identifier %q is not reverse-DNS", ErrApp, id)
	}
	for _, p := range parts {
		if p == "" || p[0] == '-' || p[len(p)-1] == '-' {
			return fmt.Errorf("%w: bundle identifier %q has an empty or hyphen-edged component", ErrApp, id)
		}
		for i := 0; i < len(p); i++ {
			if !isASCIILetter(p[i]) && !isDigit(p[i]) && p[i] != '-' {
				return fmt.Errorf("%w: bundle identifier %q contains %q", ErrApp, id, p[i])
			}
		}
	}
	return nil
}

func isWindowsDeviceName(s string) bool {
	switch u := strings.ToUpper(strings.TrimRight(s, " ")); u {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	default:
		return len(u) == 4 && (strings.HasPrefix(u, "COM") || strings.HasPrefix(u, "LPT")) && u[3] >= '0' && u[3] <= '9'
	}
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool       { return c >= '0' && c <= '9' }
