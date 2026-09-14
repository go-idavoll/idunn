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
	"path/filepath"
	"runtime"
)

// maxHelperLabelLen bounds a helper label. It names a launchd job, a Windows
// service, a pipe and a directory, and has to fit the tightest of those — the
// macOS socket path under /Library/Application Support, 103 bytes — with room.
const maxHelperLabelLen = 62

// CheckHelperLabel accepts a label for a privileged helper: reverse-DNS as for a
// launchd label, and at most 62 bytes, the most that leaves the macOS socket
// path "/Library/Application Support/<label>/helper.sock" within 103 bytes
// (docs/helper.md §2).
func CheckHelperLabel(label string) error {
	if len(label) > maxHelperLabelLen {
		return fmt.Errorf("%w: helper label %q is longer than %d bytes", ErrRequest, label, maxHelperLabelLen)
	}
	return checkReverseDNS("helper label", label)
}

// HelperPaths are where a privileged helper with a given label lives on this
// platform (docs/helper.md §3). The application and the helper both derive them
// from the label, so they cannot disagree about where to meet.
type HelperPaths struct {
	// StateDir holds the per-machine caller list. It must be a directory only
	// administrators control; the helper refuses to start otherwise.
	StateDir string
	// Endpoint is what NewHelper listens on and NewService dials.
	Endpoint string
}

// DefaultHelperPaths returns the paths for label on the running platform.
func DefaultHelperPaths(label string) (HelperPaths, error) {
	if err := CheckHelperLabel(label); err != nil {
		return HelperPaths{}, err
	}
	return helperPaths(runtime.GOOS, label)
}

// DefaultHelperEndpoint returns only the endpoint, for the application side.
func DefaultHelperEndpoint(label string) (string, error) {
	p, err := DefaultHelperPaths(label)
	return p.Endpoint, err
}

func helperPaths(goos, label string) (HelperPaths, error) {
	switch goos {
	case "darwin":
		dir := "/Library/Application Support/" + label
		return HelperPaths{StateDir: dir, Endpoint: dir + "/helper.sock"}, nil
	case "linux":
		return HelperPaths{StateDir: "/etc/" + label, Endpoint: "/run/" + label + "/helper.sock"}, nil
	case "windows":
		// programFiles fails wherever it is not Windows, which staticcheck can
		// prove there; this function is compiled for every platform.
		//
		//nolint:staticcheck // SA4023: true per platform, not per program.
		pf, err := programFiles()
		//nolint:staticcheck // SA4023: as above.
		if err != nil {
			return HelperPaths{}, err
		}
		return HelperPaths{StateDir: filepath.Join(pf, label), Endpoint: `\\.\pipe\` + label}, nil
	default:
		return HelperPaths{}, fmt.Errorf("%w: helper paths on %s", ErrNotImplemented, goos)
	}
}
