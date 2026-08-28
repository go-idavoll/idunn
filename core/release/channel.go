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

package release

import (
	"fmt"
	"strings"
)

// Pointer is the channel pointer target
// `channels/<channel>/<os>-<arch>/latest.json`. It names the currently valid
// version and the descriptor target that describes it.
//
// Its freshness is guaranteed by snapshot/timestamp (freeze defense) and its
// version increment by TUF's rollback protection — not by anything in this
// package. See docs/design.md §3.2.
type Pointer struct {
	// SchemaVersion guards the pointer format; unknown -> reject (fail closed).
	SchemaVersion int `json:"schema_version"`

	Channel string `json:"channel"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`

	// Version is the release this channel currently points at (SemVer).
	Version string `json:"version"`

	// Descriptor is the TUF target path of the matching release descriptor.
	Descriptor string `json:"descriptor"`
}

// PointerPath returns the TUF target path of a channel pointer. It is the single
// place that knows the layout, so client and packer cannot drift apart.
func PointerPath(channel, goos, goarch string) string {
	return fmt.Sprintf("channels/%s/%s-%s/latest.json", channel, goos, goarch)
}

// DescriptorPath returns the TUF target path of a release descriptor.
func DescriptorPath(goos, goarch, version string) string {
	return fmt.Sprintf("releases/%s-%s/%s.json", goos, goarch, version)
}

// PatchPath returns the TUF target path of a delta patch that turns the payload
// with hash from into the payload with hash to (docs/design.md §6.4 stage 2).
//
// The path is derived from the two content hashes and nothing else, which is
// what makes stage 2 need no descriptor field: a client that knows what it has
// and what it wants can name the patch that connects them, ask for it, and be
// told "no such target" when the publisher did not make one. Discovery is by
// convention, exactly as the design says, and the convention lives here — beside
// the other paths both the packer and the client derive — so there is one
// spelling of it rather than two that could drift.
//
// The release line is part of the path because a delegated role's patterns are
// per line: a patch is a target like any other and has to fall inside the role
// that signs the release it belongs to.
func PatchPath(major, from, to string) string {
	return fmt.Sprintf("patches/v%s/%s-%s", major, from, to)
}

// Major returns the major component of a SemVer version.
//
// It refuses anything the version parser would refuse rather than cutting at the
// first dot: this value becomes part of a target path, and a string that is not
// a version has no major to speak of.
func Major(version string) (string, error) {
	if !ValidVersion(version) {
		return "", fmt.Errorf("%w: version %q is not SemVer", ErrInvalid, version)
	}
	major, _, _ := strings.Cut(version, ".")
	return major, nil
}
