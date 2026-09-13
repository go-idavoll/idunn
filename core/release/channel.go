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

// VersionOfDescriptorPath reads a version back out of a descriptor target path,
// reporting false for anything that is not one for this platform.
//
// It is how a client learns which releases exist without a new document to sign:
// the signed targets metadata already lists every descriptor the repository
// publishes, and this is the inverse of the function that put them there. The
// path is the claim — a descriptor that disagrees with the path it lives at is
// refused when it is resolved (see Client.ReleaseVersion) — so reading a version
// out of one is a lookup, never a trust decision.
func VersionOfDescriptorPath(targetPath, goos, goarch string) (string, bool) {
	prefix := fmt.Sprintf("releases/%s-%s/", goos, goarch)
	if !strings.HasPrefix(targetPath, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(targetPath, prefix)
	version, ok := strings.CutSuffix(rest, ".json")
	if !ok || !ValidVersion(version) {
		return "", false
	}
	return version, true
}
