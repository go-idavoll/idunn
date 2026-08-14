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

import "fmt"

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
