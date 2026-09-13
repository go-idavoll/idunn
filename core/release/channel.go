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
	"crypto/sha256"
	"encoding/hex"
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

// PayloadPath returns the TUF target path of a payload file with the given
// content hash, in the release line of the given major version.
//
// Payload targets are content-addressed, which is what makes file-level delta
// free: identical bytes are one target, published once, reused by every release
// that ships them.
func PayloadPath(major string, sum []byte) string {
	return fmt.Sprintf("payloads/v%s/%s", major, hex.EncodeToString(sum))
}

// payloadOfPath splits a payload target path back into its line and its content
// hash, reporting false for anything that is not one.
func payloadOfPath(targetPath string) (major, sum string, ok bool) {
	rest, ok := strings.CutPrefix(targetPath, "payloads/v")
	if !ok {
		return "", "", false
	}
	major, sum, ok = strings.Cut(rest, "/")
	if !ok || major == "" || strings.Trim(major, "0123456789") != "" {
		return "", "", false
	}
	if len(sum) != 2*sha256.Size || strings.Trim(sum, "0123456789abcdef") != "" {
		return "", "", false
	}
	return major, sum, true
}

// PatchPath returns the TUF target path of the binary patch that turns one
// payload into another, and false if the two are not payload targets it can be
// stated for.
//
// The path is derived, not published: both content hashes are already in the
// descriptors the client resolves anyway, so a client asks for the patch it
// wants by name and the signed metadata answers whether it exists. That is why
// delta stage 2 needs no field in the descriptor and no schema bump — and why
// there is nothing here to spoof, since a patch is only ever a cheaper way to
// obtain bytes that are then checked against the signed hash of the result.
//
// A patch lives in the line of the payload it produces: that is the role whose
// publish emitted it, and the role a client following that line already has.
func PatchPath(fromPayload, toPayload string) (string, bool) {
	_, from, ok := payloadOfPath(fromPayload)
	if !ok {
		return "", false
	}
	major, to, ok := payloadOfPath(toPayload)
	if !ok || from == to {
		// A patch from a payload to itself describes nothing; the file is
		// unchanged and reuse already has it.
		return "", false
	}
	return fmt.Sprintf("patches/v%s/%s-%s", major, from, to), true
}
