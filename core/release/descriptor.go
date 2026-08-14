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

// Package release defines the app-level descriptor and channel pointer carried as
// TUF targets.
//
// TUF secures WHAT to trust (hashes, signatures, freshness); these structs carry
// the app metadata TUF does not model. They are themselves signed TUF targets, so
// nothing here re-implements trust. See docs/design.md §3.2.
package release

// SchemaVersion is the descriptor format this client understands. Any other value
// is rejected: unknown schema means unknown semantics, and we fail closed.
const SchemaVersion = 1

// LayoutSchema is the on-disk install layout this client implements (§6.1).
const LayoutSchema = 1

// Descriptor lists the payload targets belonging to one release.
type Descriptor struct {
	// SchemaVersion guards the descriptor format; unknown -> reject (fail closed).
	SchemaVersion int `json:"schema_version"`

	Name    string `json:"name"`
	Version string `json:"version"` // SemVer. Monotonicity is enforced by TUF too.
	Channel string `json:"channel"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`

	// Files maps each payload TUF target path to its install destination. The
	// hash/length live in TUF target metadata; here we keep only app attributes.
	Files []FileRef `json:"files"`

	Requirements Requirements `json:"requirements"`

	// Rollout in [0,1] drives staged/canary rollout (§14.5). Optional.
	Rollout float64 `json:"rollout,omitempty"`

	// LayoutSchema pins the on-disk install layout the client must understand.
	LayoutSchema int `json:"layout_schema"`
}

// FileKind classifies a payload file for platform-specific apply handling.
type FileKind string

// The file kinds a descriptor may declare. Anything else is rejected on ingest.
const (
	KindExe  FileKind = "exe"  // executable; may need self-replace handling.
	KindLib  FileKind = "lib"  // shared library (.dll/.so/.dylib).
	KindData FileKind = "data" // asset/config/data file.
)

// FileRef binds one TUF target to one install-relative destination.
type FileRef struct {
	// Target is the TUF target path; go-tuf resolves its verified hash/length.
	Target string `json:"target"`

	// Dst is the install-relative destination. MUST be clean, relative, and must
	// not escape the install root (validated on ingest to block traversal).
	Dst  string   `json:"dst"`
	Mode uint32   `json:"mode"` // POSIX mode; Windows honours only the exec bit.
	Kind FileKind `json:"kind"`
}

// Requirements are app-level floors on top of TUF's rollback protection.
type Requirements struct {
	// MinFromVersion blocks downgrade/skip-migration; complements TUF rollback
	// protection with an app-level floor for migration validity.
	MinFromVersion string `json:"min_from_version"`
	// MinClientVersion stops an outdated client from mishandling a newer layout.
	MinClientVersion string `json:"min_client_version"`
}
