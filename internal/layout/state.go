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

package layout

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
)

// StateSchema is the format version of state.json. A file claiming any other
// value is refused rather than read: the installer's downgrade protection acts on
// what it finds here, and a document we do not fully understand is not a basis
// for deciding to overwrite an installation (docs/design.md §14.6).
const StateSchema = 1

// MaxStateLen bounds state.json. It is far above any legitimate document.
const MaxStateLen = 64 << 10

// Install is the recorded state of the installation under a root: what is
// installed, at which version, in which on-disk layout.
//
// It is written atomically by the updater at the end of a committed transaction
// and read by the installer before it touches anything. A local attacker with
// write access to the install root can tamper with it; that is documented and
// accepted (§11.5). It defends against stale binaries and operator mistakes, not
// against an attacker who already has the privileges the file protects.
type Install struct {
	SchemaVersion int    `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	LayoutSchema  int    `json:"layout_schema"`
}

// ReadInstall returns the recorded install state, or nil when the root holds no
// installation.
//
// Every other outcome — unreadable, malformed, unknown schema, implausible
// version — is an error. "I could not read the state" must never be reported as
// "there is nothing installed", because the caller acts on that answer by
// installing over whatever is actually there.
func ReadInstall(f fsx.FS, root string) (*Install, error) {
	raw, err := fsx.ReadFile(f, State(root), MaxStateLen)
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: read state: %w", ErrLayout, err)
	}

	var in Install
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("%w: parse state: %w", ErrLayout, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: parse state: trailing data", ErrLayout)
	}

	if in.SchemaVersion != StateSchema {
		return nil, fmt.Errorf("%w: state schema_version %d is not %d", ErrLayout, in.SchemaVersion, StateSchema)
	}
	if in.Name == "" {
		return nil, fmt.Errorf("%w: state has no name", ErrLayout)
	}
	if !release.ValidVersion(in.Version) {
		return nil, fmt.Errorf("%w: state version %q is not SemVer", ErrLayout, in.Version)
	}
	if in.LayoutSchema <= 0 {
		return nil, fmt.Errorf("%w: state layout_schema %d is not positive", ErrLayout, in.LayoutSchema)
	}
	return &in, nil
}

// WriteInstall records the install state atomically.
//
// It is the last write of a committed transaction. Written any earlier it would
// claim a version that is not yet the one `current` points at, and the
// installer's preflight would refuse to repair an install that never completed.
func WriteInstall(f fsx.FS, root string, in Install) error {
	in.SchemaVersion = StateSchema
	if in.Name == "" {
		return fmt.Errorf("%w: refusing to write state without a name", ErrLayout)
	}
	if err := ValidateVersion(in.Version); err != nil {
		return err
	}
	if in.LayoutSchema <= 0 {
		return fmt.Errorf("%w: refusing to write state with layout_schema %d", ErrLayout, in.LayoutSchema)
	}

	raw, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode state: %w", ErrLayout, err)
	}
	raw = append(raw, '\n')

	if err := f.MkdirAll(Meta(root), 0o700); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	if err := fsx.WriteFileAtomic(f, State(root), raw, 0o600); err != nil {
		return fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return nil
}
