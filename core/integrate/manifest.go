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

package integrate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// ManifestSchema is the format version of integrations.json. A manifest claiming
// any other value is refused rather than read: Unregister deletes what it names,
// and a document not fully understood is no basis for that.
const ManifestSchema = 1

const (
	// maxManifestLen bounds integrations.json, far above any real one.
	maxManifestLen = 64 << 10

	// maxEntries bounds how many integrations one installation records.
	maxEntries = 64

	// maxIDLen bounds an entry's key name.
	maxIDLen = 128
)

// Kind names what a record describes. The set is closed: a manifest naming a
// kind this build does not know is refused, never skipped.
type Kind string

// The kinds of integration.
const (
	// KindWindowsUninstall is the Windows "Installed apps" entry: a key below
	// Software\Microsoft\Windows\CurrentVersion\Uninstall.
	KindWindowsUninstall Kind = "windows-uninstall"
)

// Record is one integration as the manifest keeps it: enough to find it again,
// to refresh what it derives from the installation, and to remove it. The values
// it was registered with are not kept — they are the host's, and removing an
// entry does not need them.
type Record struct {
	Kind  Kind   `json:"kind"`
	Scope Scope  `json:"scope"`
	ID    string `json:"id"`

	// Launcher is the launcher's file name in the root, which the uninstall
	// commands name and the size includes.
	Launcher string `json:"launcher"`

	// Icon is the install-relative path, inside the version directory, of the
	// file the entry shows the icon of. Empty: the launcher's.
	Icon string `json:"icon,omitempty"`
}

func (r Record) String() string {
	return fmt.Sprintf("the %s Installed apps entry %q", r.Scope, r.ID)
}

// sameEntry reports whether two records describe the same registration. Key
// names are case-insensitive in the registry.
func (r Record) sameEntry(o Record) bool {
	return r.Kind == o.Kind && r.Scope == o.Scope && strings.EqualFold(r.ID, o.ID)
}

func (r Record) validate() error {
	if r.Kind != KindWindowsUninstall {
		return fmt.Errorf("%w: unknown kind %q", ErrManifest, r.Kind)
	}
	if !r.Scope.valid() {
		return fmt.Errorf("%w: unknown scope %q", ErrManifest, r.Scope)
	}
	if err := validateID(r.ID); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if err := layout.ValidateLauncherName(r.Launcher); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if r.Icon != "" {
		if clean, err := safepath.Clean(r.Icon); err != nil || clean != r.Icon {
			return fmt.Errorf("%w: icon %q is not a clean install-relative path", ErrManifest, r.Icon)
		}
	}
	return nil
}

// validateID accepts a registry key name that can be nothing but one key: ASCII
// letters, digits, '.', '_', '-', and the braces and hyphens of a GUID, never a
// separator.
func validateID(id string) error {
	if id == "" || len(id) > maxIDLen || id == "." || id == ".." {
		return fmt.Errorf("%w: entry id %q is empty, too long, or a dot name", ErrIntegrate, id)
	}
	for _, c := range []byte(id) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '{', c == '}':
		default:
			return fmt.Errorf("%w: entry id %q may hold only letters, digits, '.', '_', '-', '{' and '}'", ErrIntegrate, id)
		}
	}
	return nil
}

type manifest struct {
	SchemaVersion int      `json:"schema_version"`
	Entries       []Record `json:"entries"`
}

// readManifest returns the manifest of root, empty when there is none. Anything
// else that is not a valid manifest is an error.
func readManifest(f fsx.FS, root string) (manifest, error) {
	raw, err := fsx.ReadFile(f, layout.Integrations(root), maxManifestLen)
	if err != nil {
		if fsx.IsNotExist(err) {
			return manifest{SchemaVersion: ManifestSchema}, nil
		}
		return manifest{}, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return manifest{}, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if dec.More() {
		return manifest{}, fmt.Errorf("%w: trailing data", ErrManifest)
	}
	if m.SchemaVersion != ManifestSchema {
		return manifest{}, fmt.Errorf("%w: schema_version %d is not %d", ErrManifest, m.SchemaVersion, ManifestSchema)
	}
	if len(m.Entries) > maxEntries {
		return manifest{}, fmt.Errorf("%w: more than %d integrations", ErrManifest, maxEntries)
	}
	for n, r := range m.Entries {
		if err := r.validate(); err != nil {
			return manifest{}, err
		}
		for _, earlier := range m.Entries[:n] {
			if earlier.sameEntry(r) {
				return manifest{}, fmt.Errorf("%w: %s is recorded twice", ErrManifest, r)
			}
		}
	}
	return m, nil
}

// writeManifest records m atomically.
func writeManifest(f fsx.FS, root string, m manifest) error {
	m.SchemaVersion = ManifestSchema
	if m.Entries == nil {
		m.Entries = []Record{}
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	raw = append(raw, '\n')
	if err := f.MkdirAll(layout.Meta(root), layout.DirMode); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if err := fsx.WriteFileAtomic(f, layout.Integrations(root), raw, layout.MetaFileMode); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	return nil
}
