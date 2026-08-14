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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/go-idavoll/idunn/internal/safepath"
)

// MaxJSONLen bounds a descriptor or pointer document. TUF already enforces the
// signed length of every target, so this is a second, local ceiling that keeps the
// parser cheap on hostile input.
const MaxJSONLen = 1 << 20 // 1 MiB

// ErrInvalid is the class of every rejection in this package. Fail closed: an
// input we do not fully understand is refused, never partially accepted.
var ErrInvalid = errors.New("invalid release metadata")

// semverRe is a deliberately strict SemVer 2.0.0 subset. Anything else is
// rejected rather than normalised — a version we cannot order is a version we
// cannot use for downgrade protection.
var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// ValidVersion reports whether v is an acceptable SemVer string.
func ValidVersion(v string) bool { return semverRe.MatchString(v) }

// Field name sets for the exact-key check below. They must stay in sync with the
// json tags on Descriptor, FileRef, Requirements and Pointer.
var (
	descriptorFields = fieldSet("schema_version", "name", "version", "channel", "os",
		"arch", "files", "requirements", "rollout", "layout_schema")
	fileFields         = fieldSet("target", "dst", "mode", "kind")
	requirementsFields = fieldSet("min_from_version", "min_client_version")
	pointerFields      = fieldSet("schema_version", "channel", "os", "arch", "version", "descriptor")
)

func fieldSet(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// checkKeys rejects any object key that is not exactly one of allowed.
//
// encoding/json matches field names case-insensitively, so "sChemA_version" would
// silently populate SchemaVersion. That gives one signed document many valid
// spellings, which is the kind of ambiguity this project refuses on principle: a
// descriptor has exactly one canonical form or it is not accepted.
func checkKeys(raw []byte, allowed map[string]bool, where string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, where, err)
	}
	for key := range obj {
		if !allowed[key] {
			return fmt.Errorf("%w: %s: unknown field %q", ErrInvalid, where, key)
		}
	}
	return nil
}

// decodeStrict decodes exactly one JSON document into v, rejecting unknown fields
// and trailing data. Unknown fields mean unknown semantics; we refuse them rather
// than guess (AGENTS.md §1.1).
func decodeStrict(raw []byte, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: empty document", ErrInvalid)
	}
	if len(raw) > MaxJSONLen {
		return fmt.Errorf("%w: document larger than %d bytes", ErrInvalid, MaxJSONLen)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after the document", ErrInvalid)
	}
	return nil
}

// ParseDescriptor decodes and validates raw descriptor bytes that TUF has already
// verified. It rejects unknown schema versions, unclean or escaping Dst paths, and
// unknown file kinds. It is the fuzz target FuzzDescriptor (docs/design.md §12)
// and must never panic on arbitrary input.
func ParseDescriptor(raw []byte) (*Descriptor, error) {
	var d Descriptor
	if err := decodeStrict(raw, &d); err != nil {
		return nil, err
	}
	if err := checkDescriptorKeys(raw); err != nil {
		return nil, err
	}

	if d.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema_version %d (want %d)", ErrInvalid, d.SchemaVersion, SchemaVersion)
	}
	if d.LayoutSchema != LayoutSchema {
		return nil, fmt.Errorf("%w: unsupported layout_schema %d (want %d)", ErrInvalid, d.LayoutSchema, LayoutSchema)
	}
	for _, f := range []struct{ name, val string }{
		{"name", d.Name}, {"channel", d.Channel}, {"os", d.OS}, {"arch", d.Arch},
	} {
		if f.val == "" {
			return nil, fmt.Errorf("%w: empty %s", ErrInvalid, f.name)
		}
	}
	if !ValidVersion(d.Version) {
		return nil, fmt.Errorf("%w: version %q is not SemVer", ErrInvalid, d.Version)
	}
	if d.Rollout < 0 || d.Rollout > 1 {
		return nil, fmt.Errorf("%w: rollout %v outside [0,1]", ErrInvalid, d.Rollout)
	}
	if err := validateRequirements(d.Requirements); err != nil {
		return nil, err
	}
	if len(d.Files) == 0 {
		return nil, fmt.Errorf("%w: no files", ErrInvalid)
	}

	// Both maps guard against a descriptor that installs two different targets
	// to one destination, or the same target twice: the resulting install would
	// depend on iteration order, and ambiguity aborts.
	seenTarget := make(map[string]bool, len(d.Files))
	seenDst := make(map[string]bool, len(d.Files))
	for i := range d.Files {
		f := &d.Files[i]

		target, err := safepath.CleanTarget(f.Target)
		if err != nil {
			return nil, fmt.Errorf("%w: files[%d].target: %v", ErrInvalid, i, err)
		}
		if target != f.Target {
			return nil, fmt.Errorf("%w: files[%d].target %q is not in clean form", ErrInvalid, i, f.Target)
		}

		dst, err := safepath.Clean(f.Dst)
		if err != nil {
			return nil, fmt.Errorf("%w: files[%d].dst: %v", ErrInvalid, i, err)
		}
		if dst != f.Dst {
			return nil, fmt.Errorf("%w: files[%d].dst %q is not in clean form", ErrInvalid, i, f.Dst)
		}

		switch f.Kind {
		case KindExe, KindLib, KindData:
		default:
			return nil, fmt.Errorf("%w: files[%d].kind %q is unknown", ErrInvalid, i, f.Kind)
		}
		// Mode carries permission bits only. setuid/setgid/sticky and any type
		// bits would let a descriptor request a privileged file.
		if f.Mode&^uint32(0o777) != 0 {
			return nil, fmt.Errorf("%w: files[%d].mode %#o has bits outside 0777", ErrInvalid, i, f.Mode)
		}

		if seenTarget[f.Target] {
			return nil, fmt.Errorf("%w: files[%d]: duplicate target %q", ErrInvalid, i, f.Target)
		}
		if seenDst[dst] {
			return nil, fmt.Errorf("%w: files[%d]: duplicate dst %q", ErrInvalid, i, dst)
		}
		seenTarget[f.Target] = true
		seenDst[dst] = true
	}

	return &d, nil
}

// checkDescriptorKeys walks the document once more to enforce exact key spelling
// at every level, including the nested files[] and requirements objects.
func checkDescriptorKeys(raw []byte) error {
	if err := checkKeys(raw, descriptorFields, "descriptor"); err != nil {
		return err
	}
	var doc struct {
		Files        []json.RawMessage `json:"files"`
		Requirements json.RawMessage   `json:"requirements"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	for i, f := range doc.Files {
		if err := checkKeys(f, fileFields, fmt.Sprintf("files[%d]", i)); err != nil {
			return err
		}
	}
	if len(doc.Requirements) > 0 && string(doc.Requirements) != "null" {
		if err := checkKeys(doc.Requirements, requirementsFields, "requirements"); err != nil {
			return err
		}
	}
	return nil
}

func validateRequirements(r Requirements) error {
	if r.MinFromVersion != "" && !ValidVersion(r.MinFromVersion) {
		return fmt.Errorf("%w: requirements.min_from_version %q is not SemVer", ErrInvalid, r.MinFromVersion)
	}
	if r.MinClientVersion != "" && !ValidVersion(r.MinClientVersion) {
		return fmt.Errorf("%w: requirements.min_client_version %q is not SemVer", ErrInvalid, r.MinClientVersion)
	}
	return nil
}

// ParsePointer decodes and validates raw channel-pointer bytes that TUF has
// already verified. Unknown schema, empty version, or a descriptor path that is
// not a clean relative target path are rejected.
func ParsePointer(raw []byte) (*Pointer, error) {
	var p Pointer
	if err := decodeStrict(raw, &p); err != nil {
		return nil, err
	}
	if err := checkKeys(raw, pointerFields, "pointer"); err != nil {
		return nil, err
	}

	if p.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema_version %d (want %d)", ErrInvalid, p.SchemaVersion, SchemaVersion)
	}
	for _, f := range []struct{ name, val string }{
		{"channel", p.Channel}, {"os", p.OS}, {"arch", p.Arch},
	} {
		if f.val == "" {
			return nil, fmt.Errorf("%w: empty %s", ErrInvalid, f.name)
		}
	}
	if !ValidVersion(p.Version) {
		return nil, fmt.Errorf("%w: version %q is not SemVer", ErrInvalid, p.Version)
	}

	target, err := safepath.CleanTarget(p.Descriptor)
	if err != nil {
		return nil, fmt.Errorf("%w: descriptor: %v", ErrInvalid, err)
	}
	if target != p.Descriptor {
		return nil, fmt.Errorf("%w: descriptor %q is not in clean form", ErrInvalid, p.Descriptor)
	}

	return &p, nil
}
