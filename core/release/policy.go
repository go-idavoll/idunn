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
	"encoding/json"
	"fmt"
	"strings"
)

// Ceilings on what a release may ask of the client that installs it. The client
// holds its own records to the same bounds (internal/layout), so a signed value
// that passes here is one the launcher can store.
const (
	MaxProbationAttempts = 20
	MaxProbationRestarts = 20
)

// policySuffix ends the file name of a release policy target. The underscore is
// the point: it is not a character SemVer allows anywhere, so no client that
// reads versions out of descriptor paths (VersionOfDescriptorPath) and no
// packer that classifies them can take a policy for a descriptor — while the
// ".json" ending keeps it inside the release line's delegated pattern
// `releases/*/<major>.*.json`, so publishing one needs no change to targets.
const policySuffix = "_policy.json"

// Policy is what a publisher asks of the client installing one release, beyond
// what the descriptor says about its files (IDN-39).
//
// It is a target of its own rather than a descriptor field, and discovered by
// name like a patch: ParseDescriptor refuses unknown fields, so a new field would
// make every deployed client refuse every new release, while a client that knows
// nothing about policies never asks for this path. The signed targets metadata
// answers whether a release has one.
type Policy struct {
	SchemaVersion int `json:"schema_version"`

	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`

	// Probation is how the release has to prove itself once installed. Nil says
	// nothing, and the host's own policy decides.
	Probation *ProbationPolicy `json:"probation,omitempty"`
}

// ProbationPolicy is a release's probation allowance.
type ProbationPolicy struct {
	// Attempts is how many launcher starts the release gets to confirm it is
	// healthy, 0 to MaxProbationAttempts. Zero says this release is not put on
	// probation at all.
	Attempts int `json:"attempts"`

	// Restarts is how many restarts it may ask for through launch.Relaunch
	// without spending attempts, 0 to MaxProbationRestarts. Zero leaves the
	// client's default.
	Restarts int `json:"restarts,omitempty"`
}

var (
	policyFields          = fieldSet("schema_version", "name", "version", "os", "arch", "probation")
	probationPolicyFields = fieldSet("attempts", "restarts")
)

// PolicyPath returns the TUF target path of a release's policy: beside its
// descriptor, in the same role.
func PolicyPath(goos, goarch, version string) string {
	return fmt.Sprintf("releases/%s-%s/%s%s", goos, goarch, version, policySuffix)
}

// VersionOfPolicyPath reads a version back out of a policy target path,
// reporting false for anything PolicyPath could not have produced.
func VersionOfPolicyPath(targetPath string) (goos, goarch, version string, ok bool) {
	rest, found := strings.CutPrefix(targetPath, "releases/")
	if !found {
		return "", "", "", false
	}
	platform, file, found := strings.Cut(rest, "/")
	if !found {
		return "", "", "", false
	}
	goos, goarch, found = strings.Cut(platform, "-")
	if !found || goos == "" || goarch == "" {
		return "", "", "", false
	}
	version, found = strings.CutSuffix(file, policySuffix)
	if !found || !ValidVersion(version) || PolicyPath(goos, goarch, version) != targetPath {
		return "", "", "", false
	}
	return goos, goarch, version, true
}

// ParsePolicy decodes and validates raw policy bytes that TUF has already
// verified. Like ParseDescriptor it refuses unknown fields at every level,
// unknown schema versions and values outside their bounds, and it must never
// panic on arbitrary input.
func ParsePolicy(raw []byte) (*Policy, error) {
	var p Policy
	if err := decodeStrict(raw, &p); err != nil {
		return nil, err
	}
	if err := checkKeys(raw, policyFields, "policy"); err != nil {
		return nil, err
	}
	var nested struct {
		Probation json.RawMessage `json:"probation"`
	}
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(nested.Probation) > 0 && string(nested.Probation) != "null" {
		if err := checkKeys(nested.Probation, probationPolicyFields, "probation"); err != nil {
			return nil, err
		}
	}

	if p.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema_version %d (want %d)", ErrInvalid, p.SchemaVersion, SchemaVersion)
	}
	for _, f := range []struct{ name, val string }{
		{"name", p.Name}, {"os", p.OS}, {"arch", p.Arch},
	} {
		if f.val == "" {
			return nil, fmt.Errorf("%w: empty %s", ErrInvalid, f.name)
		}
	}
	if !ValidVersion(p.Version) {
		return nil, fmt.Errorf("%w: version %q is not SemVer", ErrInvalid, p.Version)
	}
	if pp := p.Probation; pp != nil {
		if pp.Attempts < 0 || pp.Attempts > MaxProbationAttempts {
			return nil, fmt.Errorf("%w: probation.attempts %d outside 0..%d", ErrInvalid, pp.Attempts, MaxProbationAttempts)
		}
		if pp.Restarts < 0 || pp.Restarts > MaxProbationRestarts {
			return nil, fmt.Errorf("%w: probation.restarts %d outside 0..%d", ErrInvalid, pp.Restarts, MaxProbationRestarts)
		}
	}
	return &p, nil
}
