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

package packer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// A role name becomes a metadata file name, so a name carrying a separator or a
// traversal element would make the publisher read and write outside its own
// repository. The metadata it arrives in is signed by the publisher's own keys,
// which is a reason to be surprised by such a name — not a reason to follow it.
func TestValidRoleName(t *testing.T) {
	valid := []string{"stable", "beta", "v1", "v10", "long-term", "bin-0a", "a"}
	for _, role := range valid {
		if !validRoleName(role) {
			t.Errorf("validRoleName(%q) = false, want true", role)
		}
	}
	invalid := []string{
		"", "..", "../evil", "a/b", `a\b`, "/etc/passwd", "C:evil",
		"Stable", "-lead", ".hidden", "a b", "x..y",
		strings.Repeat("a", 65), "role\x00",
	}
	for _, role := range invalid {
		if validRoleName(role) {
			t.Errorf("validRoleName(%q) = true, want false", role)
		}
	}
}

// The guard has to fire where the names actually enter the program: the keys of
// the snapshot's meta map.
func TestSnapshotRoleNamesAreRefused(t *testing.T) {
	s := &state{snapshot: metadata.Snapshot()}
	s.snapshot.Signed.Meta = map[string]*metadata.MetaFiles{
		"targets.json": metadata.MetaFile(1),
		"stable.json":  metadata.MetaFile(1),
		"../evil.json": metadata.MetaFile(1),
	}
	_, err := s.snapshotRoles()
	if !errors.Is(err, ErrRepo) {
		t.Fatalf("err = %v, want ErrRepo", err)
	}
	if !strings.Contains(err.Error(), "../evil") {
		t.Errorf("err = %v, want it to name the role it refuses", err)
	}
}

// readContained is the second half of that pair: containment enforced by the
// operating system, so a name that got past the validator still cannot reach a
// file outside the metadata directory.
func TestReadContainedStaysInsideItsDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "metadata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("out of bounds"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.stable.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := readContained(dir, "1.stable.json"); err != nil || string(got) != "{}" {
		t.Fatalf("readContained(in-bounds) = %q, %v", got, err)
	}
	for _, name := range []string{"../secret", "../../etc/passwd", "/etc/passwd"} {
		if raw, err := readContained(dir, name); err == nil {
			t.Errorf("readContained(%q) returned %q, want an error", name, raw)
		}
	}
}

// A metadata document larger than the ceiling is refused rather than read into
// memory whole.
func TestReadContainedBoundsSize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "big.json"), make([]byte, MaxMetadataLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readContained(dir, "big.json"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want a size refusal", err)
	}
}
