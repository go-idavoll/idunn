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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// The two subtrees a repository is served from. They are part of the wire
// contract: docs/packer.md §6 and the red-team harness use the same names.
const (
	MetadataDir = "metadata"
	TargetsDir  = "targets"
)

// rootFileRe matches a version-prefixed root file.
var rootFileRe = regexp.MustCompile(`^([0-9]+)\.root\.json$`)

// state is the repository as it exists before this publish. A fresh repository
// has a root and nothing else — the packer never creates one.
type state struct {
	dir        string
	metaDir    string
	targetsDir string

	root *metadata.Metadata[metadata.RootType]

	// The four below are nil on a repository that has never been published to.
	targets   *metadata.Metadata[metadata.TargetsType]
	snapshot  *metadata.Metadata[metadata.SnapshotType]
	timestamp *metadata.Metadata[metadata.TimestampType]
	delegated map[string]*metadata.Metadata[metadata.TargetsType]

	// raw holds the exact published bytes of each role, keyed by role name. A
	// role a publish does not change is re-published as the same bytes rather
	// than re-serialized, so nothing can drift through a round trip.
	raw map[string][]byte
}

// loadState reads the repository at dir and verifies that what it reads hangs
// together: every role verified against its delegator with go-tuf's own
// verification, and every metadata file checked against the length and hashes
// the role above it signed for.
//
// This is not a second trust path — it is go-tuf verifying the publisher's own
// output. The reason to do it at all is T13: publishing on top of a repository
// that is half-uploaded, or whose keys have moved on without this tool noticing,
// produces exactly the inconsistent state the client is entitled to refuse.
func loadState(dir string) (*state, error) {
	s := &state{
		dir:        dir,
		metaDir:    filepath.Join(dir, MetadataDir),
		targetsDir: filepath.Join(dir, TargetsDir),
		delegated:  map[string]*metadata.Metadata[metadata.TargetsType]{},
		raw:        map[string][]byte{},
	}
	if err := s.loadRoot(); err != nil {
		return nil, err
	}

	tsPath := filepath.Join(s.metaDir, "timestamp.json")
	raw, err := os.ReadFile(tsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// A repository with a root and no timestamp has never been
			// published to. That is the one legitimate incomplete state.
			return s, nil
		}
		return nil, fmt.Errorf("%w: reading %s: %w", ErrRepo, tsPath, err)
	}
	if s.timestamp, err = metadata.Timestamp().FromBytes(raw); err != nil {
		return nil, fmt.Errorf("%w: parsing timestamp.json: %w", ErrRepo, err)
	}
	s.raw[metadata.TIMESTAMP] = raw
	if err := s.root.VerifyDelegate(metadata.TIMESTAMP, s.timestamp); err != nil {
		return nil, fmt.Errorf("%w: timestamp.json is not signed by the keys root names: %w", ErrRepo, err)
	}

	snapMeta, ok := s.timestamp.Signed.Meta["snapshot.json"]
	if !ok {
		return nil, fmt.Errorf("%w: timestamp.json names no snapshot", ErrRepo)
	}
	raw, err = s.readRoleFile(metadata.SNAPSHOT, snapMeta.Version, snapMeta)
	if err != nil {
		return nil, err
	}
	if s.snapshot, err = metadata.Snapshot().FromBytes(raw); err != nil {
		return nil, fmt.Errorf("%w: parsing snapshot: %w", ErrRepo, err)
	}
	s.raw[metadata.SNAPSHOT] = raw
	if err := s.root.VerifyDelegate(metadata.SNAPSHOT, s.snapshot); err != nil {
		return nil, fmt.Errorf("%w: snapshot is not signed by the keys root names: %w", ErrRepo, err)
	}
	if s.snapshot.Signed.Version != snapMeta.Version {
		return nil, fmt.Errorf("%w: timestamp names snapshot version %d, the file is version %d",
			ErrRepo, snapMeta.Version, s.snapshot.Signed.Version)
	}

	targetsMeta, ok := s.snapshot.Signed.Meta["targets.json"]
	if !ok {
		return nil, fmt.Errorf("%w: snapshot names no targets.json", ErrRepo)
	}
	if raw, err = s.readRoleFile(metadata.TARGETS, targetsMeta.Version, targetsMeta); err != nil {
		return nil, err
	}
	if s.targets, err = metadata.Targets().FromBytes(raw); err != nil {
		return nil, fmt.Errorf("%w: parsing targets.json: %w", ErrRepo, err)
	}
	s.raw[metadata.TARGETS] = raw
	if err := s.root.VerifyDelegate(metadata.TARGETS, s.targets); err != nil {
		return nil, fmt.Errorf("%w: targets.json is not signed by the keys root names: %w", ErrRepo, err)
	}

	roles, err := s.snapshotRoles()
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		meta := s.snapshot.Signed.Meta[role+".json"]
		raw, err := s.readRoleFile(role, meta.Version, meta)
		if err != nil {
			return nil, err
		}
		del, err := metadata.Targets().FromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: parsing %s: %w", ErrRepo, role, err)
		}
		if err := s.targets.VerifyDelegate(role, del); err != nil {
			return nil, fmt.Errorf("%w: delegated role %s is not signed by the keys targets.json names: %w",
				ErrRepo, role, err)
		}
		s.delegated[role] = del
		s.raw[role] = raw
	}
	return s, nil
}

// snapshotRoles lists the delegated roles the snapshot knows about, sorted so a
// load is deterministic.
//
// A name that could not be a role name is a refusal rather than a skip: every
// name here becomes a file this publisher reads and later writes, and a
// repository that names a role we cannot account for is one we do not extend.
func (s *state) snapshotRoles() ([]string, error) {
	roles := make([]string, 0, len(s.snapshot.Signed.Meta))
	for name := range s.snapshot.Signed.Meta {
		role, ok := strings.CutSuffix(name, ".json")
		if !ok || role == metadata.TARGETS {
			continue
		}
		if !validRoleName(role) {
			return nil, fmt.Errorf("%w: snapshot names role %q, which is not a usable role name", ErrRepo, role)
		}
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

// loadRoot reads the highest-numbered root file. root is an input to the packer
// and never an output: it is produced by the signing ceremony, and a publish that
// could write it would put the trust anchor behind the most frequently run
// command (docs/packer.md §4).
func (s *state) loadRoot() error {
	entries, err := os.ReadDir(s.metaDir)
	if err != nil {
		return fmt.Errorf("%w: reading %s: %w", ErrRepo, s.metaDir, err)
	}
	var newest int64
	var name string
	for _, e := range entries {
		m := rootFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || v <= newest {
			continue
		}
		newest, name = v, e.Name()
	}
	if name == "" {
		return fmt.Errorf("%w: no <version>.root.json in %s; the root ceremony creates it, the packer never does",
			ErrRepo, s.metaDir)
	}
	raw, err := os.ReadFile(filepath.Join(s.metaDir, name))
	if err != nil {
		return fmt.Errorf("%w: reading %s: %w", ErrRepo, name, err)
	}
	root, err := metadata.Root().FromBytes(raw)
	if err != nil {
		return fmt.Errorf("%w: parsing %s: %w", ErrRepo, name, err)
	}
	if root.Signed.Version != newest {
		return fmt.Errorf("%w: %s contains version %d", ErrRepo, name, root.Signed.Version)
	}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return fmt.Errorf("%w: %s is not signed by its own keys: %w", ErrRepo, name, err)
	}
	s.root = root
	return nil
}

// readRoleFile reads one version-prefixed metadata file and checks it against the
// length and hashes the delegating role signed for it. A file that does not match
// what snapshot or timestamp says is a repository we refuse to build on.
func (s *state) readRoleFile(role string, version int64, want *metadata.MetaFiles) ([]byte, error) {
	if !validRoleName(role) {
		return nil, fmt.Errorf("%w: %q is not a usable role name", ErrRepo, role)
	}
	name := fmt.Sprintf("%d.%s.json", version, role)
	raw, err := readContained(s.metaDir, name)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrRepo, name, err)
	}
	if err := want.VerifyLengthHashes(raw); err != nil {
		return nil, fmt.Errorf("%w: %s does not match what the role above it signed for: %w", ErrRepo, name, err)
	}
	return raw, nil
}

// MaxMetadataLen bounds one metadata document read back from a repository. It is
// above go-tuf's own per-role ceilings (root 512 KiB, targets 5 MB) and keeps a
// corrupt or hostile tree from being read into memory whole.
const MaxMetadataLen = 16 << 20 // 16 MiB

// readContained reads name from dir, with the containment enforced by the
// operating system rather than by string handling.
//
// os.Root refuses to open anything outside the directory it was opened on —
// traversal, absolute paths, and symlinks that leave it — which is a stronger
// statement than any check on the name, and the reason this does not simply join
// and read. The name reaching here is already validated (validRoleName); this is
// the belt to that pair of braces.
func readContained(dir, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(io.LimitReader(f, MaxMetadataLen+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxMetadataLen {
		return nil, fmt.Errorf("larger than %d bytes", MaxMetadataLen)
	}
	return raw, nil
}

// writeFile writes one repository file through a temporary file in the same
// directory, so a reader never sees a partially written metadata document and an
// interrupted publish leaves whole files or none.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	// A TUF repository is served to the world, so its directories and files are
	// world-readable by definition. This is a publisher's output tree, never an
	// install root: nothing secret is written here, and 0750/0600 would only make
	// the fixture unrepresentative of the thing being published.
	//nolint:gosec // G301: repository directories are public by design.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".idunn-packer-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// A repository is served to the world; 0644 is what its files look like.
	//nolint:gosec // G302: repository files are public by design.
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}
