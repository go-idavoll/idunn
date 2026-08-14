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
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
)

// Default validity windows. They are deliberately asymmetric: timestamp is short
// and re-signed often because it is the online freshness anchor, snapshot follows
// it, and the offline-signed targets roles live long enough that a publish does
// not depend on the offline key being reachable every week.
const (
	DefaultTargetsExpiry   = 90 * 24 * time.Hour
	DefaultSnapshotExpiry  = 7 * 24 * time.Hour
	DefaultTimestampExpiry = 24 * time.Hour
)

// Options configures one publish.
type Options struct {
	// ConfigPath is the pack.yaml describing the release.
	ConfigPath string

	// RepoDir is the repository to publish into. It must already contain a
	// root signed by the ceremony; the packer never creates one.
	RepoDir string

	// Now is the reference time every expiry is derived from. It is an input,
	// never the wall clock, because output that embeds "when it ran" cannot be
	// rebuilt and compared (AGENTS.md §1.7).
	Now time.Time

	// Validity windows. Zero selects the Default* above.
	TargetsExpiry   time.Duration
	SnapshotExpiry  time.Duration
	TimestampExpiry time.Duration

	// LookupEnv resolves role key references. Nil selects the process
	// environment.
	LookupEnv func(string) (string, bool)
}

// Result reports what a publish produced, for the operator and for tests.
type Result struct {
	Name    string
	Version string
	Channel string

	// Roles maps every role this publish wrote to its new version. A role
	// whose content did not change is absent: its file is left untouched.
	Roles map[string]int64

	// AddedTargets lists the target paths this publish added, sorted.
	AddedTargets []string

	// Delegations maps each delegated role to the number of targets it holds
	// after the publish.
	Delegations map[string]int
}

// blob is one target this publish emits: the bytes, where they live in the
// repository, and which delegated role signs for them.
type blob struct {
	target string
	data   []byte
	sum    [sha256.Size]byte
	info   *metadata.TargetFiles
	role   string

	// mutable marks the one target kind whose content legitimately changes at
	// a stable path: the channel pointer. Everything else is immutable, and
	// republishing a different payload or descriptor under a path that is
	// already published is refused.
	mutable bool
}

// Publish builds the release described by pack.yaml and writes it into the TUF
// repository at RepoDir. See docs/packer.md §4 for the flow this implements.
//
// Nothing is written until every key is resolved, the repository is loaded and
// verified, and the descriptor and pointer this publish would emit have passed
// the same parsers the client runs on ingest. A publish either lands whole or
// leaves the repository as it was.
func Publish(o Options) (*Result, error) {
	if o.ConfigPath == "" {
		return nil, fmt.Errorf("%w: no config", ErrConfig)
	}
	if o.RepoDir == "" {
		return nil, fmt.Errorf("%w: no repository directory", ErrRepo)
	}
	if o.Now.IsZero() {
		return nil, fmt.Errorf("%w: no reference time; publish output must be reproducible", ErrRepo)
	}
	o.Now = o.Now.UTC().Truncate(time.Second)
	if o.TargetsExpiry <= 0 {
		o.TargetsExpiry = DefaultTargetsExpiry
	}
	if o.SnapshotExpiry <= 0 {
		o.SnapshotExpiry = DefaultSnapshotExpiry
	}
	if o.TimestampExpiry <= 0 {
		o.TimestampExpiry = DefaultTimestampExpiry
	}
	env := o.LookupEnv
	if env == nil {
		env = os.LookupEnv
	}

	cfg, err := LoadConfig(o.ConfigPath)
	if err != nil {
		return nil, err
	}
	major := majorOf(cfg.Version)
	pointerRole, contentRole := channelRole(cfg.Channel), lineRole(major)

	// Keys first, before a single byte is read from the build tree or written
	// to the repository: a missing key must abort a publish, never truncate it
	// (T13, docs/packer.md §5).
	keys, err := resolveKeys(env, []string{pointerRole, contentRole})
	if err != nil {
		return nil, err
	}

	st, err := loadState(o.RepoDir)
	if err != nil {
		return nil, err
	}
	if err := checkRoot(st.root, keys, o.Now); err != nil {
		return nil, err
	}

	blobs, err := buildRelease(cfg, major, pointerRole, contentRole)
	if err != nil {
		return nil, err
	}
	return writeRelease(o, cfg, st, keys, blobs, []string{pointerRole, contentRole})
}

// checkRoot refuses a repository this packer cannot publish into correctly.
//
// Each check is a way a publish could otherwise "succeed" and produce something
// no client will accept: metadata signed by keys root does not name, a role that
// needs more signatures than this tool can produce, targets served without
// consistent snapshots, or a trust anchor that has already expired.
func checkRoot(root *metadata.Metadata[metadata.RootType], keys *keyring, now time.Time) error {
	if !root.Signed.ConsistentSnapshot {
		return fmt.Errorf("%w: root does not enable consistent snapshots; idunn publishes hash-prefixed targets only", ErrRepo)
	}
	if root.Signed.IsExpired(now) {
		return fmt.Errorf("%w: root expired at %s, before the reference time %s",
			ErrRepo, root.Signed.Expires.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	for _, rk := range []*roleKey{keys.targets, keys.snapshot, keys.timestamp} {
		role, ok := root.Signed.Roles[rk.role]
		if !ok {
			return fmt.Errorf("%w: root names no %s role", ErrRepo, rk.role)
		}
		if role.Threshold != 1 {
			return fmt.Errorf("%w: root requires %d signatures for %s; this packer signs with one key per role, so publishing it needs the signing ceremony",
				ErrRepo, role.Threshold, rk.role)
		}
		if !slices.Contains(role.KeyIDs, rk.id) {
			return fmt.Errorf("%w: the configured %s key (id %s) is not one root trusts for that role",
				ErrRepo, rk.role, rk.id)
		}
	}
	return nil
}

// buildRelease turns pack.yaml into the targets this publish emits: the payload
// files, one descriptor per platform, and one channel pointer per platform.
//
// Every emitted document is run through the client's own parser before it is
// published. A descriptor the client would refuse is a defect that would
// otherwise ship and fail on every machine instead of here.
func buildRelease(cfg *Config, major, pointerRole, contentRole string) ([]blob, error) {
	platforms := slices.Clone(cfg.Targets)
	sort.Slice(platforms, func(i, j int) bool {
		if platforms[i].OS != platforms[j].OS {
			return platforms[i].OS < platforms[j].OS
		}
		return platforms[i].Arch < platforms[j].Arch
	})

	var blobs []blob
	seenPayload := map[string]string{} // target path -> dst it was first seen as

	for _, p := range platforms {
		files := slices.Clone(p.Files)
		sort.Slice(files, func(i, j int) bool { return files[i].Dst < files[j].Dst })

		refs := make([]release.FileRef, 0, len(files))
		for i := range files {
			f := &files[i]
			src := cfg.srcPath(f)
			data, err := os.ReadFile(src)
			if err != nil {
				return nil, fmt.Errorf("%w: %s-%s %s: reading src: %w", ErrConfig, p.OS, p.Arch, f.Dst, err)
			}
			sum := sha256.Sum256(data)
			target := payloadTarget(major, sum)

			// Payload targets are content-addressed, so identical bytes are
			// one target. Two destinations in one release cannot share it:
			// the descriptor would name the same target twice, which the
			// client refuses as an install whose result depends on iteration
			// order. Catch it here with the reason, not there with a hash.
			if first, ok := seenPayload[target]; ok && first != f.Dst {
				return nil, fmt.Errorf("%w: %s-%s installs identical content to both %q and %q; payload targets are content-addressed, so give them distinct content",
					ErrConfig, p.OS, p.Arch, first, f.Dst)
			}
			seenPayload[target] = f.Dst

			info, err := metadata.TargetFile().FromBytes(target, data, "sha256")
			if err != nil {
				return nil, fmt.Errorf("%w: target info for %s: %w", ErrConfig, target, err)
			}
			mode, err := f.mode()
			if err != nil {
				return nil, fmt.Errorf("%w: %s-%s %s: %w", ErrConfig, p.OS, p.Arch, f.Dst, err)
			}
			blobs = append(blobs, blob{target: target, data: data, sum: sum, info: info, role: contentRole})
			refs = append(refs, release.FileRef{
				Target: target,
				Dst:    f.Dst,
				Mode:   mode,
				Kind:   release.FileKind(f.Kind),
			})
		}

		descTarget := release.DescriptorPath(p.OS, p.Arch, cfg.Version)
		desc := &release.Descriptor{
			SchemaVersion: release.SchemaVersion,
			Name:          cfg.Name,
			Version:       cfg.Version,
			Channel:       cfg.Channel,
			OS:            p.OS,
			Arch:          p.Arch,
			Files:         refs,
			Requirements: release.Requirements{
				MinFromVersion:   cfg.Requirements.MinFromVersion,
				MinClientVersion: cfg.Requirements.MinClientVersion,
			},
			Rollout:      cfg.Rollout,
			LayoutSchema: release.LayoutSchema,
		}
		descRaw, err := encodeJSON(desc)
		if err != nil {
			return nil, fmt.Errorf("%w: encoding descriptor for %s-%s: %w", ErrConfig, p.OS, p.Arch, err)
		}
		if _, err := release.ParseDescriptor(descRaw); err != nil {
			return nil, fmt.Errorf("%w: the descriptor for %s-%s would be refused by the client: %w",
				ErrConfig, p.OS, p.Arch, err)
		}
		b, err := makeBlob(descTarget, descRaw, contentRole, false)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, b)

		ptrRaw, err := encodeJSON(&release.Pointer{
			SchemaVersion: release.SchemaVersion,
			Channel:       cfg.Channel,
			OS:            p.OS,
			Arch:          p.Arch,
			Version:       cfg.Version,
			// The client derives this path from the version the pointer
			// claims and refuses a pointer that names anything else, so the
			// helper is the only thing allowed to produce it.
			Descriptor: descTarget,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: encoding pointer for %s-%s: %w", ErrConfig, p.OS, p.Arch, err)
		}
		if _, err := release.ParsePointer(ptrRaw); err != nil {
			return nil, fmt.Errorf("%w: the channel pointer for %s-%s would be refused by the client: %w",
				ErrConfig, p.OS, p.Arch, err)
		}
		b, err = makeBlob(release.PointerPath(cfg.Channel, p.OS, p.Arch), ptrRaw, pointerRole, true)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, b)
	}
	return blobs, nil
}

// makeBlob wraps bytes destined for a target path with their TUF target info.
func makeBlob(target string, data []byte, role string, mutable bool) (blob, error) {
	info, err := metadata.TargetFile().FromBytes(target, data, "sha256")
	if err != nil {
		return blob{}, fmt.Errorf("%w: target info for %s: %w", ErrConfig, target, err)
	}
	return blob{
		target:  target,
		data:    data,
		sum:     sha256.Sum256(data),
		info:    info,
		role:    role,
		mutable: mutable,
	}, nil
}

// encodeJSON renders a document exactly as it will be published: indented, with
// a stable field order given by the struct, and no trailing newline that would
// have to be reproduced byte for byte elsewhere.
func encodeJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// writeRelease merges the new targets into the delegated roles, re-signs what
// this publish touches, and writes the repository in the order a client may
// observe it.
//
// Roles this publish does not touch — another channel's pointers, an older
// release line — keep their bytes, their version and their key. A publish is not
// an excuse to re-sign the whole repository: it would churn metadata every
// client has to re-fetch, and it would need keys the operator did not intend to
// use for this release.
func writeRelease(o Options, cfg *Config, st *state, keys *keyring, blobs []blob, touched []string) (*Result, error) {
	res := &Result{
		Name:        cfg.Name,
		Version:     cfg.Version,
		Channel:     cfg.Channel,
		Roles:       map[string]int64{},
		Delegations: map[string]int{},
	}

	// Merge into the delegated roles, refusing any change to a target that is
	// already published and immutable.
	roleTargets := map[string]map[string]*metadata.TargetFiles{}
	for role, del := range st.delegated {
		roleTargets[role] = copyTargets(del.Signed.Targets)
	}
	for _, role := range touched {
		if roleTargets[role] == nil {
			roleTargets[role] = map[string]*metadata.TargetFiles{}
		}
	}
	for i := range blobs {
		b := &blobs[i]
		existing, ok := roleTargets[b.role][b.target]
		if ok && !b.mutable && !existing.Equal(*b.info) {
			return nil, fmt.Errorf("%w: %s is already published with different content; payload and descriptor targets are immutable, so publish a new version instead",
				ErrRepo, b.target)
		}
		if !ok {
			res.AddedTargets = append(res.AddedTargets, b.target)
		}
		roleTargets[b.role][b.target] = b.info
	}
	sort.Strings(res.AddedTargets)

	roleNames := make([]string, 0, len(roleTargets))
	for role := range roleTargets {
		roleNames = append(roleNames, role)
	}
	sort.Slice(roleNames, func(i, j int) bool { return roleLess(roleNames[i], roleNames[j]) })

	// pending is written in order, which is the order a client may observe:
	// delegated roles and targets.json first, snapshot after them, timestamp
	// last. A map would sort by file name and could put snapshot first.
	var pending []metadataFile
	roleRaw := map[string][]byte{}    // role -> the bytes snapshot describes
	roleVersion := map[string]int64{} // role -> the version snapshot names

	for _, role := range roleNames {
		res.Delegations[role] = len(roleTargets[role])
		if !slices.Contains(touched, role) {
			// Untouched: reuse verbatim what the repository already holds.
			roleRaw[role] = st.raw[role]
			roleVersion[role] = st.delegated[role].Signed.Version
			continue
		}
		next := metadata.Targets(o.Now.Add(o.TargetsExpiry))
		next.Signed.Targets = roleTargets[role]
		raw, version, changed, err := finalizeTargets(next, st.delegated[role], st.raw[role], keys.delegated[role])
		if err != nil {
			return nil, err
		}
		roleRaw[role], roleVersion[role] = raw, version
		if changed {
			pending = append(pending, metadataFile{fmt.Sprintf("%d.%s.json", version, role), raw})
			res.Roles[role] = version
		}
	}

	// The top-level targets.json carries no targets at all: it only delegates.
	top := metadata.Targets(o.Now.Add(o.TargetsExpiry))
	if err := buildDelegations(top, roleNames, keys, st.targets); err != nil {
		return nil, err
	}
	topRaw, topVersion, topChanged, err := finalizeTargets(top, st.targets, st.raw[metadata.TARGETS], keys.targets)
	if err != nil {
		return nil, err
	}
	roleRaw[metadata.TARGETS], roleVersion[metadata.TARGETS] = topRaw, topVersion
	if topChanged {
		pending = append(pending, metadataFile{fmt.Sprintf("%d.targets.json", topVersion), topRaw})
		res.Roles[metadata.TARGETS] = topVersion
	}

	// Snapshot names every targets role and the exact bytes of each, which is
	// what stops a client from being served a mix of versions from different
	// publishes.
	snap := metadata.Snapshot(o.Now.Add(o.SnapshotExpiry))
	snap.Signed.Meta = map[string]*metadata.MetaFiles{}
	for _, role := range append([]string{metadata.TARGETS}, roleNames...) {
		snap.Signed.Meta[role+".json"] = metaFileFor(roleVersion[role], roleRaw[role])
	}
	snapRaw, snapVersion, snapChanged, err := finalizeSnapshot(snap, st.snapshot, st.raw[metadata.SNAPSHOT], keys.snapshot)
	if err != nil {
		return nil, err
	}
	if snapChanged {
		pending = append(pending, metadataFile{fmt.Sprintf("%d.snapshot.json", snapVersion), snapRaw})
		res.Roles[metadata.SNAPSHOT] = snapVersion
	}

	ts := metadata.Timestamp(o.Now.Add(o.TimestampExpiry))
	ts.Signed.Meta = map[string]*metadata.MetaFiles{
		"snapshot.json": metaFileFor(snapVersion, snapRaw),
	}
	tsRaw, tsVersion, tsChanged, err := finalizeTimestamp(ts, st.timestamp, st.raw[metadata.TIMESTAMP], keys.timestamp)
	if err != nil {
		return nil, err
	}
	if tsChanged {
		res.Roles[metadata.TIMESTAMP] = tsVersion
	}

	// Upload order is part of the security story: a client reading the
	// repository mid-publish must never find a timestamp pointing at metadata
	// that is not there yet. Targets first, then delegated metadata and
	// targets.json, then snapshot, and timestamp last (docs/packer.md §5).
	for i := range blobs {
		b := &blobs[i]
		path := filepath.Join(st.targetsDir, filepath.FromSlash(hashPrefixedPath(b.target, b.sum)))
		if err := writeFile(path, b.data); err != nil {
			return nil, fmt.Errorf("%w: writing target %s: %w", ErrRepo, b.target, err)
		}
	}
	for _, f := range pending {
		if err := writeFile(filepath.Join(st.metaDir, f.name), f.data); err != nil {
			return nil, fmt.Errorf("%w: writing %s: %w", ErrRepo, f.name, err)
		}
	}
	if tsChanged {
		if err := writeFile(filepath.Join(st.metaDir, "timestamp.json"), tsRaw); err != nil {
			return nil, fmt.Errorf("%w: writing timestamp.json: %w", ErrRepo, err)
		}
	}
	return res, nil
}

// metadataFile is one metadata document waiting to be written.
type metadataFile struct {
	name string
	data []byte
}

// buildDelegations fills in the top-level targets.json: no targets of its own,
// one delegation per role, each with the key that signs it and the disjoint path
// patterns it is trusted for.
//
// A role this publish does not touch keeps the key it already has. Re-delegating
// it to the key at hand would be a silent key rotation for a role the operator
// did not mean to publish.
func buildDelegations(top *metadata.Metadata[metadata.TargetsType], roles []string, keys *keyring, old *metadata.Metadata[metadata.TargetsType]) error {
	top.Signed.Delegations = &metadata.Delegations{Keys: map[string]*metadata.Key{}}
	for _, role := range roles {
		paths := channelPaths(role)
		if major, ok := majorNum(role); ok {
			paths = linePaths(strconv.FormatUint(major, 10))
		}
		top.Signed.Delegations.Roles = append(top.Signed.Delegations.Roles, metadata.DelegatedRole{
			Name:      role,
			Threshold: 1,
			// Terminating: the patterns are disjoint, so the role that owns a
			// path is the only role that may provide it. If it does not have
			// the target, resolution stops rather than letting another
			// delegation answer for it.
			Terminating: true,
			Paths:       paths,
		})
		if key, ok := keys.delegated[role]; ok {
			if err := top.Signed.AddKey(key.public, role); err != nil {
				return fmt.Errorf("%w: delegating %s: %w", ErrRepo, role, err)
			}
			continue
		}
		if err := carryOverKeys(top, old, role); err != nil {
			return err
		}
	}
	return nil
}

// carryOverKeys copies an existing delegation's keys into the rebuilt
// targets.json.
func carryOverKeys(top, old *metadata.Metadata[metadata.TargetsType], role string) error {
	if old == nil || old.Signed.Delegations == nil {
		return fmt.Errorf("%w: no key for delegated role %s and none on record", ErrRepo, role)
	}
	for _, d := range old.Signed.Delegations.Roles {
		if d.Name != role {
			continue
		}
		for _, id := range d.KeyIDs {
			key, ok := old.Signed.Delegations.Keys[id]
			if !ok {
				return fmt.Errorf("%w: delegation %s names key %s, which targets.json does not hold", ErrRepo, role, id)
			}
			if err := top.Signed.AddKey(key, role); err != nil {
				return fmt.Errorf("%w: re-delegating %s: %w", ErrRepo, role, err)
			}
		}
		return nil
	}
	return fmt.Errorf("%w: no key for delegated role %s and none on record", ErrRepo, role)
}

// finalizeTargets decides the version a targets role publishes at, signs it, and
// returns the bytes.
//
// A role whose signed content is byte-identical to what is already published
// keeps its version and its existing bytes: nothing is re-signed and nothing is
// written. That is what makes two runs over the same inputs — same reference
// time included — produce the same repository (AGENTS.md §1.7), and it keeps a
// no-op publish from making every client re-fetch metadata.
func finalizeTargets(next, old *metadata.Metadata[metadata.TargetsType], oldRaw []byte, key *roleKey) ([]byte, int64, bool, error) {
	version := int64(1)
	if old != nil {
		next.Signed.Version = old.Signed.Version
		same, err := sameSigned(next.Signed, old.Signed)
		if err != nil {
			return nil, 0, false, err
		}
		if same {
			return oldRaw, old.Signed.Version, false, nil
		}
		version = old.Signed.Version + 1
	}
	next.Signed.Version = version
	raw, err := signAndEncode(next, key)
	return raw, version, true, err
}

// finalizeSnapshot is finalizeTargets for the snapshot role.
func finalizeSnapshot(next, old *metadata.Metadata[metadata.SnapshotType], oldRaw []byte, key *roleKey) ([]byte, int64, bool, error) {
	version := int64(1)
	if old != nil {
		next.Signed.Version = old.Signed.Version
		same, err := sameSigned(next.Signed, old.Signed)
		if err != nil {
			return nil, 0, false, err
		}
		if same {
			return oldRaw, old.Signed.Version, false, nil
		}
		version = old.Signed.Version + 1
	}
	next.Signed.Version = version
	raw, err := signAndEncode(next, key)
	return raw, version, true, err
}

// finalizeTimestamp is finalizeTargets for the timestamp role.
func finalizeTimestamp(next, old *metadata.Metadata[metadata.TimestampType], oldRaw []byte, key *roleKey) ([]byte, int64, bool, error) {
	version := int64(1)
	if old != nil {
		next.Signed.Version = old.Signed.Version
		same, err := sameSigned(next.Signed, old.Signed)
		if err != nil {
			return nil, 0, false, err
		}
		if same {
			return oldRaw, old.Signed.Version, false, nil
		}
		version = old.Signed.Version + 1
	}
	next.Signed.Version = version
	raw, err := signAndEncode(next, key)
	return raw, version, true, err
}

// signAndEncode signs metadata with exactly one key and renders it.
//
// Signatures are cleared first: a signature made over different content is not
// evidence of anything, and carrying one along would only pad the count a
// threshold is measured against.
func signAndEncode[T metadata.Roles](meta *metadata.Metadata[T], key *roleKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: no signing key for this role", ErrKey)
	}
	meta.ClearSignatures()
	if _, err := meta.Sign(key.signer); err != nil {
		return nil, fmt.Errorf("%w: signing %s: %w", ErrRepo, key.role, err)
	}
	raw, err := meta.ToBytes(true)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding %s: %w", ErrRepo, key.role, err)
	}
	return raw, nil
}

// copyTargets copies a target map so the loaded state is never mutated in place.
func copyTargets(in map[string]*metadata.TargetFiles) map[string]*metadata.TargetFiles {
	out := make(map[string]*metadata.TargetFiles, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// metaFileFor describes one metadata file for snapshot or timestamp: version,
// length and hash of the exact bytes published. Both are optional in TUF and
// both are emitted: they turn "the right version" into "the right bytes".
func metaFileFor(version int64, raw []byte) *metadata.MetaFiles {
	sum := sha256.Sum256(raw)
	mf := metadata.MetaFile(version)
	mf.Length = int64(len(raw))
	mf.Hashes = metadata.Hashes{"sha256": sum[:]}
	return mf
}

// sortedKeys returns a map's keys in a deterministic order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sameSigned reports whether two signed payloads are identical.
func sameSigned(a, b any) (bool, error) {
	ra, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	rb, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ra, rb), nil
}
