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

package harness

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
)

// BuildOptions describes the repository to build. The zero value is not useful;
// use DefaultBuildOptions and adjust.
type BuildOptions struct {
	Keys *KeySet

	// Now is the reference time all expiries are derived from. It is explicit so
	// a build is reproducible and expiry cases are deterministic (AGENTS.md §4).
	Now time.Time

	Name    string
	Channel string
	OS      string
	Arch    string
	Version string

	// Mutator is the attack applied to this build; nil builds the known-good
	// baseline.
	Mutator *Mutator
}

// DefaultBuildOptions returns the baseline every corpus case derives from.
func DefaultBuildOptions(keys *KeySet) BuildOptions {
	return BuildOptions{
		Keys:    keys,
		Now:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Name:    "demo",
		Channel: "stable",
		OS:      "linux",
		Arch:    "amd64",
		Version: "1.2.0",
	}
}

// Build is the mutable state of one repository build. Mutators reach into it
// between the defined phases; see Mutator.
type Build struct {
	Opts BuildOptions

	// Payloads maps a TUF target path to its content. Descriptor and pointer are
	// added to this map after the Content phase.
	Payloads map[string][]byte

	Descriptor *release.Descriptor
	Pointer    *release.Pointer

	// DescriptorRaw and PointerRaw are the exact bytes published as targets. A
	// mutator may replace them with anything, including invalid JSON.
	DescriptorRaw []byte
	PointerRaw    []byte

	Root      *metadata.Metadata[metadata.RootType]
	Targets   *metadata.Metadata[metadata.TargetsType]
	Snapshot  *metadata.Metadata[metadata.SnapshotType]
	Timestamp *metadata.Metadata[metadata.TimestampType]

	// SignWith maps a role to the key role that signs it. The baseline maps each
	// role to itself; a mutator points a role at AttackerRole to model a
	// wrong-key attack.
	SignWith map[string]string

	// RootBytes is the trust anchor a client is seeded with. It is captured
	// before any on-disk tampering so a mutated repository is still judged
	// against the root the client legitimately shipped with.
	RootBytes []byte
}

// DescriptorTarget is the target path of this build's release descriptor.
func (b *Build) DescriptorTarget() string {
	return release.DescriptorPath(b.Opts.OS, b.Opts.Arch, b.Opts.Version)
}

// PointerTarget is the target path of this build's channel pointer.
func (b *Build) PointerTarget() string {
	return release.PointerPath(b.Opts.Channel, b.Opts.OS, b.Opts.Arch)
}

// BuildRepo writes a complete TUF repository to dir and returns the build state.
//
// The phases are fixed so a mutator can attack exactly one of them: Content (the
// bytes that become targets), Metadata (the role objects before signing), Signing
// (which key signs what) and OnDisk (the written repository).
func BuildRepo(dir string, opts BuildOptions) (*Build, error) {
	if opts.Keys == nil {
		return nil, fmt.Errorf("harness: no keys")
	}
	b := &Build{
		Opts:     opts,
		Payloads: map[string][]byte{},
		SignWith: map[string]string{},
	}
	for _, role := range Roles {
		b.SignWith[role] = role
	}

	if err := b.buildContent(); err != nil {
		return nil, err
	}
	if m := opts.Mutator; m != nil && m.Content != nil {
		if err := m.Content(b); err != nil {
			return nil, err
		}
	}
	b.Payloads[b.DescriptorTarget()] = b.DescriptorRaw
	b.Payloads[b.PointerTarget()] = b.PointerRaw

	if err := b.buildMetadata(); err != nil {
		return nil, err
	}
	if m := opts.Mutator; m != nil && m.Metadata != nil {
		if err := m.Metadata(b); err != nil {
			return nil, err
		}
	}
	if m := opts.Mutator; m != nil && m.Signing != nil {
		if err := m.Signing(b); err != nil {
			return nil, err
		}
	}
	if err := b.sign(); err != nil {
		return nil, err
	}
	if err := b.write(dir); err != nil {
		return nil, err
	}
	if m := opts.Mutator; m != nil && m.OnDisk != nil {
		if err := m.OnDisk(b, dir); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// payloadPath is where a release's payload files live as TUF targets.
func (b *Build) payloadPath(name string) string {
	return path.Join("payloads", b.Opts.Version, name)
}

func (b *Build) buildContent() error {
	appTarget := b.payloadPath("app")
	libTarget := b.payloadPath("lib.so")
	b.Payloads[appTarget] = []byte("idunn test payload: app " + b.Opts.Version + "\n")
	b.Payloads[libTarget] = []byte("idunn test payload: lib " + b.Opts.Version + "\n")

	b.Descriptor = &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          b.Opts.Name,
		Version:       b.Opts.Version,
		Channel:       b.Opts.Channel,
		OS:            b.Opts.OS,
		Arch:          b.Opts.Arch,
		Files: []release.FileRef{
			{Target: appTarget, Dst: "bin/app", Mode: 0o755, Kind: release.KindExe},
			{Target: libTarget, Dst: "lib/lib.so", Mode: 0o644, Kind: release.KindLib},
		},
	}
	b.Pointer = &release.Pointer{
		SchemaVersion: release.SchemaVersion,
		Channel:       b.Opts.Channel,
		OS:            b.Opts.OS,
		Arch:          b.Opts.Arch,
		Version:       b.Opts.Version,
		Descriptor:    b.DescriptorTarget(),
	}
	return b.reencode()
}

// reencode refreshes the published bytes from the structs. Mutators that change a
// struct call this; mutators that publish deliberately broken bytes do not.
func (b *Build) reencode() error {
	var err error
	if b.DescriptorRaw, err = json.MarshalIndent(b.Descriptor, "", "  "); err != nil {
		return fmt.Errorf("harness: encoding descriptor: %w", err)
	}
	if b.PointerRaw, err = json.MarshalIndent(b.Pointer, "", "  "); err != nil {
		return fmt.Errorf("harness: encoding pointer: %w", err)
	}
	return nil
}

func (b *Build) buildMetadata() error {
	now := b.Opts.Now
	b.Targets = metadata.Targets(now.AddDate(0, 0, 7))
	for targetPath, data := range b.Payloads {
		tf, err := metadata.TargetFile().FromBytes(targetPath, data, "sha256")
		if err != nil {
			return fmt.Errorf("harness: target info for %q: %w", targetPath, err)
		}
		b.Targets.Signed.Targets[targetPath] = tf
	}

	b.Snapshot = metadata.Snapshot(now.AddDate(0, 0, 7))
	b.Timestamp = metadata.Timestamp(now.AddDate(0, 0, 1))

	b.Root = metadata.Root(now.AddDate(1, 0, 0))
	b.Root.Signed.ConsistentSnapshot = true
	for _, role := range Roles {
		key, err := metadata.KeyFromPublicKey(b.Opts.Keys.Private[role].Public())
		if err != nil {
			return fmt.Errorf("harness: key for %s: %w", role, err)
		}
		if err := b.Root.Signed.AddKey(key, role); err != nil {
			return fmt.Errorf("harness: adding %s key to root: %w", role, err)
		}
	}
	return nil
}

func (b *Build) signer(role string) (signature.Signer, error) {
	keyRole := b.SignWith[role]
	if keyRole == "" {
		keyRole = role
	}
	priv, ok := b.Opts.Keys.Private[keyRole]
	if !ok {
		return nil, fmt.Errorf("harness: no key %q", keyRole)
	}
	return signature.LoadSigner(priv, crypto.Hash(0))
}

func (b *Build) sign() error {
	for _, role := range Roles {
		s, err := b.signer(role)
		if err != nil {
			return err
		}
		switch role {
		case "root":
			_, err = b.Root.Sign(s)
		case "targets":
			_, err = b.Targets.Sign(s)
		case "snapshot":
			_, err = b.Snapshot.Sign(s)
		case "timestamp":
			_, err = b.Timestamp.Sign(s)
		}
		if err != nil {
			return fmt.Errorf("harness: signing %s: %w", role, err)
		}
	}
	return nil
}

// The two subtrees a repository is served from.
const (
	MetadataDir = "metadata"
	TargetsDir  = "targets"
)

func (b *Build) write(dir string) error {
	metaDir := filepath.Join(dir, MetadataDir)
	targetsDir := filepath.Join(dir, TargetsDir)
	for _, d := range []string{metaDir, targetsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("harness: %w", err)
		}
	}

	// Root is always version-prefixed; with consistent snapshots so are targets
	// and snapshot. Timestamp never is — that is what makes it the freshness
	// anchor a freeze attack has to defeat.
	files := map[string][]byte{}
	var err error
	if files[fmt.Sprintf("%d.root.json", b.Root.Signed.Version)], err = b.Root.ToBytes(true); err != nil {
		return fmt.Errorf("harness: encoding root: %w", err)
	}
	if files[fmt.Sprintf("%d.targets.json", b.Targets.Signed.Version)], err = b.Targets.ToBytes(true); err != nil {
		return fmt.Errorf("harness: encoding targets: %w", err)
	}
	if files[fmt.Sprintf("%d.snapshot.json", b.Snapshot.Signed.Version)], err = b.Snapshot.ToBytes(true); err != nil {
		return fmt.Errorf("harness: encoding snapshot: %w", err)
	}
	if files["timestamp.json"], err = b.Timestamp.ToBytes(true); err != nil {
		return fmt.Errorf("harness: encoding timestamp: %w", err)
	}
	b.RootBytes = files[fmt.Sprintf("%d.root.json", b.Root.Signed.Version)]

	for name, data := range files {
		if err := os.WriteFile(filepath.Join(metaDir, name), data, 0o644); err != nil {
			return fmt.Errorf("harness: writing %s: %w", name, err)
		}
	}

	for targetPath, data := range b.Payloads {
		rel, err := HashPrefixedPath(targetPath, data)
		if err != nil {
			return err
		}
		full := filepath.Join(targetsDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("harness: %w", err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			return fmt.Errorf("harness: writing target %s: %w", targetPath, err)
		}
	}
	return nil
}

// HashPrefixedPath returns the consistent-snapshot filename for a target:
// <dir>/<sha256>.<basename>. The hash is taken from the bytes actually published,
// which is what lets a mutator publish content that no longer matches the signed
// hash while still being reachable at the URL the client requests.
func HashPrefixedPath(targetPath string, data []byte) (string, error) {
	sum := sha256.Sum256(data)
	base := path.Base(targetPath)
	dir := path.Dir(targetPath)
	name := hex.EncodeToString(sum[:]) + "." + base
	if dir == "." {
		return name, nil
	}
	return path.Join(dir, name), nil
}
