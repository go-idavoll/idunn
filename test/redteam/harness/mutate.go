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
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-idavoll/idunn/core/release"
)

// Mutator is one attack. Each hook runs at a fixed phase of BuildRepo, so a case
// changes exactly one thing relative to the known-good baseline — if the client
// rejects it, we know which property did the rejecting.
type Mutator struct {
	Name string
	Desc string

	// Content tampers with the bytes that are about to become TUF targets.
	Content func(*Build) error
	// Metadata tampers with the role objects before they are signed.
	Metadata func(*Build) error
	// Signing redirects which key signs which role.
	Signing func(*Build) error
	// OnDisk tampers with the written repository, after signing. This is the only
	// phase that can make published bytes disagree with signed metadata.
	OnDisk func(b *Build, dir string) error

	// SeedMutatedRoot hands the client the mutated root as its trust anchor
	// instead of the baseline one.
	//
	// It is required for attacks ON the anchor itself. A client never re-reads a
	// served root of the same version — that is exactly the protection TUF gives
	// — so tampering with the published root and then seeding the good one tests
	// nothing. Setting this models the honest question: does the client still
	// refuse to operate when the root it shipped with is expired, unsigned, or
	// demands a threshold the repository does not meet?
	SeedMutatedRoot bool
}

// Mutators is the registry a corpus case refers to by name.
var Mutators = map[string]*Mutator{}

func register(m *Mutator) {
	if _, dup := Mutators[m.Name]; dup {
		panic("harness: duplicate mutator " + m.Name)
	}
	Mutators[m.Name] = m
}

func init() {
	// --- TUF-level attacks: caught by go-tuf, never by hand-written checks ---

	register(&Mutator{
		Name: "wrong_hash",
		Desc: "payload bytes no longer match the signed target hash",
		OnDisk: func(b *Build, dir string) error {
			return overwriteTarget(b, dir, b.payloadPath("app"), []byte("malicious payload\n"))
		},
	})

	register(&Mutator{
		Name: "wrong_length",
		Desc: "payload is longer than the signed target length",
		OnDisk: func(b *Build, dir string) error {
			target := b.payloadPath("app")
			return overwriteTarget(b, dir, target, append(append([]byte{}, b.Payloads[target]...), "trailer\n"...))
		},
	})

	register(&Mutator{
		Name: "expired_timestamp",
		Desc: "timestamp metadata is already expired at the client's reference time",
		Metadata: func(b *Build) error {
			b.Timestamp.Signed.Expires = b.Opts.Now.AddDate(0, 0, -1)
			return nil
		},
	})

	register(&Mutator{
		Name: "expired_root",
		Desc: "root metadata is already expired at the client's reference time",
		Metadata: func(b *Build) error {
			b.Root.Signed.Expires = b.Opts.Now.AddDate(0, 0, -1)
			return nil
		},
		SeedMutatedRoot: true,
	})

	register(&Mutator{
		Name: "wrong_key_targets",
		Desc: "targets is signed by a key root does not authorize for that role",
		Signing: func(b *Build) error {
			b.SignWith["targets"] = AttackerRole
			return nil
		},
	})

	register(&Mutator{
		Name: "wrong_key_root",
		Desc: "root is signed by an unknown key, so the trust anchor does not verify",
		Signing: func(b *Build) error {
			b.SignWith["root"] = AttackerRole
			return nil
		},
		SeedMutatedRoot: true,
	})

	register(&Mutator{
		Name: "wrong_key_timestamp",
		Desc: "timestamp is signed by a key that is not the timestamp key",
		Signing: func(b *Build) error {
			b.SignWith["timestamp"] = AttackerRole
			return nil
		},
	})

	register(&Mutator{
		Name: "threshold_not_met",
		Desc: "root demands two targets signatures but only one is provided",
		Metadata: func(b *Build) error {
			b.Root.Signed.Roles["targets"].Threshold = 2
			return nil
		},
		SeedMutatedRoot: true,
	})

	register(&Mutator{
		Name: "mix_and_match",
		Desc: "snapshot names a targets version other than the one published",
		Metadata: func(b *Build) error {
			// The published file becomes 2.targets.json while snapshot still
			// vouches for version 1: the two views of the repository disagree.
			b.Targets.Signed.Version = 2
			return nil
		},
	})

	// --- prior-state attacks: what the client already trusts is the weapon ---

	register(&Mutator{
		Name: "advanced_metadata_versions",
		Desc: "an honest repository, published far enough along that rolling it back is visible",
		Metadata: func(b *Build) error {
			// Not an attack by itself. It is the *first* half of one: a
			// repository a client can legitimately come to trust at version 5,
			// so that serving it version 1 afterwards is a rollback rather than
			// a first contact. Every reference is moved with it, because a
			// repository that disagreed with itself would be caught as
			// mix-and-match and prove nothing about rollback.
			const v = 5
			b.Targets.Signed.Version = v
			b.Snapshot.Signed.Version = v
			b.Snapshot.Signed.Meta["targets.json"].Version = v
			b.Timestamp.Signed.Version = v
			b.Timestamp.Signed.Meta["snapshot.json"].Version = v
			return nil
		},
	})

	// --- app-level attacks: caught by idunn's descriptor/pointer ingest ---

	register(&Mutator{
		Name: "malformed_descriptor",
		Desc: "descriptor target is correctly signed but is not valid JSON",
		Content: func(b *Build) error {
			b.DescriptorRaw = []byte(`{"schema_version": 1, "name":`)
			return nil
		},
	})

	register(&Mutator{
		Name: "unknown_schema",
		Desc: "descriptor declares a schema version this client does not implement",
		Content: func(b *Build) error {
			b.Descriptor.SchemaVersion = release.SchemaVersion + 99
			return b.reencode()
		},
	})

	register(&Mutator{
		Name: "path_traversal_dst",
		Desc: "descriptor installs a file outside the install root via ../",
		Content: func(b *Build) error {
			b.Descriptor.Files[0].Dst = "../../evil.exe"
			return b.reencode()
		},
	})

	register(&Mutator{
		Name: "absolute_dst",
		Desc: "descriptor installs a file at an absolute path",
		Content: func(b *Build) error {
			b.Descriptor.Files[0].Dst = "/etc/cron.d/evil"
			return b.reencode()
		},
	})

	register(&Mutator{
		Name: "duplicate_dst",
		Desc: "two targets claim the same destination, so the result depends on order",
		Content: func(b *Build) error {
			b.Descriptor.Files[1].Dst = b.Descriptor.Files[0].Dst
			return b.reencode()
		},
	})

	register(&Mutator{
		Name: "setuid_mode",
		Desc: "descriptor requests a setuid bit on an installed file",
		Content: func(b *Build) error {
			b.Descriptor.Files[0].Mode = 0o4755
			return b.reencode()
		},
	})

	register(&Mutator{
		Name: "pointer_descriptor_mismatch",
		Desc: "channel pointer and descriptor disagree about the version",
		Content: func(b *Build) error {
			b.Pointer.Version = "9.9.9"
			return b.reencode()
		},
	})

	register(&Mutator{
		Name: "pointer_wrong_platform",
		Desc: "channel pointer served for one platform declares another",
		Content: func(b *Build) error {
			b.Pointer.Arch = "arm64"
			return b.reencode()
		},
	})

	register(&Mutator{
		Name: "pointer_foreign_descriptor",
		Desc: "pointer names a descriptor path that is not the one for its version",
		Content: func(b *Build) error {
			b.Pointer.Descriptor = release.DescriptorPath(b.Opts.OS, b.Opts.Arch, "0.0.1")
			return b.reencode()
		},
	})
}

// overwriteTarget replaces the published bytes of a target while leaving the
// signed metadata untouched. The file keeps the filename derived from the ORIGINAL
// hash, so the client still finds it at the URL it computes from signed metadata —
// and must reject the content it gets.
func overwriteTarget(b *Build, dir, targetPath string, data []byte) error {
	rel, err := HashPrefixedPath(targetPath, b.Payloads[targetPath])
	if err != nil {
		return err
	}
	full := filepath.Join(dir, TargetsDir, filepath.FromSlash(rel))
	if _, err := os.Stat(full); err != nil {
		return fmt.Errorf("harness: target %q not found at %s: %w", targetPath, full, err)
	}
	return os.WriteFile(full, data, 0o644)
}
