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
	"github.com/go-idavoll/idunn/internal/delta"
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

	// Previous is the older release the repository must also publish for this
	// attack to be possible at all: a patch turns one exact set of bytes into
	// another, so there is nothing to attack until a client is installed on the
	// bytes it starts from (BuildOptions.Previous).
	Previous string

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
			return overwriteTarget(b, dir, b.PayloadTarget("bin/app"), []byte("malicious payload\n"))
		},
	})

	register(&Mutator{
		Name: "wrong_length",
		Desc: "payload is longer than the signed target length",
		OnDisk: func(b *Build, dir string) error {
			target := b.PayloadTarget("bin/app")
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

	// --- delta attacks: a patch is untrusted input with a signed result ------
	//
	// None of these can end in a rejection, and that is the point. A patch is
	// never trusted: the client is free to fetch one, apply it, and throw the
	// result away when it does not match the signed hash of the file it was
	// supposed to rebuild. So what these cases assert is stronger than a
	// refusal — that whatever the repository serves as a patch, the bytes that
	// end up installed are the signed ones, and nothing the attacker chose is
	// anywhere on the machine (T21).

	register(&Mutator{
		Name:     "patch_poison",
		Desc:     "a properly signed patch that reconstructs bytes of the attacker's choosing",
		Previous: previousVersion,
		Content: func(b *Build) error {
			return repatch(b, "bin/app", func(base []byte) []byte {
				return withMarker(base)
			})
		},
	})

	register(&Mutator{
		Name:     "patch_foreign_base",
		Desc:     "a valid patch, published under the path of a different pair of payloads",
		Previous: previousVersion,
		Content: func(b *Build) error {
			// The path a patch lives at states which payload it turns into
			// which. This one is a real patch — just not that one. Applying it
			// to the base the path names produces something else entirely,
			// which the signed hash of the result is what catches.
			return repatch(b, "bin/app", func(base []byte) []byte {
				return rebuilt(base, "a different build entirely")
			})
		},
	})

	register(&Mutator{
		Name:     "patch_tampered_after_signing",
		Desc:     "the published patch bytes disagree with the signed target",
		Previous: previousVersion,
		OnDisk: func(b *Build, dir string) error {
			return overwriteTarget(b, dir, b.Patches["bin/app"], []byte("not a patch at all\n"))
		},
	})
}

// previousVersion is the release a delta case starts installed on. It is older
// than DefaultBuildOptions.Version, which is what makes the update an update.
const previousVersion = "1.1.0"

// AdvancedMetadataVersions is not an attack, and is deliberately not in
// Mutators, so no case.yaml can name it as one. It is the honest half of a
// history case: a repository whose publisher has been at work for a while, with
// every role at version 5.
//
// A rollback needs it as the state the client comes to trust, so that serving
// version 1 afterwards goes backwards rather than being a first contact. A
// downgrade needs it as the state the attacker serves, so that the metadata
// moves forward while the release goes back. Every cross-reference moves with
// the versions, because a repository that disagreed with itself would be caught
// as mix-and-match and prove nothing about either.
var AdvancedMetadataVersions = &Mutator{
	Name: "advanced_metadata_versions",
	Desc: "an honest repository whose targets, snapshot and timestamp are all at version 5",
	Metadata: func(b *Build) error {
		const v = 5
		b.Targets.Signed.Version = v
		b.Snapshot.Signed.Version = v
		b.Snapshot.Signed.Meta["targets.json"].Version = v
		b.Timestamp.Signed.Version = v
		b.Timestamp.Signed.Meta["snapshot.json"].Version = v
		return nil
	},
}

// AttackerMarker is what a poisoned patch tries to smuggle onto the machine. A
// delta case passes only if it is nowhere on disk afterwards.
var AttackerMarker = []byte("idunn redteam: attacker payload")

// withMarker is the base file with the attacker's bytes written into it — a
// small change, so that the patch producing it stays small enough for a client
// to prefer over the full download. An attack the client would skip on cost
// alone proves nothing.
func withMarker(base []byte) []byte {
	out := append([]byte(nil), base...)
	copy(out[len(out)/4:], AttackerMarker)
	return out
}

// repatch republishes the patch for one destination so that it reconstructs
// something else, and records what that something is.
func repatch(b *Build, dst string, want func(base []byte) []byte) error {
	target, ok := b.Patches[dst]
	if !ok {
		return fmt.Errorf("harness: no patch published for %s", dst)
	}
	base, ok := b.Payloads[b.PreviousPayloadTarget(dst)]
	if !ok {
		return fmt.Errorf("harness: no previous payload for %s", dst)
	}

	produces := want(base)
	if b.AttackerPayload == nil {
		b.AttackerPayload = produces
	}
	patch, err := delta.Diff(base, produces)
	if err != nil {
		return fmt.Errorf("harness: building the poisoned patch: %w", err)
	}
	b.Payloads[target] = patch
	return nil
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
