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

// Package packer publishes a TUF repository from a pack.yaml.
//
// It is the publisher-side half of idunn and the mirror image of the client: the
// client is the side an attacker controls the network of, the packer is the side
// that holds the keys. Its failure mode is not "installs the wrong bytes" but
// "publishes a repository that is inconsistent, unsigned, or unreproducible" —
// threat T13. Three rules follow from that and are enforced here rather than
// documented and hoped for:
//
//   - Every role key is resolved before the first byte is written, so a missing
//     key can never leave a half-signed repository behind.
//   - The reference time is an input, never the wall clock: two runs over the same
//     inputs produce byte-identical output, which is what makes an independent
//     rebuild a supply-chain proof (AGENTS.md §1.7).
//   - root is never read for signing, never written, and never created. Key
//     rotation is a separate, offline, m-of-n ceremony; a command run on every
//     release must not be able to touch the highest asset in the model.
//
// Trust decisions are go-tuf's throughout: this package builds and signs metadata
// with go-tuf's own API and verifies the repository it publishes into with
// go-tuf's own verification, so there is no second signature implementation
// anywhere in the project (AGENTS.md §1.2).
//
// See docs/packer.md for the contract and docs/design.md §9.
package packer

import "errors"

// ErrConfig is the class of every rejection of pack.yaml itself: unknown keys,
// unusable versions, and destinations that would be refused at install time.
var ErrConfig = errors.New("packer: config")

// ErrKey is the class of every failure to resolve a signing key. It never
// carries key material — only the role, the environment variable, and the reason.
var ErrKey = errors.New("packer: key")

// ErrRepo is the class of every rejection of the repository being published
// into: a missing or expired root, a role this packer may not sign alone, an
// inconsistent on-disk state, or an attempt to change an already published
// immutable target.
var ErrRepo = errors.New("packer: repository")
