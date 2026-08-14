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

// Package stage materializes a verified release into a new version directory and
// performs the atomic swap of `current`.
//
// The install layout is a stable launcher plus `current`, a symlink/junction to a
// versioned directory. An update writes a fresh versions/<v>/ and then does a
// single atomic rename of `current`; a rollback just repoints it. See
// docs/design.md §6.1, §6.4.
package stage

import (
	"context"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// Stager writes verified files into a staging directory and swaps them in.
type Stager struct {
	FS    fsx.FS
	Trust *trust.Client
	Root  string
}

// SanitizeDst validates an install-relative destination from a descriptor: it must
// be clean, relative, free of ".." elements, not absolute, and not a drive- or
// UNC-rooted Windows path. It is the fuzz target FuzzDstSanitize (§12) and must
// never panic.
//
// It judges the path text only. Whether an existing symlink under the install root
// would redirect that path outside is a filesystem question, answered during Stage
// with the root open, not here.
func SanitizeDst(dst string) (string, error) {
	return safepath.Clean(dst)
}

// Stage materializes every file of d into a new version directory under
// versions/<version>/ and returns that directory. Each byte is checked against its
// TUF-signed target hash before it is written, whether it was downloaded, reused
// from cache, or reconstructed from a delta patch.
func (s *Stager) Stage(ctx context.Context, d *release.Descriptor) (string, error) {
	panic("not implemented")
}

// Swap atomically repoints `current` at versionDir. This is the single commit
// point of the transaction.
func (s *Stager) Swap(versionDir string) error {
	panic("not implemented")
}

// GC removes version directories beyond retain, keeping `current` and at least one
// rollback target. retain must be >= 2. See docs/design.md §14.1.
func (s *Stager) GC(retain int) error {
	panic("not implemented")
}

// ApplyPatch reconstructs a target from a base file and a delta patch. The result
// is accepted only if it matches the signed target hash; a patch that produces the
// wrong bytes is a failure, never a fallback. It is the fuzz target FuzzPatchApply.
func ApplyPatch(base, patch []byte) ([]byte, error) {
	panic("not implemented")
}
