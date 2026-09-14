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
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// ErrStage is the class of every rejection here: a destination that will not
// stay inside the install root, a version directory that is in the way, a
// retention window that would leave nothing to roll back to.
var ErrStage = errors.New("stage")

// ErrIncompleteGC reports that some old version directories could not be
// removed. It is deliberately its own class: a locked directory is a Windows
// fact of life, not a failed update, and the caller must be able to tell those
// apart instead of rolling back a perfectly good install over it (§14.1).
var ErrIncompleteGC = errors.New("garbage collection incomplete")

// MinRetain is the smallest retention window that still leaves an instant
// rollback target beside the running version.
const MinRetain = 2

// Materializer is the narrow slice of the trust client that staging needs: bytes
// that go-tuf has already checked against the signed target hash and length.
//
// It is an interface so the staging path can be driven deterministically in
// tests (docs/design.md §12) — and so the split stays visible in the type
// system: trust decides what may be trusted, this package decides only where the
// bytes go.
type Materializer interface {
	// Target returns the verified bytes of one target, fetching it if the
	// go-tuf cache does not already hold it.
	Target(targetPath string) ([]byte, error)

	// TargetLength returns the signed length of a target without fetching it,
	// so a local reuse candidate of the wrong size can be dismissed before it
	// is read. Every read and allocation staging makes beside Target is sized by
	// it, so a trust client that will not hold a target (the ceiling of IDN-12)
	// refuses here as well, and staging treats that like any other refusal.
	TargetLength(targetPath string) (int64, error)

	// VerifyTarget reports whether data are exactly the signed bytes of a
	// target. Bytes that did not come from Target — reused from an installed
	// version, later reconstructed from a patch — are admitted only by this,
	// so staging never holds a signed hash and never compares one itself.
	VerifyTarget(targetPath string, data []byte) error
}

// Stager writes verified files into a staging directory and swaps them in.
type Stager struct {
	FS    fsx.FS
	Trust Materializer
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
//
// route is the byte-level history of the releases being walked, and may be nil:
// without it every file is reused from disk or fetched whole.
//
// The files are assembled under .updater/staging/<version>/ and moved into place
// with a single rename at the end. Nothing incomplete is ever visible under
// versions/, so a crash mid-staging leaves a tree the recovery can simply delete
// rather than one it has to inspect file by file.
func (s *Stager) Stage(ctx context.Context, d *release.Descriptor, route Route) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	if s.Trust == nil {
		return "", fmt.Errorf("%w: no trust client", ErrStage)
	}
	if d == nil {
		return "", fmt.Errorf("%w: no descriptor", ErrStage)
	}
	versionDir, err := layout.VersionDir(s.Root, d.Version)
	if err != nil {
		return "", err
	}

	// Staging over the running version would write into the tree the current
	// process is executing from — the one case the blue/green layout exists to
	// avoid.
	live, err := layout.PointerTarget(s.FS, s.Root)
	if err != nil {
		return "", err
	}
	if live == d.Version {
		return "", fmt.Errorf("%w: %s is the version currently in use", ErrStage, d.Version)
	}

	stageDir := fsx.Join(layout.Staging(s.Root), d.Version)
	// A leftover staging tree from an abandoned attempt is not a base to build
	// on: it may hold files this descriptor no longer lists.
	if err := s.FS.RemoveAll(stageDir); err != nil {
		return "", fmt.Errorf("%w: clear staging: %w", ErrStage, err)
	}
	// Becomes versions/<v> by rename, so it is created with the mode the version
	// directory must have: executable by the users who run the application.
	if err := s.FS.MkdirAll(stageDir, layout.DirMode); err != nil {
		return "", fmt.Errorf("%w: create staging: %w", ErrStage, err)
	}

	// Which installed versions may donate unchanged files. Computed once: the
	// listing is the same for every file, and a release is thousands of them.
	sources := s.reuseSources(live, d.Version)

	for i := range d.Files {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("%w: %w", ErrStage, err)
		}
		if err := s.stageFile(stageDir, &d.Files[i], sources, route); err != nil {
			// Leave the staging tree where it is; the transaction's rollback
			// and the next recovery both remove it, and removing it here would
			// destroy the evidence of what went wrong.
			return "", err
		}
	}

	// The version directory must not exist yet. If it does, an earlier
	// transaction left it behind and the recovery that owns it has not run —
	// silently replacing it would delete a directory something may still point
	// at.
	if _, err := fsx.Lstat(s.FS, versionDir); err == nil {
		return "", fmt.Errorf("%w: %s already exists", ErrStage, versionDir)
	} else if !fsx.IsNotExist(err) {
		return "", fmt.Errorf("%w: %w", ErrStage, err)
	}
	if err := s.FS.MkdirAll(layout.Versions(s.Root), 0o755); err != nil {
		return "", fmt.Errorf("%w: %w", ErrStage, err)
	}
	if err := s.FS.Rename(stageDir, versionDir); err != nil {
		return "", fmt.Errorf("%w: promote staging: %w", ErrStage, err)
	}
	if err := fsx.SyncDir(s.FS, layout.Versions(s.Root)); err != nil {
		// The rename already happened, so a version directory now exists that
		// this call is about to report as a failure. Take it back: Stage either
		// produces a complete version directory or none, and a caller must not
		// have to know that one particular late failure is the exception.
		// Nothing points at it yet — the swap has not run — so removing it is
		// safe, and if the removal fails too, the recovery will find it.
		_ = s.FS.RemoveAll(versionDir)
		return "", fmt.Errorf("%w: %w", ErrStage, err)
	}
	return versionDir, nil
}

// stageFile writes one payload file into the staging tree, taking its bytes from
// an installed version when one holds exactly the signed content and from the
// trust layer otherwise.
func (s *Stager) stageFile(stageDir string, f *release.FileRef, sources []string, route Route) error {
	dst, err := SanitizeDst(f.Dst)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrStage, f.Target, err)
	}

	// Create the destination's parents one component at a time, checking each
	// one. SanitizeDst judges the path text; this is the filesystem half of the
	// same question — a symlink among the components would redirect the write
	// out of the tree no matter how clean the text was (T7).
	dir, err := s.makeDirs(stageDir, fsx.Dir(dst))
	if err != nil {
		return err
	}
	full := fsx.Join(dir, fsx.Base(dst))
	if err := s.refuseSymlink(full); err != nil {
		return err
	}

	// An unchanged file is taken from a version already on disk (delta stage 1,
	// docs/design.md §6.4) — verified against the signed target, so what is
	// reused is the content, never the trust. Everything else is fetched.
	//
	// TODO(stage): reuse still copies the bytes. Reflink/CoW, else hardlink,
	// would make an unchanged payload free rather than cheap; both need an fsx
	// operation that does not exist yet.
	data := s.reuse(f, dst, sources)
	if data == nil {
		// A changed file may still be mostly the old one. Reconstructing it
		// from what is on disk plus the patches the repository publishes is
		// delta stage 2; it produces bytes that are verified exactly like
		// downloaded ones, and falls back to the download whenever it cannot.
		data = s.patched(f, dst, sources, route)
	}
	if data == nil {
		var err error
		if data, err = s.Trust.Target(f.Target); err != nil {
			return err
		}
	}
	if err := fsx.WriteFileAtomic(s.FS, full, data, mode(f)); err != nil {
		return fmt.Errorf("%w: %w", ErrStage, err)
	}
	return nil
}

// makeDirs creates the relative directory chain under base and returns the
// resulting path, refusing to descend through a symlink.
func (s *Stager) makeDirs(base, rel string) (string, error) {
	dir := base
	if rel == "." || rel == "" {
		return dir, nil
	}
	for _, elem := range splitPath(rel) {
		dir = fsx.Join(dir, elem)
		if err := s.refuseSymlink(dir); err != nil {
			return "", err
		}
		if err := s.FS.MkdirAll(dir, layout.DirMode); err != nil {
			return "", fmt.Errorf("%w: %w", ErrStage, err)
		}
	}
	return dir, nil
}

// refuseSymlink fails if name exists and is a symlink. A name that does not
// exist is fine — it is about to be created.
func (s *Stager) refuseSymlink(name string) error {
	info, err := fsx.Lstat(s.FS, name)
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: %w", ErrStage, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink; refusing to write through it", ErrStage, name)
	}
	return nil
}

// splitPath splits a cleaned relative path into its elements.
func splitPath(rel string) []string {
	var out []string
	for _, e := range fsx.Split(rel) {
		if e != "" && e != "." {
			out = append(out, e)
		}
	}
	return out
}

// mode picks the permissions for a staged file. The descriptor's Mode has already
// been restricted to permission bits on ingest, so nothing here can grant setuid.
// A descriptor that leaves Mode unset gets the obvious default for its kind
// rather than a file nobody can read.
func mode(f *release.FileRef) fs.FileMode {
	if f.Mode != 0 {
		return fs.FileMode(f.Mode).Perm()
	}
	if f.Kind == release.KindExe {
		return 0o755
	}
	return 0o644
}

// Swap atomically repoints `current` at versionDir. This is the single commit
// point of the transaction.
func (s *Stager) Swap(versionDir string) error {
	if err := s.check(); err != nil {
		return err
	}
	version := fsx.Base(versionDir)
	if err := layout.ValidateVersion(version); err != nil {
		return err
	}
	// The pointer must never name a directory that is not there: a dangling
	// `current` is an install that looks whole and cannot start.
	if _, err := s.FS.Stat(versionDir); err != nil {
		return fmt.Errorf("%w: cannot point at %s: %w", ErrStage, versionDir, err)
	}
	return layout.SetPointer(s.FS, s.Root, version)
}

// GC removes version directories beyond retain, keeping `current` and at least one
// rollback target. retain must be >= 2. See docs/design.md §14.1.
//
// It runs only after a committed transaction, so the rollback target is never
// deleted before there is something to roll back from. A directory that will not
// go — the Windows sharing violation on a running binary — is reported as
// ErrIncompleteGC and retried next cycle, not treated as a failed update.
func (s *Stager) GC(retain int) error {
	if err := s.check(); err != nil {
		return err
	}
	if retain < MinRetain {
		return fmt.Errorf("%w: retain %d would leave no rollback target (minimum %d)",
			ErrStage, retain, MinRetain)
	}

	live, err := layout.PointerTarget(s.FS, s.Root)
	if err != nil {
		return err
	}
	if live == "" {
		// Nothing is installed, so nothing has earned the right to be kept.
		// Deleting version directories here would remove the very tree an
		// interrupted first install is about to be recovered from.
		return nil
	}

	versions, err := layout.InstalledVersions(s.FS, s.Root)
	if err != nil {
		return err
	}
	keep, err := retained(versions, live, retain)
	if err != nil {
		return err
	}

	var failed []error
	for _, v := range versions {
		if keep[v] {
			continue
		}
		dir, err := layout.VersionDir(s.Root, v)
		if err != nil {
			return err
		}
		if err := s.FS.RemoveAll(dir); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", v, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%w: %w", ErrIncompleteGC, errors.Join(failed...))
	}
	return nil
}

// retained decides which versions survive: the live one always, then the newest
// predecessors up to the window.
//
// The live version is counted as one of them, so retain=2 means "the running
// version and one older". Versions newer than the live one are kept too: they are
// not this transaction's leftovers, and deleting a newer tree because the pointer
// currently sits below it is how a rollback loses its way forward.
func retained(versions []string, live string, retain int) (map[string]bool, error) {
	keep := map[string]bool{live: true}

	older := make([]string, 0, len(versions))
	for _, v := range versions {
		c, err := release.Compare(v, live)
		if err != nil {
			return nil, err
		}
		switch {
		case c > 0:
			keep[v] = true
		case c < 0:
			older = append(older, v)
		}
	}

	var cmpErr error
	sort.Slice(older, func(i, j int) bool {
		c, err := release.Compare(older[i], older[j])
		if err != nil && cmpErr == nil {
			cmpErr = err
		}
		return c > 0 // newest first
	})
	if cmpErr != nil {
		return nil, cmpErr
	}

	for i := 0; i < len(older) && i < retain-1; i++ {
		keep[older[i]] = true
	}
	return keep, nil
}

// check validates the Stager's own configuration. A half-configured Stager must
// fail before it touches the install root, not halfway through it. Swap and GC
// only move and delete what is already there, so they do not need a trust client
// and must not demand one — recovery calls them without ever going online.
func (s *Stager) check() error {
	if s.FS == nil {
		return fmt.Errorf("%w: no filesystem", ErrStage)
	}
	if s.Root == "" {
		return fmt.Errorf("%w: no install root", ErrStage)
	}
	return nil
}
