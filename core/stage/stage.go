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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/delta"
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
	Target(targetPath string) ([]byte, error)

	// SignedLength is the length the repository signed for a target. It is how
	// a local candidate of the wrong size is skipped without being read; it is
	// not a check, and a candidate of the right size has proved nothing.
	SignedLength(targetPath string) (int64, error)

	// Accepts reports whether data is exactly the bytes signed for targetPath.
	// The verdict is go-tuf's, reached through the trust layer — this package
	// never decides whether bytes are acceptable, only where they come from and
	// where they go (AGENTS.md §1.2, §1.5).
	Accepts(targetPath string, data []byte) error

	// SignedSHA256 is the hash the repository signed for a target. It is how a
	// delta patch target is named (docs/design.md §6.4 stage 2), and it is not a
	// check: what decides whether reconstructed bytes may be used is Accepts.
	SignedSHA256(targetPath string) (string, error)
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
// The files are assembled under .updater/staging/<version>/ and moved into place
// with a single rename at the end. Nothing incomplete is ever visible under
// versions/, so a crash mid-staging leaves a tree the recovery can simply delete
// rather than one it has to inspect file by file.
func (s *Stager) Stage(ctx context.Context, d *release.Descriptor) (string, error) {
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

	// The trees a file may be reused from, newest first. Built once: it is the
	// same set for every file of this release, and it must not change halfway
	// through a staging run.
	reuseFrom, err := s.reuseSources(live)
	if err != nil {
		return "", err
	}
	// The release line this publish belongs to. A patch target lives inside the
	// delegated role that signs the release it belongs to, so its path carries
	// the line (release.PatchPath).
	major, err := release.Major(d.Version)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrStage, err)
	}

	stageDir := fsx.Join(layout.Staging(s.Root), d.Version)
	// A leftover staging tree from an abandoned attempt is not a base to build
	// on: it may hold files this descriptor no longer lists.
	if err := s.FS.RemoveAll(stageDir); err != nil {
		return "", fmt.Errorf("%w: clear staging: %w", ErrStage, err)
	}
	if err := s.FS.MkdirAll(stageDir, 0o700); err != nil {
		return "", fmt.Errorf("%w: create staging: %w", ErrStage, err)
	}

	for i := range d.Files {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("%w: %w", ErrStage, err)
		}
		if err := s.stageFile(stageDir, &d.Files[i], reuseFrom, major); err != nil {
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

// stageFile writes one payload file into the staging tree.
func (s *Stager) stageFile(stageDir string, f *release.FileRef, reuseFrom []string, major string) error {
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

	// Delta stage 1, second half (docs/design.md §6.4): a file that is already
	// installed and still holds exactly the signed bytes is reused instead of
	// fetched. The go-tuf cache covers the same ground only within one release
	// line, because a payload target's path carries its major and the cache is
	// keyed by path; this is keyed by content, so it also survives a major bump.
	data, err := s.reuse(f, reuseFrom)
	if err != nil {
		return err
	}
	if data == nil {
		// Delta stage 2: an installed copy that is *not* the target may still be
		// most of it. If the publisher made a patch from those exact bytes to
		// these, fetching it is cheaper than fetching the file.
		data = s.patch(f, reuseFrom, major)
	}
	if data == nil {
		if data, err = s.Trust.Target(f.Target); err != nil {
			return err
		}
	}
	if err := fsx.WriteFileAtomic(s.FS, full, data, mode(f)); err != nil {
		return fmt.Errorf("%w: %w", ErrStage, err)
	}
	return nil
}

// reuseSources lists the version directories a file may be reused from, newest
// first, with the live one at the front.
//
// Only installed versions are considered. The staging tree of an abandoned
// attempt is deliberately not among them: it holds bytes no committed
// transaction ever vouched for, and while Accepts would refuse anything wrong,
// there is no reason to offer them in the first place.
func (s *Stager) reuseSources(live string) ([]string, error) {
	if live == "" {
		return nil, nil // nothing installed yet: a first install has no past.
	}
	versions, err := layout.InstalledVersions(s.FS, s.Root)
	if err != nil {
		return nil, err
	}
	var cmpErr error
	sort.Slice(versions, func(i, j int) bool {
		c, err := release.Compare(versions[i], versions[j])
		if err != nil && cmpErr == nil {
			cmpErr = err
		}
		return c > 0 // newest first
	})
	if cmpErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrStage, cmpErr)
	}

	dirs := make([]string, 0, len(versions))
	for _, v := range append([]string{live}, versions...) {
		dir, err := layout.VersionDir(s.Root, v)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs, nil
}

// MaxReuseCandidate bounds a file read as a reuse candidate, and the result a
// delta patch may reconstruct. It is a ceiling on what a wrong answer can cost,
// not a policy: a candidate is only read at all once its size matches the signed
// length exactly.
const MaxReuseCandidate = 1 << 30 // 1 GiB

// reuse returns the bytes of an already-installed copy of f's target, or nil if
// there is none to be had.
//
// The destination path selects the candidate and the trust layer decides it. A
// file is never adopted because it sits where the new release wants one: same
// name, same size, and still every byte goes through the same verification a
// download does (AGENTS.md §1.5). What the name buys is not having to hash every
// installed file to find out.
//
// Anything that is not a plain regular file is skipped rather than followed. A
// symlink in an old version directory is a local attacker's way to point this
// read at something that is not a file at all, and the answer to "is this the
// target?" is not worth a read of /dev/zero to obtain.
func (s *Stager) reuse(f *release.FileRef, dirs []string) ([]byte, error) {
	if len(dirs) == 0 {
		return nil, nil
	}
	dst, err := SanitizeDst(f.Dst)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStage, f.Target, err)
	}
	want, err := s.Trust.SignedLength(f.Target)
	if err != nil {
		return nil, err
	}
	if want <= 0 || want > MaxReuseCandidate {
		return nil, nil
	}

	for _, dir := range dirs {
		name := fsx.Join(dir, dst)
		info, err := fsx.Lstat(s.FS, name)
		if err != nil || !info.Mode().IsRegular() || info.Size() != want {
			continue
		}
		data, err := fsx.ReadFile(s.FS, name, want)
		if err != nil {
			continue // unreadable is not a failure; it only means no reuse.
		}
		if err := s.Trust.Accepts(f.Target, data); err != nil {
			// The right name and the right size, and the wrong bytes: local
			// tampering, bit rot, or simply a file that changed between
			// releases. Whichever it is, it is not this target — move on and
			// let the trust layer fetch it.
			continue
		}
		return data, nil
	}
	return nil, nil
}

// patch reconstructs f's target from an installed file plus a published delta,
// or returns nil if that cannot be done.
//
// Every failure along the way is a nil rather than an error, and that is the
// design rather than laziness: the fallback is the full download, which is
// strictly more expensive and exactly as verified. There is nothing a broken,
// missing or hostile patch can achieve here beyond making this function return
// nothing — the bytes it produces are candidates, and Accepts decides
// (docs/design.md §6.4, AGENTS.md §1.5).
//
// Discovery is by convention: the patch target's path is derived from the hash of
// what is on disk and the hash the repository signed for what is wanted. Nothing
// in the descriptor points at it, so a publisher can add or drop patches between
// releases without the descriptors changing, and a client that asks for one that
// was never made is simply told there is no such target.
func (s *Stager) patch(f *release.FileRef, dirs []string, major string) []byte {
	if len(dirs) == 0 {
		return nil
	}
	want, err := s.Trust.SignedSHA256(f.Target)
	if err != nil {
		return nil
	}
	dst, err := SanitizeDst(f.Dst)
	if err != nil {
		return nil
	}

	for _, dir := range dirs {
		base := s.readCandidate(fsx.Join(dir, dst))
		if base == nil {
			continue
		}
		sum := sha256.Sum256(base)
		patchTarget := release.PatchPath(major, hex.EncodeToString(sum[:]), want)

		raw, err := s.Trust.Target(patchTarget)
		if err != nil {
			continue // no patch was published from these bytes to those.
		}
		out, err := ApplyPatch(base, raw)
		if err != nil {
			continue
		}
		if err := s.Trust.Accepts(f.Target, out); err != nil {
			// A patch that reconstructs something else is not a fallback and
			// not a fault to work around: it is discarded, and the full target
			// is fetched instead (§6.4).
			continue
		}
		return out
	}
	return nil
}

// readCandidate reads an installed file that may serve as a patch base.
//
// Unlike reuse it does not care about the length: the whole point is a file that
// is *not* the target. What it still refuses to do is follow anything that is not
// a plain regular file.
func (s *Stager) readCandidate(name string) []byte {
	info, err := fsx.Lstat(s.FS, name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxReuseCandidate {
		return nil
	}
	data, err := fsx.ReadFile(s.FS, name, MaxReuseCandidate)
	if err != nil {
		return nil
	}
	return data
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
		if err := s.FS.MkdirAll(dir, 0o700); err != nil {
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

// ApplyPatch reconstructs a target from a base file and a delta patch
// (docs/design.md §6.4 stage 2).
//
// The result is a *candidate*, and this function has no idea what the right
// answer is — which is precisely why it cannot be talked into producing it. The
// caller checks the result against the signed target hash before anything is
// written, exactly as it would a download, and a patch that reconstructs
// something else is discarded in favour of the full target rather than
// accommodated.
//
// The format and the bounds live in internal/delta, which is also where
// FuzzPatchApply covers them (§12). This is the seam the rest of core reaches it
// through.
func ApplyPatch(base, patch []byte) ([]byte, error) {
	out, err := delta.Apply(base, patch, MaxReuseCandidate)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStage, err)
	}
	return out, nil
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
