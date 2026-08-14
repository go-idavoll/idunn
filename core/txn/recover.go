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

package txn

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Result reports what Recover did, so the caller can tell an operator — and a
// Reporter — whether the previous run ended in a completed update or an undone
// one. It carries no error strings or paths: it is safe to hand to telemetry
// (docs/design.md §14.5).
type Result struct {
	// Recovered is false when there was nothing to do.
	Recovered bool

	// Completed is true when an interrupted transaction was finished, false when
	// it was undone. Meaningful only if Recovered.
	Completed bool

	// FromVersion and ToVersion identify the transaction that was recovered.
	FromVersion string
	ToVersion   string
}

// Recover inspects the journal after a crash and drives the install back to a
// valid state: a transaction past SWAPPED is completed, anything earlier is rolled
// back. It is idempotent and safe to call on every start.
func Recover(f fsx.FS, root string, m hook.Migrator) error {
	_, err := RecoverResult(context.Background(), f, root, m)
	return err
}

// RecoverResult is Recover with a context and a report of what happened. Recover
// is the plain form the design names; this is what the updater calls, because it
// has a context to honour and an Observer to tell.
func RecoverResult(ctx context.Context, f fsx.FS, root string, m hook.Migrator) (Result, error) {
	j, err := Open(f, root)
	if err != nil {
		return Result{}, err
	}

	last, ok := j.Last()
	if !ok {
		// No transaction was ever started here, or the last one was already
		// tidied away. Orphans can still exist from an abort that died before
		// it could clean up.
		return Result{}, cleanOrphans(f, root)
	}

	res := Result{Recovered: true, FromVersion: last.FromVersion, ToVersion: last.ToVersion}

	switch last.State {
	case StateCommitted, StateRolledBack:
		// A terminal state. Nothing to decide; only litter to remove.
		return Result{}, cleanOrphans(f, root)

	case StateSwapped:
		// The pointer moved and the transaction died before it could say so.
		// The new version is live, the migration ran: finishing is the only
		// answer that does not undo work already visible to the application.
		res.Completed = true
		return res, complete(f, root, j, last)

	case StateMigrated:
		// The genuinely ambiguous case. The swap is a single rename, so it
		// either happened or did not — but the record that would have said so
		// was never written. The filesystem is the authority here, not the
		// journal: ask where `current` actually points.
		live, err := layout.PointerTarget(f, root)
		if err != nil {
			return Result{}, err
		}
		if live == last.ToVersion {
			res.Completed = true
			return res, complete(f, root, j, last)
		}
		return res, rollback(ctx, f, root, j, last, m)

	case StateBegin:
		// Nothing beyond the journal write has happened yet: no migration could
		// have started, because that only follows STAGED. Undo the staging.
		return res, rollback(ctx, f, root, j, last, nil)

	case StateStaged:
		// Staging finished and the migration may have been interrupted halfway
		// through. Migrator.Rollback is contractually idempotent and safe after
		// a partial Migrate, which is exactly this case (docs/design.md §6.2).
		return res, rollback(ctx, f, root, j, last, m)

	default:
		// Unreachable through Append, which validates the state, but a journal
		// is a file on disk: an unknown state is refused rather than guessed.
		return Result{}, fmt.Errorf("%w: cannot recover from unknown state %q", ErrJournal, last.State)
	}
}

// complete finishes a transaction whose swap already happened.
func complete(f fsx.FS, root string, j *Journal, last Record) error {
	// The pointer must actually be where the record says. If it is not, the
	// install is in a state this code did not produce, and repairing it by guess
	// is how a recovery turns a crash into a corruption.
	live, err := layout.PointerTarget(f, root)
	if err != nil {
		return err
	}
	if live != last.ToVersion {
		return fmt.Errorf("%w: journal says %s is installed but current points at %q",
			ErrJournal, last.ToVersion, live)
	}

	// When the swap was found on disk rather than in the journal, record it
	// before committing. The history has to stay a sequence that could have been
	// written step by step, or a later reader cannot trust its own reading of
	// it — and the fact we just established from the filesystem is precisely
	// that the swap happened.
	if last.State == StateMigrated {
		swapped := Record{
			State:       StateSwapped,
			Name:        last.Name,
			FromVersion: last.FromVersion,
			ToVersion:   last.ToVersion,
			Phase:       hook.PhaseApply,
		}
		if err := j.Append(swapped); err != nil {
			return err
		}
		last = swapped
	}

	if err := layout.WriteInstall(f, root, layout.Install{
		Name:         last.Name,
		Version:      last.ToVersion,
		LayoutSchema: release.LayoutSchema,
	}); err != nil {
		return err
	}
	if err := j.Append(Record{
		State:       StateCommitted,
		Name:        last.Name,
		FromVersion: last.FromVersion,
		ToVersion:   last.ToVersion,
		Phase:       hook.PhaseCommit,
	}); err != nil {
		return err
	}
	return cleanOrphans(f, root)
}

// rollback undoes a transaction that had not committed.
//
// The order is deliberate: the pointer is restored first, so the previous version
// is runnable again at the earliest possible moment, and only then is the state
// the migration touched undone. A rollback that did the slow part first would
// leave the machine without a working application for the duration.
func rollback(ctx context.Context, f fsx.FS, root string, j *Journal, last Record, m hook.Migrator) error {
	if err := restorePointer(f, root, last); err != nil {
		return err
	}

	if m != nil {
		hc := hook.Context{
			Ctx:         ctx,
			FromVersion: last.FromVersion,
			ToVersion:   last.ToVersion,
			Root:        root,
			StageDir:    layout.Staging(root),
		}
		if err := m.Rollback(hc); err != nil {
			// The install is now in the one state this project refuses to paper
			// over: files reverted, host state not. Report it and leave the
			// journal where it is, so the next start tries again rather than
			// recording a rollback that did not happen.
			return fmt.Errorf("%w: migrator rollback: %w", ErrJournal, err)
		}
	}

	// The half-installed version directory is only removable once nothing points
	// at it any more, which restorePointer has just ensured.
	if last.ToVersion != last.FromVersion {
		dir, err := layout.VersionDir(root, last.ToVersion)
		if err != nil {
			return err
		}
		if err := f.RemoveAll(dir); err != nil {
			return fmt.Errorf("%w: remove %s: %w", ErrJournal, dir, err)
		}
	}

	if err := j.Append(Record{
		State:       StateRolledBack,
		Name:        last.Name,
		FromVersion: last.FromVersion,
		ToVersion:   last.ToVersion,
		Phase:       hook.PhaseRollback,
	}); err != nil {
		return err
	}
	return cleanOrphans(f, root)
}

// restorePointer puts `current` back where the transaction found it.
func restorePointer(f fsx.FS, root string, last Record) error {
	if last.FromVersion == "" {
		// A first install that failed: there is no previous version to return
		// to, so the correct end state is no installation at all.
		return layout.RemovePointer(f, root)
	}

	live, err := layout.PointerTarget(f, root)
	if err != nil {
		return err
	}
	if live == last.FromVersion {
		return nil
	}

	// Refusing here is deliberate. If the version we are supposed to fall back
	// to is not on disk, repointing would produce a dangling `current` — an
	// install that looks whole and cannot start.
	dir, err := layout.VersionDir(root, last.FromVersion)
	if err != nil {
		return err
	}
	if _, err := f.Stat(dir); err != nil {
		return fmt.Errorf("%w: cannot roll back to %s: %w", ErrJournal, last.FromVersion, err)
	}
	return layout.SetPointer(f, root, last.FromVersion)
}

// cleanOrphans removes what an interrupted transaction leaves lying around: the
// staging tree, and the scratch files of atomic writes that never got renamed.
//
// It is best-effort in scope but not in reporting: a failure is returned, because
// litter in the install root is what the next recovery would have to interpret.
func cleanOrphans(f fsx.FS, root string) error {
	if err := f.RemoveAll(layout.Staging(root)); err != nil {
		return fmt.Errorf("%w: remove staging: %w", ErrJournal, err)
	}
	for _, dir := range []string{root, layout.Meta(root), layout.Versions(root)} {
		if err := removeScratch(f, dir); err != nil {
			return err
		}
	}
	return nil
}

// removeScratch deletes the abandoned scratch files of fsx.WriteFileAtomic and
// layout.SetPointer in one directory. A missing directory is not an error: a root
// without an install has neither.
func removeScratch(f fsx.FS, dir string) error {
	entries, err := f.ReadDir(dir)
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: read %s: %w", ErrJournal, dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.Contains(name, ".idunn-") || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		if err := f.RemoveAll(fsx.Join(dir, name)); err != nil {
			return fmt.Errorf("%w: remove scratch %s: %w", ErrJournal, name, err)
		}
	}
	return nil
}
