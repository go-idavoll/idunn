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

package updater

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Apply downloads, verifies, quiesces running instances, stages, migrates, and
// atomically installs r, then garbage-collects old versions per Policy. It emits
// Observer events and an opt-in Reporter Outcome. For system-wide installs it
// routes the privileged apply through the configured Elevator. On any failure it
// rolls back files and calls Migrator.Rollback. Safe to call again after a crash.
func (u *Updater) Apply(ctx context.Context, r *Release) error {
	if r == nil || r.Descriptor == nil {
		return fmt.Errorf("%w: no release to apply", ErrConfig)
	}

	// The application lock, if one was taken, is held until everything is
	// finished — including the rollback. Migrator.Rollback touches the same
	// host state Migrate did, so releasing before it ran would hand the
	// application back a database somebody is still undoing changes to.
	phase, unlock, err := u.apply(ctx, r)
	defer unlock()

	if err == nil {
		u.reportOutcome(ctx, r, "committed", classNone, "")
		return nil
	}

	// Everything past this point is failure handling, and none of it may hide
	// the failure it is handling. The rollback's own error is joined to the
	// original rather than replacing it: an operator needs to know both that
	// the update failed and that undoing it did too.
	result := "aborted"
	if rbErr := u.rollback(ctx); rbErr != nil {
		err = errors.Join(err, rbErr)
	} else if phaseIsTransactional(phase) {
		result = "rolled_back"
	}
	u.reportOutcome(ctx, r, result, classify(err), phase)
	return err
}

// apply is the transaction proper. It returns the phase it failed in and the
// function that releases the application lock; the caller owns rollback,
// unlocking and reporting, so that no early return here can skip any of them.
func (u *Updater) apply(ctx context.Context, r *Release) (hook.Phase, func(), error) {
	d := r.Descriptor
	unlock := func() {}

	// Apply does not refresh metadata — CheckForUpdate did — so the clock is
	// checked again here rather than assumed to still be sane. An update that
	// was resolved honestly and is applied after the clock was turned back is
	// the same rollback attack with an extra step (§14.7, T22).
	if err := u.floor.Check(u.now()); err != nil {
		return hook.PhaseCheck, unlock, err
	}

	// An interrupted transaction has to be settled before a new one opens: the
	// journal keeps one history, and BEGIN replaces it. Running recovery here
	// rather than trusting the caller to have done it means a crashed update is
	// never silently built on top of.
	if _, err := txn.RecoverResult(ctx, u.fs, u.root, u.migrate); err != nil {
		return hook.PhaseCheck, unlock, err
	}

	// The Release may be minutes old, and the tree may have moved under it —
	// another instance updated, an operator rolled back. Re-reading is cheap;
	// applying a plan derived from a state that no longer exists is not.
	installed, err := u.installedVersion()
	if err != nil {
		return hook.PhaseCheck, unlock, err
	}
	if installed != r.FromVersion {
		return hook.PhaseCheck, unlock, fmt.Errorf("%w: it was resolved against %q but %q is installed",
			ErrStale, r.FromVersion, installed)
	}
	if installed == d.Version {
		return hook.PhaseCheck, unlock, fmt.Errorf("%w: %s is already installed", ErrStale, d.Version)
	}
	if err := u.applicable(d, installed); err != nil {
		return hook.PhaseCheck, unlock, err
	}

	hc := hook.Context{
		Ctx:         ctx,
		FromVersion: installed,
		ToVersion:   d.Version,
		Root:        u.root,
		StageDir:    fsx.Join(layout.Staging(u.root), d.Version),
	}

	if u.check != nil {
		u.emit(hook.PhaseCheck, "running pre-flight checks", nil)
		if err := u.check.Check(hc); err != nil {
			return hook.PhaseCheck, unlock, fmt.Errorf("%w: %w", ErrCheck, err)
		}
	}
	if u.prompt != nil {
		ok, err := u.prompt.Confirm(ctx, fmt.Sprintf("Install %s %s now?", d.Name, d.Version))
		if err != nil {
			return hook.PhaseCheck, unlock, err
		}
		if !ok {
			return hook.PhaseCheck, unlock, ErrDeclined
		}
	}

	j, err := txn.Open(u.fs, u.root)
	if err != nil {
		return hook.PhaseCheck, unlock, err
	}
	record := func(state txn.State, phase hook.Phase) error {
		return j.Append(txn.Record{
			State:       state,
			Name:        d.Name,
			FromVersion: installed,
			ToVersion:   d.Version,
			Phase:       phase,
		})
	}

	if err := record(txn.StateBegin, hook.PhaseCheck); err != nil {
		return hook.PhaseCheck, unlock, err
	}

	// From here on every failure is transactional: the journal exists, and the
	// caller's rollback will find it and undo whatever got done.
	u.emit(hook.PhaseDownload, "staging "+d.Version, nil)
	versionDir, err := u.stager.Stage(ctx, d)
	if err != nil {
		return hook.PhaseStage, unlock, err
	}
	if err := record(txn.StateStaged, hook.PhaseStage); err != nil {
		return hook.PhaseStage, unlock, err
	}

	unlock, err = u.quiesce(ctx, hc)
	if err != nil {
		return hook.PhaseQuiesce, unlock, err
	}

	if u.migrate != nil {
		u.emit(hook.PhaseMigrate, "migrating state", nil)
		if err := u.migrate.Migrate(hc); err != nil {
			return hook.PhaseMigrate, unlock, fmt.Errorf("%w: %w", ErrMigrate, err)
		}
	}
	if err := record(txn.StateMigrated, hook.PhaseMigrate); err != nil {
		return hook.PhaseMigrate, unlock, err
	}

	u.emit(hook.PhaseApply, "installing "+d.Version, nil)
	if err := u.swap(ctx, d, versionDir); err != nil {
		return hook.PhaseApply, unlock, err
	}
	if err := record(txn.StateSwapped, hook.PhaseApply); err != nil {
		return hook.PhaseApply, unlock, err
	}

	if u.policy.VerifyAfterApply {
		u.emit(hook.PhaseVerify, "verifying the installed files", nil)
		if err := u.verifyInstalled(ctx, d, versionDir); err != nil {
			return hook.PhaseVerify, unlock, err
		}
	}

	// The install state is written before the commit record, so a crash between
	// them leaves recovery with a state that already matches the live pointer.
	if err := layout.WriteInstall(u.fs, u.root, layout.Install{
		Name:         d.Name,
		Version:      d.Version,
		LayoutSchema: d.LayoutSchema,
	}); err != nil {
		return hook.PhaseCommit, unlock, err
	}
	if err := record(txn.StateCommitted, hook.PhaseCommit); err != nil {
		return hook.PhaseCommit, unlock, err
	}
	u.emit(hook.PhaseCommit, "installed "+d.Version, nil)

	// The staging tree has served its purpose. Removing it here rather than
	// leaving it for the next recovery keeps a committed install free of
	// anything that looks like an unfinished one.
	if err := u.fs.RemoveAll(layout.Staging(u.root)); err != nil {
		u.emit(hook.PhaseGC, "could not remove the staging tree", err)
	}

	// GC runs only after the commit, so the rollback target is never deleted
	// before there is something to roll back from. A directory that will not go
	// is reported and retried next cycle — it is not a reason to undo a
	// successful update (§14.1).
	if err := u.stager.GC(u.policy.RetainVersions); err != nil {
		if !errors.Is(err, stage.ErrIncompleteGC) {
			return hook.PhaseGC, unlock, err
		}
		u.emit(hook.PhaseGC, "some old versions could not be removed yet", err)
	}
	return "", unlock, nil
}

// swap installs the staged version, directly or through the privileged helper.
func (u *Updater) swap(ctx context.Context, d *release.Descriptor, versionDir string) error {
	if u.policy.Elevation == ElevationNone {
		return u.stager.Swap(versionDir)
	}
	// The privileged side re-verifies everything it installs; the descriptor is
	// untrusted input to it, not a verdict it may act on (AGENTS.md §1.4). This
	// call is a request, and everything it asks for is checked again on the
	// other side of the boundary.
	return u.elevator.Apply(ctx, u.root, d)
}

// verifyInstalled re-reads what is on disk and compares it with the verified
// target bytes.
//
// The bytes were checked when they were staged; this catches what happened
// between then and now — a truncated write that reported success, a local
// tamper in the window before the swap (§11.3 T9). It is off by default because
// it costs a full re-read of the release.
func (u *Updater) verifyInstalled(ctx context.Context, d *release.Descriptor, versionDir string) error {
	for i := range d.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		f := &d.Files[i]
		want, err := u.trust.Target(f.Target)
		if err != nil {
			return err
		}
		dst, err := stage.SanitizeDst(f.Dst)
		if err != nil {
			return err
		}
		got, err := fsx.ReadFile(u.fs, fsx.Join(versionDir, dst), int64(len(want)))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrVerify, err)
		}
		if !bytes.Equal(got, want) {
			// No paths, no contents: this string can reach a Reporter.
			return fmt.Errorf("%w: an installed file does not match its verified target", ErrVerify)
		}
	}
	return nil
}

// quiesce brings running instances of the host application to a state where they
// are not writing, and returns the function that releases the lock again.
//
// The exclusive application lock is the ground truth; Coordinator.RequestShutdown
// is only how the instances are asked (§14.3). A host that offers no lock cannot
// prove quiescence, and the updater does not pretend otherwise — it proceeds,
// because that is the pre-existing behaviour of an updater with no coordination
// at all, and says so through the Observer.
func (u *Updater) quiesce(ctx context.Context, hc hook.Context) (func(), error) {
	noop := func() {}
	if u.lock == nil {
		if u.coordinate != nil {
			if err := u.coordinate.RequestShutdown(hc); err != nil {
				return noop, fmt.Errorf("%w: %w", ErrBusy, err)
			}
		}
		return noop, nil
	}

	u.emit(hook.PhaseQuiesce, "waiting for the application to stop writing", nil)
	held, err := u.lock.TryLock(ctx)
	if err != nil {
		return noop, err
	}
	if held {
		return u.unlock, nil
	}

	if u.coordinate != nil {
		if err := u.coordinate.RequestShutdown(hc); err != nil {
			return noop, fmt.Errorf("%w: %w", ErrBusy, err)
		}
	}

	deadline := u.now().Add(u.policy.QuiesceTimeout)
	for u.now().Before(deadline) {
		if err := sleep(ctx, quiescePollInterval); err != nil {
			return noop, err
		}
		held, err := u.lock.TryLock(ctx)
		if err != nil {
			return noop, err
		}
		if held {
			return u.unlock, nil
		}
	}

	switch u.policy.OnBusy {
	case BusyAbort:
		return noop, fmt.Errorf("%w: still running after %s", ErrBusy, u.policy.QuiesceTimeout)

	case BusyDeferToRestart:
		// TODO(updater): §14.3 wants the staged tree kept and the swap finished
		// by the launcher at the next start. That needs a launcher and a resting
		// journal state for a deferred transaction, so that recovery does not
		// undo what was deliberately left staged. Until both exist, deferring
		// means undoing cleanly and telling the caller to try again later —
		// which is correct, only more expensive than it needs to be.
		return noop, fmt.Errorf("%w: still running after %s", ErrDeferred, u.policy.QuiesceTimeout)

	case BusyForce:
		// Terminating the instances is the host's business: only it knows which
		// processes are its own. The updater's part of "force" is to proceed
		// without the proof of quiescence it wanted — which is why this is
		// opt-in and documented as a data-loss risk (§11.5).
		u.emit(hook.PhaseQuiesce, "proceeding without an exclusive lock (BusyForce)", nil)
		return noop, nil

	default:
		return noop, fmt.Errorf("%w: unknown OnBusy policy %d", ErrConfig, u.policy.OnBusy)
	}
}

// unlock releases the application lock, reporting a failure through the Observer.
// It runs on the way out of a transaction that has already succeeded or failed on
// its own terms, so it has no result of its own to return.
func (u *Updater) unlock() {
	if err := u.lock.Unlock(); err != nil {
		u.emit(hook.PhaseCommit, "could not release the application lock", err)
	}
}

// sleep waits for d or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// rollback undoes whatever the transaction managed to do.
//
// It runs the same code as crash recovery, on purpose: a failure path that is its
// own implementation is a failure path nobody exercises, and this one is reached
// exactly when things are already going wrong.
func (u *Updater) rollback(ctx context.Context) error {
	// The context may already be cancelled — that is one of the ways we got
	// here — but the tree still has to be put back. Undoing is not optional
	// work that a cancellation may skip.
	if err := txn.Rollback(context.WithoutCancel(ctx), u.fs, u.root, u.migrate); err != nil {
		u.emit(hook.PhaseRollback, "rollback failed", err)
		return err
	}
	u.emit(hook.PhaseRollback, "rolled back", nil)
	return nil
}

// phaseIsTransactional reports whether the failure happened after the journal
// opened, and therefore whether "rolled_back" is an honest description of what
// the rollback did. A release refused in pre-flight was never applied, and
// reporting it as rolled back would inflate exactly the number a publisher
// watches to decide whether a release is bad (§14.5).
func phaseIsTransactional(phase hook.Phase) bool {
	switch phase {
	case hook.PhaseStage, hook.PhaseQuiesce, hook.PhaseMigrate,
		hook.PhaseApply, hook.PhaseVerify, hook.PhaseCommit, hook.PhaseGC:
		return true
	default:
		return false
	}
}

// emit delivers one lifecycle event. A nil Observer is the headless default, and
// an Observer that panics is the host's problem, not something to guard against
// here — it runs in the host's own process, as its own compiled code.
func (u *Updater) emit(phase hook.Phase, message string, err error) {
	if u.observe == nil {
		return
	}
	u.observe.OnEvent(hook.Event{Phase: phase, Message: message, Progress: -1, Err: err})
}

// checkFailed emits a failure event for the check phase and returns the error
// unchanged, so a caller can write `return nil, u.checkFailed(err)` without the
// event and the return value drifting apart. The transactional phases do not use
// it: their failures are reported once, by Apply, together with the outcome.
func (u *Updater) checkFailed(err error) error {
	u.emit(hook.PhaseCheck, "failed", err)
	return err
}

// reportOutcome hands the terminal result to the Reporter.
//
// Reporting is best-effort and must never affect the update result (§14.5): the
// Reporter's own error is surfaced to the Observer and then dropped. Everything
// in the Outcome is coarse and categorized — versions, platform, phase, error
// class — and nothing in it is a path, a raw error string, or anything about the
// machine it came from.
func (u *Updater) reportOutcome(ctx context.Context, r *Release, result, class string, phase hook.Phase) {
	if u.report == nil {
		return
	}
	o := hook.Outcome{
		FromVersion: r.FromVersion,
		ToVersion:   r.Descriptor.Version,
		OS:          u.goos,
		Arch:        u.goarch,
		Result:      result,
		FailedPhase: phase,
		ErrorClass:  class,
		At:          u.now(),
	}
	if err := u.report.Report(context.WithoutCancel(ctx), o); err != nil {
		u.emit(phase, "reporting the outcome failed", err)
	}
}
