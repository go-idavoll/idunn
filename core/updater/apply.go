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
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/integrate"
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
//
// Usually that is one installation. It becomes several when the release refuses
// to migrate from the version installed here (Requirements.MinFromVersion) and
// the repository publishes releases in between that bridge the gap: those are
// then installed in order, each a complete update of its own — its own
// transaction, its own migration hooks, its own commit. A release that skipped
// a migration is exactly what the floor exists to prevent, and walking to it is
// the only way to honour that and still arrive.
//
// Each step is a real installation, so a failure part-way leaves the install on
// the last release that committed — a published release, not a half-state — and
// says so. A step that defers to the next restart stops the walk there; the
// remaining releases follow when the deferred one has been applied.
func (u *Updater) Apply(ctx context.Context, r *Release) error {
	if r == nil || r.Descriptor == nil {
		return fmt.Errorf("%w: no release to apply", ErrConfig)
	}

	// A root this process cannot write gets no transaction from it at all: the
	// helper runs the whole of one, walk included (§14.2).
	if u.policy.Elevation != ElevationNone {
		return u.applyElevated(ctx, r)
	}

	// A launcher an interrupted swap left missing is put back before anything
	// else. It is not part of the transaction and never fails it: the update
	// is as good with or without it, and the report says what happened.
	u.repairLauncher()

	// Whatever the walk below ends on — the release asked for, a step on the
	// way, or the version it started from — is what the OS integrations have
	// to say (IDN-36).
	defer u.refreshIntegrations(ctx)

	from := r.FromVersion
	for i, step := range u.plan(ctx, r) {
		if err := u.applyRelease(ctx, &Release{Descriptor: step, FromVersion: from}); err != nil {
			if i == 0 {
				return err
			}
			return fmt.Errorf("%w (on the way to %s, this install is now %s)", err, r.Descriptor.Version, from)
		}
		from = step.Version
	}
	return nil
}

// plan settles an interrupted transaction and then works out which releases
// have to be installed to reach the one asked for.
//
// The order of the three things it does is the whole of it.
//
// The clock first, because everything after it is a decision taken on this
// machine's word about the time. Recovery finishes an update forward or undoes
// it, and planning reads repository metadata whose expiry is judged against
// this very clock — neither may happen below the known-good floor, which is
// what makes turning the clock back useless rather than merely detectable
// (§14.7, T22).
//
// Recovery second, and this is the only reason this function exists rather
// than the planning happening inline. A crash between the swap and the commit
// leaves `current` already pointing at the new version with nothing having said
// so; a plan made from that state refuses the very transaction recovery is
// about to finish, and the install keeps a pointer to one version and a state
// file naming another for as long as anyone keeps trying.
//
// Everything here may then give up and answer "just the release that was asked
// for". A clock below the floor, a precondition that no longer holds, a journal
// that will not settle, a migration floor with no path around it: each of those
// is refused inside the transaction below, where it is rolled back and reported
// like any other failure. Refusing them here as well would mean two places
// deciding the same thing, which is one place too many for them to still agree
// in a year.
func (u *Updater) plan(ctx context.Context, r *Release) []*release.Descriptor {
	alone := []*release.Descriptor{r.Descriptor}

	if err := u.floor.Check(u.now()); err != nil {
		return alone
	}
	if _, err := txn.RecoverResult(ctx, u.fs, u.root, u.migrate); err != nil {
		return alone
	}
	installed, err := u.installedVersion()
	if err != nil || installed != r.FromVersion || installed == r.Descriptor.Version {
		return alone
	}
	walk, err := u.steps(r.Descriptor, installed)
	if err != nil {
		return alone
	}
	return walk
}

// steps is the releases that have to be installed to reach d, in order.
//
// It is one release — d itself — unless d refuses to migrate from what is
// installed. That refusal is the only one a path can answer: a downgrade or a
// client too old for the layout says this machine may not have the release at
// all, while a migration floor says only that it is too far back to arrive in
// one step.
//
// The walk it produces is the shortest one the repository supports, and every
// release on it is checked by the same applicable() the apply path enforces —
// so a step this planner picks cannot be one the apply then refuses. Releases
// of another channel are not stepping stones: a stable install does not pass
// through a beta to get anywhere.
func (u *Updater) steps(d *release.Descriptor, installed string) ([]*release.Descriptor, error) {
	err := u.applicable(d, installed)
	if err == nil {
		return []*release.Descriptor{d}, nil
	}
	if !errors.Is(err, ErrMigrationFloor) {
		return nil, err
	}

	hist, ok := u.trust.(History)
	if !ok {
		return nil, err
	}
	// Between rather than Chain: stepping through releases for their migrations
	// does not need the installed release to still be published, only the ones
	// on top of it.
	openLines(hist, d.OS, d.Arch, installed, d.Version)
	walk, walkErr := release.Between(hist.Versions(d.OS, d.Arch), installed, d.Version)
	if walkErr != nil {
		return nil, err
	}

	// The far end of the walk is in hand already; the rest has to be resolved.
	candidates := make([]*release.Descriptor, 0, len(walk))
	for _, v := range walk[:len(walk)-1] {
		step, sErr := hist.ReleaseVersion(d.OS, d.Arch, v)
		if sErr != nil || step.Channel != d.Channel {
			continue
		}
		candidates = append(candidates, step)
	}
	candidates = append(candidates, d)

	var out []*release.Descriptor
	for at := installed; at != d.Version; {
		next := furthestReachable(u, candidates, at)
		if next == nil {
			return nil, fmt.Errorf("%w; and no published release bridges the gap", err)
		}
		out = append(out, next)
		at = next.Version
		if len(out) > maxWalk {
			return nil, fmt.Errorf("%w; and the published path to it is longer than %d releases", err, maxWalk)
		}
	}
	return out, nil
}

// furthestReachable picks the newest candidate that may be installed on top of
// at — the fewest installations that still honour every floor on the way.
func furthestReachable(u *Updater, candidates []*release.Descriptor, at string) *release.Descriptor {
	var pick *release.Descriptor
	for _, c := range candidates {
		newer, err := release.Newer(c.Version, at)
		if err != nil || !newer {
			continue
		}
		if u.applicable(c, at) == nil {
			pick = c // candidates are in ascending order, so the last wins
		}
	}
	return pick
}

// applyRelease installs one release: the transaction, its rollback, the
// application lock, and the outcome report.
func (u *Updater) applyRelease(ctx context.Context, r *Release) error {

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

	// A deferred update is not a failed one. The tree is staged, the journal
	// says so, and rolling back here would throw away exactly the work the
	// policy asked to keep.
	if errors.Is(err, ErrDeferred) {
		u.reportOutcome(ctx, r, "deferred", classify(err), phase)
		return err
	}

	// Everything past this point is failure handling, and none of it may hide
	// the failure it is handling. The rollback's own error is joined to the
	// original rather than replacing it: an operator needs to know both that
	// the update failed and that undoing it did too.
	//
	// What is undone is this call's own transaction, and only that. A refusal
	// in pre-flight opened none, and an interrupted one it happens to find is
	// not its to undo: rolling that back moves `current` and deletes a version
	// directory, which is a decision about what runs on this machine — taken by
	// a call that has just established it may not take one. A clock below the
	// floor is exactly that case, and undoing a swapped transaction under it
	// would be a downgrade for the asking (§14.7, T22). An older transaction is
	// settled by recovery instead, at the start of the next apply or the next
	// launch, both of which check the floor first.
	result := "aborted"
	if phaseIsTransactional(phase) {
		if rbErr := u.rollback(ctx); rbErr != nil {
			err = errors.Join(err, rbErr)
		} else {
			result = "rolled_back"
		}
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
	rec, err := txn.RecoverResult(ctx, u.fs, u.root, u.migrate)
	if err != nil {
		return hook.PhaseCheck, unlock, err
	}
	// A transaction that is already staged and waiting for a restart is not one
	// to run again: the tree is on disk, verified, and the only thing missing is
	// a moment when the application is not running. Re-staging it would download
	// and write everything a second time to arrive at the state it is already
	// in. A *different* version may supersede it — that is a new decision, and
	// the journal allows BEGIN after DEFERRED for exactly that.
	if rec.Deferred && rec.ToVersion == d.Version {
		return hook.PhaseQuiesce, unlock, fmt.Errorf(
			"%w: %s is staged and waiting for the next start", ErrDeferred, d.Version)
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
	versionDir, err := u.stager.Stage(ctx, d, u.route(d, installed))
	if err != nil {
		return hook.PhaseStage, unlock, err
	}
	if err := record(txn.StateStaged, hook.PhaseStage); err != nil {
		return hook.PhaseStage, unlock, err
	}

	unlock, err = u.quiesce(ctx, hc)
	if err != nil {
		if errors.Is(err, ErrDeferred) {
			// Deferring is not a failure to undo: the verified tree is already
			// on disk and stays there. The journal moves to its resting state
			// so the next recovery leaves it alone and the launcher can finish
			// it while no instance holds the lock.
			if rerr := record(txn.StateDeferred, hook.PhaseQuiesce); rerr != nil {
				return hook.PhaseQuiesce, unlock, errors.Join(err, rerr)
			}
			u.emit(hook.PhaseQuiesce, "staged "+d.Version+"; it will be applied at the next start", nil)
		}
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
	if err := u.stager.Swap(versionDir); err != nil {
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

	// The launcher this release carries, if any, is staged for the next start
	// now and not a moment earlier: the COMMITTED record is durable, so no
	// launcher is ever staged for an update that did not happen. A crash before
	// this line leaves it pending in the staging tree, and the next recovery
	// sees COMMITTED and promotes it (txn, IDN-17).
	//
	// A promotion that fails does not unmake a committed update. It is reported,
	// and the staging tree is kept so the next recovery tries again.
	if err := layout.PromoteLauncher(u.fs, u.root, d.Version); err != nil {
		u.emit(hook.PhaseCommit, "the new launcher could not be staged; the next update check retries", err)
	} else if err := u.fs.RemoveAll(layout.Staging(u.root)); err != nil {
		// The staging tree has served its purpose. Removing it here rather
		// than leaving it for the next recovery keeps a committed install free
		// of anything that looks like an unfinished one.
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

// verifyInstalled re-reads what is on disk and compares it with the verified
// target bytes.
//
// The bytes were checked when they were staged; this catches what happened
// between then and now — a truncated write that reported success, a local
// tamper in the window before the swap (§11.3 T9). It is off by default because
// it costs a full re-read of the release.
//
// It asks the trust layer for a verdict on what it read rather than for the
// target itself, so verifying costs no network. That is not a convenience: since
// staging reuses unchanged files from the previous version (§6.4 stage 1), the
// bytes of an unchanged payload may never have been downloaded at all, and a
// verify that fetched them would spend the traffic the reuse just saved — on a
// release whose bulk is a browser runtime, all of it.
func (u *Updater) verifyInstalled(ctx context.Context, d *release.Descriptor, versionDir string) error {
	for i := range d.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		f := &d.Files[i]
		dst, err := stage.SanitizeDst(f.Dst)
		if err != nil {
			return err
		}
		if err := u.verifyFile(fsx.Join(versionDir, dst), f.Target); err != nil {
			return err
		}
	}
	return nil
}

// verifyFile streams one installed file past the trust layer's verdict.
//
// Streaming is what makes this affordable to turn on: the re-read used to hold
// each file whole, so the belt-and-braces check cost as much memory as the
// install did, on top of an install that had just finished. Now it costs a copy
// window (IDN-12).
func (u *Updater) verifyFile(name, target string) error {
	f, err := u.fs.Open(name)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVerify, err)
	}
	defer func() { _ = f.Close() }()

	if err := u.trust.VerifyStream(target, f); err != nil {
		// No paths, no contents: this string can reach a Reporter.
		return fmt.Errorf("%w: an installed file does not match its verified target", ErrVerify)
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
		// The staged tree stays where it is and the swap waits for the next
		// start, when nothing is running (§14.3). apply turns this into a
		// DEFERRED journal record; the caller must not roll it back.
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

// refreshIntegrations brings the installation's OS integrations — the version
// the Windows "Installed apps" entry shows — in line with the version that is
// live (core/integrate, IDN-36).
//
// It runs after the transaction, never inside it: the swap is the transaction,
// and the registry is not part of it. A failure is reported and changes nothing
// about the update's outcome, and the launcher reconciles again at the next
// start. It runs on a context that is not canceled with the update's, so an
// update that committed and was then interrupted still says so.
func (u *Updater) refreshIntegrations(ctx context.Context) {
	if u.registry == nil {
		return
	}
	in, err := integrate.New(integrate.Options{FS: u.fs, Root: u.root, Registry: u.registry, Now: u.now, Observe: u.observe})
	if err == nil {
		err = in.Refresh(context.WithoutCancel(ctx))
	}
	if err != nil {
		u.emit(hook.PhaseCommit, "the Installed apps entry could not be brought up to date; the next start retries", err)
	}
}

// emit delivers one lifecycle event. A nil Observer is the headless default, and
// an Observer that panics is the host's problem, not something to be caught
// here: swallowing it would hide a bug in the very code that renders the update.
func (u *Updater) emit(phase hook.Phase, message string, err error) {
	if u.observe == nil {
		return
	}
	u.observe.OnEvent(hook.Event{Phase: phase, Message: message, Progress: -1, Err: err})
}

// stageProgress turns staging's byte reports into Observer events.
//
// It returns nil when nobody is watching, which is what keeps the streaming path
// free of a per-write callback on a headless install: a nil stage.Progress is
// never called at all.
//
// Progress is the fraction of the release written, and it is derived here rather
// than in core/stage because it is a presentation question — staging deals in
// bytes, which is the quantity that is actually true. A release whose signed
// lengths sum to zero has no fraction to report, and says so with -1 rather than
// with a bar that is either always full or always empty.
func (u *Updater) stageProgress() stage.Progress {
	if u.observe == nil {
		return nil
	}
	return func(r stage.Report) {
		fraction := -1.0
		if r.Total > 0 {
			fraction = min(float64(r.Done)/float64(r.Total), 1)
		}
		u.observe.OnEvent(hook.Event{
			Phase:      hook.PhaseDownload,
			Message:    stageMessage(r),
			Progress:   fraction,
			File:       r.Dst,
			FileIndex:  r.Index,
			FileCount:  r.Files,
			Source:     hook.Source(r.Source),
			BytesDone:  r.Done,
			BytesTotal: r.Total,
			FileDone:   r.FileDone,
			FileSize:   r.FileSize,
		})
	}
}

// stageMessage describes one file in the words of what it is actually costing,
// so a UI that shows nothing but the message still tells the truth about whether
// this is the network or the local disk.
func stageMessage(r stage.Report) string {
	verb := "staging"
	switch r.Source {
	case stage.SourceReuse:
		verb = "reusing"
	case stage.SourcePatch:
		verb = "patching"
	case stage.SourceDownload:
		verb = "downloading"
	}
	return verb + " " + r.Dst
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

// History is the optional capability of looking a release up by version and
// saying which releases exist at all.
//
// It is separate from Resolver because it is not part of applying an update: a
// client that cannot answer these questions still updates, it just fetches full
// targets where it could have patched. Keeping it optional also keeps the
// mandatory trust surface at what the apply path truly needs (the same reason
// installer.VersionResolver stands apart).
type History interface {
	// ReleaseVersion resolves one explicitly named release.
	ReleaseVersion(goos, goarch, version string) (*release.Descriptor, error)

	// Versions lists the releases the repository publishes for a platform,
	// oldest first.
	Versions(goos, goarch string) []string

	// OpenLine makes one release line's descriptors visible to Versions.
	OpenLine(goos, goarch, major string)
}

// maxLines bounds how many release lines a walk will open. Each one is a
// metadata file to fetch and verify, and a client this many majors behind is
// not going to be walked anywhere — it will be told to fetch the release it is
// going to, which is the fallback either way.
const maxLines = 8

// openLines makes every release line between two versions visible to the walk.
//
// Without it a walk can only see the line it is going to. Delegated roles load
// lazily, so a client that has just resolved a 2.0.0 head knows the 2.x
// descriptors and no others — and would conclude that the 1.5.0 it has to step
// through, or patch through, was never published.
func openLines(hist History, goos, goarch, from, to string) {
	first, ok := release.Major(from)
	last, ok2 := release.Major(to)
	if !ok || !ok2 || last < first || last-first > maxLines {
		return
	}
	// Counted by steps rather than by counting up to `last`: a major of
	// 18446744073709551615 is a version SemVer allows, and a loop that
	// increments past it wraps to zero and never ends. The span is bounded
	// above, so first+step cannot pass last either.
	for step := uint64(0); step <= last-first; step++ {
		hist.OpenLine(goos, goarch, strconv.FormatUint(first+step, 10))
	}
}

// maxWalk bounds how many releases a patched update will walk through.
//
// It is a cost bound, not a safety one — every hop is verified, so a longer
// walk is not less trustworthy, only less likely to be worth it. A client this
// far behind is better served by downloading the release it is going to, which
// is exactly what an unavailable route falls back to.
const maxWalk = 32

// route works out the byte-level history of the release being applied: for each
// destination, the payload targets it had at the releases between the installed
// version and this one.
//
// Everything here is an optimisation with the same fallback — fetch the full
// target — so nothing in it returns an error. A trust client that cannot list
// releases, a chain that is not published end to end, an intermediate
// descriptor that will not resolve: each simply means there is no route, and
// the update proceeds the way it did before patches existed.
func (u *Updater) route(d *release.Descriptor, installed string) stage.Route {
	hist, ok := u.trust.(History)
	if !ok || installed == "" {
		return nil
	}

	// Resolving the installed release first is not only for its file list: it
	// is also the descriptor whose payload targets the first patch starts from,
	// and a release the repository no longer publishes is one no patch can be
	// applied against.
	first, err := hist.ReleaseVersion(d.OS, d.Arch, installed)
	if err != nil {
		return nil
	}
	openLines(hist, d.OS, d.Arch, installed, d.Version)
	walk, err := release.Chain(hist.Versions(d.OS, d.Arch), installed, d.Version)
	if err != nil || len(walk) > maxWalk {
		return nil
	}

	route := stage.Route{}
	for i, v := range walk {
		step := first
		switch {
		case i == 0:
		case v == d.Version:
			step = d
		default:
			if step, err = hist.ReleaseVersion(d.OS, d.Arch, v); err != nil {
				return nil
			}
		}
		for j := range step.Files {
			f := &step.Files[j]
			route[f.Dst] = append(route[f.Dst], f.Target)
		}
	}
	return route
}
