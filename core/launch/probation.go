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

package launch

import (
	"context"
	"fmt"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Probation (IDN-39) is how a committed version shows it works on this machine.
//
// An updater with a probation policy leaves a record for the version it
// installs. From then on every launcher start counts an attempt, until the
// application calls MarkHealthy. A version that has used up its attempts, or
// reported MarkUnhealthy, is rolled back at the next start: `current` returns to
// the version it replaced, the host's migration is undone, and the version is
// blocked so the updater does not install it again.
//
// Starts are counted rather than seconds timed, so nothing has to wait for the
// application and the launcher can keep handing over with exec on POSIX. The
// cost is that a user who closes the application before it confirms spends an
// attempt; that is what the allowance is sized for.

// ProbationResult reports what a start did about a version on probation.
type ProbationResult struct {
	// Version is the version on probation this start dealt with, if any.
	Version string

	// Attempt is the attempt this start counted, starting at 1. Zero when the
	// start counted none: nothing is on probation, the version has confirmed,
	// or this start was a restart the application asked for.
	Attempt int

	// Restart is true when this start was a restart the application asked for
	// (Relaunch) and so counted no attempt.
	Restart bool

	// Reverted is true when this start rolled Version back to To. Reason says
	// why, in the application's words or the launcher's.
	Reverted bool
	To       string
	Reason   string

	// Kept is true when Version failed its probation and could not be rolled
	// back, because the version it replaced is no longer installed.
	Kept bool

	// Err is why the probation record could not be read or written, or why a
	// rollback stopped part-way. It never makes Start fail: a rollback that
	// stopped is finished by the next start, which finds it recorded.
	Err error
}

// MarkHealthy ends the probation of version: the application is up and working.
//
// Call it once the application is actually ready — after its own start-up and
// migrations, not first thing in main. It is idempotent and cheap, and it does
// nothing when version is not on probation, so an application can call it on
// every start without asking first.
func MarkHealthy(f fsx.FS, root, version string) error {
	return mark(f, root, version, func(p *layout.Probation) {
		p.Status = layout.ProbationConfirmed
		p.RestartPending = false
	})
}

// MarkUnhealthy reports that version does not work on this machine, and why.
// The application should exit after it: the next launcher start rolls the
// version back without spending further attempts.
//
// The reason is stored, reported to the host's hooks and shown to whoever looks,
// so it is sanitized and bounded here (layout.SanitizeReason). It does nothing
// when version is not on probation: a version that already confirmed has passed,
// and taking that back is a decision for a new release, not for one bad start.
func MarkUnhealthy(f fsx.FS, root, version, reason string) error {
	return mark(f, root, version, func(p *layout.Probation) {
		p.Status = layout.ProbationUnhealthy
		p.Reason = layout.SanitizeReason(reason)
		if p.Reason == "" {
			p.Reason = "the application reported itself unhealthy"
		}
	})
}

func mark(f fsx.FS, root, version string, change func(*layout.Probation)) error {
	if f == nil {
		return fmt.Errorf("%w: no filesystem", ErrLaunch)
	}
	if root == "" {
		return fmt.Errorf("%w: no install root", ErrLaunch)
	}
	p, err := layout.ReadProbation(f, root)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	if p == nil || p.Version != version || p.Status != layout.ProbationActive {
		return nil
	}
	change(p)
	if err := layout.WriteProbation(f, root, *p); err != nil {
		return fmt.Errorf("%w: %w", ErrLaunch, err)
	}
	return nil
}

// markRestart records, before the application leaves through Relaunch, that the
// next start is one it asked for. It is best-effort: an application that cannot
// write the record — a system-wide root — still relaunches, and the next start
// then counts as an attempt.
func markRestart(f fsx.FS, root string) {
	p, err := layout.ReadProbation(f, root)
	if err != nil || p == nil || p.Status != layout.ProbationActive {
		return
	}
	// Only the version that runs asks for its own restart. A record for another
	// version is an update waiting for this very restart to be applied.
	if live, err := layout.PointerTarget(f, root); err != nil || live != p.Version {
		return
	}
	if p.Restarts <= p.RestartsAllowed {
		p.Restarts++
	}
	p.RestartPending = true
	_ = layout.WriteProbation(f, root, *p)
}

// probation settles the version on probation before the application starts:
// counts the attempt, or rolls the version back. locked says whether this start
// already holds the application lock.
func (o Options) probation(ctx context.Context, res *Result, locked bool) {
	pr := &res.Probation
	p, err := layout.ReadProbation(o.FS, o.Root)
	if err != nil {
		pr.Err = fmt.Errorf("%w: %w", ErrLaunch, err)
		o.emit(hook.PhaseRollback, "the probation record could not be read", pr.Err)
		return
	}
	if p == nil {
		return
	}
	if p.Status == layout.ProbationReverting {
		// A rollback that a previous start did not finish. It is finished
		// before anything else is decided, wherever `current` points by now.
		o.revert(ctx, pr, p, p.Reason, locked)
		return
	}
	live, err := layout.PointerTarget(o.FS, o.Root)
	if err != nil {
		pr.Err = fmt.Errorf("%w: %w", ErrLaunch, err)
		return
	}
	if live != p.Version {
		// A transaction that did not commit, or a deferred one this start did
		// not apply: not the version that runs.
		return
	}

	switch p.Status {
	case layout.ProbationUnhealthy:
		o.revert(ctx, pr, p, p.Reason, locked)
	case layout.ProbationReverted:
		// The version rolled back is live again: an updater that predates
		// probation — the one in the version rolled back to — installed it
		// once more. It has not become any better.
		o.emit(hook.PhaseRollback, p.Version+" was installed again after it was rolled back", nil)
		o.revert(ctx, pr, p, p.Reason, locked)
	case layout.ProbationActive:
		pr.Version = p.Version
		if p.RestartPending {
			if p.Restarts > p.RestartsAllowed {
				o.revert(ctx, pr, p, fmt.Sprintf("asked to be restarted more than %s without confirming it is healthy",
					plural(p.RestartsAllowed, "time")), locked)
				return
			}
			p.RestartPending = false
			pr.Restart = true
		} else {
			if p.Attempts >= p.AttemptsAllowed {
				o.revert(ctx, pr, p, fmt.Sprintf("not confirmed healthy after %s", plural(p.AttemptsAllowed, "start")), locked)
				return
			}
			p.Attempts++
			pr.Attempt = p.Attempts
		}
		// Written before the application starts: a start that crashes the
		// machine has still been counted.
		if err := layout.WriteProbation(o.FS, o.Root, *p); err != nil {
			pr.Err = fmt.Errorf("%w: %w", ErrLaunch, err)
			o.emit(hook.PhaseRollback, "the probation attempt could not be recorded", pr.Err)
		}
	}
}

// revert rolls the version on probation back to the one it replaced.
//
// Every step can be repeated, and the REVERTING record goes first, so a start
// that is interrupted anywhere in here is finished by the next one: `current`
// is set again, the host's rollback hook — idempotent by contract — runs again,
// the install state is written again.
//
// The transaction journal is not touched. It still says the update committed,
// which it did; recovery reads a COMMITTED record as nothing to do, and the next
// update begins a new history from whatever `current` names.
func (o Options) revert(ctx context.Context, pr *ProbationResult, p *layout.Probation, reason string, locked bool) {
	pr.Version = p.Version
	reason = layout.SanitizeReason(reason)

	// Moving `current` and undoing a migration under a running instance is what
	// the lock exists to prevent; the rollback waits for a start that gets it.
	if o.Lock != nil && !locked {
		held, err := o.Lock.TryLock(ctx)
		if err != nil {
			pr.Err = err
			return
		}
		if !held {
			o.emit(hook.PhaseRollback, "an instance is still running; rolling back "+p.Version+" waits", nil)
			return
		}
		defer func() {
			if err := o.Lock.Unlock(); err != nil {
				o.emit(hook.PhaseRollback, "the application lock could not be released", err)
			}
		}()
	}

	fail := func(msg string, err error) {
		pr.Err = fmt.Errorf("%w: rolling back %s: %s: %w", ErrLaunch, p.Version, msg, err)
		o.emit(hook.PhaseRollback, "rolling back "+p.Version+" stopped; the next start continues", pr.Err)
	}

	prevDir, err := layout.VersionDir(o.Root, p.Previous)
	if err != nil {
		fail("the previous version", err)
		return
	}
	if _, err := o.FS.Stat(prevDir); err != nil {
		if !fsx.IsNotExist(err) {
			fail("the previous version", err)
			return
		}
		if p.Status == layout.ProbationReverting {
			// The pointer may already have moved; without the directory it
			// named there is nothing a rollback can finish.
			fail("the previous version is gone", err)
			return
		}
		p.Status = layout.ProbationKept
		p.Reason = layout.SanitizeReason(reason + "; " + p.Previous + " is no longer installed, so it stays")
		if err := layout.WriteProbation(o.FS, o.Root, *p); err != nil {
			fail("recording that it stays", err)
			return
		}
		pr.Kept, pr.Reason = true, p.Reason
		o.emit(hook.PhaseRollback, p.Version+" failed its probation and cannot be rolled back: "+p.Reason, nil)
		return
	}

	if p.Status != layout.ProbationReverting {
		p.Status = layout.ProbationReverting
		p.Reason = reason
		if err := layout.WriteProbation(o.FS, o.Root, *p); err != nil {
			fail("recording the rollback", err)
			return
		}
	}
	o.emit(hook.PhaseRollback, "rolling back "+p.Version+" to "+p.Previous+": "+reason, nil)

	st := &stage.Stager{FS: o.FS, Root: o.Root}
	if err := st.Swap(prevDir); err != nil {
		fail("moving current", err)
		return
	}
	if o.Migrate != nil {
		if err := o.Migrate.Rollback(hook.Context{
			Ctx:         ctx,
			FromVersion: p.Previous,
			ToVersion:   p.Version,
			Root:        o.Root,
			StageDir:    layout.Staging(o.Root),
		}); err != nil {
			fail("the host's rollback hook", err)
			return
		}
	}
	in, err := layout.ReadInstall(o.FS, o.Root)
	if err == nil && in == nil {
		err = fmt.Errorf("%w: no install state names the application", ErrLaunch)
	}
	if err != nil {
		fail("the install state", err)
		return
	}
	if in.Version != p.Previous {
		if err := layout.WriteInstall(o.FS, o.Root, layout.Install{
			Name:         in.Name,
			Version:      p.Previous,
			LayoutSchema: release.LayoutSchema,
		}); err != nil {
			fail("the install state", err)
			return
		}
	}

	p.Status = layout.ProbationReverted
	p.Reason = reason
	p.RestartPending = false
	p.Blocked = &layout.BlockedVersion{Version: p.Version, Reason: reason}
	if err := layout.WriteProbation(o.FS, o.Root, *p); err != nil {
		fail("recording the rollback", err)
		return
	}
	pr.Reverted, pr.To, pr.Reason = true, p.Previous, reason
	o.emit(hook.PhaseRollback, "rolled back "+p.Version+" to "+p.Previous, nil)

	// The rolled-back tree goes last and only if it will: on Windows a file of
	// it may still be open, and the next update's GC collects what stays.
	if dir, err := layout.VersionDir(o.Root, p.Version); err == nil {
		if err := o.FS.RemoveAll(dir); err != nil {
			o.emit(hook.PhaseGC, "the rolled-back version could not be removed yet", err)
		}
	}
}

// plural renders a count with its noun, for reasons a user reads.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
