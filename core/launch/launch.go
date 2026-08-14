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

// Package launch is the start-of-day half of the update lifecycle: it settles
// whatever the last run left behind, applies an update that was deliberately
// deferred, and hands over to the application (docs/design.md §6.1, §14.3).
//
// It exists because of one ordering problem. An update that has to migrate host
// state and move `current` needs a moment when the application is not running,
// and the updater — which runs inside that application — never has one. The
// launcher does: it is what starts the application, so before it does, nobody
// is writing.
//
// Nothing here is a trust decision. Everything this package touches was verified
// when it was staged, and it has no network, no keys and no TUF client: it moves
// a pointer and runs the host's migration hook. That is deliberate, because this
// code runs on every single start of the application, and the smallest thing
// that can go wrong here is a program that will not start.
package launch

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

// ErrLaunch is the class of every rejection here.
var ErrLaunch = errors.New("launch")

// AppLock is the host's exclusive application lock. It is the same shape as
// updater.AppLock and deliberately re-declared: a launcher that had to import the
// updater to state "nothing is running" would pull the whole update path into a
// binary whose job is to start a program.
//
// It is optional. A launcher is normally the thing that starts the application,
// so by construction no instance is up — but "normally" is not "provably", and a
// host that can prove it should hand the proof over.
type AppLock interface {
	TryLock(ctx context.Context) (bool, error)
	Unlock() error
}

// Options configures one start.
type Options struct {
	// FS is the filesystem to work through.
	FS fsx.FS

	// Root is the install root: the tree holding current/, versions/ and
	// .updater/.
	Root string

	// Migrate is the host's migration hook. A deferred update runs it here,
	// which is the whole reason the work was postponed to a moment when the
	// application is not running.
	Migrate hook.Migrator

	// Observe receives progress events. Optional.
	Observe hook.Observer

	// Lock proves no instance is running. Optional; see AppLock.
	Lock AppLock

	// RetainVersions is how many version directories to keep after a deferred
	// update is finished. Zero selects the minimum that still leaves a rollback
	// target.
	RetainVersions int
}

// Deferred describes an update that is staged and waiting for a start.
type Deferred struct {
	Name        string
	FromVersion string
	ToVersion   string
}

// Result reports what a start did.
type Result struct {
	// Recovered is true when an interrupted transaction from a previous run was
	// settled — finished or undone.
	Recovered bool

	// Applied is true when a deferred update was completed by this start.
	Applied bool

	// Skipped is true when a deferred update was found but left waiting,
	// because the application lock said an instance is still running.
	Skipped bool

	// FromVersion and ToVersion name the transaction this start settled.
	FromVersion string
	ToVersion   string
}

// Waiting reports the update a previous run deferred, or nil when there is none.
//
// It is read-only, and a launcher that only wants to know whether this start
// will be a slow one can ask before doing anything else.
func Waiting(f fsx.FS, root string) (*Deferred, error) {
	if f == nil {
		return nil, fmt.Errorf("%w: no filesystem", ErrLaunch)
	}
	if root == "" {
		return nil, fmt.Errorf("%w: no install root", ErrLaunch)
	}
	j, err := txn.Open(f, root)
	if err != nil {
		return nil, err
	}
	last, ok := j.Last()
	if !ok || last.State != txn.StateDeferred {
		return nil, nil
	}
	return &Deferred{Name: last.Name, FromVersion: last.FromVersion, ToVersion: last.ToVersion}, nil
}

// Start settles the install root and returns once it is ready to be run.
//
// It does two things, in this order and for this reason: recovery first, because
// an interrupted transaction has to be resolved before anything new is decided,
// and only then the deferred update, because finishing one is a new decision.
//
// A start that cannot finish a deferred update is not a start that fails. The
// application still has a complete, working installation — the one it has been
// running all along — so the error is reported and the caller runs it anyway.
// The alternative is a machine that will not launch its application because an
// update it did not ask for could not be applied.
func Start(ctx context.Context, o Options) (Result, error) {
	if o.FS == nil {
		return Result{}, fmt.Errorf("%w: no filesystem", ErrLaunch)
	}
	if o.Root == "" {
		return Result{}, fmt.Errorf("%w: no install root", ErrLaunch)
	}
	if o.RetainVersions == 0 {
		o.RetainVersions = stage.MinRetain
	}
	if o.RetainVersions < stage.MinRetain {
		return Result{}, fmt.Errorf("%w: RetainVersions %d leaves no rollback target (minimum %d)",
			ErrLaunch, o.RetainVersions, stage.MinRetain)
	}

	rec, err := txn.RecoverResult(ctx, o.FS, o.Root, o.Migrate)
	if err != nil {
		return Result{}, err
	}
	res := Result{Recovered: rec.Recovered, FromVersion: rec.FromVersion, ToVersion: rec.ToVersion}
	if !rec.Deferred {
		return res, nil
	}

	// Everything below moves `current` and runs the host's migration. Both are
	// only safe while the application is not writing, which is what the lock is
	// asked about.
	if o.Lock != nil {
		held, err := o.Lock.TryLock(ctx)
		if err != nil {
			return res, err
		}
		if !held {
			// Another instance is up. The update stays deferred — it has waited
			// this long — and this start proceeds with the version that is
			// live, which is the one that instance is already running.
			o.emit(hook.PhaseQuiesce, "an instance is still running; "+rec.ToVersion+" stays deferred", nil)
			res.Skipped = true
			return res, nil
		}
		defer func() {
			if err := o.Lock.Unlock(); err != nil {
				o.emit(hook.PhaseCommit, "the application lock could not be released", err)
			}
		}()
	}

	o.emit(hook.PhaseApply, "applying the deferred update "+rec.ToVersion, nil)
	st := &stage.Stager{FS: o.FS, Root: o.Root}
	done, err := txn.ResumeDeferred(ctx, o.FS, o.Root, o.Migrate, func(version string) error {
		dir, err := layout.VersionDir(o.Root, version)
		if err != nil {
			return err
		}
		return st.Swap(dir)
	})
	if err != nil {
		o.emit(hook.PhaseApply, "the deferred update could not be applied", err)
		return res, err
	}
	res.Applied = done.Completed
	o.emit(hook.PhaseCommit, "installed "+rec.ToVersion, nil)

	// GC runs only after the commit, so the rollback target is never removed
	// before there is something to roll back from. A directory that will not go
	// is reported and retried next start; it is not a reason to fail a start
	// (§14.1).
	if err := st.GC(o.RetainVersions); err != nil {
		if !errors.Is(err, stage.ErrIncompleteGC) {
			return res, err
		}
		o.emit(hook.PhaseGC, "some old versions could not be removed yet", err)
	}
	return res, nil
}

// emit notifies the Observer if the host registered one.
func (o Options) emit(phase hook.Phase, msg string, err error) {
	if o.Observe == nil {
		return
	}
	o.Observe.OnEvent(hook.Event{Phase: phase, Message: msg, Progress: -1, Err: err})
}
