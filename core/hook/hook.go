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

// Package hook defines the host's optional extension points. Hooks are the host
// application's own compiled Go code — never code fetched from the network
// (AGENTS.md §1.3). A nil hook is a no-op. See docs/design.md §7.
package hook

import (
	"context"
	"time"
)

// Context is the immutable view a hook gets of the running transaction.
type Context struct {
	Ctx         context.Context // cancellation / deadline.
	FromVersion string          // installed version ("" for a fresh install).
	ToVersion   string          // version being installed.
	Root        string          // verified install root.
	StageDir    string          // verified staged files (read-only view).
}

// Checker runs pre-flight validation before anything is applied. A non-nil error
// aborts cleanly with zero changes on disk.
type Checker interface {
	Check(Context) error
}

// Migrator performs a stateful migration together with its exact inverse.
// The packer never contains migration logic; it lives here in the host.
type Migrator interface {
	Migrate(Context) error  // committed only if the whole transaction succeeds.
	Rollback(Context) error // idempotent; safe even if Migrate partially ran.
}

// Observer receives lifecycle events. UI sidecars implement this to render
// progress. Headless operation simply registers no Observer.
type Observer interface {
	OnEvent(Event)
}

// Prompter is an optional interactive gate (e.g. "Install now?"). Headless
// deployments leave it nil, in which case the configured default decision wins.
type Prompter interface {
	Confirm(ctx context.Context, question string) (bool, error)
}

// Coordinator lets the updater bring running instances of the host app to a
// consistent, non-writing state before migration touches shared resources outside
// the install root. The exclusive app lock remains the ground truth that no writer
// is left (§14.3).
type Coordinator interface {
	// RequestShutdown asks all running instances to quit or stop writing. It
	// returns once the request has been delivered, not once they have exited.
	RequestShutdown(Context) error
}

// Reporter receives the terminal outcome of an update transaction so a publisher
// is not blind to a bad release. Opt-in and privacy-first: core produces only
// coarse, categorized data (no paths, no raw error strings, no PII). Reporting is
// best-effort and MUST NOT affect the update result (§14.5).
type Reporter interface {
	Report(ctx context.Context, o Outcome) error
}

// Outcome is the coarse, PII-free result of one transaction.
type Outcome struct {
	FromVersion string
	ToVersion   string
	OS, Arch    string
	Result      string    // "committed" | "rolled_back" | "aborted".
	FailedPhase Phase     // last phase reached on failure (empty on success).
	ErrorClass  string    // taxonomy, e.g. "verify", "migrate", "disk", "network", "clock_skew".
	At          time.Time // set by the updater from its injected clock, never time.Now.
}

// Phase names a step of the transaction; it is part of the Reporter taxonomy, so
// values are stable and must not be renamed casually.
type Phase string

// The phases of one update transaction, in the order they are entered.
const (
	PhaseCheck    Phase = "check"
	PhaseDownload Phase = "download"
	PhaseVerify   Phase = "verify"
	PhaseQuiesce  Phase = "quiesce" // wait for running instances to release the lock.
	PhaseStage    Phase = "stage"
	PhaseMigrate  Phase = "migrate"
	PhaseApply    Phase = "apply"
	PhaseCommit   Phase = "commit"
	PhaseGC       Phase = "gc" // prune old version dirs after a successful commit.
	PhaseRollback Phase = "rollback"
)

// Event is one lifecycle notification delivered to an Observer.
type Event struct {
	Phase    Phase
	Message  string
	Progress float64 // in [0,1], or -1 if indeterminate.
	Err      error   // set on failure events.
}
