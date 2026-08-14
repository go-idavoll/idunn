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

// Package updater orchestrates verified, transactional in-place updates.
//
// It owns no trust logic: every trust decision belongs to core/trust (go-tuf), and
// this package only sequences check, download, quiesce, stage, migrate, swap,
// commit and GC — atomically, or not at all. See docs/design.md §6.3.
package updater

import (
	"context"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
)

// Options configures an Updater. Every dependency is injected so no path in the
// update flow depends on ambient global state (AGENTS.md §2).
type Options struct {
	Trust   *trust.Client    // go-tuf wrapper: Refresh, LatestRelease, Materialize.
	Fetcher fetch.Fetcher    // enterprise-aware go-tuf Fetcher (proxy/PAC, system CAs).
	FS      fsx.FS           // filesystem abstraction (OS or in-memory).
	Now     func() time.Time // injected clock; go-tuf exposes UnsafeSetRefTime for tests.
	Root    string
	Channel string

	// Hooks — all optional; a nil hook is a no-op.
	Check      hook.Checker
	Migrate    hook.Migrator
	Observe    hook.Observer
	Prompt     hook.Prompter
	Coordinate hook.Coordinator // signal running instances to quiesce (§14.3).
	Report     hook.Reporter    // opt-in, privacy-first outcome telemetry (§14.5).

	// Elevator performs the privileged apply for system-wide installs; nil for
	// per-user installs (Policy.Elevation == ElevationNone). See §14.2.
	Elevator elevate.Elevator

	Policy Policy
}

// Policy holds the operator-tunable decisions. The zero value is the safe one:
// no downgrade, expiry enforced.
type Policy struct {
	AllowDowngrade   bool // default false (blocks rollback attacks).
	EnforceExpiry    bool // default true; descriptor validity on top of TUF metadata expiry.
	VerifyAfterApply bool // re-hash installed files post-swap (belt & braces).

	// RetainVersions is how many version dirs to keep after a successful commit,
	// including `current`. Must be >= 2 so an instant rollback target survives.
	// Older dirs are garbage-collected at the end of Apply (§14.1).
	RetainVersions int // default 2 => current + one previous.

	// Elevation selects how a privileged apply is performed when the install root
	// is not writable by the current process (§14.2).
	Elevation ElevationMode // default ElevationNone (per-user install).

	// QuiesceTimeout bounds how long Apply waits for running app instances to
	// release the exclusive lock before aborting or deferring (§14.3).
	QuiesceTimeout time.Duration // default 30s.

	// OnBusy decides what happens if the target app cannot be quiesced in time.
	OnBusy BusyPolicy // default BusyDeferToRestart.
}

// ElevationMode selects how a privileged apply is performed.
type ElevationMode int

const (
	ElevationNone        ElevationMode = iota // in-process; per-user install.
	ElevationInteractive                      // request UAC/polkit prompt on demand.
	ElevationService                          // hand off to a privileged helper via IPC.
)

// BusyPolicy decides what happens when running instances will not release the lock.
type BusyPolicy int

const (
	BusyAbort          BusyPolicy = iota // fail the update, retry later.
	BusyDeferToRestart                   // stage now, apply+migrate at next launch.
	BusyForce                            // force-terminate after grace (last resort).
)

// Release is a verified, applicable release: the descriptor plus the resolved
// version currently installed.
type Release struct {
	Descriptor  *release.Descriptor
	FromVersion string
}

// Updater is the orchestration entry point. It is immutable after New.
type Updater struct {
	// unexported: immutable config + injected deps.
}

// New validates o, applies the policy defaults, and returns an Updater. An
// inconsistent configuration (e.g. RetainVersions < 2, or an elevated policy with
// no Elevator) is an error here rather than a surprise mid-transaction.
func New(o Options) (*Updater, error) {
	panic("not implemented")
}

// CheckForUpdate runs trust.Refresh (TUF), resolves the channel pointer to the
// newest applicable release Descriptor, and returns it or nil if already up to
// date. All metadata trust (signatures, rollback, freeze, expiry) is go-tuf's.
func (u *Updater) CheckForUpdate(ctx context.Context) (*Release, error) {
	panic("not implemented")
}

// Apply downloads, verifies, quiesces running instances, stages, migrates, and
// atomically installs r, then garbage-collects old versions per Policy. It emits
// Observer events and an opt-in Reporter Outcome. For system-wide installs it
// routes the privileged apply through the configured Elevator. On any failure it
// rolls back files and calls Migrator.Rollback. Safe to call again after a crash.
func (u *Updater) Apply(ctx context.Context, r *Release) error {
	panic("not implemented")
}

// Root returns the install root this Updater manages.
func (u *Updater) Root() string {
	panic("not implemented")
}
