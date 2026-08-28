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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/core/timefloor"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Resolver is the narrow trust surface the updater consumes.
//
// It is an interface, not *trust.Client, for the reason the design gives for
// every dependency here: no path in the update flow may depend on ambient state,
// and every path must be reachable in a test without a live TUF repository
// (docs/design.md §12). *trust.Client satisfies it. Nothing in this package may
// grow a second way to decide what is trustworthy — Refresh and LatestRelease
// are where that question is asked and answered (AGENTS.md §1.2).
type Resolver interface {
	// Refresh runs the TUF client workflow. Expiry, rollback, freeze and
	// mix-and-match are rejected here, before anything else runs.
	Refresh() error

	// LatestRelease resolves the channel pointer to a verified descriptor.
	LatestRelease(channel, goos, goarch string) (*release.Descriptor, error)

	// Target returns the verified bytes of one target.
	Target(targetPath string) ([]byte, error)
}

// AppLock is the exclusive lock a running host application holds, and the ground
// truth that no instance is still writing (docs/design.md §14.3).
//
// The host owns it because only the host knows where its data lives: the lock
// guards state outside the install root, such as a database in AppData. A nil
// AppLock means the host has not offered one, and the updater then has no way to
// prove quiescence — see Policy.OnBusy for what it does about that.
type AppLock interface {
	// TryLock attempts to take the lock without waiting. It reports whether the
	// lock was acquired; a false with a nil error means "someone else holds it",
	// which is an answer, not a failure.
	TryLock(ctx context.Context) (bool, error)

	// Unlock releases a lock this process holds.
	Unlock() error
}

// Options configures an Updater. Every dependency is injected so no path in the
// update flow depends on ambient global state (AGENTS.md §2).
type Options struct {
	Trust   Resolver         // go-tuf wrapper: Refresh, LatestRelease, Target.
	Fetcher fetch.Fetcher    // the transport the trust client was built with; carried so a host configures one place. The updater performs no I/O of its own.
	FS      fsx.FS           // filesystem abstraction (OS or in-memory).
	Now     func() time.Time // injected clock; go-tuf exposes UnsafeSetRefTime for tests.
	Root    string
	Channel string

	// OS and Arch select the platform to resolve. They default to the running
	// platform; a cross-platform packer or a test sets them explicitly.
	OS   string
	Arch string

	// ClientVersion is this client's own version, checked against a descriptor's
	// MinClientVersion (§11.3 T14). If a descriptor demands a minimum and this is
	// empty, the update is refused: an unknown client version cannot be shown to
	// be new enough.
	ClientVersion string

	// BuildTime is when this client was built. It is the first floor under the
	// system clock: a program cannot have been built after the moment it runs,
	// so a clock below it is wrong before anything else is known (§14.7, T22).
	// Zero means the build stamped none, and then only observed refreshes
	// establish the floor.
	BuildTime time.Time

	// ClientID is the stable identifier a staged rollout self-selects on
	// (§14.5). It never leaves the machine — only the derived bucket decides —
	// so any stable per-install string will do.
	ClientID string

	// Hooks — all optional; a nil hook is a no-op.
	Check      hook.Checker
	Migrate    hook.Migrator
	Observe    hook.Observer
	Prompt     hook.Prompter
	Coordinate hook.Coordinator // signal running instances to quiesce (§14.3).
	Report     hook.Reporter    // opt-in, privacy-first outcome telemetry (§14.5).

	// Lock is the host's exclusive application lock (§14.3). Optional.
	Lock AppLock

	// Elevator performs the privileged apply for system-wide installs; nil for
	// per-user installs (Policy.Elevation == ElevationNone). See §14.2.
	Elevator elevate.Elevator

	Policy Policy
}

// Policy holds the operator-tunable decisions. The zero value is the safe one:
// no downgrade, expiry enforced.
type Policy struct {
	AllowDowngrade bool // default false (blocks rollback attacks).

	// EnforceExpiry is always on and cannot be turned off from here.
	//
	// TUF metadata expiry is checked inside go-tuf during Refresh, which runs
	// before this package decides anything, and no flag above it may relax that
	// — the freeze defence is exactly that check (§11.3 T5). New sets this to
	// true whatever the caller passed, because Go cannot distinguish "left
	// unset" from "deliberately false" and the unsafe reading must not be the
	// one that wins by accident.
	//
	// TODO(release): schema 1 descriptors carry no validity window of their own.
	// When they do, this flag governs that app-level check on top of TUF's.
	EnforceExpiry bool

	// VerifyAfterApply re-reads every installed file after the swap and compares
	// it against its verified target bytes. Belt and braces: the bytes were
	// already checked when they were staged, and this catches what happened to
	// them between then and now (§11.3 T9).
	VerifyAfterApply bool

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
	//
	// The zero value is BusyAbort and stays that way. BusyDeferToRestart is what
	// docs/design.md §14.3 recommends for a host whose running application
	// updates itself, and a host that wants it says so — New does not promote an
	// unset field to it. Go cannot tell "left unset" from "deliberately chosen",
	// so promoting would turn a forgotten field into a change of behaviour in
	// the apply path: an update that quietly stays staged and lands at the next
	// start, on a host that never asked for one. The safe reading has to be the
	// one that wins by accident (AGENTS.md §1.1).
	OnBusy BusyPolicy
}

// ElevationMode selects how a privileged apply is performed.
type ElevationMode int

// The supported elevation modes. The zero value is the unprivileged one.
const (
	ElevationNone        ElevationMode = iota // in-process; per-user install.
	ElevationInteractive                      // request UAC/polkit prompt on demand.
	ElevationService                          // hand off to a privileged helper via IPC.
)

// BusyPolicy decides what happens when running instances will not release the lock.
type BusyPolicy int

// The supported busy policies. The zero value fails rather than forces.
const (
	BusyAbort          BusyPolicy = iota // fail the update, retry later.
	BusyDeferToRestart                   // stage now, apply+migrate at next launch.
	BusyForce                            // force-terminate after grace (last resort).
)

// DefaultQuiesceTimeout bounds the wait for running instances when Policy leaves
// QuiesceTimeout unset.
const DefaultQuiesceTimeout = 30 * time.Second

// quiescePollInterval is how often the app lock is retried while waiting.
const quiescePollInterval = 250 * time.Millisecond

// Release is a verified, applicable release: the descriptor plus the resolved
// version currently installed.
type Release struct {
	Descriptor  *release.Descriptor
	FromVersion string
}

// Updater is the orchestration entry point. It is immutable after New.
type Updater struct {
	trust  Resolver
	fs     fsx.FS
	now    func() time.Time
	stager *stage.Stager

	root          string
	channel       string
	goos          string
	goarch        string
	clientVersion string
	clientID      string
	floor         timefloor.Floor

	check      hook.Checker
	migrate    hook.Migrator
	observe    hook.Observer
	prompt     hook.Prompter
	coordinate hook.Coordinator
	report     hook.Reporter
	lock       AppLock
	elevator   elevate.Elevator

	policy Policy
}

// New validates o, applies the policy defaults, and returns an Updater. An
// inconsistent configuration (e.g. RetainVersions < 2, or an elevated policy with
// no Elevator) is an error here rather than a surprise mid-transaction.
func New(o Options) (*Updater, error) {
	if o.Trust == nil {
		return nil, fmt.Errorf("%w: no trust client", ErrConfig)
	}
	if o.FS == nil {
		return nil, fmt.Errorf("%w: no filesystem", ErrConfig)
	}
	if o.Root == "" {
		return nil, fmt.Errorf("%w: no install root", ErrConfig)
	}
	if o.Channel == "" {
		return nil, fmt.Errorf("%w: no channel", ErrConfig)
	}

	p := o.Policy
	if p.RetainVersions == 0 {
		p.RetainVersions = stage.MinRetain
	}
	if p.RetainVersions < stage.MinRetain {
		return nil, fmt.Errorf("%w: RetainVersions %d leaves no rollback target (minimum %d)",
			ErrConfig, p.RetainVersions, stage.MinRetain)
	}
	if p.QuiesceTimeout == 0 {
		p.QuiesceTimeout = DefaultQuiesceTimeout
	}
	if p.QuiesceTimeout < 0 {
		return nil, fmt.Errorf("%w: negative QuiesceTimeout %s", ErrConfig, p.QuiesceTimeout)
	}
	switch p.OnBusy {
	case BusyAbort, BusyDeferToRestart, BusyForce:
	default:
		return nil, fmt.Errorf("%w: unknown OnBusy policy %d", ErrConfig, p.OnBusy)
	}
	switch p.Elevation {
	case ElevationNone:
	case ElevationInteractive, ElevationService:
		if o.Elevator == nil {
			return nil, fmt.Errorf("%w: elevation mode %d without an Elevator", ErrConfig, p.Elevation)
		}
	default:
		return nil, fmt.Errorf("%w: unknown elevation mode %d", ErrConfig, p.Elevation)
	}
	// See the field comment: expiry is not negotiable from here, and the value
	// Go gives an unset bool is the unsafe one.
	p.EnforceExpiry = true

	now := o.Now
	if now == nil {
		now = time.Now
	}
	goos, goarch := o.OS, o.Arch
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	return &Updater{
		trust:         o.Trust,
		fs:            o.FS,
		now:           now,
		stager:        &stage.Stager{FS: o.FS, Trust: o.Trust, Root: o.Root},
		root:          o.Root,
		channel:       o.Channel,
		goos:          goos,
		goarch:        goarch,
		clientVersion: o.ClientVersion,
		clientID:      o.ClientID,
		floor:         timefloor.Floor{FS: o.FS, Root: o.Root, BuildTime: o.BuildTime},
		check:         o.Check,
		migrate:       o.Migrate,
		observe:       o.Observe,
		prompt:        o.Prompt,
		coordinate:    o.Coordinate,
		report:        o.Report,
		lock:          o.Lock,
		elevator:      o.Elevator,
		policy:        p,
	}, nil
}

// CheckForUpdate runs trust.Refresh (TUF), resolves the channel pointer to the
// newest applicable release Descriptor, and returns it or nil if already up to
// date. All metadata trust (signatures, rollback, freeze, expiry) is go-tuf's.
//
// It is not read-only: a successful refresh raises the persisted known-good time
// floor (§14.7). That is deliberate — checking is the frequent operation and
// updating the rare one, so a floor advanced only by applied updates would lag
// by however long a machine goes without one.
func (u *Updater) CheckForUpdate(ctx context.Context) (*Release, error) {
	u.emit(hook.PhaseCheck, "checking for updates", nil)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The clock is an input to expiry, so it is checked before the metadata that
	// depends on it. A clock below the floor is refused here rather than allowed
	// to make expired metadata look fresh (§14.7, T22).
	if err := u.floor.Check(u.now()); err != nil {
		return nil, u.checkFailed(err)
	}
	if err := u.trust.Refresh(); err != nil {
		return nil, u.checkFailed(err)
	}
	// The refresh succeeded, so this machine has been at this local time with a
	// repository it trusts answering. That is the new floor.
	if err := u.floor.Observe(u.now()); err != nil {
		return nil, u.checkFailed(err)
	}
	d, err := u.trust.LatestRelease(u.channel, u.goos, u.goarch)
	if err != nil {
		return nil, u.checkFailed(err)
	}

	installed, err := u.installedVersion()
	if err != nil {
		return nil, u.checkFailed(err)
	}
	if installed == d.Version {
		u.emit(hook.PhaseCheck, "already up to date", nil)
		return nil, nil
	}

	if err := u.applicable(d, installed); err != nil {
		return nil, u.checkFailed(err)
	}
	if !u.inRollout(d) {
		u.emit(hook.PhaseCheck, "not in the rollout window for "+d.Version, nil)
		return nil, nil
	}

	u.emit(hook.PhaseCheck, "update available: "+d.Version, nil)
	return &Release{Descriptor: d, FromVersion: installed}, nil
}

// Root returns the install root this Updater manages.
func (u *Updater) Root() string { return u.root }

// installedVersion reads the version `current` points at, or "" if there is no
// installation. The pointer is authoritative rather than state.json: it is what
// actually decides which code runs.
func (u *Updater) installedVersion() (string, error) {
	return layout.PointerTarget(u.fs, u.root)
}

// applicable enforces the app-level floors on top of TUF's own rollback
// protection: the descriptor's requirements and this client's downgrade policy.
//
// TUF has already refused metadata that goes backwards. These checks answer a
// different question — whether this particular install may make this particular
// jump — which the repository cannot know.
func (u *Updater) applicable(d *release.Descriptor, installed string) error {
	if d.Channel != u.channel {
		return fmt.Errorf("%w: descriptor is for channel %q, not %q", ErrPolicy, d.Channel, u.channel)
	}
	if d.OS != u.goos || d.Arch != u.goarch {
		return fmt.Errorf("%w: descriptor is for %s-%s, not %s-%s",
			ErrPolicy, d.OS, d.Arch, u.goos, u.goarch)
	}

	if req := d.Requirements.MinClientVersion; req != "" {
		if u.clientVersion == "" {
			return fmt.Errorf("%w: release requires client version >= %s and this client does not state its own",
				ErrPolicy, req)
		}
		older, err := release.Compare(u.clientVersion, req)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPolicy, err)
		}
		if older < 0 {
			return fmt.Errorf("%w: release requires client version >= %s, this client is %s",
				ErrPolicy, req, u.clientVersion)
		}
	}

	if installed == "" {
		// A first install has no version to jump from, so neither the migration
		// floor nor the downgrade rule has anything to say about it.
		return nil
	}

	newer, err := release.Newer(d.Version, installed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	if !newer && !u.policy.AllowDowngrade {
		return fmt.Errorf("%w: %s is not newer than the installed %s and downgrades are not allowed",
			ErrPolicy, d.Version, installed)
	}

	if req := d.Requirements.MinFromVersion; req != "" {
		c, err := release.Compare(installed, req)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPolicy, err)
		}
		if c < 0 {
			return fmt.Errorf("%w: release migrates only from %s or newer, this install is %s",
				ErrPolicy, req, installed)
		}
	}
	return nil
}

// inRollout reports whether this client is inside a staged rollout window.
//
// The bucket is derived locally from ClientID and never leaves the machine, so a
// canary needs no server-side cohort and no identifier on the wire (§14.5). A
// descriptor with no rollout is a full rollout: the field is optional, and its
// absence must not mean "nobody".
func (u *Updater) inRollout(d *release.Descriptor) bool {
	if d.Rollout <= 0 || d.Rollout >= 1 {
		return true
	}
	if u.clientID == "" {
		// Without a stable identifier a client cannot be assigned to a bucket
		// consistently, and one that flip-flops between checks would install a
		// canary and then be offered it again. Staying out is the stable answer.
		return false
	}
	return bucket(u.clientID, d.Version) < d.Rollout
}

// bucket maps an identifier to a uniform value in [0,1).
//
// The version is mixed in so consecutive rollouts pick different cohorts: a
// client that is unlucky once should not be first in line forever, and a client
// that is lucky once should not become a permanent canary.
func bucket(clientID, version string) float64 {
	sum := sha256.Sum256([]byte(clientID + "\x00" + version))
	n := binary.BigEndian.Uint64(sum[:8])
	return float64(n>>11) / float64(uint64(1)<<53)
}
