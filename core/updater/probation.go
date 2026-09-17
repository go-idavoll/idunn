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
	"fmt"

	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/layout"
)

// DefaultProbationRestarts is how many restarts a version on probation may ask
// for through launch.Relaunch when ProbationPolicy.Restarts is left at zero.
const DefaultProbationRestarts = 3

// ProbationPolicy makes a committed update prove itself (IDN-39).
//
// With Attempts set, every update this Updater commits is recorded as on
// probation. The launcher counts each start of the new version; the application
// ends the probation with launch.MarkHealthy once it is actually working. A
// version that is started Attempts times without confirming, or that reports
// launch.MarkUnhealthy, is rolled back to the version it replaced at the next
// start and not installed again — a newer release is.
//
// The zero value is off, and off is what a host gets that never calls
// MarkHealthy: an application that does not know about probation must not be
// rolled back for not confirming. That includes a release whose publisher asks
// for probation: the release's signed policy is followed only by a host that
// says so (FollowRelease), because the one who knows whether the application
// confirms is the host, not whoever signs the release.
//
// The version rolled back to has to honour the block too, and only a version
// built with this library does: an older one installs the blocked version again,
// and the launcher rolls it back again at the next start. Turn probation on in a
// release whose predecessor already understands it.
type ProbationPolicy struct {
	// Attempts is how many launcher starts a new version gets to confirm it is
	// healthy, 1 to layout.MaxProbationAttempts. Zero turns probation off. Size
	// it for users closing the application before it confirms and for machines
	// losing power: 3 is a sensible floor.
	Attempts int

	// Restarts is how many restarts the version may ask for through
	// launch.Relaunch while on probation — a migration that needs several
	// starts — without spending attempts. Zero selects
	// DefaultProbationRestarts; at most layout.MaxProbationRestarts.
	Restarts int

	// FollowRelease lets each release's signed policy decide
	// (release.PolicyPath): a release that states a probation allowance gets
	// that allowance — including none at all — and Attempts and Restarts above
	// apply only to a release that states nothing. The trust client must be a
	// PolicyResolver.
	FollowRelease bool

	// MaxAttempts caps the attempts any release gets on this host, 0 for no
	// cap — a canary fleet that should fall back after one bad start whatever
	// the publisher allows. It applies to the release's allowance and bounds
	// Attempts, which may not exceed it.
	MaxAttempts int
}

// PolicyResolver is the optional capability of resolving a release's signed
// policy, nil when the release has none. *trust.Client implements it.
type PolicyResolver interface {
	ReleasePolicy(goos, goarch, version string) (*release.Policy, error)
}

// validate checks the policy and fills in its defaults.
func (p *ProbationPolicy) validate(elevation ElevationMode, trust Resolver) error {
	if p.MaxAttempts < 0 || p.MaxAttempts > layout.MaxProbationAttempts {
		return fmt.Errorf("%w: probation max attempts %d is not within 0..%d", ErrConfig, p.MaxAttempts, layout.MaxProbationAttempts)
	}
	if p.Attempts == 0 && !p.FollowRelease {
		return nil
	}
	if p.FollowRelease {
		if _, ok := trust.(PolicyResolver); !ok {
			return fmt.Errorf("%w: probation follows the release, but the trust client cannot resolve release policies", ErrConfig)
		}
	}
	if p.MaxAttempts > 0 && p.Attempts > p.MaxAttempts {
		return fmt.Errorf("%w: probation attempts %d exceed the host's own ceiling of %d", ErrConfig, p.Attempts, p.MaxAttempts)
	}
	if p.Attempts < 0 || p.Attempts > layout.MaxProbationAttempts {
		return fmt.Errorf("%w: probation attempts %d is not within 1..%d", ErrConfig, p.Attempts, layout.MaxProbationAttempts)
	}
	if p.Restarts == 0 {
		p.Restarts = DefaultProbationRestarts
	}
	if p.Restarts < 0 || p.Restarts > layout.MaxProbationRestarts {
		return fmt.Errorf("%w: probation restarts %d is not within 1..%d", ErrConfig, p.Restarts, layout.MaxProbationRestarts)
	}
	if elevation != ElevationNone {
		// The launcher counts attempts and the application confirms by writing
		// under the root, which in a system-wide install neither of them can
		// (IDN-23). A policy that could never act is refused, not ignored.
		return fmt.Errorf("%w: probation is not supported for an install root this process cannot write", ErrConfig)
	}
	return nil
}

// blocked returns why version must not be installed, or "" when it may be: it
// is the version the last failed probation rolled back.
func (u *Updater) blocked(version string) (string, error) {
	p, err := layout.ReadProbation(u.fs, u.root)
	if err != nil {
		return "", err
	}
	if p == nil || p.Blocked == nil || p.Blocked.Version != version {
		return "", nil
	}
	return p.Blocked.Reason, nil
}

// armProbation records that the version this transaction installs is on
// probation once it is live.
//
// It is written before the transaction begins, and that is safe because the
// launcher acts on a record only while `current` names its version: if the
// transaction rolls back, the record describes a version that never went live
// and is ignored; if it defers, the launcher that applies it finds the record
// waiting. Written after the commit instead, a crash in between would leave a
// committed version nobody watches — and a deferred update, committed by the
// launcher, would get no record at all.
//
// A record of an unfinished rollback is not replaced: it is what makes that
// rollback finish, and the launcher that finishes it runs before any update.
// The blocked version survives every new record.
func (u *Updater) armProbation(installed string, d *release.Descriptor) error {
	if installed == "" {
		return nil
	}
	attempts, restarts, err := u.probationFor(d)
	if err != nil || attempts == 0 {
		return err
	}
	version := d.Version
	prev, err := layout.ReadProbation(u.fs, u.root)
	if err != nil {
		return err
	}
	next := layout.Probation{
		Version:         version,
		Previous:        installed,
		Status:          layout.ProbationActive,
		AttemptsAllowed: attempts,
		RestartsAllowed: restarts,
	}
	if prev != nil {
		if prev.Status == layout.ProbationReverting {
			return fmt.Errorf("%w: rolling back %s is not finished; start the application through its launcher first",
				ErrStale, prev.Version)
		}
		next.Blocked = prev.Blocked
		// An update over a version that never confirmed does not make that
		// version the one to fall back to: it may be the very version this
		// update fixes. The new probation returns to what the unconfirmed one
		// would have returned to — the last version known to work here —
		// which GC has kept pinned all along.
		unconfirmed := prev.Status == layout.ProbationActive || prev.Status == layout.ProbationUnhealthy
		if unconfirmed && prev.Version == installed && prev.Previous != version && u.versionInstalled(prev.Previous) {
			next.Previous = prev.Previous
		}
	}
	return layout.WriteProbation(u.fs, u.root, next)
}

// probationFor is the allowance the release d is installed with: its own signed
// policy where the host follows releases and the release states one, the host's
// policy otherwise. Zero attempts means no probation.
//
// A policy that is published and cannot be resolved fails the update, like any
// other target that cannot be: installing the release without the probation its
// publisher asked for would be deciding on less than the signed metadata says.
func (u *Updater) probationFor(d *release.Descriptor) (attempts, restarts int, err error) {
	pol := u.policy.Probation
	attempts, restarts = pol.Attempts, pol.Restarts
	if pol.FollowRelease {
		// New refused FollowRelease without a PolicyResolver.
		resolver, ok := u.trust.(PolicyResolver)
		if !ok {
			return 0, 0, fmt.Errorf("%w: the trust client cannot resolve release policies", ErrConfig)
		}
		p, err := resolver.ReleasePolicy(u.goos, u.goarch, d.Version)
		if err != nil {
			return 0, 0, err
		}
		if p != nil && p.Probation != nil {
			attempts = p.Probation.Attempts
			if p.Probation.Restarts != 0 {
				restarts = p.Probation.Restarts
			}
		}
	}
	if pol.MaxAttempts > 0 && attempts > pol.MaxAttempts {
		attempts = pol.MaxAttempts
	}
	if restarts == 0 {
		restarts = DefaultProbationRestarts
	}
	return attempts, restarts, nil
}

// reportProbationOutcomes hands the failed probations the launcher left behind
// to the Reporter (§14.5, IDN-39).
//
// A rollback happens in the launcher, which has neither a Reporter nor a
// network, and the version it leaves running is the one whose updater reports
// it — at its next check, the call a host makes anyway. The outcome carries a
// class from a closed vocabulary, never the application's reason.
//
// Each outcome is removed once reported. One the Reporter refuses stays and is
// offered again at the next check; one that cannot be read is removed, because
// telemetry that never parses would otherwise be retried forever. Like every
// report it is best-effort and never affects the check. An elevated host leaves
// them alone: it could not remove them, and would report them on every check.
func (u *Updater) reportProbationOutcomes(ctx context.Context) {
	if u.report == nil || u.policy.Elevation != ElevationNone {
		return
	}
	names, err := layout.ProbationOutcomeNames(u.fs, u.root)
	if err != nil {
		u.emit(hook.PhaseProbation, "the failed probations could not be listed", err)
		return
	}
	for _, name := range names {
		o, err := layout.ReadProbationOutcome(u.fs, u.root, name)
		if err != nil {
			u.emit(hook.PhaseProbation, "an unreadable probation outcome was dropped", err)
			_ = layout.RemoveProbationOutcome(u.fs, u.root, name)
			continue
		}
		if err := u.report.Report(context.WithoutCancel(ctx), hook.Outcome{
			FromVersion: o.FromVersion,
			ToVersion:   o.ToVersion,
			OS:          o.OS,
			Arch:        o.Arch,
			Result:      o.Result,
			FailedPhase: hook.PhaseProbation,
			ErrorClass:  o.Class,
			At:          o.At,
		}); err != nil {
			u.emit(hook.PhaseProbation, "reporting a failed probation failed; it is offered again at the next check", err)
			return
		}
		if err := layout.RemoveProbationOutcome(u.fs, u.root, name); err != nil {
			u.emit(hook.PhaseProbation, "a reported probation outcome could not be removed", err)
			return
		}
	}
}

// versionInstalled reports whether version still has its directory under the
// root — a record written before GC pinned it may name one that is gone.
func (u *Updater) versionInstalled(version string) bool {
	dir, err := layout.VersionDir(u.root, version)
	if err != nil {
		return false
	}
	_, err = u.fs.Stat(dir)
	return err == nil
}
