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
	"fmt"

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
// rolled back for not confirming.
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
}

// validate checks the policy and fills in its defaults.
func (p *ProbationPolicy) validate(elevation ElevationMode) error {
	if p.Attempts == 0 {
		return nil
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
func (u *Updater) armProbation(installed, version string) error {
	pol := u.policy.Probation
	if pol.Attempts == 0 || installed == "" {
		return nil
	}
	prev, err := layout.ReadProbation(u.fs, u.root)
	if err != nil {
		return err
	}
	next := layout.Probation{
		Version:         version,
		Previous:        installed,
		Status:          layout.ProbationActive,
		AttemptsAllowed: pol.Attempts,
		RestartsAllowed: pol.Restarts,
	}
	if prev != nil {
		if prev.Status == layout.ProbationReverting {
			return fmt.Errorf("%w: rolling back %s is not finished; start the application through its launcher first",
				ErrStale, prev.Version)
		}
		next.Blocked = prev.Blocked
	}
	return layout.WriteProbation(u.fs, u.root, next)
}
