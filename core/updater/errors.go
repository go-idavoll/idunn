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
	"io/fs"
	"net"

	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/core/timefloor"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// The error classes of this package. They are sentinels rather than strings
// because the Reporter taxonomy is built on classification: a publisher watching
// the rolled_back rate has to be able to tell a bad release from a busy machine
// (AGENTS.md §3, docs/design.md §14.5).
var (
	// ErrConfig is an Updater that was never usable: a missing dependency, a
	// retention window with no rollback target, elevation without an elevator.
	ErrConfig = errors.New("updater configuration")

	// ErrPolicy is a release this install may not take: a downgrade, a client
	// too old for the layout, a migration floor this install is below.
	ErrPolicy = errors.New("update policy")

	// ErrBusy is a host application that would not stop writing in time.
	ErrBusy = errors.New("application busy")

	// ErrDeferred reports that the update was postponed rather than failed,
	// because the application was busy and the policy is BusyDeferToRestart.
	ErrDeferred = errors.New("update deferred to restart")

	// ErrDeclined is a Prompter that said no. It is not a failure of anything.
	ErrDeclined = errors.New("update declined")

	// ErrCheck is a Checker hook that refused the update in pre-flight.
	ErrCheck = errors.New("pre-flight check failed")

	// ErrMigrate is a Migrator hook that failed. It is its own class because it
	// is the one failure whose blast radius is outside the install root.
	ErrMigrate = errors.New("migration failed")

	// ErrVerify is a post-apply verification mismatch: what is installed is not
	// what was verified.
	ErrVerify = errors.New("post-apply verification failed")

	// ErrStale is a Release that no longer describes this install — the tree
	// changed between CheckForUpdate and Apply.
	ErrStale = errors.New("release no longer applies to this install")
)

// The Reporter error classes. They are a closed vocabulary, not free text: an
// Outcome carries no paths and no raw error strings, so these labels are all a
// publisher ever sees of a failure (§14.5).
const (
	classNone       = ""
	classCancelled  = "cancelled"
	classClockSkew  = "clock_skew"
	classNetwork    = "network"
	classVerify     = "verify"
	classResolve    = "resolve"
	classPolicy     = "policy"
	classBusy       = "busy"
	classDeclined   = "declined"
	classCheck      = "check"
	classMigrate    = "migrate"
	classDisk       = "disk"
	classPermission = "permission"
	classConfig     = "config"
	classUnknown    = "unknown"
)

// classify reduces an error to one of the classes above.
//
// The order matters: the most specific diagnosis wins. Expired metadata is
// reported as clock_skew rather than as a verification failure, because it is the
// one failure a user can usually fix themselves, and telling them "update failed"
// when the answer is "your clock is wrong" is how a fail-closed system becomes an
// unexplained one (§14.7).
func classify(err error) string {
	var netErr net.Error

	switch {
	case err == nil:
		return classNone
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return classCancelled
	case trust.IsExpiry(err), errors.Is(err, timefloor.ErrClockRollback):
		return classClockSkew
	case errors.As(err, &netErr):
		return classNetwork
	case errors.Is(err, ErrDeclined):
		return classDeclined
	case errors.Is(err, ErrDeferred), errors.Is(err, ErrBusy):
		return classBusy
	case errors.Is(err, ErrCheck):
		return classCheck
	case errors.Is(err, ErrMigrate):
		return classMigrate
	case errors.Is(err, ErrPolicy), errors.Is(err, ErrStale):
		return classPolicy
	case errors.Is(err, ErrConfig):
		return classConfig
	case errors.Is(err, ErrVerify), errors.Is(err, trust.ErrTrust):
		return classVerify
	case errors.Is(err, trust.ErrResolve):
		return classResolve
	case errors.Is(err, fs.ErrPermission):
		return classPermission
	case errors.Is(err, stage.ErrStage), errors.Is(err, txn.ErrJournal),
		errors.Is(err, layout.ErrLayout), errors.Is(err, safepath.ErrUnsafe),
		errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrExist):
		return classDisk
	default:
		return classUnknown
	}
}
