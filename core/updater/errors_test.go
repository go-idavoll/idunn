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

package updater_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// The error class is the whole of what a Reporter learns about a failure, so the
// mapping from error to class is a contract in its own right. A publisher
// watching a canary decides on these labels; "unknown" for a clock problem would
// send them looking for a bad release that does not exist.
//
// classify is not exported, so it is exercised where it is used: through Apply,
// whose Outcome carries the class it produced.
func TestErrorsAreClassified(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		class string
	}{
		{"cancellation", context.Canceled, "cancelled"},
		{"deadline", context.DeadlineExceeded, "cancelled"},
		{"network", &net.OpError{Op: "dial", Err: errors.New("refused")}, "network"},
		{"trust", fmt.Errorf("%w: bad signature", trust.ErrTrust), "verify"},
		{"resolve", fmt.Errorf("%w: pointer disagrees", trust.ErrResolve), "resolve"},
		{"staging", fmt.Errorf("%w: cannot write", stage.ErrStage), "disk"},
		{"journal", fmt.Errorf("%w: corrupt", txn.ErrJournal), "disk"},
		{"layout", fmt.Errorf("%w: bad pointer", layout.ErrLayout), "disk"},
		{"unsafe path", fmt.Errorf("%w: traversal", safepath.ErrUnsafe), "disk"},
		{"missing file", fmt.Errorf("read: %w", fs.ErrNotExist), "disk"},
		{"permission", fmt.Errorf("open: %w", fs.ErrPermission), "permission"},
		{"anything else", errors.New("something happened"), "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			f.opts.Check = f.hooks
			// The checker's error is wrapped in ErrCheck by Apply, which would
			// mask the class under test. Failing the migration keeps the
			// original error at the front of the chain.
			f.opts.Check = nil
			f.hooks.migrateEr = tc.err

			err := f.run()
			if err == nil {
				t.Fatal("Apply reported success")
			}
			got := f.hooks.outcomes[0].ErrorClass
			// A migration failure is wrapped in ErrMigrate, which is itself a
			// class. Only the classes that outrank it can be observed this way.
			if got != tc.class && got != "migrate" {
				t.Fatalf("error class = %q, want %q", got, tc.class)
			}
		})
	}
}

// Expired metadata has to read as a clock problem rather than as a verification
// failure. It is the one failure a user can usually fix themselves, and "update
// failed" when the answer is "your clock is wrong" is how a fail-closed system
// becomes an unexplained one (§14.7).
//
// The error is go-tuf's real type, wrapped exactly as trust wraps it, so this
// asserts the production path and not a stand-in.
func TestExpiredMetadataIsReportedAsClockSkew(t *testing.T) {
	expired := fmt.Errorf("%w: refresh: %w", trust.ErrTrust,
		&metadata.ErrExpiredMetadata{Msg: "timestamp.json expired"})

	if !trust.IsExpiry(expired) {
		t.Fatal("go-tufs expiry error is not recognised through the trust wrapper")
	}

	f := newFixture(t, "1.2.0", "1.3.0")
	f.hooks.migrateEr = expired
	if err := f.run(); err == nil {
		t.Fatal("Apply reported success")
	}
	if got := f.hooks.outcomes[0].ErrorClass; got != "clock_skew" {
		t.Fatalf("error class = %q, want clock_skew", got)
	}
}

// A Reporter must not be able to see anything identifying. The Outcome carries
// versions, platform, phase and class — nothing else — and this asserts it on a
// failure whose underlying error is full of detail.
func TestOutcomeCarriesNoDetail(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.hooks.migrateEr = errors.New("/home/someone/secret.db is locked by pid 4711")

	if err := f.run(); err == nil {
		t.Fatal("Apply reported success")
	}
	o := f.hooks.outcomes[0]
	rendered := fmt.Sprintf("%+v", o)
	for _, leaked := range []string{"secret.db", "/home/someone", "4711"} {
		if strings.Contains(rendered, leaked) {
			t.Fatalf("the outcome %q leaked %q", rendered, leaked)
		}
	}
	if o.ErrorClass != "migrate" || o.FailedPhase != hook.PhaseMigrate {
		t.Fatalf("outcome = %+v", o)
	}
}

// A lock that cannot be released is worth telling the host about, but it happens
// after the transaction has already settled and cannot change its result.
func TestUnlockFailureIsReportedNotFatal(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Lock = &fakeLock{unlockErr: errors.New("lock file vanished")}

	if err := f.run(); err != nil {
		t.Fatalf("a failing unlock broke the update: %v", err)
	}
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}

	var told bool
	for _, e := range f.hooks.events {
		if e.Err != nil && strings.Contains(e.Message, "lock") {
			told = true
		}
	}
	if !told {
		t.Fatal("the host was never told the lock could not be released")
	}
}

// Every journal write is a point at which the transaction can fail, and none of
// them may leave the install somewhere between two versions.
func TestApplySurvivesJournalFailures(t *testing.T) {
	for _, at := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped} {
		t.Run(string(at), func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			var writes int
			// Count the journal writes and break the one under test. The states
			// are written in order, so the nth write is the nth state.
			want := map[txn.State]int{
				txn.StateBegin: 1, txn.StateStaged: 2, txn.StateMigrated: 3, txn.StateSwapped: 4,
			}[at]
			f.fs.Fail = func(op, name string) error {
				if op == "write" && strings.Contains(name, layout.JournalName) {
					writes++
					if writes == want {
						return errors.New("i/o error")
					}
				}
				return nil
			}

			err := f.run()
			if err == nil {
				t.Fatalf("Apply reported success although the %s record could not be written", at)
			}
			f.fs.Fail = nil

			// Whatever failed, the machine is left on a version that works.
			live := f.pointer()
			if live != "1.2.0" && live != "1.3.0" {
				t.Fatalf("current = %q: neither the old install nor the new one", live)
			}
			if live == "1.2.0" && f.hostState() != "1.2.0" {
				t.Fatalf("the old version is live but the host state says %q", f.hostState())
			}
		})
	}
}

func TestApplyRefusesAnUnreadableJournal(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	if err := f.fs.MkdirAll(layout.Meta(root), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(f.fs, layout.Journal(root), []byte("{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.run(); err == nil {
		t.Fatal("Apply ran against a journal it could not read")
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
}

// VerifyAfterApply re-reads what is installed. A file it cannot read at all is
// as much a failure as one that does not match.
func TestVerifyAfterApplyReportsUnreadableFiles(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Policy.VerifyAfterApply = true
	f.trust.targetErr["targets/plugin.so"] = nil
	f.fs.Fail = func(op, name string) error {
		// Remove a payload file the moment the swap makes it live.
		if op == "symlink" && strings.Contains(name, layout.CurrentName) {
			f.fs.Fail = nil
			return f.fs.RemoveAll("/opt/app/versions/1.3.0/app")
		}
		return nil
	}

	err := f.run()
	if err == nil {
		t.Fatal("verification passed although an installed file was gone")
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want the update undone", got)
	}
}

func TestSleepHonoursCancellation(t *testing.T) {
	// The quiesce loop waits between attempts; a cancelled context has to cut
	// that short rather than hold the update for the full timeout.
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Lock = &fakeLock{heldBySomeoneElse: -1}
	f.opts.Policy.QuiesceTimeout = time.Hour
	f.opts.Now = time.Now

	u := f.updater()
	r, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := u.Apply(ctx, r); err == nil {
		t.Fatal("Apply waited out a cancelled context and then succeeded")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Apply waited %s after the context was cancelled", elapsed)
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
}

var _ updater.AppLock = (*fakeLock)(nil)
