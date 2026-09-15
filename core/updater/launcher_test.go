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
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/launcherfile"
	"github.com/go-idavoll/idunn/internal/layout"
)

var rootLauncher = fsx.Join(root, "launcher")

// withLauncher is a fixture whose host ships its launcher in every release, and
// whose root holds the launcher that was installed.
func withLauncher(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, "1.2.0", "1.3.0")
	f.trust.descriptor.Files = append(f.trust.descriptor.Files, ref("targets/launcher", "bin/launcher"))
	f.trust.targets["targets/launcher"] = []byte("launcher 1.3.0")
	f.opts.Launcher = stage.Launcher{Source: "bin/launcher", Name: "launcher"}
	if err := fsx.WriteFileAtomic(f.fs, rootLauncher, []byte("launcher 1.2.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) stagedLauncher() (string, bool) {
	f.t.Helper()
	next, err := layout.LauncherNext(root, "launcher")
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := fsx.ReadFile(f.fs, next, 1<<20)
	if fsx.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw), true
}

// The launcher a release carries is staged for the next start with exactly the
// bytes the trust layer handed over — and not before the update has committed.
func TestApplyStagesTheLauncherOnlyAfterTheCommit(t *testing.T) {
	f := withLauncher(t)
	next, _ := layout.LauncherNext(root, "launcher")
	promoted := false
	f.fs.Fail = func(op, name string) error {
		if op == "rename" && name == next {
			promoted = true
			if s := journalState(t, f); s != txn.StateCommitted {
				t.Errorf("the launcher was staged while the journal is at %s", s)
			}
		}
		return nil
	}

	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	f.fs.Fail = nil
	if !promoted {
		t.Fatal("the launcher was not staged through a rename")
	}
	if got, ok := f.stagedLauncher(); !ok || got != "launcher 1.3.0" {
		t.Fatalf("staged launcher = %q (%v), want the verified bytes", got, ok)
	}
	info, err := fsx.Lstat(f.fs, next)
	if err != nil || info.Mode().Perm() != layout.MetaFileMode {
		t.Errorf("staged launcher mode = %v (%v), want %v", info.Mode().Perm(), err, layout.MetaFileMode)
	}
	if f.exists(layout.Staging(root)) {
		t.Error("the staging tree survived the commit")
	}
	// The updater stages; only the launcher swaps.
	if raw, _ := fsx.ReadFile(f.fs, rootLauncher, 1<<20); string(raw) != "launcher 1.2.0" {
		t.Errorf("the updater touched the launcher itself: %q", raw)
	}
}

// Negative: an update that does not commit stages no launcher, whatever step it
// failed in — including a launcher target the trust layer refuses.
func TestAFailedUpdateStagesNoLauncher(t *testing.T) {
	boom := errors.New("boom")
	for name, arrange := range map[string]func(f *fixture){
		"the trust layer refuses the launcher": func(f *fixture) {
			f.trust.targetErr["targets/launcher"] = boom
		},
		"a later target is refused after the launcher was staged": func(f *fixture) {
			f.trust.descriptor.Files = append(f.trust.descriptor.Files, ref("targets/late", "zz/late"))
			f.trust.targetErr["targets/late"] = boom
		},
		"the migration fails": func(f *fixture) { f.hooks.migrateEr = boom },
		"the swap fails": func(f *fixture) {
			f.fs.Fail = func(op, name string) error {
				if op == "rename" && strings.HasSuffix(name, "/"+layout.CurrentName) {
					return boom
				}
				return nil
			}
		},
		"verification after the swap fails": func(f *fixture) {
			f.opts.Policy.VerifyAfterApply = true
			f.fs.Fail = func(op, name string) error {
				if op == "rename" && strings.HasSuffix(name, "versions/1.3.0") {
					f.trust.targets["targets/app"] = []byte("something else entirely")
				}
				return nil
			}
		},
		"the install state cannot be written": func(f *fixture) {
			f.fs.Fail = func(op, name string) error {
				if op == "rename" && name == layout.State(root) {
					return boom
				}
				return nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := withLauncher(t)
			arrange(f)
			if err := f.run(); err == nil {
				t.Fatal("Apply reported success")
			}
			f.fs.Fail = nil

			if got := f.pointer(); got != "1.2.0" {
				t.Fatalf("current = %q, want the rollback", got)
			}
			if got, ok := f.stagedLauncher(); ok {
				t.Errorf("a launcher %q was staged for an update that did not commit", got)
			}
			if dir, _ := layout.LauncherPendingDir(root, "1.3.0"); f.exists(dir) {
				t.Error("the pending launcher survived the rollback")
			}
		})
	}
}

// Negative: a deferred update has not committed, so its launcher stays pending
// with the rest of the staged tree and is not offered to the next start yet.
func TestADeferredUpdateKeepsItsLauncherPending(t *testing.T) {
	f := withLauncher(t)
	f.opts.Lock = &fakeLock{heldBySomeoneElse: -1}
	f.opts.Policy.OnBusy = updater.BusyDeferToRestart
	f.opts.Policy.QuiesceTimeout = time.Millisecond
	f.opts.Now = time.Now // the wait is measured on a clock that moves.

	if err := f.run(); !errors.Is(err, updater.ErrDeferred) {
		t.Fatalf("Apply = %v, want ErrDeferred", err)
	}
	if got, ok := f.stagedLauncher(); ok {
		t.Errorf("a launcher %q was staged for a deferred update", got)
	}
	if dir, _ := layout.LauncherPendingDir(root, "1.3.0"); !f.exists(dir) {
		t.Error("the deferred update lost its pending launcher")
	}
}

// A promotion that fails after the commit does not unmake the update: it is
// reported, the pending launcher is kept, and the next recovery stages it.
func TestAFailedPromotionIsRetriedByTheNextRecovery(t *testing.T) {
	f := withLauncher(t)
	next, _ := layout.LauncherNext(root, "launcher")
	boom := errors.New("boom")
	f.fs.Fail = func(op, name string) error {
		if op == "rename" && name == next {
			return boom
		}
		return nil
	}
	if err := f.run(); err != nil {
		t.Fatalf("Apply = %v; a committed update must not fail over its launcher", err)
	}
	f.fs.Fail = nil
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q", got)
	}
	if !sawEvent(f, "could not be staged") {
		t.Errorf("the failed promotion was not reported: %+v", f.hooks.events)
	}
	if _, ok := f.stagedLauncher(); ok {
		t.Fatal("fixture: the promotion happened anyway")
	}

	if err := txn.Recover(f.fs, root, nil); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got, ok := f.stagedLauncher(); !ok || got != "launcher 1.3.0" {
		t.Errorf("after recovery the staged launcher = %q (%v)", got, ok)
	}
	if f.exists(layout.Staging(root)) {
		t.Error("the staging tree survived the recovery")
	}
}

// Negative: the launcher configuration can name one file inside a version
// directory and one file name directly in the root — nothing else.
func TestLauncherConfigurationIsValidated(t *testing.T) {
	for name, l := range map[string]stage.Launcher{
		"source escapes":           {Source: "../launcher", Name: "launcher"},
		"source escapes deeper":    {Source: "bin/../../launcher", Name: "launcher"},
		"absolute source":          {Source: "/usr/bin/launcher", Name: "launcher"},
		"source not clean":         {Source: "bin//launcher", Name: "launcher"},
		"backslash source":         {Source: `bin\launcher`, Name: "launcher"},
		"name with a separator":    {Source: "bin/launcher", Name: "bin/launcher"},
		"name escapes":             {Source: "bin/launcher", Name: ".."},
		"name is the pointer":      {Source: "bin/launcher", Name: "current"},
		"name is the meta dir":     {Source: "bin/launcher", Name: ".UPDATER"},
		"name is versions":         {Source: "bin/launcher", Name: "versions"},
		"name collides a leftover": {Source: "bin/launcher", Name: "launcher.idunn-old-1"},
		"name is a device":         {Source: "bin/launcher", Name: "NUL"},
		"only a source":            {Source: "bin/launcher"},
		"only a name":              {Name: "launcher"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			f.opts.Launcher = l
			if _, err := updater.New(f.opts); !errors.Is(err, updater.ErrConfig) {
				t.Errorf("New = %v, want ErrConfig", err)
			}
		})
	}
}

// A release that does not carry the launcher stages none. That is the ordinary
// case, not a failure.
func TestAReleaseWithoutTheLauncherStagesNone(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.Launcher = stage.Launcher{Source: "bin/launcher", Name: "launcher"}
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, ok := f.stagedLauncher(); ok {
		t.Errorf("staged %q from a release that does not carry it", got)
	}
}

// The repair from the application's side (IDN-17): a launcher an interrupted
// swap left missing is put back by the updater, because the launcher that would
// repair it at its start is the one that is not there.
func TestApplyRepairsAMissingLauncher(t *testing.T) {
	f := withLauncher(t)
	if err := f.fs.Rename(rootLauncher, rootLauncher+launcherfile.AsideSuffix+"1"); err != nil {
		t.Fatal(err)
	}
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if raw, err := fsx.ReadFile(f.fs, rootLauncher, 1<<20); err != nil || string(raw) != "launcher 1.2.0" {
		t.Fatalf("the launcher reads %q, %v; want the old one back", raw, err)
	}
	if !sawEvent(f, "was undone") {
		t.Errorf("the repair was not reported: %+v", f.hooks.events)
	}
}

// ApplyRequested repairs as well, even when there is nothing to install: that is
// the call a privileged helper makes into a root the application cannot write.
func TestApplyRequestedRepairsEvenWhenUpToDate(t *testing.T) {
	f := newFixture(t, "1.3.0", "1.3.0")
	f.opts.Launcher = stage.Launcher{Source: "bin/launcher", Name: "launcher"}
	aside := rootLauncher + launcherfile.AsideSuffix + "3"
	if err := fsx.WriteFileAtomic(f.fs, aside, []byte("launcher 1.3.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.updater().ApplyRequested(context.Background(), "1.3.0"); err != nil {
		t.Fatalf("ApplyRequested: %v", err)
	}
	if raw, err := fsx.ReadFile(f.fs, rootLauncher, 1<<20); err != nil || string(raw) != "launcher 1.3.0" {
		t.Fatalf("the launcher reads %q, %v", raw, err)
	}
}

// Negative: a repair that fails is reported and never stops the update; and an
// updater with no launcher configured, or one that elevates, repairs nothing.
func TestRepairLauncherBoundaries(t *testing.T) {
	t.Run("a failed repair does not stop the update", func(t *testing.T) {
		f := withLauncher(t)
		aside := rootLauncher + launcherfile.AsideSuffix + "1"
		if err := f.fs.Rename(rootLauncher, aside); err != nil {
			t.Fatal(err)
		}
		f.fs.Fail = func(op, name string) error {
			if op == "rename" && name == rootLauncher {
				return errors.New("sharing violation")
			}
			return nil
		}
		if err := f.run(); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !sawEvent(f, "could not be undone") {
			t.Errorf("the failed repair was not reported: %+v", f.hooks.events)
		}
	})
	t.Run("not configured", func(t *testing.T) {
		f := newFixture(t, "1.2.0", "1.3.0")
		aside := rootLauncher + launcherfile.AsideSuffix + "1"
		if err := fsx.WriteFileAtomic(f.fs, aside, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		if restored, err := f.updater().RepairLauncher(); restored || err != nil {
			t.Errorf("RepairLauncher = %v, %v", restored, err)
		}
		if !f.exists(aside) || f.exists(rootLauncher) {
			t.Error("an unconfigured updater touched the root")
		}
	})
	t.Run("elevated", func(t *testing.T) {
		f := withLauncher(t)
		f.opts.Policy.Elevation = updater.ElevationInteractive
		f.opts.Elevator = &fakeElevator{}
		if err := f.fs.Rename(rootLauncher, rootLauncher+launcherfile.AsideSuffix+"1"); err != nil {
			t.Fatal(err)
		}
		if restored, err := f.updater().RepairLauncher(); restored || err != nil {
			t.Errorf("RepairLauncher = %v, %v", restored, err)
		}
	})
}

func sawEvent(f *fixture, substr string) bool {
	for _, e := range f.hooks.events {
		if strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}
