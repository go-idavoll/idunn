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

package launch_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

const (
	root    = "/opt/app"
	appName = "acme-app"
)

// migrator is the host's migration hook, writing a marker outside the install
// root — the state a deferred update exists to be able to change safely.
type migrator struct {
	fs       fsx.FS
	migrated int
	rolled   int
	err      error
	seen     string
}

func (m *migrator) Migrate(c hook.Context) error {
	m.migrated++
	m.seen = c.FromVersion + "->" + c.ToVersion
	if m.err != nil {
		return m.err
	}
	return fsx.WriteFileAtomic(m.fs, "/appdata/schema", []byte(c.ToVersion), 0o644)
}

func (m *migrator) Rollback(hook.Context) error { m.rolled++; return nil }

// lock is the host's exclusive application lock.
type lock struct {
	held     bool // held by someone else
	err      error
	attempts int
	unlocked int
}

func (l *lock) TryLock(context.Context) (bool, error) {
	l.attempts++
	return !l.held, l.err
}

func (l *lock) Unlock() error { l.unlocked++; return nil }

// events collects what the Observer was told.
type events struct{ seen []hook.Event }

func (e *events) OnEvent(ev hook.Event) { e.seen = append(e.seen, ev) }

// tree builds an install root with the given versions and `current` on one.
func tree(t *testing.T, versions []string, current string) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll("/appdata", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range versions {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fsx.WriteFileAtomic(m, fsx.Join(dir, "app"), []byte(v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := layout.SetPointer(m, root, current); err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteInstall(m, root, layout.Install{
		Name: appName, Version: current, LayoutSchema: release.LayoutSchema,
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

// deferredTree is what an update that could not quiesce leaves behind.
func deferredTree(t *testing.T) *fsx.Mem {
	t.Helper()
	m := tree(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateDeferred} {
		if err := j.Append(txn.Record{
			State: s, Name: appName, FromVersion: "1.2.0", ToVersion: "1.3.0",
		}); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func pointer(t *testing.T, m fsx.FS) string {
	t.Helper()
	v, err := layout.PointerTarget(m, root)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The ordinary start: nothing was interrupted, nothing was deferred, and the
// launcher gets out of the way.
func TestQuietStart(t *testing.T) {
	m := tree(t, []string{"1.2.0"}, "1.2.0")
	mig := &migrator{fs: m}

	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Migrate: mig})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Applied || res.Recovered || res.Skipped {
		t.Errorf("result = %+v, want nothing to do", res)
	}
	if mig.migrated != 0 {
		t.Errorf("Migrate ran %d times on a quiet start", mig.migrated)
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Errorf("current = %q, want 1.2.0", got)
	}
}

func TestWaitingReportsADeferredUpdate(t *testing.T) {
	m := deferredTree(t)

	d, err := launch.Waiting(m, root)
	if err != nil {
		t.Fatalf("Waiting: %v", err)
	}
	if d == nil {
		t.Fatal("Waiting reported nothing on a deferred tree")
	}
	if d.FromVersion != "1.2.0" || d.ToVersion != "1.3.0" || d.Name != appName {
		t.Errorf("waiting = %+v", d)
	}

	quiet := tree(t, []string{"1.2.0"}, "1.2.0")
	if d, err := launch.Waiting(quiet, root); err != nil || d != nil {
		t.Errorf("Waiting on a quiet root = %+v, %v; want nil", d, err)
	}
}

// The point of the whole exercise: what the updater could not finish while the
// application was running, the launcher finishes before it starts again.
func TestStartAppliesTheDeferredUpdate(t *testing.T) {
	m := deferredTree(t)
	mig := &migrator{fs: m}
	ev := &events{}

	res, err := launch.Start(context.Background(), launch.Options{
		FS: m, Root: root, Migrate: mig, Observe: ev,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !res.Applied || res.ToVersion != "1.3.0" {
		t.Fatalf("result = %+v, want 1.3.0 applied", res)
	}
	if got := pointer(t, m); got != "1.3.0" {
		t.Errorf("current = %q, want 1.3.0", got)
	}
	if mig.migrated != 1 || mig.seen != "1.2.0->1.3.0" {
		t.Errorf("migrator: %d runs, saw %q", mig.migrated, mig.seen)
	}
	// The host's own state moved with it.
	raw, err := fsx.ReadFile(m, "/appdata/schema", 64)
	if err != nil || string(raw) != "1.3.0" {
		t.Errorf("host state = %q (%v), want 1.3.0", raw, err)
	}
	in, err := layout.ReadInstall(m, root)
	if err != nil || in == nil || in.Version != "1.3.0" {
		t.Errorf("install state = %+v (%v)", in, err)
	}
	if len(ev.seen) == 0 {
		t.Error("the observer was told nothing about a slow start")
	}
}

// A second start has nothing left to do. A launcher runs on every start, so
// doing nothing has to be the cheap, silent, reliable case.
func TestStartIsIdempotent(t *testing.T) {
	m := deferredTree(t)
	mig := &migrator{fs: m}
	o := launch.Options{FS: m, Root: root, Migrate: mig}

	if _, err := launch.Start(context.Background(), o); err != nil {
		t.Fatalf("first start: %v", err)
	}
	res, err := launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if res.Applied {
		t.Error("the second start applied the update again")
	}
	if mig.migrated != 1 {
		t.Errorf("Migrate ran %d times across two starts, want once", mig.migrated)
	}
}

// The lock is the proof that nothing is running. Without it the launcher would
// migrate host state under a live application — the exact situation the deferral
// was protecting against.
func TestStartLeavesTheUpdateWhenAnInstanceIsRunning(t *testing.T) {
	m := deferredTree(t)
	mig := &migrator{fs: m}
	l := &lock{held: true}

	res, err := launch.Start(context.Background(), launch.Options{
		FS: m, Root: root, Migrate: mig, Lock: l,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !res.Skipped || res.Applied {
		t.Fatalf("result = %+v, want the update skipped", res)
	}
	if mig.migrated != 0 {
		t.Error("the migration ran while another instance holds the lock")
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Errorf("current = %q; the swap must not happen either", got)
	}
	// And it is still waiting, so the next start can finish it.
	if d, err := launch.Waiting(m, root); err != nil || d == nil {
		t.Errorf("the deferred update was lost: %+v, %v", d, err)
	}
}

// A lock this start took is a lock it releases.
func TestStartReleasesTheLock(t *testing.T) {
	m := deferredTree(t)
	l := &lock{}

	if _, err := launch.Start(context.Background(), launch.Options{
		FS: m, Root: root, Migrate: &migrator{fs: m}, Lock: l,
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if l.unlocked != 1 {
		t.Errorf("the lock was released %d times, want once", l.unlocked)
	}
}

// A lock that cannot be consulted is not an answer. Proceeding would mean
// migrating on the strength of a question nobody answered.
func TestStartStopsWhenTheLockCannotBeConsulted(t *testing.T) {
	m := deferredTree(t)
	mig := &migrator{fs: m}

	_, err := launch.Start(context.Background(), launch.Options{
		FS: m, Root: root, Migrate: mig, Lock: &lock{err: errors.New("no lock file")},
	})
	if err == nil {
		t.Fatal("Start succeeded although the lock could not be consulted")
	}
	if mig.migrated != 0 {
		t.Error("the migration ran anyway")
	}
}

// A failed migration leaves the update deferred: the tree is still good, and the
// next start may well work. What it must not do is lose the update or leave the
// install half-moved.
func TestStartKeepsTheUpdateWhenMigrationFails(t *testing.T) {
	m := deferredTree(t)
	mig := &migrator{fs: m, err: errors.New("the database is locked")}

	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Migrate: mig})
	if err == nil {
		t.Fatal("a failed migration was reported as a successful start")
	}
	if res.Applied {
		t.Error("the result claims the update was applied")
	}
	if got := pointer(t, m); got != "1.2.0" {
		t.Errorf("current = %q, want the untouched 1.2.0", got)
	}
	if d, err := launch.Waiting(m, root); err != nil || d == nil {
		t.Errorf("the deferred update was lost: %+v, %v", d, err)
	}
}

// An interrupted transaction is settled first — that is recovery's job, and it
// happens on every start whether or not anything was deferred.
func TestStartRecoversAnInterruptedTransaction(t *testing.T) {
	m := tree(t, []string{"1.2.0", "1.3.0"}, "1.3.0")
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	// A crash between the swap and the commit: `current` is already on 1.3.0.
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped} {
		if err := j.Append(txn.Record{
			State: s, Name: appName, FromVersion: "1.2.0", ToVersion: "1.3.0",
		}); err != nil {
			t.Fatal(err)
		}
	}

	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Migrate: &migrator{fs: m}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !res.Recovered {
		t.Error("the interrupted transaction was not reported as recovered")
	}
	if in, err := layout.ReadInstall(m, root); err != nil || in == nil || in.Version != "1.3.0" {
		t.Errorf("install state = %+v (%v), want the completed 1.3.0", in, err)
	}
}

func TestStartRequiresItsInputs(t *testing.T) {
	m := tree(t, []string{"1.2.0"}, "1.2.0")
	for _, tt := range []struct {
		name string
		o    launch.Options
	}{
		{"no filesystem", launch.Options{Root: root}},
		{"no root", launch.Options{FS: m}},
		{"one retained version leaves no rollback target", launch.Options{FS: m, Root: root, RetainVersions: 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := launch.Start(context.Background(), tt.o); !errors.Is(err, launch.ErrLaunch) {
				t.Fatalf("err = %v, want ErrLaunch", err)
			}
		})
	}
}

func TestWaitingRequiresItsInputs(t *testing.T) {
	if _, err := launch.Waiting(nil, root); !errors.Is(err, launch.ErrLaunch) {
		t.Errorf("err = %v, want ErrLaunch", err)
	}
	if _, err := launch.Waiting(fsx.NewMem(), ""); !errors.Is(err, launch.ErrLaunch) {
		t.Errorf("err = %v, want ErrLaunch", err)
	}
}

// Old versions are pruned once the deferred update is committed — but only then,
// so the rollback target is never removed before there is something to roll back
// from.
func TestStartCollectsOldVersionsAfterApplying(t *testing.T) {
	m := tree(t, []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0"}, "1.2.0")
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateDeferred} {
		if err := j.Append(txn.Record{
			State: s, Name: appName, FromVersion: "1.2.0", ToVersion: "1.3.0",
		}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := launch.Start(context.Background(), launch.Options{
		FS: m, Root: root, Migrate: &migrator{fs: m}, RetainVersions: 2,
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The live version and one rollback target survive.
	for _, v := range []string{"1.3.0", "1.2.0"} {
		dir, _ := layout.VersionDir(root, v)
		if _, err := m.Stat(dir); err != nil {
			t.Errorf("%s was collected: %v", v, err)
		}
	}
	for _, v := range []string{"1.0.0", "1.1.0"} {
		dir, _ := layout.VersionDir(root, v)
		if _, err := m.Stat(dir); err == nil {
			t.Errorf("%s survived garbage collection", v)
		}
	}
}
