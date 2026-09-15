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

package uninstall_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/uninstall"
	"github.com/go-idavoll/idunn/internal/launcherfile"
	"github.com/go-idavoll/idunn/internal/layout"
)

const (
	root     = "/opt/acme"
	appName  = "acme-app"
	self     = root + "/launcher"
	cache    = "/home/user/.cache/idunn/installer/0123456789abcdef"
	outside  = "/srv/precious"
	userFile = root + "/notes.txt"
)

// tree builds a committed installation of 1.2.0 then 1.3.0, with everything an
// installation accumulates beside the version directories: a launcher and an
// old image of it, a staged launcher, idunn's TUF cache and clock, scratch
// files, and the installer's cache outside the root. Beside it lies a directory
// nobody may touch.
func tree(t *testing.T) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	for _, v := range []string{"1.2.0", "1.3.0"} {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatal(err)
		}
		write(t, m, fsx.Join(dir, "bin", "app"), v)
		write(t, m, fsx.Join(dir, "lib", "data.bin"), v)
	}
	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteInstall(m, root, layout.Install{Name: appName, Version: "1.3.0", LayoutSchema: release.LayoutSchema}); err != nil {
		t.Fatal(err)
	}
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted} {
		if err := j.Append(txn.Record{State: s, Name: appName, FromVersion: "1.2.0", ToVersion: "1.3.0"}); err != nil {
			t.Fatal(err)
		}
	}
	write(t, m, self, "launcher")
	write(t, m, self+launcherfile.AsideSuffix+"1", "old launcher")
	write(t, m, fsx.Join(layout.LauncherNextDir(root), "launcher"), "next launcher")
	write(t, m, fsx.Join(layout.Meta(root), layout.TrustCacheName, "root.json"), "{}")
	write(t, m, layout.Clock(root), "{}")
	write(t, m, fsx.Join(root, "current.idunn-7-1.tmp"), "scratch")
	write(t, m, fsx.Join(cache, "metadata", "timestamp.json"), "{}")
	write(t, m, fsx.Join(outside, "keep.txt"), "precious")
	return m
}

func write(t *testing.T, m *fsx.Mem, name, content string) {
	t.Helper()
	if err := m.MkdirAll(fsx.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(m, name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(t *testing.T, m *fsx.Mem, name string) bool {
	t.Helper()
	_, err := fsx.Lstat(m, name)
	if err != nil && !fsx.IsNotExist(err) {
		t.Fatalf("Lstat(%s): %v", name, err)
	}
	return err == nil
}

// noRootCheck stands in for the platform's check, which the in-memory
// filesystem has nothing to answer with.
func noRootCheck(t *testing.T) {
	uninstall.SetCheckRoot(t, func(string) error { return nil })
}

func options(m *fsx.Mem) uninstall.Options {
	return uninstall.Options{
		FS:       m,
		Root:     root,
		Name:     appName,
		Caches:   []string{cache},
		SelfPath: self,
	}
}

// intact asserts the installation is exactly as tree built it: an uninstall
// that refused must not have changed a thing.
func intact(t *testing.T, m *fsx.Mem) {
	t.Helper()
	if v, err := layout.PointerTarget(m, root); err != nil || v != "1.3.0" {
		t.Fatalf("pointer = %q, %v; want 1.3.0", v, err)
	}
	for _, name := range []string{
		fsx.Join(root, "versions", "1.2.0", "bin", "app"),
		fsx.Join(root, "versions", "1.3.0", "bin", "app"),
		layout.State(root), layout.Clock(root), self, cache,
	} {
		if !exists(t, m, name) {
			t.Fatalf("%s is gone", name)
		}
	}
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	if last, _ := j.Last(); last.State != txn.StateCommitted {
		t.Fatalf("journal = %s, want COMMITTED", last.State)
	}
}

// gone asserts that nothing of the installation is left, and that nothing
// beside it was touched.
func gone(t *testing.T, m *fsx.Mem) {
	t.Helper()
	for _, name := range []string{root, cache} {
		if exists(t, m, name) {
			t.Fatalf("%s is still there", name)
		}
	}
	if !exists(t, m, fsx.Join(outside, "keep.txt")) {
		t.Fatal("a directory beside the installation was removed")
	}
	if !exists(t, m, fsx.Dir(cache)) {
		t.Fatal("the cache's parent was removed along with the cache")
	}
}

func TestRemovesTheInstallation(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	var events []hook.Event
	o := options(m)
	o.Observe = observer(func(e hook.Event) { events = append(events, e) })

	res, err := uninstall.Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	gone(t, m)
	want := uninstall.Result{Name: appName, Version: "1.3.0", RootRemoved: true}
	if res.Name != want.Name || res.Version != want.Version || !res.RootRemoved || res.Resumed || res.SelfScheduled || len(res.Kept) != 0 {
		t.Fatalf("Result = %+v, want %+v", res, want)
	}
	if len(events) == 0 || events[len(events)-1].Phase != hook.PhaseUninstall || events[len(events)-1].Message != "uninstalled" {
		t.Fatalf("events = %+v, want uninstall events ending in \"uninstalled\"", events)
	}
}

func TestRefusesWhatIsNotAnInstallationOfThisApplication(t *testing.T) {
	noRootCheck(t)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, m *fsx.Mem) uninstall.Options
	}{
		{"another application", func(_ *testing.T, m *fsx.Mem) uninstall.Options {
			o := options(m)
			o.Name = "other-app"
			return o
		}},
		{"no install state and no journal", func(t *testing.T, m *fsx.Mem) uninstall.Options {
			if err := m.Remove(layout.State(root)); err != nil {
				t.Fatal(err)
			}
			if err := m.Remove(layout.Journal(root)); err != nil {
				t.Fatal(err)
			}
			return options(m)
		}},
		{"a root that does not exist", func(_ *testing.T, m *fsx.Mem) uninstall.Options {
			o := options(m)
			o.Root, o.SelfPath = "/opt/nothing", "/opt/nothing/launcher"
			return o
		}},
		{"a root that is a link", func(t *testing.T, m *fsx.Mem) uninstall.Options {
			if err := m.Symlink(root, "/opt/alias"); err != nil {
				t.Fatal(err)
			}
			o := options(m)
			o.Root, o.SelfPath = "/opt/alias", "/opt/alias/launcher"
			return o
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tree(t)
			o := tc.setup(t, m)
			_, err := uninstall.Run(context.Background(), o)
			if !errors.Is(err, uninstall.ErrNotInstalled) {
				t.Fatalf("Run = %v, want ErrNotInstalled", err)
			}
			for _, name := range []string{fsx.Join(root, "versions", "1.3.0", "bin", "app"), self, cache} {
				if !exists(t, m, name) {
					t.Fatalf("%s was removed by a refused uninstall", name)
				}
			}
		})
	}
}

func TestAnUnreadableJournalOrStateIsNotNothingInstalled(t *testing.T) {
	noRootCheck(t)
	for _, name := range []string{layout.Journal(root), layout.State(root)} {
		t.Run(fsx.Base(name), func(t *testing.T) {
			m := tree(t)
			write(t, m, name, "{not json")
			_, err := uninstall.Run(context.Background(), options(m))
			if err == nil || errors.Is(err, uninstall.ErrNotInstalled) {
				t.Fatalf("Run = %v, want an error that is not ErrNotInstalled", err)
			}
			if !exists(t, m, fsx.Join(root, "versions", "1.3.0", "bin", "app")) {
				t.Fatal("files were removed on the strength of an unreadable record")
			}
		})
	}
}

// Links below the root are removed as links. What they point at — a directory
// outside the installation — survives, wherever the link sits.
func TestLinksAreRemovedAndNeverFollowed(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	for _, link := range []string{
		fsx.Join(root, "versions", "1.3.0", "lib", "escape"),
		fsx.Join(root, "versions", "9.9.9"),
		fsx.Join(layout.Meta(root), "staging"),
		fsx.Join(cache, "escape"),
		fsx.Join(root, "launcher"+launcherfile.AsideSuffix+"2"),
	} {
		if err := m.Symlink(outside, link); err != nil {
			t.Fatalf("Symlink %s: %v", link, err)
		}
	}

	if _, err := uninstall.Run(context.Background(), options(m)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	gone(t, m)
	if !exists(t, m, fsx.Join(outside, "keep.txt")) {
		t.Fatal("the target of a link was removed")
	}
}

// A `versions` or meta directory that is itself a link is removed as a link.
func TestLayoutDirectoriesThatAreLinksAreNotFollowed(t *testing.T) {
	noRootCheck(t)
	for _, dir := range []string{layout.Versions(root), fsx.Join(layout.Meta(root), layout.TrustCacheName)} {
		t.Run(fsx.Base(dir), func(t *testing.T) {
			m := tree(t)
			if err := m.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			if err := m.Symlink(outside, dir); err != nil {
				t.Fatal(err)
			}
			if _, err := uninstall.Run(context.Background(), options(m)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			gone(t, m)
		})
	}
}

func TestKeepsWhatIdunnDidNotInstall(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	write(t, m, userFile, "mine")

	res, err := uninstall.Run(context.Background(), options(m))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Equal(res.Kept, []string{"notes.txt"}) || res.RootRemoved {
		t.Fatalf("Result = %+v, want notes.txt kept and the root with it", res)
	}
	if !exists(t, m, userFile) {
		t.Fatal("a file idunn did not install was removed")
	}
	entries, err := m.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("root holds %v, want only notes.txt", names)
	}
}

func TestTheApplicationMayRefuse(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	h := &hooks{refuse: errors.New("unsaved work")}
	o := options(m)
	o.Hooks = h

	if _, err := uninstall.Run(context.Background(), o); !errors.Is(err, uninstall.ErrRefused) {
		t.Fatalf("Run = %v, want ErrRefused", err)
	}
	intact(t, m)
	if h.purged != 0 {
		t.Fatal("PurgeData ran for a refused uninstall")
	}
}

func TestARunningApplicationStopsTheUninstall(t *testing.T) {
	noRootCheck(t)
	for _, tc := range []struct {
		name string
		lock *lock
		want error
	}{
		{"held by an instance", &lock{held: true}, uninstall.ErrBusy},
		{"cannot be consulted", &lock{err: errors.New("lock file unreadable")}, uninstall.ErrUninstall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tree(t)
			o := options(m)
			o.Lock = tc.lock
			if _, err := uninstall.Run(context.Background(), o); !errors.Is(err, tc.want) {
				t.Fatalf("Run = %v, want %v", err, tc.want)
			}
			intact(t, m)
		})
	}
}

func TestTheLockIsReleased(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	l := &lock{}
	o := options(m)
	o.Lock = l
	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l.locked != 1 || l.unlocked != 1 {
		t.Fatalf("lock taken %d, released %d; want 1 and 1", l.locked, l.unlocked)
	}
}

func TestPurgeRemovesTheApplicationsData(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	h := &hooks{}
	o := options(m)
	o.Hooks, o.Purge = h, true
	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if h.before != 1 || h.purged != 1 {
		t.Fatalf("BeforeUninstall %d, PurgeData %d; want 1 and 1", h.before, h.purged)
	}
	if h.root != root || h.version != "1.3.0" {
		t.Fatalf("hook context root %q version %q", h.root, h.version)
	}
	gone(t, m)
}

func TestWithoutPurgeTheDataIsLeftAlone(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	h := &hooks{}
	o := options(m)
	o.Hooks = h
	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if h.purged != 0 {
		t.Fatal("PurgeData ran without a purge")
	}
}

// A purge that fails leaves the uninstall unfinished and marked; the next run
// retries it without asking the application again whether it may.
func TestAFailedPurgeIsFinishedByTheNextRun(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	h := &hooks{purgeErr: errors.New("database locked")}
	o := options(m)
	o.Hooks, o.Purge = h, true

	if _, err := uninstall.Run(context.Background(), o); !errors.Is(err, uninstall.ErrIncomplete) {
		t.Fatalf("Run = %v, want ErrIncomplete", err)
	}
	refusesToStart(t, m)

	h.purgeErr = nil
	res, err := uninstall.Run(context.Background(), o)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !res.Resumed || h.before != 1 || h.purged != 2 {
		t.Fatalf("Resumed %v, BeforeUninstall %d, PurgeData %d; want true, 1, 2", res.Resumed, h.before, h.purged)
	}
	gone(t, m)
}

func TestAnInterruptedUpdateIsSettledFirst(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	// 1.4.0 was staged and migrated when the process died.
	dir, _ := layout.VersionDir(root, "1.4.0")
	write(t, m, fsx.Join(dir, "bin", "app"), "1.4.0")
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated} {
		if err := j.Append(txn.Record{State: s, Name: appName, FromVersion: "1.3.0", ToVersion: "1.4.0"}); err != nil {
			t.Fatal(err)
		}
	}
	mig := &migrator{}
	o := options(m)
	o.Migrate = mig

	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if mig.rolledBack != 1 {
		t.Fatalf("the interrupted migration was rolled back %d times, want 1", mig.rolledBack)
	}
	gone(t, m)
}

func TestADeferredUpdateIsDroppedWithTheInstallation(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	dir, _ := layout.VersionDir(root, "1.4.0")
	write(t, m, fsx.Join(dir, "bin", "app"), "1.4.0")
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateDeferred} {
		if err := j.Append(txn.Record{State: s, Name: appName, FromVersion: "1.3.0", ToVersion: "1.4.0"}); err != nil {
			t.Fatal(err)
		}
	}
	mig := &migrator{}
	o := options(m)
	o.Migrate = mig
	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if mig.migrated != 0 || mig.rolledBack != 0 {
		t.Fatalf("the migrator ran (migrate %d, rollback %d) for an update that never started", mig.migrated, mig.rolledBack)
	}
	gone(t, m)
}

// A crash at any point of an uninstall leaves one of two trees: the installation
// untouched, or one marked as being uninstalled that nothing will start or update.
// Running the uninstall again from either finishes it.
func TestAnUninstallInterruptedAnywhereIsFinishedByRunningItAgain(t *testing.T) {
	noRootCheck(t)

	// Count the mutating operations of a clean run.
	m := tree(t)
	ops := 0
	m.Fail = func(string, string) error { ops++; return nil }
	if _, err := uninstall.Run(context.Background(), options(m)); err != nil {
		t.Fatalf("clean Run: %v", err)
	}
	if ops < 10 {
		t.Fatalf("a clean run made only %d mutating operations; the fault injection is not reaching it", ops)
	}

	crash := errors.New("injected crash")
	for k := 1; k <= ops; k++ {
		m := tree(t)
		n := 0
		m.Fail = func(string, string) error {
			n++
			if n == k {
				return crash
			}
			return nil
		}
		res, err := uninstall.Run(context.Background(), options(m))
		m.Fail = nil

		switch {
		case err == nil:
			// The one failure an uninstall does not return: the empty root
			// itself would not go. Everything else is gone.
			if res.RootRemoved {
				t.Fatalf("op %d: a failure went unnoticed", k)
			}
			entries, rerr := m.ReadDir(root)
			if rerr != nil || len(entries) != 0 || exists(t, m, cache) {
				t.Fatalf("op %d: Run reported success with the root not empty (%v)", k, rerr)
			}
			continue
		case !errors.Is(err, crash):
			t.Fatalf("op %d: Run = %v, want the injected crash in it", k, err)
		}

		j, jerr := txn.Open(m, root)
		switch last, ok := j.Last(); {
		case jerr != nil:
			t.Fatalf("op %d: the journal is unreadable after the crash: %v", k, jerr)
		case ok && last.State == txn.StateUninstalling:
			refusesToStart(t, m)
		case ok:
			// Crashed before the record was durable: nothing may have changed.
			intact(t, m)
		default:
			// The journal is the last record to go. Without it, nothing may
			// be left that reads as an installation.
			for _, name := range []string{layout.State(root), layout.Current(root), layout.Versions(root)} {
				if exists(t, m, name) {
					t.Fatalf("op %d: the journal is gone but %s is still there", k, name)
				}
			}
		}

		if _, err := uninstall.Run(context.Background(), options(m)); err != nil {
			t.Fatalf("op %d: the second Run did not finish: %v", k, err)
		}
		gone(t, m)
	}
}

func TestOnlyTheLauncherLeftIsFinished(t *testing.T) {
	noRootCheck(t)
	m := fsx.NewMem()
	write(t, m, self, "launcher")
	if err := m.MkdirAll(layout.Meta(root), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := uninstall.Run(context.Background(), options(m))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Resumed || !res.RootRemoved || exists(t, m, root) {
		t.Fatalf("Result = %+v, root exists %v; want it finished", res, exists(t, m, root))
	}
}

// Without a launcher to finish, a directory holding only idunn-looking leftovers
// is not taken for an installation.
func TestLeftoversWithoutALauncherAreNotAnInstallation(t *testing.T) {
	noRootCheck(t)
	m := fsx.NewMem()
	if err := m.MkdirAll(layout.Meta(root), 0o755); err != nil {
		t.Fatal(err)
	}
	o := options(m)
	o.SelfPath = ""
	if _, err := uninstall.Run(context.Background(), o); !errors.Is(err, uninstall.ErrNotInstalled) {
		t.Fatalf("Run = %v, want ErrNotInstalled", err)
	}
}

func TestALauncherThatCannotGoYetIsHandedOver(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	var gotSelf, gotRoot string
	var gotRemoveRoot bool
	uninstall.SetRemoveSelf(t, func(_ fsx.FS, s, r string, removeRoot bool) (bool, error) {
		gotSelf, gotRoot, gotRemoveRoot = s, r, removeRoot
		return true, nil
	})
	res, err := uninstall.Run(context.Background(), options(m))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.SelfScheduled || res.RootRemoved {
		t.Fatalf("Result = %+v, want the launcher handed over and the root left to it", res)
	}
	if gotSelf != self || gotRoot != root || !gotRemoveRoot {
		t.Fatalf("handed over %q in %q (remove root %v)", gotSelf, gotRoot, gotRemoveRoot)
	}
	if !exists(t, m, root) || exists(t, m, layout.Versions(root)) {
		t.Fatal("the root should wait for the launcher; its contents should not")
	}
}

func TestAFailedLauncherRemovalIsIncomplete(t *testing.T) {
	noRootCheck(t)
	m := tree(t)
	uninstall.SetRemoveSelf(t, func(fsx.FS, string, string, bool) (bool, error) {
		return false, errors.New("in use")
	})
	if _, err := uninstall.Run(context.Background(), options(m)); !errors.Is(err, uninstall.ErrIncomplete) {
		t.Fatalf("Run = %v, want ErrIncomplete", err)
	}
}

func TestTheRootCheckComesFirst(t *testing.T) {
	for _, want := range []error{uninstall.ErrNotWritable, uninstall.ErrUnsafeRoot} {
		t.Run(want.Error(), func(t *testing.T) {
			uninstall.SetCheckRoot(t, func(string) error { return want })
			m := tree(t)
			if _, err := uninstall.Run(context.Background(), options(m)); !errors.Is(err, want) {
				t.Fatalf("Run = %v, want %v", err, want)
			}
			intact(t, m)
		})
	}
}

func TestOptionsAreChecked(t *testing.T) {
	noRootCheck(t)
	for _, tc := range []struct {
		name   string
		modify func(o *uninstall.Options)
	}{
		{"no filesystem", func(o *uninstall.Options) { o.FS = nil }},
		{"a filesystem without Lstat", func(o *uninstall.Options) { o.FS = noLstat{o.FS} }},
		{"no root", func(o *uninstall.Options) { o.Root = "" }},
		{"a launcher outside the root", func(o *uninstall.Options) { o.SelfPath = "/usr/bin/launcher" }},
		{"a launcher below the root", func(o *uninstall.Options) { o.SelfPath = root + "/versions/1.3.0/launcher" }},
		{"purge without a way to purge", func(o *uninstall.Options) { o.Purge = true }},
		{"a relative cache", func(o *uninstall.Options) { o.Caches = []string{"cache/idunn"} }},
		{"a top-level cache", func(o *uninstall.Options) { o.Caches = []string{"/home"} }},
		{"a volume as cache", func(o *uninstall.Options) { o.Caches = []string{"C:/"} }},
		{"the root as cache", func(o *uninstall.Options) { o.Caches = []string{root} }},
		{"a cache inside the root", func(o *uninstall.Options) { o.Caches = []string{root + "/versions"} }},
		{"a cache above the root", func(o *uninstall.Options) { o.Caches = []string{"/opt"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tree(t)
			o := options(m)
			tc.modify(&o)
			_, err := uninstall.Run(context.Background(), o)
			if !errors.Is(err, uninstall.ErrUninstall) {
				t.Fatalf("Run = %v, want a refusal", err)
			}
			intact(t, m)
		})
	}
}

// refusesToStart asserts what the launcher and the updater see in a tree an
// uninstall has marked: a refusal, not a recovery.
func refusesToStart(t *testing.T, m *fsx.Mem) {
	t.Helper()
	if _, err := txn.RecoverResult(context.Background(), m, root, nil); !errors.Is(err, txn.ErrUninstalling) {
		t.Fatalf("RecoverResult = %v, want ErrUninstalling", err)
	}
}

type observer func(hook.Event)

func (o observer) OnEvent(e hook.Event) { o(e) }

type hooks struct {
	refuse   error
	purgeErr error
	before   int
	purged   int
	root     string
	version  string
}

func (h *hooks) BeforeUninstall(hook.Context) error {
	h.before++
	return h.refuse
}

func (h *hooks) PurgeData(c hook.Context) error {
	h.purged++
	h.root, h.version = c.Root, c.FromVersion
	return h.purgeErr
}

type lock struct {
	held             bool
	err              error
	locked, unlocked int
}

func (l *lock) TryLock(context.Context) (bool, error) {
	if l.err != nil {
		return false, l.err
	}
	if l.held {
		return false, nil
	}
	l.locked++
	return true, nil
}

func (l *lock) Unlock() error { l.unlocked++; return nil }

type migrator struct{ migrated, rolledBack int }

func (m *migrator) Migrate(hook.Context) error  { m.migrated++; return nil }
func (m *migrator) Rollback(hook.Context) error { m.rolledBack++; return nil }

// noLstat hides the Lstat of the filesystem it wraps.
type noLstat struct{ fsx.FS }
