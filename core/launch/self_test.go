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
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/launcherfile"
	"github.com/go-idavoll/idunn/internal/layout"
)

const shimName = "launcher"

var shim = fsx.Join(root, shimName)

// stageNext puts a launcher where a committed update stages it.
func stageNext(t *testing.T, m *fsx.Mem, name, data string) string {
	t.Helper()
	next, err := layout.LauncherNext(root, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MkdirAll(layout.LauncherNextDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(m, next, []byte(data), layout.MetaFileMode); err != nil {
		t.Fatal(err)
	}
	return next
}

// selfFixture is an install with version 1.3.0 live, a launcher at the top of the
// root (unless installed is empty), and a staged launcher (unless staged is
// empty).
func selfFixture(t *testing.T, staged, installed string) (*fsx.Mem, launch.Options) {
	t.Helper()
	m := tree(t, []string{"1.3.0"}, "1.3.0")
	if installed != "" {
		if err := fsx.WriteFileAtomic(m, shim, []byte(installed), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if staged != "" {
		stageNext(t, m, shimName, staged)
	}
	return m, launch.Options{FS: m, Root: root, SelfPath: shim}
}

func readFile(t *testing.T, f fsx.FS, name string) string {
	t.Helper()
	raw, err := fsx.ReadFile(f, name, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(raw)
}

func exists(t *testing.T, f fsx.FS, name string) bool {
	t.Helper()
	_, err := fsx.Lstat(f, name)
	if err != nil && !fsx.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// start runs Start and fails the test if it returns an error: nothing about the
// launcher may ever make a start fail.
func start(t *testing.T, o launch.Options) launch.Result {
	t.Helper()
	res, err := launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return res
}

// rootEntries lists the top level of the root, to show nothing was left behind.
func rootEntries(t *testing.T, m *fsx.Mem) []string {
	t.Helper()
	entries, err := m.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func journal(t *testing.T, m *fsx.Mem, from, to string, states ...txn.State) {
	t.Helper()
	j, err := txn.Open(m, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		if err := j.Append(txn.Record{State: s, Name: appName, FromVersion: from, ToVersion: to}); err != nil {
			t.Fatal(err)
		}
	}
}

func pending(t *testing.T, m *fsx.Mem, version, data string) {
	t.Helper()
	if err := layout.WriteLauncherPending(m, root, version, shimName, []byte(data)); err != nil {
		t.Fatal(err)
	}
}

// The launcher a committed update staged is swapped in at the next start, and
// the staged file goes once it has been.
func TestTheStagedLauncherIsSwappedIn(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")
	ev := &events{}
	o.Observe = ev

	res := start(t, o)
	if !res.SelfReplaced || res.SelfErr != nil {
		t.Fatalf("SelfReplaced = %v, SelfErr = %v", res.SelfReplaced, res.SelfErr)
	}
	if got := readFile(t, m, shim); got != "launcher v2" {
		t.Errorf("the launcher reads %q, want the staged one", got)
	}
	if next, _ := layout.LauncherNext(root, shimName); exists(t, m, next) {
		t.Error("the staged launcher survived the swap")
	}
	if !saw(ev, "replaced") {
		t.Errorf("the replacement was not reported: %+v", ev.seen)
	}
	// And the start after that has nothing to do.
	if res := start(t, o); res.SelfReplaced || res.SelfErr != nil {
		t.Errorf("second start: SelfReplaced = %v, SelfErr = %v", res.SelfReplaced, res.SelfErr)
	}
}

// The size bounds are inclusive where a launcher can be: one byte and exactly the
// limit are swapped in; the empty and the over-limit file are refused
// (TestAStagedLauncherThatIsNotAPlainFileIsRefused).
func TestAStagedLauncherAtTheSizeBoundsIsSwappedIn(t *testing.T) {
	for name, staged := range map[string]string{
		"one byte":          "x",
		"exactly the limit": strings.Repeat("x", 64<<20),
	} {
		t.Run(name, func(t *testing.T) {
			m, o := selfFixture(t, staged, "launcher v1")
			res := start(t, o)
			if !res.SelfReplaced || res.SelfErr != nil {
				t.Fatalf("SelfReplaced = %v, SelfErr = %v", res.SelfReplaced, res.SelfErr)
			}
			info, err := fsx.Lstat(m, shim)
			if err != nil || info.Size() != int64(len(staged)) {
				t.Errorf("the launcher is %v (%v), want the staged %d bytes", info, err, len(staged))
			}
		})
	}
}

// A launcher that already matches the staged one — a start that died after the
// swap but before it removed the staged file — is not rewritten; only the staged
// file goes.
func TestAnAlreadySwappedLauncherIsNotRewritten(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v2")
	m.Fail = func(op, name string) error {
		if op != "open" && strings.HasPrefix(name, shim) {
			t.Errorf("%s %s: an unchanged launcher was touched", op, name)
		}
		return nil
	}
	if res := start(t, o); res.SelfReplaced || res.SelfErr != nil {
		t.Errorf("SelfReplaced = %v, SelfErr = %v", res.SelfReplaced, res.SelfErr)
	}
	m.Fail = nil
	if next, _ := layout.LauncherNext(root, shimName); exists(t, m, next) {
		t.Error("the staged launcher was left behind")
	}
}

// Nothing staged is the ordinary start, not a failure — and neither is a host
// that did not name its launcher, whatever is staged.
func TestNothingStagedOrNotConfiguredChangesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		staged string
		clear  bool
	}{
		"nothing staged":   {},
		"no SelfPath":      {staged: "launcher v2", clear: true},
		"an invalid name":  {staged: "launcher v2"},
		"staged elsewhere": {staged: "launcher v2"},
	} {
		t.Run(name, func(t *testing.T) {
			m, o := selfFixture(t, tc.staged, "launcher v1")
			if tc.clear {
				o.SelfPath = ""
			}
			if name == "an invalid name" {
				o.SelfPath = fsx.Join(root, "current")
			}
			if name == "staged elsewhere" {
				// A second binary in the root: the launcher staged for "launcher"
				// is not its to take.
				other := fsx.Join(root, "acme-cli")
				if err := fsx.WriteFileAtomic(m, other, []byte("cli v1"), 0o755); err != nil {
					t.Fatal(err)
				}
				o.SelfPath = other
			}
			if res := start(t, o); res.SelfReplaced || res.SelfErr != nil {
				t.Errorf("SelfReplaced = %v, SelfErr = %v", res.SelfReplaced, res.SelfErr)
			}
			if got := readFile(t, m, shim); got != "launcher v1" {
				t.Errorf("the launcher reads %q, want it untouched", got)
			}
			if name == "staged elsewhere" && readFile(t, m, fsx.Join(root, "acme-cli")) != "cli v1" {
				t.Error("the second binary took the launcher staged for another name")
			}
		})
	}
}

// Negative: only a plain file staged for this launcher, in the root it serves, is
// swapped in. Each case offers something else and must leave the launcher as it
// was, report ErrSelfRefused — and still start.
func TestAStagedLauncherThatIsNotAPlainFileIsRefused(t *testing.T) {
	next, _ := layout.LauncherNext(root, shimName)
	for name, setup := range map[string]func(t *testing.T, m *fsx.Mem, o *launch.Options){
		"a symlink as the staged file": func(t *testing.T, m *fsx.Mem, _ *launch.Options) {
			if err := fsx.WriteFileAtomic(m, "/appdata/evil", []byte("launcher ev"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := m.Remove(next); err != nil {
				t.Fatal(err)
			}
			if err := m.Symlink("/appdata/evil", next); err != nil {
				t.Fatal(err)
			}
		},
		"a directory as the staged file": func(t *testing.T, m *fsx.Mem, _ *launch.Options) {
			if err := m.Remove(next); err != nil {
				t.Fatal(err)
			}
			if err := m.MkdirAll(next, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink as the staging directory": func(t *testing.T, m *fsx.Mem, _ *launch.Options) {
			if err := m.MkdirAll("/appdata/next", 0o700); err != nil {
				t.Fatal(err)
			}
			if err := fsx.WriteFileAtomic(m, "/appdata/next/"+shimName, []byte("launcher ev"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := m.RemoveAll(layout.LauncherNextDir(root)); err != nil {
				t.Fatal(err)
			}
			if err := m.Symlink("/appdata/next", layout.LauncherNextDir(root)); err != nil {
				t.Fatal(err)
			}
		},
		"an empty staged file": func(t *testing.T, m *fsx.Mem, _ *launch.Options) {
			if err := fsx.WriteFileAtomic(m, next, nil, layout.MetaFileMode); err != nil {
				t.Fatal(err)
			}
		},
		"a staged file too large to be a launcher": func(t *testing.T, m *fsx.Mem, _ *launch.Options) {
			if err := fsx.WriteFileAtomic(m, next, make([]byte, 64<<20+1), layout.MetaFileMode); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink at the launcher's name": func(t *testing.T, m *fsx.Mem, _ *launch.Options) {
			if err := fsx.WriteFileAtomic(m, "/appdata/real", []byte("launcher v1"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := m.Remove(shim); err != nil {
				t.Fatal(err)
			}
			if err := m.Symlink("/appdata/real", shim); err != nil {
				t.Fatal(err)
			}
		},
		"a directory at the launcher's name": func(t *testing.T, m *fsx.Mem, _ *launch.Options) {
			if err := m.Remove(shim); err != nil {
				t.Fatal(err)
			}
			if err := m.MkdirAll(shim, 0o755); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, o := selfFixture(t, "launcher v2", "launcher v1")
			setup(t, m, &o)

			res := start(t, o)
			if res.SelfReplaced || !errors.Is(res.SelfErr, launch.ErrSelfRefused) {
				t.Errorf("SelfReplaced = %v, SelfErr = %v; want ErrSelfRefused", res.SelfReplaced, res.SelfErr)
			}
			// Each refusal for its own reason: a link or a directory has no
			// meaningful size, so the size check alone would hide a missing
			// type check.
			want := "regular file"
			switch {
			case strings.Contains(name, "staging directory"):
				want = "not a directory"
			case strings.Contains(name, "empty"), strings.Contains(name, "too large"):
				want = "no launcher"
			}
			if res.SelfErr != nil && !strings.Contains(res.SelfErr.Error(), want) {
				t.Errorf("SelfErr = %v, want it refused as %q", res.SelfErr, want)
			}
			if raw, err := fsx.ReadFile(m, shim, 1<<20); err == nil && string(raw) != "launcher v1" {
				t.Errorf("the launcher reads %q, want it untouched", raw)
			}
			if exists(t, m, "/appdata/real") && readFile(t, m, "/appdata/real") != "launcher v1" {
				t.Error("the swap was written through a link")
			}
		})
	}
}

// Negative: only the launcher in the root being served is replaced. A launcher
// elsewhere, pointed at this root, must not copy the root's staged file over
// itself.
func TestALauncherOutsideTheRootIsNotReplaced(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")
	outside := "/usr/local/bin/" + shimName
	if err := m.MkdirAll(fsx.Dir(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(m, outside, []byte("launcher v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{outside, root + "/bin/" + shimName, "/opt/app2/" + shimName, "/opt/" + shimName} {
		o.SelfPath = p
		res := start(t, o)
		if res.SelfReplaced || !errors.Is(res.SelfErr, launch.ErrSelfRefused) {
			t.Errorf("SelfPath %s: SelfReplaced = %v, SelfErr = %v", p, res.SelfReplaced, res.SelfErr)
		}
	}
	if got := readFile(t, m, outside); got != "launcher v1" {
		t.Errorf("the outside launcher reads %q", got)
	}
}

// Negative: a root this process cannot write — a system-wide install started by
// an ordinary user — is a soft skip. The start succeeds, the condition is
// reported as ErrSelfNotWritable, and nothing under the root was changed: no
// scratch file, no launcher moved aside, and the staged launcher is still there
// for a start that can.
func TestAnUnwritableRootIsASoftSkip(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")
	before := rootEntries(t, m)
	ev := &events{}
	o.Observe = ev
	var tried []string
	m.Fail = func(op, name string) error {
		if op == "open" {
			return nil
		}
		if op == "remove" || op == "removeall" {
			// Removing what is not there changes nothing, and a real
			// filesystem answers it without an access check.
			if _, err := m.Lstat(name); fsx.IsNotExist(err) {
				return nil
			}
		}
		if name == root || strings.HasPrefix(name, root+"/") {
			tried = append(tried, op+" "+name)
			return fs.ErrPermission
		}
		return nil
	}

	res := start(t, o)
	if res.SelfReplaced || !errors.Is(res.SelfErr, launch.ErrSelfNotWritable) {
		t.Fatalf("SelfReplaced = %v, SelfErr = %v; want ErrSelfNotWritable", res.SelfReplaced, res.SelfErr)
	}
	if !strings.Contains(res.SelfErr.Error(), "IDN-23") || !saw(ev, "IDN-23") {
		t.Errorf("the report does not point at IDN-23: %v / %+v", res.SelfErr, ev.seen)
	}
	m.Fail = nil
	if got := readFile(t, m, shim); got != "launcher v1" {
		t.Errorf("the launcher reads %q, want it untouched", got)
	}
	if after := rootEntries(t, m); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Errorf("the root changed: %v -> %v", before, after)
	}
	if next, _ := layout.LauncherNext(root, shimName); !exists(t, m, next) {
		t.Error("the staged launcher was lost")
	}
	if len(tried) == 0 {
		t.Error("fixture: nothing was attempted, so nothing was proven")
	}
}

// The journal decides whether a launcher is ever staged. A pending launcher is
// promoted only behind a COMMITTED record for its version; every other state
// leaves the launcher as it is.
func TestOnlyACommittedUpdateStagesItsLauncher(t *testing.T) {
	for name, tc := range map[string]struct {
		states  []txn.State
		pointer string // where `current` is before the start
		want    string
	}{
		// A crash right after the commit record: recovery promotes, the start
		// swaps.
		"committed": {
			states:  []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted},
			pointer: "1.3.0", want: "launcher v2",
		},
		// A crash after the swap: recovery completes forward, then promotes.
		"swapped": {
			states:  []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped},
			pointer: "1.3.0", want: "launcher v2",
		},
		// Negative: staged but never swapped — rolled back, nothing staged.
		"staged": {
			states:  []txn.State{txn.StateBegin, txn.StateStaged},
			pointer: "1.2.0", want: "launcher v1",
		},
		// Negative: migrated, pointer did not move — rolled back.
		"migrated, not swapped": {
			states:  []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated},
			pointer: "1.2.0", want: "launcher v1",
		},
		// Negative: an update already rolled back leaves only litter.
		"rolled back": {
			states:  []txn.State{txn.StateBegin, txn.StateStaged, txn.StateRolledBack},
			pointer: "1.2.0", want: "launcher v1",
		},
		// Negative: a committed record, but `current` was moved since — not
		// this version's launcher to stage.
		"committed, pointer moved": {
			states:  []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted},
			pointer: "1.2.0", want: "launcher v1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := tree(t, []string{"1.2.0", "1.3.0"}, tc.pointer)
			if err := fsx.WriteFileAtomic(m, shim, []byte("launcher v1"), 0o755); err != nil {
				t.Fatal(err)
			}
			journal(t, m, "1.2.0", "1.3.0", tc.states...)
			pending(t, m, "1.3.0", "launcher v2")

			res := start(t, launch.Options{FS: m, Root: root, SelfPath: shim, Migrate: &migrator{fs: m}})
			if res.SelfErr != nil {
				t.Fatalf("SelfErr = %v", res.SelfErr)
			}
			if got := readFile(t, m, shim); got != tc.want {
				t.Errorf("the launcher reads %q, want %q", got, tc.want)
			}
			if tc.want == "launcher v1" {
				if next, _ := layout.LauncherNext(root, shimName); exists(t, m, next) {
					t.Error("a launcher was staged for an update that did not commit")
				}
			}
			if dir, _ := layout.LauncherPendingDir(root, "1.3.0"); exists(t, m, dir) {
				t.Error("the pending launcher outlived the settled transaction")
			}
		})
	}
}

// A deferred update carries its pending launcher through the wait, and the start
// that finishes it swaps the launcher in as well.
func TestTheLauncherIsSwappedAfterADeferredUpdate(t *testing.T) {
	m := deferredTree(t)
	if err := fsx.WriteFileAtomic(m, shim, []byte("launcher v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	pending(t, m, "1.3.0", "launcher v2")

	res := start(t, launch.Options{FS: m, Root: root, SelfPath: shim, Migrate: &migrator{fs: m}})
	if !res.Applied || !res.SelfReplaced {
		t.Fatalf("Applied = %v, SelfReplaced = %v, SelfErr = %v", res.Applied, res.SelfReplaced, res.SelfErr)
	}
	if got := readFile(t, m, shim); got != "launcher v2" {
		t.Errorf("the launcher reads %q, want the one 1.3.0 carries", got)
	}
}

// Negative: a deferred update an instance is still running under stays deferred,
// and its launcher stays pending — it has not committed.
func TestASkippedDeferredUpdateStagesNoLauncher(t *testing.T) {
	m := deferredTree(t)
	if err := fsx.WriteFileAtomic(m, shim, []byte("launcher v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	pending(t, m, "1.3.0", "launcher v2")

	res := start(t, launch.Options{FS: m, Root: root, SelfPath: shim, Lock: &lock{held: true}})
	if !res.Skipped || res.SelfReplaced {
		t.Fatalf("Skipped = %v, SelfReplaced = %v", res.Skipped, res.SelfReplaced)
	}
	if next, _ := layout.LauncherNext(root, shimName); exists(t, m, next) {
		t.Error("a launcher was staged for an update that is still deferred")
	}
	if dir, _ := layout.LauncherPendingDir(root, "1.3.0"); !exists(t, m, dir) {
		t.Error("the deferred update lost its pending launcher")
	}
}

// Negative: a failure or crash at every step a start takes to swap the launcher
// ends, after the next start, with the staged launcher in place — and at no point
// in between with an empty name that the next start does not repair.
func TestAnInterruptedSwapEndsWithAWorkingLauncher(t *testing.T) {
	mutating := func(op, name string) bool {
		return op != "open" && (strings.HasPrefix(name, shim) || strings.HasPrefix(name, layout.LauncherNextDir(root)))
	}
	for sname, replace := range map[string]launcherfile.Func{
		"rename (POSIX)":  launcherfile.ReplaceByRename,
		"aside (Windows)": launcherfile.ReplaceAside(nil),
	} {
		t.Run(sname, func(t *testing.T) {
			restore := launch.SetReplaceForTest(replace)
			t.Cleanup(restore)

			m, o := selfFixture(t, "launcher v2", "launcher v1")
			steps := 0
			m.Fail = func(op, name string) error {
				if mutating(op, name) {
					steps++
				}
				return nil
			}
			if res := start(t, o); !res.SelfReplaced {
				t.Fatalf("clean run: %v", res.SelfErr)
			}
			if steps < 2 {
				t.Fatalf("fixture: only %d steps observed", steps)
			}

			for k := 0; k < steps; k++ {
				for _, crash := range []bool{false, true} {
					t.Run(fmt.Sprintf("step %d crash=%v", k, crash), func(t *testing.T) {
						m, o := selfFixture(t, "launcher v2", "launcher v1")
						n := 0
						m.Fail = func(op, name string) error {
							if !mutating(op, name) {
								return nil
							}
							n++
							if n-1 == k || (crash && n-1 > k) {
								return errCrash
							}
							return nil
						}
						_, _ = launch.Start(context.Background(), o)
						m.Fail = nil

						if got, err := fsx.ReadFile(m, shim, 1<<20); err == nil {
							if s := string(got); s != "launcher v1" && s != "launcher v2" {
								t.Fatalf("after the interruption the launcher reads %q", s)
							}
						} else if !crash {
							t.Fatalf("a failure without a crash left no launcher: %v", err)
						}

						res := start(t, o)
						if res.SelfErr != nil {
							t.Fatalf("next start: %v", res.SelfErr)
						}
						if got := readFile(t, m, shim); got != "launcher v2" {
							t.Fatalf("after the next start the launcher reads %q", got)
						}
						if next, _ := layout.LauncherNext(root, shimName); exists(t, m, next) {
							t.Error("the staged launcher survived a completed swap")
						}
						start(t, o) // the leftovers go once nothing runs from them.
						for _, e := range rootEntries(t, m) {
							if strings.HasPrefix(e, shimName+launcherfile.AsideSuffix) {
								t.Errorf("left behind: %s", e)
							}
						}
					})
				}
			}
		})
	}
}

// Negative: when the repair before recovery cannot put a missing launcher back,
// that is reported, no swap is attempted on top of it, and the start still
// succeeds.
func TestAFailedRepairIsReportedAndNothingIsSwapped(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")
	aside := shim + launcherfile.AsideSuffix + "1"
	if err := m.Rename(shim, aside); err != nil {
		t.Fatal(err)
	}
	m.Fail = func(op, name string) error {
		if op == "rename" && name == shim { // fsx.Mem reports a rename by its new name.
			return errCrash
		}
		if op == "create" && strings.HasPrefix(name, shim) {
			t.Errorf("a swap was attempted on an unrepaired name: %s", name)
		}
		return nil
	}
	res := start(t, o)
	if !errors.Is(res.SelfErr, errCrash) || res.SelfReplaced || res.SelfRestored {
		t.Fatalf("SelfErr = %v, SelfReplaced = %v, SelfRestored = %v", res.SelfErr, res.SelfReplaced, res.SelfRestored)
	}
}

var errCrash = errors.New("injected")

func saw(ev *events, substr string) bool {
	for _, e := range ev.seen {
		if strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}
