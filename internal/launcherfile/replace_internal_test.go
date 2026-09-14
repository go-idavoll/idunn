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

package launcherfile

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
)

const (
	dir    = "/opt/app"
	target = dir + "/launcher"
	oldBin = "the old launcher"
	newBin = "the new launcher, longer"
)

var errCrash = errors.New("injected")

func strategies() map[string]Func {
	return map[string]Func{
		"rename (POSIX)":  ReplaceByRename,
		"aside (Windows)": ReplaceAside(nil),
	}
}

func withLauncher(t *testing.T) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(m, target, []byte(oldBin), 0o755); err != nil {
		t.Fatal(err)
	}
	return m
}

// mutating reports whether op changes the filesystem.
func mutating(op string) bool { return op != "open" }

// launcherAt returns what is at the launcher's name, or "" if nothing is.
func launcherAt(t *testing.T, m *fsx.Mem) string {
	t.Helper()
	raw, err := fsx.ReadFile(m, target, 1<<20)
	if fsx.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Negative: an interrupted replacement leaves a runnable launcher — the old one
// or the new one, complete — at the name a user starts.
//
// Two kinds of interruption, at every mutating step of each strategy:
//
//   - a failed step: the operation errors and the code's own undo runs;
//   - a crash: that step and everything after it never happen, so no undo runs.
//
// POSIX's rename is atomic, so the name always holds one launcher. The Windows
// strategy has one crash point where the name is empty — between moving the
// running launcher aside and renaming the new one in — and for that one the next
// start's sweep must put the old launcher back.
func TestAnInterruptedReplacementLeavesARunnableLauncher(t *testing.T) {
	for name, replace := range strategies() {
		t.Run(name, func(t *testing.T) {
			// A clean run, to count the steps.
			m := withLauncher(t)
			steps := 0
			m.Fail = func(op, _ string) error {
				if mutating(op) {
					steps++
				}
				return nil
			}
			if err := replace(m, target, []byte(newBin)); err != nil {
				t.Fatalf("clean run: %v", err)
			}
			if steps < 2 {
				t.Fatalf("fixture: only %d steps observed", steps)
			}

			for k := 0; k < steps; k++ {
				for _, crash := range []bool{false, true} {
					t.Run(fmt.Sprintf("step %d crash=%v", k, crash), func(t *testing.T) {
						m := withLauncher(t)
						n := 0
						m.Fail = func(op, _ string) error {
							if !mutating(op) {
								return nil
							}
							n++
							if n-1 == k || (crash && n-1 > k) {
								return errCrash
							}
							return nil
						}
						err := replace(m, target, []byte(newBin))
						m.Fail = nil

						got := launcherAt(t, m)
						if !crash && err == nil && got != newBin {
							t.Fatalf("no error, but the launcher reads %q", got)
						}
						if got == "" && crash {
							// The one legitimate gap: Repair closes it.
							if !sweep(t, m, target) {
								t.Fatal("the launcher's name is empty and the sweep did not restore it")
							}
							got = launcherAt(t, m)
						}
						if got != oldBin && got != newBin {
							t.Fatalf("after the interruption the launcher reads %q (err %v)", got, err)
						}

						// And the next attempt, with nothing failing, completes
						// and leaves nothing behind once swept.
						if err := replace(m, target, []byte(newBin)); err != nil {
							t.Fatalf("retry: %v", err)
						}
						if got := launcherAt(t, m); got != newBin {
							t.Fatalf("after the retry the launcher reads %q", got)
						}
						sweep(t, m, target)
						entries, err := m.ReadDir(dir)
						if err != nil {
							t.Fatal(err)
						}
						for _, e := range entries {
							if e.Name() != "launcher" && !isScratch(e.Name()) {
								t.Errorf("left behind: %s", e.Name())
							}
						}
					})
				}
			}
		})
	}
}

// isScratch recognises what recovery's scratch sweep removes (txn.cleanOrphans):
// a crash inside fsx.WriteFileAtomic leaves one, by design, for that sweep.
func isScratch(name string) bool {
	return len(name) > len(".tmp") && name[len(name)-len(".tmp"):] == ".tmp"
}

// The old image cannot be removed while it runs; the Windows strategy asks for a
// delete at reboot, and the next start's sweep removes it.
func TestALeftoverIsScheduledAndSwept(t *testing.T) {
	m := withLauncher(t)
	var scheduled []string
	replace := ReplaceAside(func(name string) { scheduled = append(scheduled, name) })
	m.Fail = func(op, name string) error {
		if op == "remove" && name == target+AsideSuffix+"1" {
			return errors.New("the process cannot access the file") // it is running.
		}
		return nil
	}
	if err := replace(m, target, []byte(newBin)); err != nil {
		t.Fatal(err)
	}
	if len(scheduled) != 1 || scheduled[0] != target+AsideSuffix+"1" {
		t.Fatalf("scheduled %v", scheduled)
	}

	m.Fail = nil
	if sweep(t, m, target) {
		t.Error("the sweep restored a launcher that was there")
	}
	if _, err := m.Lstat(target + AsideSuffix + "1"); !fsx.IsNotExist(err) {
		t.Errorf("the leftover survived the sweep: %v", err)
	}
	if got := launcherAt(t, m); got != newBin {
		t.Errorf("the launcher reads %q", got)
	}
}

// With the name empty, the newest old launcher is the one that goes back.
func TestTheSweepRestoresTheNewestOldLauncher(t *testing.T) {
	m := withLauncher(t)
	for i, data := range map[int]string{2: "older", 10: "newest", 9: "old"} {
		if err := fsx.WriteFileAtomic(m, fmt.Sprintf("%s%s%d", target, AsideSuffix, i), []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Remove(target); err != nil {
		t.Fatal(err)
	}
	if !sweep(t, m, target) {
		t.Fatal("nothing was restored")
	}
	if got := launcherAt(t, m); got != "newest" {
		t.Errorf("restored %q, want the newest", got)
	}
	if next := nextAside(m, target); next != target+AsideSuffix+"10" {
		// 10 went back to the name; 9 is now the highest left, so 10 is free.
		t.Errorf("nextAside = %s", next)
	}
}

// sweep runs Repair and fails the test if it reports an error.
func sweep(t *testing.T, f fsx.FS, path string) bool {
	t.Helper()
	restored, err := Repair(f, path)
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	return restored
}

// Repair also removes an abandoned scratch file of a replacement that died
// before it touched the running launcher.
func TestRepairRemovesAnAbandonedScratchFile(t *testing.T) {
	m := withLauncher(t)
	if err := fsx.WriteFileAtomic(m, target+NewSuffix, []byte("half"), 0o755); err != nil {
		t.Fatal(err)
	}
	if sweep(t, m, target) {
		t.Error("restored a launcher that was there")
	}
	if _, err := m.Lstat(target + NewSuffix); !fsx.IsNotExist(err) {
		t.Errorf("the scratch file survived: %v", err)
	}
	if got := launcherAt(t, m); got != oldBin {
		t.Errorf("the launcher reads %q", got)
	}
}

// Negative: a restore that cannot happen is reported, not swallowed — the
// install has no launcher, and the caller has to be able to say so.
func TestAFailedRestoreIsReported(t *testing.T) {
	m := withLauncher(t)
	aside := target + AsideSuffix + "1"
	if err := m.Rename(target, aside); err != nil {
		t.Fatal(err)
	}
	m.Fail = func(op, _ string) error {
		if op == "rename" {
			return errCrash
		}
		return nil
	}
	restored, err := Repair(m, target)
	if restored || !errors.Is(err, errCrash) {
		t.Fatalf("Repair = %v, %v; want the rename failure", restored, err)
	}
	m.Fail = nil
	if _, err := m.Lstat(aside); err != nil {
		t.Errorf("the old launcher is gone: %v", err)
	}
}

// Negative: something at the launcher's name that is not a regular file is not
// touched, and neither are the leftovers beside it.
func TestRepairLeavesANonRegularNameAlone(t *testing.T) {
	m := withLauncher(t)
	aside := target + AsideSuffix + "1"
	if err := m.Rename(target, aside); err != nil {
		t.Fatal(err)
	}
	if err := m.Symlink("/elsewhere", target); err != nil {
		t.Fatal(err)
	}
	if sweep(t, m, target) {
		t.Error("restored over a link")
	}
	if _, err := m.Lstat(aside); err != nil {
		t.Errorf("the old launcher was removed beside a link: %v", err)
	}
	if info, err := m.Lstat(target); err != nil || info.Mode().IsRegular() {
		t.Errorf("the link was replaced: %v", err)
	}
}

// Leftovers that are not ours — a directory, a non-canonical counter — are
// neither restored nor counted.
func TestForeignAsidesAreIgnored(t *testing.T) {
	m := withLauncher(t)
	for _, name := range []string{AsideSuffix + "01", AsideSuffix + "0", AsideSuffix + "x"} {
		if err := fsx.WriteFileAtomic(m, target+name, []byte("foreign"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.MkdirAll(target+AsideSuffix+"7", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(target); err != nil {
		t.Fatal(err)
	}
	if sweep(t, m, target) {
		t.Fatalf("restored %q from a foreign leftover", launcherAt(t, m))
	}
	if next := nextAside(m, target); next != target+AsideSuffix+"1" {
		t.Errorf("nextAside = %s", next)
	}
}
