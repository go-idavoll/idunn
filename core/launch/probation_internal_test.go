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

package launch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
)

// probationRoot is a real install root on disk with 1.3.0 live and on
// probation, and the launcher at its top.
func probationRoot(t *testing.T, status layout.ProbationStatus, live string) (root, launcher string) {
	t.Helper()
	dir := t.TempDir()
	root = fsx.Slash(dir)
	f := fsx.OS()
	for _, v := range []string{"1.2.0", "1.3.0"} {
		vd, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.MkdirAll(vd, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := layout.SetPointer(f, root, live); err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteProbation(f, root, layout.Probation{
		Version: "1.3.0", Previous: "1.2.0", Status: status, AttemptsAllowed: 3, RestartsAllowed: 1,
	}); err != nil {
		t.Fatal(err)
	}
	launcher = filepath.Join(dir, "launcher")
	if err := os.WriteFile(launcher, []byte("launcher"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root, launcher
}

func readRecord(t *testing.T, root string) *layout.Probation {
	t.Helper()
	p, err := layout.ReadProbation(fsx.OS(), root)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The application marks its restart before it leaves, under a supervising
// launcher and beside one alike, with or without --root.
func TestRelaunchMarksTheRestartOfAVersionOnProbation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		supervised bool
		withRoot   bool
	}{
		{"supervised", true, true},
		{"beside the launcher", false, true},
		{"root from the launcher's directory", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			if tc.supervised {
				env[SupervisedEnv] = "1"
			}
			fakeSystem(t, env, false)
			root, launcher := probationRoot(t, layout.ProbationActive, "1.3.0")
			o := RelaunchOptions{Launcher: launcher}
			if tc.withRoot {
				o.Root = filepath.FromSlash(root)
			}
			if _, err := Relaunch(o); err != nil {
				t.Fatalf("Relaunch: %v", err)
			}
			if p := readRecord(t, root); !p.RestartPending || p.Restarts != 1 {
				t.Fatalf("record = %+v, want one pending restart", p)
			}
		})
	}
}

func TestMarkRestartLeavesOtherRecordsAlone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status layout.ProbationStatus
		live   string
	}{
		{"confirmed", layout.ProbationConfirmed, "1.3.0"},
		{"another version is live", layout.ProbationActive, "1.2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := probationRoot(t, tc.status, tc.live)
			before := readRecord(t, root)
			markRestart(fsx.OS(), root)
			if after := readRecord(t, root); *after != *before {
				t.Fatalf("record = %+v, want %+v", after, before)
			}
		})
	}
}

// The count stops one past the allowance, which is what the next start rolls
// back on; a record the parser would refuse is never written.
func TestMarkRestartStopsCountingPastTheAllowance(t *testing.T) {
	root, _ := probationRoot(t, layout.ProbationActive, "1.3.0")
	for i := 0; i < 5; i++ {
		markRestart(fsx.OS(), root)
	}
	if p := readRecord(t, root); p.Restarts != p.RestartsAllowed+1 || !p.RestartPending {
		t.Fatalf("record = %+v", p)
	}
}

func TestRelaunchRoot(t *testing.T) {
	abs := t.TempDir()
	launcher := filepath.Join(abs, "launcher")
	for _, tc := range []struct {
		o    RelaunchOptions
		want string
	}{
		{RelaunchOptions{Launcher: launcher, Root: abs}, fsx.Slash(abs)},
		{RelaunchOptions{Launcher: launcher}, fsx.Slash(abs)},
		{RelaunchOptions{Launcher: "launcher"}, ""},
		{RelaunchOptions{Launcher: launcher, Root: "relative"}, ""},
	} {
		if got := relaunchRoot(tc.o); got != tc.want {
			t.Errorf("relaunchRoot(%+v) = %q, want %q", tc.o, got, tc.want)
		}
	}
}
