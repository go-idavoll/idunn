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

package layout_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
)

func TestLauncherPaths(t *testing.T) {
	next, err := layout.LauncherNext(root, "acme.exe")
	if err != nil || next != "/opt/app/.updater/launcher.next/acme.exe" {
		t.Errorf("LauncherNext = %q, %v", next, err)
	}
	pending, err := layout.LauncherPendingDir(root, "1.3.0")
	if err != nil || pending != "/opt/app/.updater/staging/1.3.0.launcher" {
		t.Errorf("LauncherPendingDir = %q, %v", pending, err)
	}
	if _, err := layout.LauncherPendingDir(root, "../1.3.0"); !errors.Is(err, layout.ErrLayout) {
		t.Errorf("LauncherPendingDir(traversal) = %v", err)
	}
}

// Negative: a launcher name is one file name directly in the root, and nothing
// the layout itself uses.
func TestValidateLauncherNameRejects(t *testing.T) {
	for _, name := range []string{
		"", ".", "..", "../acme", "bin/acme", "/acme", `C:\acme.exe`, `bin\acme`, "acme/",
		"current", "Versions", ".updater", "acme.idunn-old-1", "acme.idunn-new.tmp",
		"NUL", "com1.exe", "acme.", "acme ", "a\x00b",
	} {
		if err := layout.ValidateLauncherName(name); !errors.Is(err, layout.ErrLayout) {
			t.Errorf("ValidateLauncherName(%q) = %v, want ErrLayout", name, err)
		}
	}
	for _, name := range []string{"acme", "acme.exe", "Acme Launcher.exe", "launcher"} {
		if err := layout.ValidateLauncherName(name); err != nil {
			t.Errorf("ValidateLauncherName(%q) = %v", name, err)
		}
	}
}

func readNext(t *testing.T, m *fsx.Mem, name string) (string, bool) {
	t.Helper()
	next, err := layout.LauncherNext(root, name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fsx.ReadFile(m, next, 1<<20)
	if fsx.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), true
}

// Pending, then promoted: the bytes arrive under the launcher's name with the
// meta file mode, the pending directory is gone, and promoting again is a no-op.
func TestPromoteLauncher(t *testing.T) {
	m := newRoot(t)
	if err := layout.WriteLauncherPending(m, root, "1.3.0", "acme", []byte("launcher 1.3.0")); err != nil {
		t.Fatal(err)
	}
	if _, ok := readNext(t, m, "acme"); ok {
		t.Fatal("a pending launcher is already offered")
	}
	for i := range 2 {
		if err := layout.PromoteLauncher(m, root, "1.3.0"); err != nil {
			t.Fatalf("PromoteLauncher #%d: %v", i, err)
		}
	}
	if got, ok := readNext(t, m, "acme"); !ok || got != "launcher 1.3.0" {
		t.Fatalf("staged launcher = %q (%v)", got, ok)
	}
	next, _ := layout.LauncherNext(root, "acme")
	if info, err := fsx.Lstat(m, next); err != nil || info.Mode().Perm() != layout.MetaFileMode {
		t.Errorf("mode = %v, %v", info.Mode().Perm(), err)
	}
	dir, _ := layout.LauncherPendingDir(root, "1.3.0")
	if _, err := fsx.Lstat(m, dir); !fsx.IsNotExist(err) {
		t.Errorf("the pending directory survived: %v", err)
	}
}

// Nothing pending is the ordinary case.
func TestPromoteNothingPending(t *testing.T) {
	m := newRoot(t)
	if err := layout.PromoteLauncher(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := fsx.Lstat(m, layout.LauncherNextDir(root)); !fsx.IsNotExist(err) {
		t.Errorf("promoting nothing created %s: %v", layout.LauncherNextDir(root), err)
	}
}

// Only the pending launcher of the version named is promoted: another version's
// is not this commit's launcher.
func TestPromoteOnlyTheNamedVersion(t *testing.T) {
	m := newRoot(t)
	if err := layout.WriteLauncherPending(m, root, "1.4.0", "acme", []byte("launcher 1.4.0")); err != nil {
		t.Fatal(err)
	}
	if err := layout.PromoteLauncher(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	if got, ok := readNext(t, m, "acme"); ok {
		t.Errorf("promoted %q for a version that did not commit", got)
	}
}

// A launcher staged under an old name is superseded by the one staged now.
func TestPromoteSupersedesAnotherName(t *testing.T) {
	m := newRoot(t)
	for v, name := range map[string]string{"1.2.0": "old", "1.3.0": "acme"} {
		if err := layout.WriteLauncherPending(m, root, v, name, []byte("launcher "+v)); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"1.2.0", "1.3.0"} {
		if err := layout.PromoteLauncher(m, root, v); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := readNext(t, m, "old"); ok {
		t.Errorf("the old name's launcher %q survived", got)
	}
	if got, ok := readNext(t, m, "acme"); !ok || got != "launcher 1.3.0" {
		t.Errorf("acme = %q (%v)", got, ok)
	}
}

// Negative: anything in the pending place that staging does not write is refused
// and left where it is — never promoted.
func TestPromoteRefusesWhatStagingDoesNotWrite(t *testing.T) {
	dir, _ := layout.LauncherPendingDir(root, "1.3.0")
	for name, setup := range map[string]func(t *testing.T, m *fsx.Mem){
		"a symlink as the pending directory": func(t *testing.T, m *fsx.Mem) {
			mustMkdir(t, m, "/elsewhere")
			mustWrite(t, m, "/elsewhere/acme", "evil")
			mustMkdir(t, m, layout.Staging(root))
			if err := m.Symlink("/elsewhere", dir); err != nil {
				t.Fatal(err)
			}
		},
		"a file as the pending directory": func(t *testing.T, m *fsx.Mem) {
			mustMkdir(t, m, layout.Staging(root))
			mustWrite(t, m, dir, "evil")
		},
		"two launchers": func(t *testing.T, m *fsx.Mem) {
			mustMkdir(t, m, dir)
			mustWrite(t, m, dir+"/acme", "one")
			mustWrite(t, m, dir+"/other", "two")
		},
		"a symlink as the launcher": func(t *testing.T, m *fsx.Mem) {
			mustMkdir(t, m, dir)
			mustWrite(t, m, "/opt/evil", "evil")
			if err := m.Symlink("/opt/evil", dir+"/acme"); err != nil {
				t.Fatal(err)
			}
		},
		"a directory as the launcher": func(t *testing.T, m *fsx.Mem) {
			mustMkdir(t, m, dir+"/acme")
		},
		"a name that is a path element of the layout": func(t *testing.T, m *fsx.Mem) {
			mustMkdir(t, m, dir)
			mustWrite(t, m, dir+"/current", "evil")
		},
		"a symlink as the staged directory": func(t *testing.T, m *fsx.Mem) {
			if err := layout.WriteLauncherPending(m, root, "1.3.0", "acme", []byte("launcher")); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, m, "/elsewhere")
			if err := m.Symlink("/elsewhere", layout.LauncherNextDir(root)); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newRoot(t)
			setup(t, m)
			if err := layout.PromoteLauncher(m, root, "1.3.0"); !errors.Is(err, layout.ErrLayout) {
				t.Fatalf("PromoteLauncher = %v, want ErrLayout", err)
			}
			if got, ok := readNext(t, m, "acme"); ok {
				t.Errorf("staged %q from a refused pending launcher", got)
			}
		})
	}
}

// Negative: a crash or failure at every step of writing and promoting ends with
// either nothing staged or the complete launcher staged — never a prefix — and a
// retry completes.
func TestPromoteSurvivesInterruptionAtEveryStep(t *testing.T) {
	const data = "launcher 1.3.0"
	steps := 0
	{
		m := newRoot(t)
		if err := layout.WriteLauncherPending(m, root, "1.3.0", "acme", []byte(data)); err != nil {
			t.Fatal(err)
		}
		m.Fail = func(op, _ string) error {
			if op != "open" {
				steps++
			}
			return nil
		}
		if err := layout.PromoteLauncher(m, root, "1.3.0"); err != nil {
			t.Fatal(err)
		}
	}
	for k := range steps {
		for _, crash := range []bool{false, true} {
			t.Run(fmt.Sprintf("step %d crash=%v", k, crash), func(t *testing.T) {
				m := newRoot(t)
				if err := layout.WriteLauncherPending(m, root, "1.3.0", "acme", []byte(data)); err != nil {
					t.Fatal(err)
				}
				n := 0
				m.Fail = func(op, _ string) error {
					if op == "open" {
						return nil
					}
					n++
					if n-1 == k || (crash && n-1 > k) {
						return errors.New("injected")
					}
					return nil
				}
				_ = layout.PromoteLauncher(m, root, "1.3.0")
				m.Fail = nil
				if got, ok := readNext(t, m, "acme"); ok && got != data {
					t.Fatalf("after the interruption the staged launcher reads %q", got)
				}
				if err := layout.PromoteLauncher(m, root, "1.3.0"); err != nil {
					t.Fatalf("retry: %v", err)
				}
				if got, ok := readNext(t, m, "acme"); !ok || got != data {
					t.Fatalf("after the retry the staged launcher = %q (%v)", got, ok)
				}
			})
		}
	}
}

func mustMkdir(t *testing.T, m *fsx.Mem, dir string) {
	t.Helper()
	if err := m.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, m *fsx.Mem, name, data string) {
	t.Helper()
	if err := fsx.WriteFileAtomic(m, name, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
