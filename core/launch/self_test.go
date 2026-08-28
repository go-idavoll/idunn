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
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/internal/layout"
)

// selfFixture is an install with a version directory that ships a launcher and a
// shim at the top of the root.
func selfFixture(t *testing.T, shipped, installed string) (*fsx.Mem, launch.Options) {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := layout.VersionDir(root, "1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MkdirAll(fsx.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if shipped != "" {
		if err := fsx.WriteFileAtomic(m, fsx.Join(dir, "bin", "launcher"), []byte(shipped), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if installed != "" {
		if err := fsx.WriteFileAtomic(m, fsx.Join(root, "launcher"), []byte(installed), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	return m, launch.Options{
		FS:         m,
		Root:       root,
		SelfSource: "bin/launcher",
		SelfPath:   fsx.Join(root, "launcher"),
	}
}

func readFile(t *testing.T, f fsx.FS, name string) string {
	t.Helper()
	raw, err := fsx.ReadFile(f, name, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(raw)
}

// The layout is the reason this step exists: a release's files land inside a
// version directory, and the shim lives above it, so the swap never touches it.
func TestTheShimIsRefreshedFromTheLiveVersion(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")

	res, err := launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !res.SelfReplaced {
		t.Fatal("the shim was not refreshed")
	}
	if got := readFile(t, m, fsx.Join(root, "launcher")); got != "launcher v2" {
		t.Errorf("the shim reads %q, want the shipped launcher", got)
	}
}

// A shim that already matches is left alone. Rewriting it on every start would
// churn a file the operating system may be holding an image section on, for no
// change at all.
func TestAnUnchangedShimIsNotRewritten(t *testing.T) {
	_, o := selfFixture(t, "launcher v2", "launcher v2")

	res, err := launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.SelfReplaced {
		t.Error("an unchanged shim was replaced anyway")
	}
}

// Most releases change the application and leave the launcher alone. That is the
// ordinary case, not a failure.
func TestAReleaseThatShipsNoLauncherChangesNothing(t *testing.T) {
	m, o := selfFixture(t, "", "launcher v1")

	res, err := launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.SelfReplaced {
		t.Error("a release that ships no launcher replaced the shim")
	}
	if got := readFile(t, m, fsx.Join(root, "launcher")); got != "launcher v1" {
		t.Errorf("the shim reads %q, want it untouched", got)
	}
}

// A host that does not configure it gets no self-replacement, whatever a release
// happens to contain. Which file is the launcher is host knowledge; a release
// cannot nominate one.
func TestSelfReplacementIsOffWithoutConfiguration(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")
	o.SelfSource, o.SelfPath = "", ""

	res, err := launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.SelfReplaced {
		t.Error("the shim was replaced although the host never asked for it")
	}
	if got := readFile(t, m, fsx.Join(root, "launcher")); got != "launcher v1" {
		t.Errorf("the shim reads %q, want it untouched", got)
	}
}

// A source path that would leave the install root is refused. It reaches this
// code from the host's own build flags rather than from a descriptor, but it is
// still a string that addresses the filesystem, and this package has exactly one
// validator for those.
func TestASelfSourceThatEscapesTheRootIsRefused(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")
	o.SelfSource = "../../../etc/passwd"

	if _, err := launch.Start(context.Background(), o); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The start still succeeds — a shim that cannot be refreshed is not a
	// reason to refuse to launch — but nothing was written.
	if got := readFile(t, m, fsx.Join(root, "launcher")); got != "launcher v1" {
		t.Errorf("the shim reads %q, want it untouched", got)
	}
}

// A start that cannot refresh the shim still starts. The installation that is
// live is complete and runnable either way, and refusing to launch over the
// launcher would be the worse outcome by a wide margin.
func TestAFailedRefreshDoesNotFailTheStart(t *testing.T) {
	m, o := selfFixture(t, "launcher v2", "launcher v1")
	// A directory where the shim should be: not a regular file, so it is left
	// alone rather than replaced.
	if err := m.Remove(fsx.Join(root, "launcher")); err != nil {
		t.Fatal(err)
	}
	if err := m.MkdirAll(fsx.Join(root, "launcher"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := launch.Start(context.Background(), o); err != nil {
		t.Fatalf("Start: %v", err)
	}
}
