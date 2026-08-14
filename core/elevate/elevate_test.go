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

package elevate_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-idavoll/idunn/core/elevate"
)

func TestNeedsElevationIsFalseForAWritableRoot(t *testing.T) {
	t.Parallel()

	needs, err := elevate.NeedsElevation(t.TempDir())
	if err != nil {
		t.Fatalf("NeedsElevation(temp dir) = %v, want nil", err)
	}
	if needs {
		t.Fatal("NeedsElevation(temp dir) = true, want false: the test's own directory is writable")
	}
}

// A root that does not exist yet is the normal first-install case. The answer
// then belongs to the directory that would have to be created.
func TestNeedsElevationLooksAtTheDeepestExistingDirectory(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "apps", "demo", "1.0.0")
	needs, err := elevate.NeedsElevation(root)
	if err != nil {
		t.Fatalf("NeedsElevation(%q) = %v, want nil", root, err)
	}
	if needs {
		t.Fatalf("NeedsElevation(%q) = true, want false", root)
	}
}

func TestNeedsElevationLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := elevate.NeedsElevation(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the probe left %d entries behind: %v", len(entries), entries)
	}
}

// Fail closed: every answer this function cannot establish is reported as an
// error *and* as "needs elevation", never as the false that would send a
// system-wide install down the unprivileged path.
func TestNeedsElevationFailsClosed(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	roots := []string{
		"",                         // no root at all.
		"relative/path",            // resolved against an unknown working directory.
		file,                       // a file where a directory must be.
		filepath.Join(file, "sub"), // a directory below a file.
	}
	for _, root := range roots {
		needs, err := elevate.NeedsElevation(root)
		if err == nil {
			t.Fatalf("NeedsElevation(%q) = nil error, want a refusal", root)
		}
		if !needs {
			t.Fatalf("NeedsElevation(%q) reported false alongside an error; it must err towards true", root)
		}
	}
}

// The point of the whole package: a system-wide root that this process cannot
// write must come back as "needs elevation" without an error, so the updater
// routes the apply through the helper instead of failing.
func TestNeedsElevationIsTrueForASystemRoot(t *testing.T) {
	t.Parallel()

	root := systemRoot(t)
	needs, err := elevate.NeedsElevation(root)
	if err != nil {
		t.Fatalf("NeedsElevation(%q) = %v, want a clean answer", root, err)
	}
	if !needs {
		t.Skipf("%q is writable from this process; run the test unelevated to exercise the check", root)
	}
}

// A root on a drive that does not exist has no existing ancestor at all. The walk
// must stop at the drive root and report that, not loop.
func TestNeedsElevationRefusesARootWithNoExistingAncestor(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "windows" {
		t.Skip("every POSIX path has an existing ancestor in /")
	}
	root := unusedDrive(t) + `:\apps\demo`
	needs, err := elevate.NeedsElevation(root)
	if err == nil {
		t.Fatalf("NeedsElevation(%q) = nil error, want a refusal", root)
	}
	if !needs {
		t.Fatalf("NeedsElevation(%q) reported false alongside an error", root)
	}
}

func unusedDrive(t *testing.T) string {
	t.Helper()
	for _, letter := range "QZYXW" {
		if _, err := os.Stat(string(letter) + `:\`); err != nil {
			return string(letter)
		}
	}
	t.Skip("no unused drive letter to test with")
	return ""
}

func systemRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return "/usr"
	}
	dir := os.Getenv("SystemRoot")
	if dir == "" {
		t.Skip("SystemRoot is not set")
	}
	return filepath.Join(dir, "System32")
}

func TestNewServiceIsNotImplemented(t *testing.T) {
	t.Parallel()

	el, err := elevate.NewService()
	if !errors.Is(err, elevate.ErrNotImplemented) {
		t.Fatalf("NewService() = %v, want ErrNotImplemented", err)
	}
	if el != nil {
		t.Fatal("NewService() returned an Elevator alongside its error")
	}
}

// Everywhere the prompt is not built, elevation must refuse at construction. An
// updater that cannot elevate has to fail before it starts an apply, not
// discover it mid-swap.
func TestNewInteractiveIsNotImplementedOffWindows(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("Windows has an implementation; see the windows-only tests")
	}
	el, err := elevate.NewInteractive(elevate.InteractiveOptions{})
	if !errors.Is(err, elevate.ErrNotImplemented) {
		t.Fatalf("NewInteractive() = %v, want ErrNotImplemented", err)
	}
	if el != nil {
		t.Fatal("NewInteractive() returned an Elevator alongside its error")
	}
}
