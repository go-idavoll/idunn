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

// The point of the whole package: a root this process may not write must come
// back as "needs elevation" *without* an error, so the updater routes the apply
// through the helper instead of failing.
//
// The unwritable root is constructed rather than borrowed from the system. A
// hardcoded system path answers a different question on every platform —
// /usr is a read-only volume on macOS, not a permission denial — and that turns
// the assertion into a statement about the runner's disk layout.
func TestNeedsElevationIsTrueForAnUnwritableRoot(t *testing.T) {
	t.Parallel()

	root := unwritableDir(t)
	needs, err := elevate.NeedsElevation(root)
	if err != nil {
		t.Fatalf("NeedsElevation(%q) = %v, want a clean answer", root, err)
	}
	if !needs {
		t.Fatalf("NeedsElevation(%q) = false, want true", root)
	}
}

// unwritableDir returns a directory this process cannot create a file in.
//
// On Windows a mode bit would not produce that (permissions are ACLs, and the
// mode os.Chmod writes is only the read-only attribute), so the check uses the
// real system directory — which is exactly the root an ElevationInteractive
// install has to deal with.
func unwritableDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		root := systemRoot(t)
		if _, err := os.Stat(filepath.Join(root, "kernel32.dll")); err != nil {
			t.Skipf("%q does not look like the system directory: %v", root, err)
		}
		if writable(t, root) {
			t.Skipf("%q is writable from this process; run the test unelevated", root)
		}
		return root
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: no directory is unwritable")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	// t.TempDir's cleanup needs to get back in.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	return dir
}

func writable(t *testing.T, dir string) bool {
	t.Helper()
	f, err := os.CreateTemp(dir, ".idunn-writable-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
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
