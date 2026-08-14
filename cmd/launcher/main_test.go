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

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
)

const appName = "acme-app"

// started records what the launcher handed over to, instead of replacing the
// process — which is the one thing a test cannot let it do.
type started struct {
	path string
	args []string
	code int
	err  error
}

func (s *started) exec(path string, args []string) (int, error) {
	s.path, s.args = path, args
	return s.code, s.err
}

// install writes a real install tree on the real filesystem, because that is
// what this binary works against.
func install(t *testing.T, versions []string, current string) string {
	t.Helper()
	root := t.TempDir()
	fs := fsx.OS()
	for _, v := range versions {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatal(err)
		}
		if err := fs.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fsx.WriteFileAtomic(fs, fsx.Join(dir, "app"), []byte(v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := layout.SetPointer(fs, root, current); err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteInstall(fs, root, layout.Install{
		Name: appName, Version: current, LayoutSchema: release.LayoutSchema,
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

func deferUpdate(t *testing.T, root, from, to string) {
	t.Helper()
	j, err := txn.Open(fsx.OS(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateDeferred} {
		if err := j.Append(txn.Record{State: s, Name: appName, FromVersion: from, ToVersion: to}); err != nil {
			t.Fatal(err)
		}
	}
}

// The ordinary start: hand over to the installed version, quickly and quietly.
func TestLaunchesTheInstalledVersion(t *testing.T) {
	root := install(t, []string{"1.2.0"}, "1.2.0")
	var out bytes.Buffer
	s := &started{}

	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 0 {
		t.Fatalf("run = %d, want 0\n%s", code, &out)
	}
	want, err := layout.VersionDir(root, "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if s.path != fsx.Join(want, "app") {
		t.Errorf("started %q, want %q", s.path, fsx.Join(want, "app"))
	}
}

// A start with a deferred update applies it first, and then launches the version
// it just made live — not the one that was live when the process began.
func TestAppliesADeferredUpdateBeforeLaunching(t *testing.T) {
	root := install(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	deferUpdate(t, root, "1.2.0", "1.3.0")
	var out bytes.Buffer
	s := &started{}

	if code := run([]string{"--root", root}, &out, &out, s.exec); code != 0 {
		t.Fatalf("run = %d, want 0\n%s", code, &out)
	}
	if !strings.Contains(s.path, "1.3.0") {
		t.Errorf("started %q, want the freshly applied 1.3.0", s.path)
	}
	if d, err := launch.Waiting(fsx.OS(), root); err != nil || d != nil {
		t.Errorf("the update is still deferred after a start: %+v, %v", d, err)
	}
	if !strings.Contains(out.String(), "1.3.0") {
		t.Errorf("the slow start was not explained to the user: %q", out.String())
	}
}

// Arguments after the launcher's own reach the application untouched: the
// launcher is in the way of nothing.
func TestArgumentsAreForwarded(t *testing.T) {
	root := install(t, []string{"1.2.0"}, "1.2.0")
	var out bytes.Buffer
	s := &started{}

	code := run([]string{"--root", root, "--quiet", "--", "--verbose", "file.txt"}, &out, &out, s.exec)
	if code != 0 {
		t.Fatalf("run = %d\n%s", code, &out)
	}
	if len(s.args) != 2 || s.args[0] != "--verbose" || s.args[1] != "file.txt" {
		t.Errorf("forwarded %v, want [--verbose file.txt]", s.args)
	}
}

// The application's exit code is the launcher's exit code. Anything else would
// make the launcher a liar to whatever supervises it.
func TestTheApplicationsExitCodeIsPassedThrough(t *testing.T) {
	root := install(t, []string{"1.2.0"}, "1.2.0")
	var out bytes.Buffer
	s := &started{code: 42}

	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 42 {
		t.Fatalf("run = %d, want the application's 42", code)
	}
}

// An update that cannot be applied must not stop the application from starting.
// The installation that is live is complete and runnable; refusing to launch it
// because of an update nobody asked for would be the worse failure.
func TestAFailedUpdateStillLaunches(t *testing.T) {
	root := install(t, []string{"1.2.0"}, "1.2.0")
	// A deferred transaction whose staged version is not on disk: resuming it
	// cannot work.
	deferUpdate(t, root, "1.2.0", "9.9.9")
	var out bytes.Buffer
	s := &started{}

	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 0 {
		t.Fatalf("run = %d, want the application to start anyway\n%s", code, &out)
	}
	if !strings.Contains(s.path, "1.2.0") {
		t.Errorf("started %q, want the still-live 1.2.0", s.path)
	}
	if !strings.Contains(out.String(), "not applied") {
		t.Errorf("the failure was not reported: %q", out.String())
	}
}

// A root with no installation has nothing to launch, and says so rather than
// starting something arbitrary.
func TestNoInstallationIsAnError(t *testing.T) {
	var out bytes.Buffer
	s := &started{}

	if code := run([]string{"--root", t.TempDir(), "--quiet"}, &out, &out, s.exec); code != exitError {
		t.Fatalf("run = %d, want %d\n%s", code, exitError, &out)
	}
	if s.path != "" {
		t.Errorf("something was started: %q", s.path)
	}
}

// An --app that is not in the installed version is an error too: launching what
// is there instead would be a guess.
func TestAMissingApplicationIsAnError(t *testing.T) {
	root := install(t, []string{"1.2.0"}, "1.2.0")
	var out bytes.Buffer
	s := &started{}

	if code := run([]string{"--root", root, "--app", "bin/other", "--quiet"}, &out, &out, s.exec); code != exitError {
		t.Fatalf("run = %d, want %d\n%s", code, exitError, &out)
	}
	if s.path != "" {
		t.Errorf("something was started: %q", s.path)
	}
}

// --app names a path inside the installed version, and is validated the same way
// every other install-relative path in this project is.
func TestAppPathIsSanitized(t *testing.T) {
	root := install(t, []string{"1.2.0"}, "1.2.0")
	for _, bad := range []string{"../../etc/passwd", "/bin/sh", "", "bin/../../out"} {
		var out bytes.Buffer
		s := &started{}
		if code := run([]string{"--root", root, "--app", bad, "--quiet"}, &out, &out, s.exec); code != exitUsage {
			t.Errorf("--app %q = %d, want %d", bad, code, exitUsage)
		}
		if s.path != "" {
			t.Errorf("--app %q started %q", bad, s.path)
		}
	}
}

// A hand-over that fails is a launcher failure, and distinguishable from an
// application that ran and exited non-zero.
func TestAFailedHandOverIsReported(t *testing.T) {
	root := install(t, []string{"1.2.0"}, "1.2.0")
	var out bytes.Buffer
	s := &started{err: errors.New("permission denied")}

	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != exitError {
		t.Fatalf("run = %d, want %d", code, exitError)
	}
	if !strings.Contains(out.String(), "starting the application") {
		t.Errorf("stderr = %q", out.String())
	}
}

func TestUnknownFlagIsUsage(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--wat"}, &out, &out, (&started{}).exec); code != exitUsage {
		t.Fatalf("run = %d, want %d", code, exitUsage)
	}
}

// The default root is the directory the launcher itself sits in, which is what
// lets a host ship it as the thing a user clicks.
func TestRootDefaultsToTheBinarysDirectory(t *testing.T) {
	got, err := resolveRoot("")
	if err != nil {
		t.Fatalf("resolveRoot: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Dir(self) {
		t.Errorf("resolveRoot() = %q, want %q", got, filepath.Dir(self))
	}
}
