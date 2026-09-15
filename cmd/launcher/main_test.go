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
	"strconv"
	"strings"
	"testing"
	"time"

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
	// Any code but launch.RelaunchExitCode, which is the one code a supervising
	// launcher acts on rather than passes through (IDN-29).
	s := &started{code: 17}

	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 17 {
		t.Fatalf("run = %d, want the application's 17", code)
	}
}

// sequence is an application whose successive runs exit with the given codes.
type sequence struct {
	codes []int
	runs  int
	bins  []string
}

func (q *sequence) exec(path string, _ []string) (int, error) {
	q.bins = append(q.bins, path)
	code := q.codes[len(q.codes)-1]
	if q.runs < len(q.codes) {
		code = q.codes[q.runs]
	}
	q.runs++
	return code, nil
}

func supervising(t *testing.T, on bool) {
	t.Helper()
	saved := supervises
	supervises = on
	t.Cleanup(func() { supervises = saved })
}

// An application that exits with RelaunchExitCode under a supervising launcher is
// started again — after the launcher has finished the update it deferred, so the
// second run is the new version (IDN-29).
func TestRelaunchFinishesTheDeferredUpdateAndStartsTheNewVersion(t *testing.T) {
	supervising(t, true)
	root := install(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	var out bytes.Buffer
	q := &sequence{codes: []int{launch.RelaunchExitCode, 0}}

	// The first run defers 1.3.0 and asks to be relaunched.
	first := true
	exec := func(path string, args []string) (int, error) {
		if first {
			first = false
			deferUpdate(t, root, "1.2.0", "1.3.0")
		}
		return q.exec(path, args)
	}
	if code := run([]string{"--root", root, "--quiet"}, &out, &out, exec); code != 0 {
		t.Fatalf("run = %d, want 0\n%s", code, &out)
	}
	if q.runs != 2 {
		t.Fatalf("the application ran %d times, want 2", q.runs)
	}
	if !strings.Contains(filepath.ToSlash(q.bins[1]), "versions/1.3.0/") {
		t.Fatalf("the relaunch started %s, want the 1.3.0 binary", q.bins[1])
	}
	if got, _ := layout.PointerTarget(fsx.OS(), root); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
}

// A launcher that does not stay the parent (POSIX) passes the code through: it is
// not there to act on it, and an application there relaunches with
// launch.Relaunch instead.
func TestRelaunchCodeIsPassedThroughWhenNotSupervising(t *testing.T) {
	supervising(t, false)
	root := install(t, []string{"1.2.0"}, "1.2.0")
	var out bytes.Buffer
	q := &sequence{codes: []int{launch.RelaunchExitCode}}
	if code := run([]string{"--root", root, "--quiet"}, &out, &out, q.exec); code != launch.RelaunchExitCode || q.runs != 1 {
		t.Fatalf("run = %d after %d runs, want %d after 1", code, q.runs, launch.RelaunchExitCode)
	}
}

// An application that asks to be relaunched over and over without running for a
// while is not relaunched forever.
func TestQuickRelaunchesAreBounded(t *testing.T) {
	supervising(t, true)
	root := install(t, []string{"1.2.0"}, "1.2.0")
	var out bytes.Buffer
	q := &sequence{codes: []int{launch.RelaunchExitCode}}
	if code := run([]string{"--root", root, "--quiet"}, &out, &out, q.exec); code != exitError {
		t.Fatalf("run = %d, want %d", code, exitError)
	}
	if q.runs != maxQuickRelaunches+1 {
		t.Fatalf("the application ran %d times, want %d", q.runs, maxQuickRelaunches+1)
	}
	if !strings.Contains(out.String(), "relaunched") {
		t.Errorf("the refusal does not say why: %q", out.String())
	}
}

// A run that lasted resets the count: an application updated twice in a long
// session is relaunched both times.
func TestALongRunResetsTheRelaunchCount(t *testing.T) {
	supervising(t, true)
	root := install(t, []string{"1.2.0"}, "1.2.0")
	clock := time.Unix(1_700_000_000, 0)
	saved := now
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = saved })

	var out bytes.Buffer
	codes := []int{launch.RelaunchExitCode, launch.RelaunchExitCode, launch.RelaunchExitCode, launch.RelaunchExitCode, launch.RelaunchExitCode, 0}
	q := &sequence{codes: codes}
	exec := func(path string, args []string) (int, error) {
		clock = clock.Add(time.Hour) // every run lasts an hour.
		return q.exec(path, args)
	}
	if code := run([]string{"--root", root, "--quiet"}, &out, &out, exec); code != 0 || q.runs != len(codes) {
		t.Fatalf("run = %d after %d runs, want 0 after %d\n%s", code, q.runs, len(codes), &out)
	}
}

// Started by launch.Relaunch beside a previous instance, the launcher waits for
// that instance, and neither applies nor starts anything while it is still up.
func TestAfterPIDWaitsAndRefusesWhileTheInstanceRuns(t *testing.T) {
	root := install(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	deferUpdate(t, root, "1.2.0", "1.3.0")
	var out bytes.Buffer
	s := &started{}

	// This test process is the "previous instance": it is certainly still up.
	savedTimeout := afterPIDTimeoutFor
	afterPIDTimeoutFor = func() time.Duration { return 300 * time.Millisecond }
	t.Cleanup(func() { afterPIDTimeoutFor = savedTimeout })

	args := []string{"--root", root, "--quiet", "--after-pid", strconv.Itoa(os.Getpid())}
	if code := run(args, &out, &out, s.exec); code != exitError {
		t.Fatalf("run = %d, want %d\n%s", code, exitError, &out)
	}
	if s.path != "" {
		t.Fatal("the application was started while the previous instance was still running")
	}
	if got, _ := layout.PointerTarget(fsx.OS(), root); got != "1.2.0" {
		t.Fatalf("current = %q; the deferred update was applied under a live instance", got)
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

// --version answers which launcher is sitting in the install root — the question
// that has no other answer once the launcher can replace itself — and starts
// nothing.
func TestVersionPrintsTheStampAndStartsNothing(t *testing.T) {
	for stamp, want := range map[string]string{"1.3.0": "idunn launcher 1.3.0", "": "unknown"} {
		old := launcherVersion
		launcherVersion = stamp
		var out bytes.Buffer
		s := &started{}
		code := run([]string{"--version"}, &out, &out, s.exec)
		launcherVersion = old
		if code != exitOK || !strings.Contains(out.String(), want) {
			t.Errorf("stamp %q: run = %d, %q", stamp, code, out.String())
		}
		if s.path != "" {
			t.Errorf("--version started %q", s.path)
		}
	}
}

// selfInstall is an install for which a committed update staged a new launcher,
// and whose root holds the old one. selfPath points at that old one for the
// length of the test: the test binary itself must not be replaced.
func selfInstall(t *testing.T, staged string) (root, shim string) {
	t.Helper()
	root = install(t, []string{"1.2.0"}, "1.2.0")
	fs := fsx.OS()
	shim = fsx.Join(fsx.Slash(root), "launcher")
	next, err := layout.LauncherNext(root, "launcher")
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll(layout.LauncherNextDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(fs, next, []byte(staged), layout.MetaFileMode); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(fs, shim, []byte("launcher v1"), 0o755); err != nil {
		t.Fatal(err)
	}

	oldSelf := selfPath
	selfPath = func() (string, error) { return shim, nil }
	t.Cleanup(func() { selfPath = oldSelf })
	return root, shim
}

func TestTheLauncherSwapsInTheStagedOneAndLaunches(t *testing.T) {
	root, shim := selfInstall(t, "launcher v2")
	var out bytes.Buffer
	s := &started{}

	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 0 {
		t.Fatalf("run = %d\n%s", code, &out)
	}
	if s.path == "" {
		t.Fatal("the application was not started")
	}
	if got, _ := os.ReadFile(shim); string(got) != "launcher v2" { //nolint:gosec // G304: test fixture.
		t.Errorf("the launcher reads %q\n%s", got, &out)
	}
	next, _ := layout.LauncherNext(root, "launcher")
	if _, err := os.Lstat(next); !os.IsNotExist(err) {
		t.Errorf("the staged launcher is still there after the swap: %v", err)
	}
}

// Nothing staged is the ordinary start: nothing is replaced and nothing is said.
func TestNothingStagedIsSilent(t *testing.T) {
	root, shim := selfInstall(t, "launcher v2")
	if err := os.RemoveAll(layout.LauncherNextDir(root)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := &started{}
	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 0 || out.Len() != 0 {
		t.Fatalf("run = %d, output %q", code, &out)
	}
	if got, _ := os.ReadFile(shim); string(got) != "launcher v1" { //nolint:gosec // G304: test fixture.
		t.Errorf("the launcher reads %q", got)
	}
}

// Negative: a staged launcher that is not a regular file is refused, the refusal
// is reported, and the application still starts.
func TestARefusedStagedLauncherIsReportedAndTheAppStillStarts(t *testing.T) {
	root, shim := selfInstall(t, "launcher v2")
	next, _ := layout.LauncherNext(root, "launcher")
	if err := os.Remove(next); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(next, 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := &started{}

	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 0 {
		t.Fatalf("run = %d\n%s", code, &out)
	}
	if s.path == "" {
		t.Fatal("the application was not started")
	}
	if !strings.Contains(out.String(), "was not replaced") {
		t.Errorf("the refusal was not reported: %q", out.String())
	}
	if got, _ := os.ReadFile(shim); string(got) != "launcher v1" { //nolint:gosec // G304: test fixture.
		t.Errorf("the launcher reads %q", got)
	}
}
