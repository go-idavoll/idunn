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
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/internal/launcherfile"
)

type launcherCall struct {
	path string
	argv []string
}

// fakeSystem replaces the environment and the process start for one test.
func fakeSystem(t *testing.T, env map[string]string, wait bool) *[]launcherCall {
	t.Helper()
	var calls []launcherCall
	savedEnv, savedStart, savedWait := getenv, startLauncher, waitForCaller
	getenv = func(k string) string { return env[k] }
	startLauncher = func(path string, argv []string) (int, error) {
		calls = append(calls, launcherCall{path, argv})
		return 0, nil
	}
	waitForCaller = wait
	t.Cleanup(func() { getenv, startLauncher, waitForCaller = savedEnv, savedStart, savedWait })
	return &calls
}

func launcherFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "launcher")
	if err := os.WriteFile(p, []byte("launcher"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// Under a supervising launcher Relaunch starts nothing: it hands back the code
// the launcher acts on.
func TestRelaunchUnderASupervisingLauncherReturnsTheCode(t *testing.T) {
	calls := fakeSystem(t, map[string]string{SupervisedEnv: "1"}, true)
	code, err := Relaunch(RelaunchOptions{Launcher: "not even checked"})
	if err != nil || code != RelaunchExitCode {
		t.Fatalf("Relaunch = %d, %v; want %d", code, err, RelaunchExitCode)
	}
	if len(*calls) != 0 {
		t.Fatal("a supervised relaunch started a launcher of its own")
	}
}

// Otherwise the launcher is started with the application's arguments after "--",
// so none of them can be read as a launcher flag.
func TestRelaunchStartsTheLauncherWithTheArgumentsAfterADoubleDash(t *testing.T) {
	calls := fakeSystem(t, nil, false)
	launcher := launcherFile(t)
	root := filepath.Dir(launcher)
	if _, err := Relaunch(RelaunchOptions{Launcher: launcher, Root: root, Args: []string{"--root", "/elsewhere", "open"}}); err != nil {
		t.Fatal(err)
	}
	want := []string{launcher, "--root", root, "--", "--root", "/elsewhere", "open"}
	if len(*calls) != 1 || !slices.Equal((*calls)[0].argv, want) {
		t.Fatalf("argv = %v, want %v", *calls, want)
	}
}

// Where the new launcher runs beside this process, it is told which process to
// wait for.
func TestRelaunchBesideTheCallerNamesItsPID(t *testing.T) {
	calls := fakeSystem(t, nil, true)
	launcher := launcherFile(t)
	if _, err := Relaunch(RelaunchOptions{Launcher: launcher}); err != nil {
		t.Fatal(err)
	}
	want := []string{launcher, "--after-pid", strconv.Itoa(os.Getpid()), "--"}
	if !slices.Equal((*calls)[0].argv, want) {
		t.Fatalf("argv = %v, want %v", (*calls)[0].argv, want)
	}
}

func TestRelaunchRefusesAnUnusableLauncher(t *testing.T) {
	calls := fakeSystem(t, nil, false)
	for name, o := range map[string]RelaunchOptions{
		"relative":      {Launcher: "launcher"},
		"missing":       {Launcher: filepath.Join(t.TempDir(), "absent")},
		"a directory":   {Launcher: t.TempDir()},
		"relative root": {Launcher: launcherFile(t), Root: "install"},
	} {
		if _, err := Relaunch(o); !errors.Is(err, ErrLaunch) {
			t.Errorf("Relaunch(%s) = %v, want ErrLaunch", name, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("a refused relaunch started something")
	}
}

// Negative: a launcher an interrupted self-replacement left missing is repaired
// from the application's side before it is started — the launcher that would
// repair it at its own start is the one that is not there (IDN-17).
func TestRelaunchRepairsAMissingLauncherFirst(t *testing.T) {
	calls := fakeSystem(t, nil, false)
	launcher := launcherFile(t)
	aside := launcher + launcherfile.AsideSuffix + "1"
	if err := os.Rename(launcher, aside); err != nil {
		t.Fatal(err)
	}
	if _, err := Relaunch(RelaunchOptions{Launcher: launcher}); err != nil {
		t.Fatalf("Relaunch = %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("started %d launchers, want 1", len(*calls))
	}
	if raw, err := os.ReadFile(launcher); err != nil || string(raw) != "launcher" { //nolint:gosec // G304: test fixture.
		t.Fatalf("the launcher reads %q, %v", raw, err)
	}
	if _, err := os.Lstat(aside); !os.IsNotExist(err) {
		t.Errorf("the leftover is still there: %v", err)
	}
}

func TestWaitForExit(t *testing.T) {
	if err := WaitForExit(context.Background(), os.Getpid(), 200*time.Millisecond); !errors.Is(err, ErrStillRunning) {
		t.Fatalf("WaitForExit(self) = %v, want ErrStillRunning", err)
	}
	if err := WaitForExit(context.Background(), 0, time.Second); !errors.Is(err, ErrLaunch) {
		t.Fatalf("WaitForExit(0) = %v, want ErrLaunch", err)
	}

	// A child that has exited and been reaped is gone.
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatalf("running a short-lived child: %v", err)
	}
	if err := WaitForExit(context.Background(), cmd.Process.Pid, 5*time.Second); err != nil {
		t.Fatalf("WaitForExit(exited child) = %v, want nil", err)
	}
}
