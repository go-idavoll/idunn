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

//go:build e2e && windows

package e2elocal

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// appSignaled is hostapp's exit code after a clean shutdown on a console control
// event or termination request (--linger).
const appSignaled = 7

// lingerWork is how long the lingering application takes to shut down cleanly:
// long enough that a launcher which does not wait for it is caught exiting first,
// well inside the five seconds Windows grants a closed console.
const lingerWork = 1500 * time.Millisecond

// ---------------------------------------------------------------------------
// IDN-40. On Windows the launcher is the application's parent for its whole
// lifetime. These scenarios hold it to what that promises: the application does
// not outlive it, and it does not die before the application.
// ---------------------------------------------------------------------------

// TestKilledLauncherTakesTheApplicationAlong kills the launcher the way Task
// Manager and taskkill /F do and expects the application, and the process the
// application started, to end with it rather than run on as orphans.
func TestKilledLauncherTakesTheApplicationAlong(t *testing.T) {
	l := startLingering(t, 0, "--spawn", "grandchild")
	app := l.process("app")
	grandchild := l.process("grandchild")

	if err := l.cmd.Process.Kill(); err != nil {
		t.Fatalf("killing the launcher: %v", err)
	}
	l.wait()

	for name, h := range map[string]windows.Handle{"application": app, "process the application started": grandchild} {
		if !exitedWithin(h, 10*time.Second) {
			t.Errorf("the %s outlived its killed launcher", name)
		}
	}
}

// TestNormalExitLeavesWhatTheApplicationStarted is the other side of the job:
// an application that exits on its own may leave a process running on purpose —
// a browser it opened, a detached helper — and that process must not die
// because the launcher in front of the application exits too.
func TestNormalExitLeavesWhatTheApplicationStarted(t *testing.T) {
	l := startLingering(t, 0, "--spawn", "grandchild", "--exit-after", "2s")
	app := l.process("app")
	grandchild := l.process("grandchild")

	l.wait()
	if l.code != exitOK {
		t.Fatalf("launcher = %#x, want 0\n%s", uint32(l.code), l.output())
	}
	if !exitedWithin(app, 0) {
		t.Fatal("the launcher exited while the application still ran")
	}
	if exitedWithin(grandchild, 2*time.Second) {
		t.Error("the process the application left running ended with the launcher")
	}
}

// TestCtrlBreakIsTheApplicationsToAnswer sends Ctrl+Break to the launcher's
// console process group. The application handles it and takes a while to shut
// down; the launcher must neither exit before it nor replace its exit code.
//
// Ctrl+Break rather than Ctrl+C: Windows sends Ctrl+C only to every process on
// the console, this test's own included, while Ctrl+Break can be aimed at one
// process group. Go reports both as os.Interrupt.
func TestCtrlBreakIsTheApplicationsToAnswer(t *testing.T) {
	l := startLingering(t, windows.CREATE_NEW_PROCESS_GROUP)
	l.process("app")

	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(l.cmd.Process.Pid)); err != nil {
		t.Skipf("no console to send Ctrl+Break on: %v", err)
	}
	l.wait()

	if got := l.fact("app", "signal"); got != "interrupt" {
		t.Errorf("the application saw %q, want interrupt", got)
	}
	if !l.doneAtExit {
		t.Errorf("the launcher exited before the application finished shutting down")
	}
	if l.code != appSignaled {
		t.Errorf("launcher = %#x, want the application's own %d\n%s", uint32(l.code), appSignaled, l.output())
	}
}

// TestClosedConsoleLetsTheApplicationFinish closes the console window the
// launcher and the application share. Windows sends both CTRL_CLOSE_EVENT and
// gives them a grace period; the launcher must stay up for as long as the
// application uses it, because once the launcher is gone the application is
// gone too (TestKilledLauncherTakesTheApplicationAlong).
func TestClosedConsoleLetsTheApplicationFinish(t *testing.T) {
	l := startLingering(t, windows.CREATE_NEW_CONSOLE, "--console-window")
	l.process("app")
	hwnd, err := strconv.ParseUint(l.fact("app", "hwnd"), 10, 64)
	if err != nil || hwnd == 0 {
		t.Skipf("the application has no console window to close (%q)", l.fact("app", "hwnd"))
	}

	postMessage := windows.NewLazySystemDLL("user32.dll").NewProc("PostMessageW")
	const wmClose = 0x0010
	if ok, _, err := postMessage.Call(uintptr(hwnd), wmClose, 0, 0); ok == 0 {
		t.Fatalf("PostMessage(WM_CLOSE): %v", err)
	}
	if _, ok := l.waitFact("app", "signal", 10*time.Second); !ok {
		// With Windows Terminal as the default terminal the console is not a
		// conhost window, and WM_CLOSE to its handle closes nothing.
		t.Skip("closing the console window sent no close event; is the default terminal conhost?")
	}
	l.wait()

	if got := l.fact("app", "signal"); got != "terminated" {
		t.Errorf("the application saw %q, want terminated", got)
	}
	if !l.doneAtExit {
		t.Errorf("the launcher exited before the application finished shutting down (launcher = %#x)", uint32(l.code))
	}
}

// ---------------------------------------------------------------------------

// lingering is a launcher running a lingering hostapp, and what the scenario has
// learned about both.
type lingering struct {
	t     *testing.T
	cmd   *exec.Cmd
	state string // hostapp --state
	log   string // the launcher's and the application's stdout and stderr

	exited     chan struct{}
	code       int
	doneAtExit bool // app.done existed the moment the launcher's exit was seen
}

// startLingering installs 1.0.0 and starts it through cmd/launcher with
// creationFlags, as hostapp --linger with extra arguments.
//
// Output goes to a file rather than a pipe: the application inherits the
// handle, and a pipe it keeps open after the launcher died would never reach EOF.
func startLingering(t *testing.T, creationFlags uint32, extra ...string) *lingering {
	t.Helper()
	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)
	in.mustInstall("1.0.0")

	l := &lingering{t: t, state: filepath.Join(r.dir, "linger"), log: filepath.Join(r.dir, "launcher.log"), exited: make(chan struct{})}
	if err := os.MkdirAll(l.state, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(l.log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })

	args := append([]string{"-root", in.root, "-quiet", "--",
		"--linger", "--state", l.state, "--name", "app", "--work", lingerWork.String()}, extra...)
	// Background, not t.Context: the scenario decides when the launcher ends,
	// and the cleanup below kills it if nothing else did.
	//nolint:gosec // G204: the launcher under test, built by this suite.
	l.cmd = exec.CommandContext(context.Background(), suite.launcher, args...)
	l.cmd.Env = childEnv()
	l.cmd.Stdout, l.cmd.Stderr = out, out
	l.cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: creationFlags, HideWindow: true}
	if err := l.cmd.Start(); err != nil {
		t.Fatalf("starting the launcher: %v", err)
	}
	go func() {
		_ = l.cmd.Wait()
		_, err := os.Stat(filepath.Join(l.state, "app.done"))
		l.doneAtExit = err == nil
		l.code = l.cmd.ProcessState.ExitCode()
		close(l.exited)
	}()
	t.Cleanup(func() {
		_ = l.cmd.Process.Kill()
		<-l.exited
	})
	return l
}

// process waits for the lingering process called name to be up and returns a
// handle to it, which the scenario owns: the process is terminated when the test
// ends, whether or not the launcher took it along.
func (l *lingering) process(name string) windows.Handle {
	l.t.Helper()
	raw, ok := l.waitFact(name, "pid", lineTimeout)
	if !ok {
		l.t.Fatalf("%s did not start:\n%s", name, l.output())
	}
	pid, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		l.t.Fatalf("%s.pid = %q", name, raw)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		l.t.Fatalf("opening %s (pid %d): %v", name, pid, err)
	}
	l.t.Cleanup(func() {
		_ = windows.TerminateProcess(h, 1)
		_ = windows.CloseHandle(h)
	})
	if exitedWithin(h, 0) {
		l.t.Fatalf("%s exited right after starting:\n%s", name, l.output())
	}
	return h
}

// wait blocks until the launcher has exited.
func (l *lingering) wait() {
	l.t.Helper()
	select {
	case <-l.exited:
	case <-time.After(lineTimeout):
		l.t.Fatalf("the launcher did not exit:\n%s", l.output())
	}
}

// fact is what the process called name reported as kind, or "" if nothing yet.
func (l *lingering) fact(name, kind string) string {
	raw, err := os.ReadFile(filepath.Join(l.state, name+"."+kind))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// waitFact polls for a fact until timeout.
func (l *lingering) waitFact(name, kind string, timeout time.Duration) (string, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(filepath.Join(l.state, name+"."+kind)); err == nil {
			return l.fact(name, kind), true
		} else if !errors.Is(err, fs.ErrNotExist) {
			l.t.Fatal(err)
		}
		if time.Now().After(deadline) {
			return "", false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (l *lingering) output() string {
	raw, _ := os.ReadFile(l.log)
	return string(raw)
}

// exitedWithin reports whether the process behind h has exited, waiting up to d.
func exitedWithin(h windows.Handle, d time.Duration) bool {
	ev, err := windows.WaitForSingleObject(h, uint32(d/time.Millisecond))
	return err == nil && ev == windows.WAIT_OBJECT_0
}
