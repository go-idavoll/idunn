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

//go:build windows

package elevate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// These tests drive the real Win32 path — ShellExecuteEx, the process handle, the
// wait, the exit code — with the verb "open" instead of "runas". Everything is
// exercised except the consent dialog itself, which needs an interactive
// administrator and therefore lives behind IDUNN_TEST_UAC (see the end of the
// file). Substituting the verb is the only thing faked here: no launcher, no
// stubbed syscall, no injected quoting.

// helper writes a batch file that behaves like a privileged apply helper and
// returns its path. Batch is deliberate: it is parsed by the real Windows
// command-line splitter, so a quoting bug shows up as wrong arguments rather
// than being hidden behind Go's own exec quoting.
func helper(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "helper.bat")
	script := "@echo off\r\n" + body + "\r\n"
	if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// unprivileged returns an elevator that launches without a consent prompt.
func unprivileged(t *testing.T, path string) *interactive {
	t.Helper()
	el, err := NewInteractive(InteractiveOptions{HelperPath: path})
	if err != nil {
		t.Fatalf("NewInteractive(%q) = %v", path, err)
	}
	e := el.(*interactive)
	e.verb = "open"
	return e
}

func TestApplyReportsASuccessfulHelper(t *testing.T) {
	t.Parallel()

	e := unprivileged(t, helper(t, "exit /b 0"))
	if err := e.Apply(context.Background(), `C:\Program Files\demo`, descriptor("stable", "1.0.0")); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
}

// The helper receives exactly the request and nothing else. This is the quoting
// contract: a root with a space must arrive as one argument, and no value may
// split into a second one.
func TestApplyPassesTheRequestAsDistinctArguments(t *testing.T) {
	t.Parallel()

	// %* is the raw tail of the command line, written where the test can read it.
	p := helper(t, `echo %*>"%~dp0args.txt"`)
	e := unprivileged(t, p)

	root := `C:\Program Files\demo app`
	if err := e.Apply(context.Background(), root, descriptor("stable", "1.0.0")); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}

	raw, err := os.ReadFile(filepath.Join(filepath.Dir(p), "args.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// CommandLineToArgvW treats the first token specially, so it is decomposed
	// with a stand-in program name in front, exactly as the helper's own C
	// runtime would see it.
	got, err := windows.DecomposeCommandLine("helper.bat " + strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"helper.bat", "apply", "--root", root, "--channel", "stable", "--version", "1.0.0"}
	if len(got) != len(want) {
		t.Fatalf("the helper saw %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the helper saw %q, want %q", got, want)
		}
	}
}

func TestApplyReportsAFailedHelper(t *testing.T) {
	t.Parallel()

	e := unprivileged(t, helper(t, "exit /b 3"))
	err := e.Apply(context.Background(), `C:\apps\demo`, descriptor("stable", "1.0.0"))
	if !errors.Is(err, ErrHelper) {
		t.Fatalf("Apply() = %v, want ErrHelper", err)
	}
	if !strings.Contains(err.Error(), "status 3") {
		t.Fatalf("Apply() = %v, want the exit status in the message", err)
	}
}

// A helper that exits with ERROR_CANCELLED is relaying "the user said no", not a
// broken update. Classifying it as a failure would put a consent dialog in a
// retry loop.
func TestApplyMapsACancelledHelperToErrDeclined(t *testing.T) {
	t.Parallel()

	e := unprivileged(t, helper(t, "exit /b 1223"))
	if err := e.Apply(context.Background(), `C:\apps\demo`, descriptor("stable", "1.0.0")); !errors.Is(err, ErrDeclined) {
		t.Fatalf("Apply() = %v, want ErrDeclined", err)
	}
}

// Cancelling stops the wait, not the apply. The elevated process owns the swap
// from the moment it starts; tearing it down mid-write is the half-installed
// state the journal exists to prevent.
func TestApplyStopsWaitingWhenTheContextIsDone(t *testing.T) {
	t.Parallel()

	// Not t.TempDir: this test deliberately walks away from a running process,
	// and the directory it is still holding open cannot be removed while it runs.
	dir, err := os.MkdirTemp("", "idunn-elevate-wait")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, "helper.bat")
	if err := os.WriteFile(p, []byte("@echo off\r\nping -n 30 127.0.0.1 >nul\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := unprivileged(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = e.Apply(ctx, `C:\apps\demo`, descriptor("stable", "1.0.0"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Apply() = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Apply() waited %v after the deadline", elapsed)
	}
	if !strings.Contains(err.Error(), "keeps running") {
		t.Fatalf("Apply() = %v, want the message to say the elevated apply continues", err)
	}
}

// An already-cancelled context must not start a privileged process at all.
func TestApplyStartsNothingForACancelledContext(t *testing.T) {
	t.Parallel()

	p := helper(t, `echo started>"%~dp0started.txt"`)
	e := unprivileged(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := e.Apply(ctx, `C:\apps\demo`, descriptor("stable", "1.0.0")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply() = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), "started.txt")); err == nil {
		t.Fatal("the helper ran for a cancelled context")
	}
}

// A rejected request must not reach ShellExecuteEx. The helper below records any
// launch, so a regression that escapes-and-forwards instead of refusing fails
// here rather than silently starting an administrator process with an
// attacker-shaped command line.
func TestApplyRefusesABadRequestWithoutLaunching(t *testing.T) {
	t.Parallel()

	p := helper(t, `echo started>"%~dp0started.txt"`)
	e := unprivileged(t, p)

	if err := e.Apply(context.Background(), `C:\apps\demo`, descriptor("stable", `1.0.0" --root C:\Windows`)); !errors.Is(err, ErrRequest) {
		t.Fatalf("Apply() = %v, want ErrRequest", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), "started.txt")); err == nil {
		t.Fatal("the helper ran for a rejected request")
	}
}

func TestNewInteractiveDefaultsToTheRunningExecutable(t *testing.T) {
	t.Parallel()

	el, err := NewInteractive(InteractiveOptions{})
	if err != nil {
		t.Fatalf("NewInteractive() = %v, want the running executable", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	e := el.(*interactive)
	if e.helper != exe {
		t.Fatalf("helper = %q, want %q", e.helper, exe)
	}
	if e.verb != runasVerb {
		t.Fatalf("verb = %q, want %q", e.verb, runasVerb)
	}
	if e.dir != filepath.Dir(exe) {
		t.Fatalf("working directory = %q, want %q", e.dir, filepath.Dir(exe))
	}
	if e.show != swHide {
		t.Fatalf("show = %d, want SW_HIDE (%d)", e.show, swHide)
	}
}

func TestNewInteractiveShowsTheWindowOnRequest(t *testing.T) {
	t.Parallel()

	el, err := NewInteractive(InteractiveOptions{HelperPath: helper(t, "exit /b 0"), ShowWindow: true})
	if err != nil {
		t.Fatal(err)
	}
	if show := el.(*interactive).show; show != swShowNormal {
		t.Fatalf("show = %d, want SW_SHOWNORMAL (%d)", show, swShowNormal)
	}
}

func TestNewInteractiveRejectsAnUnusableHelper(t *testing.T) {
	t.Parallel()

	for _, p := range []string{`helper.exe`, `\\fileserver\tools\helper.exe`, filepath.Join(t.TempDir(), "absent.exe")} {
		if _, err := NewInteractive(InteractiveOptions{HelperPath: p}); !errors.Is(err, ErrRequest) {
			t.Fatalf("NewInteractive(%q) = %v, want ErrRequest", p, err)
		}
	}
}

// ShellExecuteEx refuses a verb an object does not support. The error must come
// back as ErrHelper rather than as a success with no process to wait for.
func TestStartReportsAShellFailure(t *testing.T) {
	t.Parallel()

	e := unprivileged(t, helper(t, "exit /b 0"))
	e.verb = "idunn-no-such-verb"
	err := e.Apply(context.Background(), `C:\apps\demo`, descriptor("stable", "1.0.0"))
	if !errors.Is(err, ErrHelper) {
		t.Fatalf("Apply() with an unsupported verb = %v, want ErrHelper", err)
	}
}

// A string with an embedded NUL cannot become a UTF-16 command line. Win32 would
// silently truncate at the NUL, which is how a rejected suffix turns into a
// different program, a different root, or a different verb — so the conversion
// error has to surface as a refusal.
func TestStartRefusesUnconvertibleStrings(t *testing.T) {
	t.Parallel()

	nul := "open\x00extra"
	for _, tc := range []struct {
		name  string
		mutan func(*interactive)
	}{
		{"verb", func(e *interactive) { e.verb = nul }},
		{"helper", func(e *interactive) { e.helper = nul }},
		{"directory", func(e *interactive) { e.dir = nul }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := unprivileged(t, helper(t, "exit /b 0"))
			tc.mutan(e)
			if err := e.Apply(context.Background(), `C:\apps\demo`, descriptor("stable", "1.0.0")); !errors.Is(err, ErrRequest) {
				t.Fatalf("Apply() with a NUL in the %s = %v, want ErrRequest", tc.name, err)
			}
		})
	}
}

// A wait or an exit-code read that fails is never "the update worked". Both are
// forced here with a handle that cannot be waited on.
func TestWaitAndExitStatusFailClosed(t *testing.T) {
	t.Parallel()

	// A NULL handle, not windows.InvalidHandle: -1 is the pseudo-handle for the
	// current process, and waiting on that is a wait for our own exit.
	if err := waitForHelper(context.Background(), 0); !errors.Is(err, ErrHelper) {
		t.Fatalf("waitForHelper(invalid handle) = %v, want ErrHelper", err)
	}
	if err := helperExitStatus(0); !errors.Is(err, ErrHelper) {
		t.Fatalf("helperExitStatus(invalid handle) = %v, want ErrHelper", err)
	}
}

func TestCommandLineQuotesEveryArgument(t *testing.T) {
	t.Parallel()

	args := []string{"apply", "--root", `C:\Program Files\demo app`, "--channel", "stable", "--version", "1.0.0"}
	got, err := windows.DecomposeCommandLine("helper.exe " + commandLine(args))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(args)+1 {
		t.Fatalf("decomposed to %q, want %q behind a program name", got, args)
	}
	for i, want := range args {
		if got[i+1] != want {
			t.Fatalf("argument %d = %q, want %q", i, got[i+1], want)
		}
	}
}

// The real thing: verb "runas", a genuine UAC prompt, an administrator at the
// keyboard. Opt in with IDUNN_TEST_UAC=1; it can never run unattended, which is
// exactly why everything above avoids needing it.
func TestApplyElevatesForReal(t *testing.T) {
	if os.Getenv("IDUNN_TEST_UAC") != "1" {
		t.Skip("set IDUNN_TEST_UAC=1 to run the interactive UAC test")
	}
	p := helper(t, `echo %* >"%~dp0elevated.txt"`)
	el, err := NewInteractive(InteractiveOptions{HelperPath: p})
	if err != nil {
		t.Fatal(err)
	}
	err = el.Apply(context.Background(), `C:\Program Files\demo`, descriptor("stable", "1.0.0"))
	if errors.Is(err, ErrDeclined) {
		t.Fatal("the elevation prompt was declined; accept it to complete this test")
	}
	if err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	out, err := os.ReadFile(filepath.Join(filepath.Dir(p), "elevated.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "--version 1.0.0") {
		t.Fatalf("the elevated helper recorded %q", out)
	}
}
