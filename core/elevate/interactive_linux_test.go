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

package elevate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests run the real launcher (startDetached) with a shell script standing
// in for pkexec, the way the Windows tests run ShellExecuteEx with the verb
// "open": everything but polkit itself — the argument vector, the environment,
// the terminal, the working directory, the exit status, the abandoned wait. The
// ownership checks are pkexec_internal_test.go's; a temporary directory could
// never pass them. The real prompt is behind IDUNN_TEST_PKEXEC.

// standIn writes an executable shell script and returns its path. The script
// only uses shell builtins and absolute paths: it runs with an empty
// environment, so there is no PATH to find anything by.
func standIn(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "pkexec")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixture returns an elevator whose pkexec is the given script body and whose
// helper is a file next to it.
func fixture(t *testing.T, dir, body string) *pkexecElevator {
	t.Helper()
	helper := filepath.Join(dir, "helper")
	if err := os.WriteFile(helper, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return &pkexecElevator{pkexec: standIn(t, dir, body), helper: helper, start: startDetached}
}

func TestStartDetachedPassesOnlyTheArgumentVector(t *testing.T) {
	// A marker in this process's environment. If it arrives on the other side,
	// the boundary carries whatever the host was started with.
	t.Setenv("IDUNN_ELEVATE_SENTINEL", "must-not-cross")

	dir := t.TempDir()
	log := filepath.Join(dir, "call.log")
	e := fixture(t, dir, `{
  echo "pid=$$"
  read -r _ _ _ _ _ sid _ < /proc/$$/stat
  echo "sid=$sid"
  echo "pwd=$(pwd)"
  export -p
  for a in "$@"; do echo "arg=$a"; done
} > '`+log+`'`)

	if err := e.Apply(context.Background(), "/opt/acme app", descriptor("stable", "1.3.0")); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the stand-in did not run: %v", err)
	}
	out := string(raw)
	var args []string
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if v, ok := strings.CutPrefix(line, "arg="); ok {
			args = append(args, v)
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			values[k] = v
		}
	}
	want := []string{e.helper, "apply", "--root", "/opt/acme app", "--channel", "stable", "--version", "1.3.0"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("pkexec received %q, want %q", args, want)
	}
	if strings.Contains(out, "IDUNN_ELEVATE_SENTINEL") {
		t.Errorf("the environment crossed the boundary:\n%s", out)
	}
	if values["pwd"] != dir {
		t.Errorf("working directory = %q, want the helper's %q", values["pwd"], dir)
	}
	// Its own session: no controlling terminal to fall back to prompting on.
	if values["pid"] == "" || values["sid"] != values["pid"] {
		t.Errorf("pkexec is not a session leader (pid %q, sid %q)", values["pid"], values["sid"])
	}
}

// The tests that start a script are not parallel: writing an executable while
// another goroutine forks can leak the write descriptor into that child and
// fail the exec with ETXTBSY (golang/go#22315).
func TestStartDetachedExitStatus(t *testing.T) {
	for _, tc := range []struct {
		code int
		want error
	}{
		{0, nil},
		{126, ErrDeclined},
		{127, ErrHelper},
		{3, ErrHelper},
	} {
		t.Run(strconv.Itoa(tc.code), func(t *testing.T) {
			e := fixture(t, t.TempDir(), "exit "+strconv.Itoa(tc.code))
			err := e.Apply(context.Background(), "/opt/acme", descriptor("stable", "1.3.0"))
			if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("exit %d: Apply = %v, want %v", tc.code, err, tc.want)
			}
		})
	}
	e := fixture(t, t.TempDir(), "kill -KILL $$")
	if err := e.Apply(context.Background(), "/opt/acme", descriptor("stable", "1.3.0")); !errors.Is(err, ErrHelper) {
		t.Fatalf("killed: Apply = %v, want ErrHelper", err)
	}
}

func TestStartDetachedRefusesARelativeProgram(t *testing.T) {
	t.Parallel()

	if _, err := startDetached([]string{"pkexec"}, "/"); err == nil {
		t.Fatal("startDetached ran a program by name")
	}
}

// Cancelling abandons the wait and leaves the process running to completion.
func TestStartDetachedCancelDoesNotKill(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	finished := filepath.Join(dir, "finished")
	e := fixture(t, dir, ": > '"+started+"'\n/bin/sleep 1\n: > '"+finished+"'")

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Apply(ctx, "/opt/acme", descriptor("stable", "1.3.0")) }()
	waitForFile(t, started)
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply = %v, want context.Canceled", err)
	}
	waitForFile(t, finished)
}

func waitForFile(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(name); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", name)
}

// The running test binary lives in a directory its user owns, so it cannot be
// the helper; or there is no pkexec. Either way nothing is returned to elevate
// with.
func TestNewInteractiveRefusesAUserOwnedExecutable(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("as root, the test binary may well be root-owned")
	}
	el, err := NewInteractive(InteractiveOptions{})
	if !errors.Is(err, ErrRequest) && !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("NewInteractive() = %v, want ErrRequest or ErrNotImplemented", err)
	}
	if el != nil {
		t.Fatal("an Elevator was returned alongside the error")
	}
}

// The real thing: pkexec, a polkit agent, an administrator's password. Opt in
// with IDUNN_TEST_PKEXEC=1 from a desktop session; CI never sets it. The helper
// is /usr/bin/true, which is root-owned on any stock system and ignores the
// request, so accepting the prompt changes nothing.
func TestApplyElevatesWithPkexecForReal(t *testing.T) {
	if os.Getenv("IDUNN_TEST_PKEXEC") != "1" {
		t.Skip("set IDUNN_TEST_PKEXEC=1 to run the interactive pkexec test")
	}
	el, err := NewInteractive(InteractiveOptions{HelperPath: "/usr/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	err = el.Apply(context.Background(), "/opt/idunn-test-does-not-exist", descriptor("stable", "1.0.0"))
	if errors.Is(err, ErrDeclined) {
		t.Fatal("the authentication dialog was dismissed; authenticate to complete this test")
	}
	if err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
}
