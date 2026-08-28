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

//go:build linux

// The GOOS suffix rule only applies to a name ending in _linux.go or
// _linux_test.go, and this file ends in _internal_test.go — so the constraint
// has to be written out.

package elevate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/release"
)

// The whole pkexec path is exercised with a stand-in for pkexec, the way the
// Windows tests exercise ShellExecuteEx with a verb that does not need an
// administrator at the machine. What is under test is everything around the
// privilege transition: the argument vector, the environment, the working
// directory, the wait, and how an exit code is read.
//
// polkit itself is not under test. It is the operating system's, it is tested
// there, and a test that needed a real authentication dialog would not run in
// CI at all — which is the same as not existing.

// fakePkexec writes a shell script that records how it was called and exits with
// the given status.
func fakePkexec(t *testing.T, exitCode int) (path, logFile string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "pkexec")
	logFile = filepath.Join(dir, "call.log")
	script := "#!/bin/sh\n" +
		"{ echo \"pwd=$(pwd)\"; env; for a in \"$@\"; do echo \"arg=$a\"; done; } > " +
		logFile + "\n" +
		"exit " + itoa(exitCode) + "\n"
	//nolint:gosec // G306: it has to be executable to stand in for a program.
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, logFile
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// helperBinary is a file that passes checkHelperPath: absolute, local, regular.
func helperBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "acme-helper")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // it stands in for a binary.
		t.Fatal(err)
	}
	return p
}

func descriptorFor(version string) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "acme",
		Version:       version,
		Channel:       "stable",
		OS:            "linux",
		Arch:          "amd64",
	}
}

// The request reaches pkexec as an argument vector: the helper first, then the
// verb and the three scalars, each its own element. Nothing is rendered into a
// string that anything downstream has to split apart again.
func TestPkexecReceivesTheRequestAsAnArgumentVector(t *testing.T) {
	// A marker in this process's environment. If it turns up on the other side
	// of the elevation, the boundary is leaking whatever the host happened to be
	// started with -- which on a desktop is a session's worth of variables.
	t.Setenv("IDUNN_ELEVATE_SENTINEL", "must-not-cross")

	pkexec, logFile := fakePkexec(t, 0)
	helper := helperBinary(t)
	e := &interactive{elevator: pkexec, helper: helper, dir: filepath.Dir(helper)}

	if err := e.Apply(t.Context(), "/opt/acme", descriptorFor("1.3.0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("the stand-in was not run: %v", err)
	}
	var args []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if v, ok := strings.CutPrefix(line, "arg="); ok {
			args = append(args, v)
		}
	}
	want := []string{helper, "apply", "--root", "/opt/acme", "--channel", "stable", "--version", "1.3.0"}
	if len(args) != len(want) {
		t.Fatalf("pkexec was called with %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("argument %d = %q, want %q", i, args[i], want[i])
		}
	}

	// And with nothing carried across from this process's environment: what
	// pkexec sanitizes is our environment, and the smallest thing to sanitize is
	// an empty one.
	if strings.Contains(string(raw), "IDUNN_ELEVATE_SENTINEL") {
		t.Errorf("the elevated side inherited this process's environment:\n%s", raw)
	}
	// The working directory is the helper's own, not whatever the host set.
	if !strings.Contains(string(raw), "pwd="+filepath.Dir(helper)) {
		t.Errorf("the working directory was not the helper's:\n%s", raw)
	}
}

// A dismissed dialog is a decision, and it must be reported as one. Classifying
// it as a failure is what turns "not now" into a password prompt every few
// minutes.
func TestADismissedPromptIsDeclined(t *testing.T) {
	pkexec, _ := fakePkexec(t, pkexecNotAuthorized)
	helper := helperBinary(t)
	e := &interactive{elevator: pkexec, helper: helper, dir: filepath.Dir(helper)}

	err := e.Apply(t.Context(), "/opt/acme", descriptorFor("1.3.0"))
	if !errors.Is(err, elevateDeclined()) {
		t.Fatalf("err = %v, want ErrDeclined", err)
	}
}

func elevateDeclined() error { return ErrDeclined }

// pkexec failing to run the helper is an operational problem, not a user
// decision: the two must stay distinguishable or a broken deployment looks like
// a user who keeps saying no.
func TestAHelperThatCannotBeRunIsAHelperFailure(t *testing.T) {
	pkexec, _ := fakePkexec(t, pkexecNotRun)
	helper := helperBinary(t)
	e := &interactive{elevator: pkexec, helper: helper, dir: filepath.Dir(helper)}

	err := e.Apply(t.Context(), "/opt/acme", descriptorFor("1.3.0"))
	if !errors.Is(err, ErrHelper) {
		t.Fatalf("err = %v, want ErrHelper", err)
	}
	if errors.Is(err, ErrDeclined) {
		t.Error("a deployment problem was reported as a user decision")
	}
}

// The helper's own non-zero status comes back as a helper failure with the code.
func TestAFailedApplyCarriesTheExitCode(t *testing.T) {
	pkexec, _ := fakePkexec(t, 3)
	helper := helperBinary(t)
	e := &interactive{elevator: pkexec, helper: helper, dir: filepath.Dir(helper)}

	err := e.Apply(t.Context(), "/opt/acme", descriptorFor("1.3.0"))
	if !errors.Is(err, ErrHelper) {
		t.Fatalf("err = %v, want ErrHelper", err)
	}
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("the error does not carry the exit status: %v", err)
	}
}

// A request outside the grammar never becomes a process. The elevator is the one
// place where an unvalidated value would end up on a root process's command
// line, so the check has to happen before anything is started.
func TestAnInvalidRequestStartsNothing(t *testing.T) {
	pkexec, logFile := fakePkexec(t, 0)
	helper := helperBinary(t)
	e := &interactive{elevator: pkexec, helper: helper, dir: filepath.Dir(helper)}

	err := e.Apply(t.Context(), "relative/root", descriptorFor("1.3.0"))
	if !errors.Is(err, ErrRequest) {
		t.Fatalf("err = %v, want ErrRequest", err)
	}
	if _, statErr := os.Stat(logFile); statErr == nil {
		t.Fatal("VULNERABILITY: an invalid request started an elevated process")
	}
}

// A cancelled context stops the waiting, not the apply. Killing a helper that may
// be mid-swap is the half-written install everything else here exists to prevent.
func TestACancelledContextAbandonsTheWaitAndNotTheHelper(t *testing.T) {
	dir := t.TempDir()
	pkexec := filepath.Join(dir, "pkexec")
	started := filepath.Join(dir, "started")
	marker := filepath.Join(dir, "finished")
	script := "#!/bin/sh\ntouch " + started + "\nsleep 1\ntouch " + marker + "\nexit 0\n"
	if err := os.WriteFile(pkexec, []byte(script), 0o755); err != nil { //nolint:gosec // it stands in for a program.
		t.Fatal(err)
	}
	helper := helperBinary(t)
	e := &interactive{elevator: pkexec, helper: helper, dir: filepath.Dir(helper)}

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() { errCh <- e.Apply(ctx, "/opt/acme", descriptorFor("1.3.0")) }()

	// Cancel only once the elevated side is really running. Cancelling earlier
	// would be answered by the check at the top of Apply, and the test would
	// pass without ever having started anything to abandon.
	waitFor(t, started)
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	// The elevated process is still running and still allowed to finish.
	waitFor(t, marker)
}

// waitFor blocks until name exists.
func waitFor(t *testing.T, name string) {
	t.Helper()
	deadline := 30
	for range deadline {
		if _, err := os.Stat(name); err == nil {
			return
		}
		sleepASecond()
	}
	t.Fatal("the abandoned helper never finished; cancelling appears to have killed it")
}

func sleepASecond() { time.Sleep(100 * time.Millisecond) }
