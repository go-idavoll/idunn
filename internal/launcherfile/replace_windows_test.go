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

package launcherfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
)

const sleeperEnv = "IDUNN_LAUNCH_TEST_SLEEPER"

// TestSleeper is not a test: it is the running launcher in the test below — a
// copy of this test binary that does nothing but stay alive.
func TestSleeper(t *testing.T) {
	if os.Getenv(sleeperEnv) == "" {
		t.Skip("helper process for TestReplacingARunningExecutable")
	}
	time.Sleep(60 * time.Second)
}

// The mechanism is a claim about Windows, so it is tested against Windows: an
// executable that is running cannot be replaced by a rename over its name, and
// can be renamed aside, after which the new one takes its name.
func TestReplacingARunningExecutable(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self) //nolint:gosec // G304: the test binary itself.
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "launcher.exe")
	if err := os.WriteFile(path, raw, 0o755); err != nil { //nolint:gosec // G306: an executable.
		t.Fatal(err)
	}

	cmd := exec.CommandContext(t.Context(), path, "-test.run=^TestSleeper$") //nolint:gosec // G204: the copy made above.
	cmd.Env = append(os.Environ(), sleeperEnv+"=1")
	if err := cmd.Start(); err != nil {
		// Attack-surface-reduction policies refuse to run fresh binaries from
		// some directories; that is the host, not the mechanism.
		t.Skipf("cannot start a copy of the test binary here (set TMP to a directory executables may run from): %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	time.Sleep(200 * time.Millisecond) // let the loader map the image.
	if cmd.ProcessState != nil {
		t.Skipf("the helper exited at once: %v", cmd.ProcessState)
	}

	name := fsx.Slash(path)
	f := fsx.OS()

	// The premise: a plain atomic write over a running image is refused.
	if err := ReplaceByRename(f, name, []byte("new launcher")); err == nil {
		t.Fatal("a rename over a running executable succeeded; the aside mechanism would be unnecessary here")
	}

	var scheduled []string
	if err := ReplaceAside(func(n string) { scheduled = append(scheduled, n) })(f, name, []byte("new launcher")); err != nil {
		t.Fatalf("replaceAside on a running executable: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: the file under test.
	if err != nil || string(got) != "new launcher" {
		t.Fatalf("the launcher reads %q, %v", got, err)
	}
	aside := name + AsideSuffix + "1"
	if _, err := os.Lstat(aside); err != nil {
		t.Fatalf("the running image is not beside the new launcher: %v", err)
	}
	if len(scheduled) != 1 || scheduled[0] != aside {
		t.Errorf("the undeletable leftover was not scheduled: %v", scheduled)
	}

	// While it runs, the sweep cannot remove it and says nothing.
	if sweep(t, f, name) {
		t.Error("the sweep restored something while the launcher was in place")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	// Once nothing runs from it, the next start's sweep removes it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		sweep(t, f, name)
		if _, err := os.Lstat(aside); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the leftover survived the sweep after its process exited")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
