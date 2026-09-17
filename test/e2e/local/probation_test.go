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

//go:build e2e

package e2elocal

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// IDN-39. A committed update is on probation until the application confirms it
// is healthy; one that does not is rolled back by the launcher and not
// installed again.
// ---------------------------------------------------------------------------

// launchApp starts the installed application through cmd/launcher and asserts
// which version ran.
func (in *install) launchApp(version string, appArgs ...string) string {
	in.t.Helper()
	args := []string{"-quiet"}
	if len(appArgs) > 0 {
		args = append(append(args, "--", "--root", in.root), appArgs...)
	}
	code, out := in.runLauncher(args...)
	if code != exitOK || !strings.Contains(out, "app "+version+"\n") {
		in.t.Fatalf("launcher = %d, want app %s:\n%s", code, version, out)
	}
	return out
}

func TestUnconfirmedUpdateIsRolledBackAndNotOfferedAgain(t *testing.T) {
	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)
	in.mustInstall("1.0.0")

	r.publish("1.1.0")
	if code, out := in.selfUpdate("--probation-attempts", "2"); code != exitOK {
		t.Fatalf("self-update = %d\n%s", code, out)
	}
	in.observe().settled(t, "1.1.0", "1.0.0", "1.1.0")

	// Two starts that never confirm.
	in.launchApp("1.1.0")
	in.launchApp("1.1.0")

	// The third is refused 1.1.0 and gets 1.0.0 back, and says why.
	out := in.launchApp("1.0.0")
	if !strings.Contains(out, "1.1.0 failed its probation and was rolled back to 1.0.0: not confirmed healthy after 2 starts") {
		t.Fatalf("the launcher did not report the rollback:\n%s", out)
	}
	s := in.observe()
	// The journal still says 1.1.0 committed, which it did; the pointer and the
	// install state are what moved back.
	if s.installed != "1.0.0" || !equal(s.versions, []string{"1.0.0"}) || s.staging != 0 {
		t.Fatalf("after the rollback: %s", s)
	}
	in.launchApp("1.0.0")

	// The application's own updater does not take 1.1.0 again.
	code, out := in.selfUpdate("--probation-attempts", "2")
	if code != appNoUpdate || !strings.Contains(out, "1.1.0 was rolled back on this machine") {
		t.Fatalf("self-update over the rolled-back release = %d, want %d\n%s", code, appNoUpdate, out)
	}

	// The next release is offered, and one that confirms stays.
	r.publish("1.2.0")
	if code, out := in.selfUpdate("--probation-attempts", "2"); code != exitOK {
		t.Fatalf("self-update to 1.2.0 = %d\n%s", code, out)
	}
	in.launchApp("1.2.0", "--mark", "healthy")
	for range 3 {
		in.launchApp("1.2.0")
	}
	in.observe().settled(t, "1.2.0", "1.0.0", "1.2.0")
}

func TestUnhealthyUpdateIsRolledBackAtTheNextStart(t *testing.T) {
	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)
	in.mustInstall("1.0.0")

	r.publish("1.1.0")
	if code, out := in.selfUpdate("--probation-attempts", "5"); code != exitOK {
		t.Fatalf("self-update = %d\n%s", code, out)
	}
	in.launchApp("1.1.0", "--mark", "unhealthy", "--reason", "schema 7 is newer than this build understands")

	out := in.launchApp("1.0.0")
	if !strings.Contains(out, "rolled back to 1.0.0: schema 7 is newer than this build understands") {
		t.Fatalf("the launcher did not report the application's reason:\n%s", out)
	}
	if s := in.observe(); s.installed != "1.0.0" {
		t.Fatalf("after the rollback: %s", s)
	}
}
