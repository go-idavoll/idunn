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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/integrate"
)

// TestInstalledAppsEntry drives the Windows "Installed apps" entry through real
// processes and the real registry (IDN-36): cmd/installer registers it,
// cmd/launcher reconciles it at a start and removes it with --uninstall, and a
// second install brings it to the new version.
//
// The entry is the current user's: a root in the test's scratch directory is
// not administrators-only. It is keyed by the release name, so this scenario
// must be the only one that registers.
func TestInstalledAppsEntry(t *testing.T) {
	reg := integrate.OSRegistry()
	key := integrate.UninstallKey + `\hostapp`
	if _, err := reg.ReadKey(integrate.HiveUser, key); err == nil {
		t.Skipf(`HKEY_CURRENT_USER\%s already exists and is not this test's`, key)
	}

	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)
	t.Cleanup(func() {
		if v, err := reg.ReadKey(integrate.HiveUser, key); err == nil && strings.EqualFold(v[integrate.OwnerValue].S, in.root) {
			_ = reg.DeleteKey(integrate.HiveUser, key)
		}
	})

	if code, out := in.runInstallerBinary(suite.registrar); code != 0 {
		t.Fatalf("installer = %d\n%s", code, out)
	}
	entry := func() map[string]integrate.Value {
		t.Helper()
		v, err := reg.ReadKey(integrate.HiveUser, key)
		if err != nil {
			t.Fatalf("the entry: %v", err)
		}
		return v
	}
	v := entry()
	self := filepath.Join(in.root, exe("launcher"))
	if v["DisplayVersion"].S != "1.0.0" || !strings.EqualFold(v[integrate.OwnerValue].S, in.root) ||
		!strings.EqualFold(v["UninstallString"].S, `"`+self+`" --uninstall`) {
		t.Fatalf("entry after the install = %v", v)
	}

	// The launcher sits in the root, as a real installation keeps it.
	raw, err := os.ReadFile(suite.launcher)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(self, raw, 0o755); err != nil {
		t.Fatal(err)
	}

	// An entry that says the wrong version is corrected by the next start.
	if err := reg.WriteKey(integrate.HiveUser, key, map[string]integrate.Value{"DisplayVersion": integrate.String("0.0.1")}, nil); err != nil {
		t.Fatal(err)
	}
	if code, out := runProc(t, self, "-root", in.root); code != exitOK || !strings.Contains(out, "app 1.0.0") {
		t.Fatalf("start = %d: %q", code, out)
	}
	if got := entry()["DisplayVersion"].S; got != "1.0.0" {
		t.Fatalf("DisplayVersion after a start = %q, want 1.0.0", got)
	}

	// A newer install brings the entry along.
	r.publish("1.1.0")
	if code, out := in.runInstallerBinary(suite.registrar); code != 0 {
		t.Fatalf("second installer = %d\n%s", code, out)
	}
	if got := entry()["DisplayVersion"].S; got != "1.1.0" {
		t.Fatalf("DisplayVersion after installing 1.1.0 = %q", got)
	}

	if elevated() {
		// See TestUninstall: an elevated process is refused a user-owned root.
		return
	}
	if code, out := runProc(t, self, "-root", in.root, "--uninstall"); code != exitOK {
		t.Fatalf("--uninstall = %d\n%s", code, out)
	}
	if _, err := reg.ReadKey(integrate.HiveUser, key); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the entry outlived the uninstall: %v", err)
	}
	deadline := time.Now().Add(lineTimeout)
	for {
		if _, err := os.Stat(in.root); errors.Is(err, fs.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the root was not removed in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
