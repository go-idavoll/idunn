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

package launch_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/integrate"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/internal/layout"
)

// register records an "Installed apps" entry for the installation as it is now.
func register(t *testing.T, m *fsx.Mem) *integrate.MemRegistry {
	t.Helper()
	reg := &integrate.MemRegistry{}
	in, err := integrate.New(integrate.Options{FS: m, Root: root, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.RegisterUninstallEntry(context.Background(), integrate.UninstallEntry{
		Scope: integrate.ScopeUser, ID: appName, DisplayName: "Acme", Launcher: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func shown(t *testing.T, reg integrate.Registry) string {
	t.Helper()
	v, err := reg.ReadKey(integrate.HiveUser, integrate.UninstallKey+`\`+appName)
	if err != nil {
		t.Fatal(err)
	}
	return v["DisplayVersion"].S
}

func TestStartReconcilesTheInstalledAppsEntry(t *testing.T) {
	t.Run("after a deferred update", func(t *testing.T) {
		m := deferredTree(t)
		reg := register(t, m)
		res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Migrate: &migrator{fs: m}, Registry: reg})
		if err != nil || res.IntegrateErr != nil {
			t.Fatalf("Start = %v, IntegrateErr %v", err, res.IntegrateErr)
		}
		if got := shown(t, reg); got != "1.3.0" {
			t.Fatalf("DisplayVersion = %q, want 1.3.0", got)
		}
	})
	t.Run("after an update that did not refresh it", func(t *testing.T) {
		m := tree(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
		reg := register(t, m)
		if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
			t.Fatal(err)
		}
		if _, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Registry: reg}); err != nil {
			t.Fatal(err)
		}
		if got := shown(t, reg); got != "1.3.0" {
			t.Fatalf("DisplayVersion = %q, want 1.3.0", got)
		}
	})
	t.Run("while the deferred update waits", func(t *testing.T) {
		m := deferredTree(t)
		reg := register(t, m)
		_ = reg.WriteKey(integrate.HiveUser, integrate.UninstallKey+`\`+appName,
			map[string]integrate.Value{"DisplayVersion": integrate.String("0.9.0")}, nil)
		res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root, Lock: &lock{held: true}, Registry: reg})
		if err != nil || !res.Skipped {
			t.Fatalf("Start = %+v, %v", res, err)
		}
		if got := shown(t, reg); got != "1.2.0" {
			t.Fatalf("DisplayVersion = %q, want the live 1.2.0", got)
		}
	})
}

// A start never fails over the entry, and one that finds it current writes
// nothing — which is what lets an unprivileged start of a system-wide
// installation succeed.
func TestStartDoesNotFailOverTheEntry(t *testing.T) {
	m := tree(t, []string{"1.2.0", "1.3.0"}, "1.2.0")
	reg := register(t, m)
	denied := errors.New("access denied")
	reg.Fail = func(op string, _ integrate.Hive, _ string) error {
		if op != "read" {
			return denied
		}
		return nil
	}
	ev := &events{}
	o := launch.Options{FS: m, Root: root, Registry: reg, Observe: ev}

	res, err := launch.Start(context.Background(), o)
	if err != nil || res.IntegrateErr != nil {
		t.Fatalf("a current entry: Start = %v, IntegrateErr %v", err, res.IntegrateErr)
	}

	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	res, err = launch.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start = %v", err)
	}
	if !errors.Is(res.IntegrateErr, denied) || !errors.Is(res.IntegrateErr, launch.ErrLaunch) {
		t.Fatalf("IntegrateErr = %v, want ErrLaunch wrapping %v", res.IntegrateErr, denied)
	}
	if len(ev.seen) == 0 || !errors.Is(ev.seen[len(ev.seen)-1].Err, denied) {
		t.Fatal("the failure was not reported")
	}
}

func TestStartWithoutRegistryIgnoresTheRecord(t *testing.T) {
	m := tree(t, []string{"1.2.0"}, "1.2.0")
	register(t, m)
	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: root})
	if err != nil || res.IntegrateErr != nil {
		t.Fatalf("Start = %v, IntegrateErr %v", err, res.IntegrateErr)
	}
}

func TestStartReportsAnUnusableRoot(t *testing.T) {
	m := tree(t, []string{"1.2.0"}, "1.2.0")
	res, err := launch.Start(context.Background(), launch.Options{FS: m, Root: "opt/app", Registry: &integrate.MemRegistry{}})
	if err != nil {
		t.Fatalf("Start = %v", err)
	}
	if !errors.Is(res.IntegrateErr, integrate.ErrIntegrate) {
		t.Fatalf("IntegrateErr = %v, want ErrIntegrate", res.IntegrateErr)
	}
}
