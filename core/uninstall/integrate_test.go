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

package uninstall_test

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/integrate"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/uninstall"
	"github.com/go-idavoll/idunn/internal/layout"
)

const entryKey = integrate.UninstallKey + `\` + appName

// registered is tree with an "Installed apps" entry registered for it.
func registered(t *testing.T) (*fsx.Mem, *integrate.MemRegistry) {
	t.Helper()
	m := tree(t)
	reg := &integrate.MemRegistry{}
	in, err := integrate.New(integrate.Options{FS: m, Root: root, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.RegisterUninstallEntry(context.Background(), integrate.UninstallEntry{
		Scope: integrate.ScopeUser, ID: appName, DisplayName: "Acme", Launcher: fsx.Base(self),
	}); err != nil {
		t.Fatal(err)
	}
	return m, reg
}

func entryExists(t *testing.T, reg integrate.Registry) bool {
	t.Helper()
	_, err := reg.ReadKey(integrate.HiveUser, entryKey)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadKey: %v", err)
	}
	return err == nil
}

func TestTheInstalledAppsEntryGoesWithTheInstallation(t *testing.T) {
	noRootCheck(t)
	m, reg := registered(t)
	o := options(m)
	o.Registry = reg
	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	gone(t, m)
	if entryExists(t, reg) {
		t.Fatal("the Installed apps entry outlived the installation")
	}
}

// An installation whose record could not be acted on is not begun: removing the
// root would lose the only record of what to unregister.
func TestRecordedIntegrationsAreNotAbandoned(t *testing.T) {
	noRootCheck(t)
	t.Run("no registry", func(t *testing.T) {
		m, reg := registered(t)
		if _, err := uninstall.Run(context.Background(), options(m)); !errors.Is(err, uninstall.ErrUninstall) {
			t.Fatalf("Run = %v, want ErrUninstall", err)
		}
		intact(t, m)
		if !entryExists(t, reg) {
			t.Fatal("the entry is gone")
		}
	})
	t.Run("unreadable record", func(t *testing.T) {
		m := tree(t)
		write(t, m, layout.Integrations(root), "{")
		o := options(m)
		o.Registry = &integrate.MemRegistry{}
		if _, err := uninstall.Run(context.Background(), o); !errors.Is(err, integrate.ErrManifest) {
			t.Fatalf("Run = %v, want ErrManifest", err)
		}
		intact(t, m)
	})
}

func TestAnEntryThatWillNotGoIsFinishedByTheNextRun(t *testing.T) {
	noRootCheck(t)
	m, reg := registered(t)
	denied := errors.New("access denied")
	reg.Fail = func(op string, _ integrate.Hive, _ string) error {
		if op == "delete" {
			return denied
		}
		return nil
	}
	o := options(m)
	o.Registry = reg
	if _, err := uninstall.Run(context.Background(), o); !errors.Is(err, uninstall.ErrIncomplete) || !errors.Is(err, denied) {
		t.Fatalf("Run = %v, want ErrIncomplete wrapping %v", err, denied)
	}
	refusesToStart(t, m)
	if !exists(t, m, layout.Integrations(root)) || !entryExists(t, reg) {
		t.Fatal("the record of an entry that is still registered is gone")
	}

	reg.Fail = nil
	res, err := uninstall.Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed {
		t.Error("the second run did not resume")
	}
	gone(t, m)
	if entryExists(t, reg) {
		t.Fatal("the entry survived")
	}
}

func TestAnEntryOfAnotherRootIsLeftAlone(t *testing.T) {
	noRootCheck(t)
	m, reg := registered(t)
	if err := reg.WriteKey(integrate.HiveUser, entryKey, map[string]integrate.Value{
		integrate.OwnerValue: integrate.String(`D:\elsewhere\acme`),
	}, nil); err != nil {
		t.Fatal(err)
	}
	o := options(m)
	o.Registry = reg
	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	gone(t, m)
	if !entryExists(t, reg) {
		t.Fatal("an entry of another installation was removed")
	}
}

// The crash property of the uninstall, with an entry registered: wherever the
// filesystem fails, the entry is gone exactly when the uninstall began, and a
// second run always ends with neither the installation nor the entry.
func TestAnUninstallWithAnEntryInterruptedAnywhereIsFinished(t *testing.T) {
	noRootCheck(t)

	m, reg := registered(t)
	ops := 0
	m.Fail = func(string, string) error { ops++; return nil }
	o := options(m)
	o.Registry = reg
	if _, err := uninstall.Run(context.Background(), o); err != nil {
		t.Fatalf("clean Run: %v", err)
	}

	crash := errors.New("injected crash")
	for k := 1; k <= ops; k++ {
		m, reg := registered(t)
		n := 0
		m.Fail = func(string, string) error {
			n++
			if n == k {
				return crash
			}
			return nil
		}
		o := options(m)
		o.Registry = reg
		_, err := uninstall.Run(context.Background(), o)
		m.Fail = nil

		if err == nil {
			// Only the empty root itself would not go (see
			// TestAnUninstallInterruptedAnywhereIsFinishedByRunningItAgain).
			if entryExists(t, reg) {
				t.Fatalf("op %d: the entry outlived the installation", k)
			}
			continue
		}
		j, jerr := txn.Open(m, root)
		if jerr != nil {
			t.Fatalf("op %d: journal: %v", k, jerr)
		}
		if last, ok := j.Last(); ok && last.State != txn.StateUninstalling {
			intact(t, m)
			if !entryExists(t, reg) {
				t.Fatalf("op %d: the entry went although the uninstall never began", k)
			}
		}
		if _, err := uninstall.Run(context.Background(), o); err != nil {
			t.Fatalf("op %d: the second Run did not finish: %v", k, err)
		}
		gone(t, m)
		if entryExists(t, reg) {
			t.Fatalf("op %d: the entry outlived the installation", k)
		}
	}
}
