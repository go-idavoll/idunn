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

package updater_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/integrate"
)

// withEntry registers an "Installed apps" entry for the fixture's installation
// and hands the updater the registry it lives in.
func withEntry(t *testing.T, f *fixture) *integrate.MemRegistry {
	t.Helper()
	reg := &integrate.MemRegistry{}
	in, err := integrate.New(integrate.Options{FS: f.fs, Root: root, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.RegisterUninstallEntry(context.Background(), integrate.UninstallEntry{
		Scope: integrate.ScopeUser, ID: appName, DisplayName: "Acme", Launcher: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	f.opts.Registry = reg
	return reg
}

func displayVersion(t *testing.T, reg integrate.Registry) string {
	t.Helper()
	v, err := reg.ReadKey(integrate.HiveUser, integrate.UninstallKey+`\`+appName)
	if err != nil {
		t.Fatal(err)
	}
	return v["DisplayVersion"].S
}

func TestApplyRefreshesTheInstalledAppsEntry(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	reg := withEntry(t, f)
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	if got := displayVersion(t, reg); got != "1.3.0" {
		t.Fatalf("DisplayVersion = %q after the update, want 1.3.0", got)
	}
}

// The registry is not part of the transaction: an entry that cannot be written
// is reported, and the committed update stands.
func TestAnEntryThatCannotBeWrittenDoesNotFailTheUpdate(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	reg := withEntry(t, f)
	denied := errors.New("access denied")
	reg.Fail = func(op string, _ integrate.Hive, _ string) error {
		if op == "write" {
			return denied
		}
		return nil
	}
	if err := f.run(); err != nil {
		t.Fatalf("Apply = %v; a registry failure failed the update", err)
	}
	if f.pointer() != "1.3.0" || f.stateVersion() != "1.3.0" {
		t.Fatalf("pointer %q, state %q: the update did not stand", f.pointer(), f.stateVersion())
	}
	reported := false
	for _, e := range f.hooks.events {
		reported = reported || (e.Phase == hook.PhaseCommit && errors.Is(e.Err, denied))
	}
	if !reported {
		t.Fatal("the failed refresh was not reported")
	}
	if got := displayVersion(t, reg); got != "1.2.0" {
		t.Fatalf("DisplayVersion = %q", got)
	}
}

// An update that rolls back leaves the entry naming the version that is live —
// and, since that is what it already says, writes nothing.
func TestARolledBackUpdateLeavesTheEntryAlone(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	reg := withEntry(t, f)
	f.hooks.migrateEr = errors.New("migration failed")
	reg.Fail = func(op string, _ integrate.Hive, _ string) error {
		if op != "read" {
			return errors.New("written")
		}
		return nil
	}
	if err := f.run(); err == nil {
		t.Fatal("the update did not fail")
	}
	for _, e := range f.hooks.events {
		if e.Err != nil && e.Phase == hook.PhaseCommit {
			t.Fatalf("the entry was touched: %v", e.Err)
		}
	}
	if got := displayVersion(t, reg); got != "1.2.0" {
		t.Fatalf("DisplayVersion = %q, want 1.2.0", got)
	}
}

// A canceled context still refreshes: the update may have committed before the
// cancellation reached it.
func TestTheRefreshOutlivesACanceledApply(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	reg := withEntry(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.opts.Observe = observerFunc(func(e hook.Event) {
		if e.Phase == hook.PhaseCommit && e.Err == nil {
			cancel()
		}
	})
	u := f.updater()
	r, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Apply(ctx, r); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("the context was not canceled after the commit")
	}
	if got := displayVersion(t, reg); got != "1.3.0" {
		t.Fatalf("DisplayVersion = %q, want 1.3.0", got)
	}
}

func TestAnUnreadableRecordIsReportedNotFailed(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	withEntry(t, f)
	// A manifest that does not validate stands for any integrate failure.
	if err := f.fs.MkdirAll(root+"/.updater", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(f.fs, root+"/.updater/integrations.json", []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.run(); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	reported := false
	for _, e := range f.hooks.events {
		reported = reported || errors.Is(e.Err, integrate.ErrManifest)
	}
	if !reported {
		t.Fatal("the failure was not reported")
	}
}

type observerFunc func(hook.Event)

func (o observerFunc) OnEvent(e hook.Event) { o(e) }
