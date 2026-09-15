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

package integrate_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/integrate"
	"github.com/go-idavoll/idunn/internal/layout"
)

const (
	root    = "/apps/acme"
	winRoot = `\apps\acme`
	other   = "/apps/acme-old"
	id      = "acme-app"
	key     = integrate.UninstallKey + `\` + id
)

var at = time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

// installed builds a root with a live 1.2.0 of 3000 bytes and a 1000-byte
// launcher, and 1.3.0 staged beside it.
func installed(t *testing.T) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	for v, size := range map[string]int{"1.2.0": 3000, "1.3.0": 5000} {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatal(err)
		}
		write(t, m, fsx.Join(dir, "bin", "acme.exe"), strings.Repeat("x", size-100))
		write(t, m, fsx.Join(dir, "data.bin"), strings.Repeat("y", 100))
	}
	write(t, m, fsx.Join(root, "acme.exe"), strings.Repeat("l", 1000))
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	return m
}

func write(t *testing.T, m *fsx.Mem, name, content string) {
	t.Helper()
	if err := m.MkdirAll(fsx.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(m, name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func entry() integrate.UninstallEntry {
	return integrate.UninstallEntry{
		Scope:       integrate.ScopeUser,
		ID:          id,
		DisplayName: "Acme Editor",
		Publisher:   "Acme Corp",
		Launcher:    "acme.exe",
	}
}

type events []hook.Event

func (e *events) OnEvent(ev hook.Event) { *e = append(*e, ev) }

func newIntegrator(t *testing.T, m *fsx.Mem, reg integrate.Registry) (*integrate.Integrator, *events) {
	t.Helper()
	ev := &events{}
	in, err := integrate.New(integrate.Options{FS: m, Root: root, Registry: reg, Now: func() time.Time { return at }, Observe: ev})
	if err != nil {
		t.Fatal(err)
	}
	return in, ev
}

func readKey(t *testing.T, reg integrate.Registry, h integrate.Hive, path string) map[string]integrate.Value {
	t.Helper()
	v, err := reg.ReadKey(h, path)
	if err != nil {
		t.Fatalf("ReadKey(%s): %v", path, err)
	}
	return v
}

func records(t *testing.T, in *integrate.Integrator) []integrate.Record {
	t.Helper()
	r, err := in.Registered()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterWritesTheEntry(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)

	if err := in.RegisterUninstallEntry(context.Background(), entry()); err != nil {
		t.Fatal(err)
	}
	got := readKey(t, reg, integrate.HiveUser, key)
	want := map[string]integrate.Value{
		"DisplayName":          integrate.String("Acme Editor"),
		"Publisher":            integrate.String("Acme Corp"),
		"DisplayVersion":       integrate.String("1.2.0"),
		"DisplayIcon":          integrate.String(winRoot + `\acme.exe`),
		"InstallLocation":      integrate.String(winRoot),
		"InstallDate":          integrate.String("20260915"),
		"EstimatedSize":        integrate.DWord(4), // 3000 + 1000 bytes, rounded up to KiB
		"UninstallString":      integrate.String(`"` + winRoot + `\acme.exe" --uninstall`),
		"QuietUninstallString": integrate.String(`"` + winRoot + `\acme.exe" --uninstall --quiet`),
		"NoModify":             integrate.DWord(1),
		"NoRepair":             integrate.DWord(1),
		integrate.OwnerValue:   integrate.String(winRoot),
	}
	if len(got) != len(want) {
		t.Errorf("entry has %d values, want %d: %v", len(got), len(want), got)
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %+v, want %+v", name, got[name], v)
		}
	}
	if r := records(t, in); len(r) != 1 || r[0] != (integrate.Record{Kind: integrate.KindWindowsUninstall, Scope: integrate.ScopeUser, ID: id, Launcher: "acme.exe"}) {
		t.Errorf("manifest = %+v", r)
	}
	if _, err := reg.ReadKey(integrate.HiveMachine, key); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a user entry reached the machine hive: %v", err)
	}
}

func TestRegisterMachineScope(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	e := entry()
	e.Scope = integrate.ScopeMachine
	if err := in.RegisterUninstallEntry(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	readKey(t, reg, integrate.HiveMachine, key)
	if _, err := reg.ReadKey(integrate.HiveUser, key); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a machine entry reached the user hive: %v", err)
	}
}

// A sidecar registers Modify and Repair; the installer run again resets them,
// and the install date of the first registration survives both.
func TestRegisterAgainUpdatesModifyAndKeepsTheInstallDate(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	ctx := context.Background()
	if err := in.RegisterUninstallEntry(ctx, entry()); err != nil {
		t.Fatal(err)
	}

	later, _ := integrate.New(integrate.Options{FS: m, Root: root, Registry: reg, Now: func() time.Time { return at.AddDate(0, 1, 0) }})
	e := entry()
	e.ModifyPath = `"C:\Apps\acme-ui.exe" --modify`
	e.Repair = true
	e.Publisher = ""
	if err := later.RegisterUninstallEntry(ctx, e); err != nil {
		t.Fatal(err)
	}
	got := readKey(t, reg, integrate.HiveUser, key)
	if got["ModifyPath"] != integrate.String(e.ModifyPath) || got["NoModify"] != integrate.DWord(0) || got["NoRepair"] != integrate.DWord(0) {
		t.Errorf("modify values = %v", got)
	}
	if _, ok := got["Publisher"]; ok {
		t.Error("an emptied publisher was left in the entry")
	}
	if got["InstallDate"] != integrate.String("20260915") {
		t.Errorf("InstallDate = %v, want the first registration's", got["InstallDate"])
	}

	if err := later.RegisterUninstallEntry(ctx, entry()); err != nil {
		t.Fatal(err)
	}
	got = readKey(t, reg, integrate.HiveUser, key)
	if _, ok := got["ModifyPath"]; ok || got["NoModify"] != integrate.DWord(1) || got["NoRepair"] != integrate.DWord(1) {
		t.Errorf("a registration without Modify left it: %v", got)
	}
	if r := records(t, in); len(r) != 1 {
		t.Errorf("registering the same entry again recorded %d entries", len(r))
	}
}

func TestRegisterUpdatesARecordWithTheSameIdentity(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	ctx := context.Background()
	if err := in.RegisterUninstallEntry(ctx, entry()); err != nil {
		t.Fatal(err)
	}
	e := entry()
	e.ID = strings.ToUpper(id) // the registry does not tell these apart
	e.Icon = "bin/acme.exe"
	if err := in.RegisterUninstallEntry(ctx, e); err != nil {
		t.Fatal(err)
	}
	r := records(t, in)
	if len(r) != 1 || r[0].Icon != "bin/acme.exe" || r[0].ID != strings.ToUpper(id) {
		t.Fatalf("manifest = %+v", r)
	}
	if got := readKey(t, reg, integrate.HiveUser, key)["DisplayIcon"]; got != integrate.String(winRoot+`\versions\1.2.0\bin\acme.exe`) {
		t.Errorf("DisplayIcon = %v", got)
	}
}

func TestRegisterRefusesInvalidEntries(t *testing.T) {
	cases := map[string]func(*integrate.UninstallEntry){
		"scope":             func(e *integrate.UninstallEntry) { e.Scope = "everyone" },
		"empty id":          func(e *integrate.UninstallEntry) { e.ID = "" },
		"separator in id":   func(e *integrate.UninstallEntry) { e.ID = `acme\..\Other` },
		"slash in id":       func(e *integrate.UninstallEntry) { e.ID = "acme/app" },
		"dot id":            func(e *integrate.UninstallEntry) { e.ID = ".." },
		"long id":           func(e *integrate.UninstallEntry) { e.ID = strings.Repeat("a", 129) },
		"no name":           func(e *integrate.UninstallEntry) { e.DisplayName = " " },
		"control in name":   func(e *integrate.UninstallEntry) { e.DisplayName = "Acme\x00Editor" },
		"control in modify": func(e *integrate.UninstallEntry) { e.ModifyPath = "a\nb" },
		"repair alone":      func(e *integrate.UninstallEntry) { e.Repair = true },
		"no launcher":       func(e *integrate.UninstallEntry) { e.Launcher = "" },
		"launcher path":     func(e *integrate.UninstallEntry) { e.Launcher = "bin/acme.exe" },
		"launcher layout":   func(e *integrate.UninstallEntry) { e.Launcher = "versions" },
		"icon traversal":    func(e *integrate.UninstallEntry) { e.Icon = "../../evil.ico" },
		"icon absolute":     func(e *integrate.UninstallEntry) { e.Icon = "/evil.ico" },
		"icon unclean":      func(e *integrate.UninstallEntry) { e.Icon = "bin//acme.exe" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := installed(t)
			reg := &integrate.MemRegistry{}
			in, _ := newIntegrator(t, m, reg)
			e := entry()
			mutate(&e)
			if err := in.RegisterUninstallEntry(context.Background(), e); !errors.Is(err, integrate.ErrIntegrate) {
				t.Fatalf("err = %v, want an ErrIntegrate", err)
			}
			nothingWritten(t, m, reg)
		})
	}
}

func nothingWritten(t *testing.T, m *fsx.Mem, reg *integrate.MemRegistry) {
	t.Helper()
	if reg.Keys() != 0 {
		t.Errorf("%d registry keys were written", reg.Keys())
	}
	if _, err := fsx.Lstat(m, layout.Integrations(root)); !fsx.IsNotExist(err) {
		t.Errorf("a manifest was written: %v", err)
	}
}

func TestRegisterWithoutRegistryOrInstallation(t *testing.T) {
	ctx := context.Background()
	t.Run("no registry", func(t *testing.T) {
		m := installed(t)
		in, _ := newIntegrator(t, m, nil)
		if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, integrate.ErrNotSupported) {
			t.Fatalf("err = %v, want ErrNotSupported", err)
		}
		nothingWritten(t, m, &integrate.MemRegistry{})
	})
	t.Run("no installation", func(t *testing.T) {
		m := fsx.NewMem()
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, integrate.ErrNotInstalled) {
			t.Fatalf("err = %v, want ErrNotInstalled", err)
		}
		nothingWritten(t, m, reg)
	})
	t.Run("canceled", func(t *testing.T) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := in.RegisterUninstallEntry(cctx, entry()); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		nothingWritten(t, m, reg)
	})
	t.Run("unreadable key", func(t *testing.T) {
		m := installed(t)
		boom := errors.New("access denied")
		reg := &integrate.MemRegistry{Fail: func(string, integrate.Hive, string) error { return boom }}
		in, _ := newIntegrator(t, m, reg)
		if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		nothingWritten(t, m, reg)
	})
}

// The negative tests of ownership: nothing is written over an entry that is not
// this installation's.
func TestRegisterRefusesAnEntryThatIsNotOurs(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		values   map[string]integrate.Value
		otherApp bool
	}{
		"other software":        {values: map[string]integrate.Value{"DisplayName": integrate.String("Not idunn")}},
		"a live other root":     {values: map[string]integrate.Value{integrate.OwnerValue: integrate.String(`\apps\acme-old`)}, otherApp: true},
		"a relative owner":      {values: map[string]integrate.Value{integrate.OwnerValue: integrate.String(`acme-old`)}},
		"a root inside of ours": {values: map[string]integrate.Value{integrate.OwnerValue: integrate.String(winRoot + `\sub`)}, otherApp: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := installed(t)
			if c.otherApp {
				write(t, m, layout.State(other), "{}")
				write(t, m, layout.State(root+"/sub"), "{}")
			}
			reg := &integrate.MemRegistry{}
			if err := reg.WriteKey(integrate.HiveUser, key, c.values, nil); err != nil {
				t.Fatal(err)
			}
			in, _ := newIntegrator(t, m, reg)
			if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, integrate.ErrConflict) {
				t.Fatalf("err = %v, want ErrConflict", err)
			}
			if got := readKey(t, reg, integrate.HiveUser, key); len(got) != len(c.values) {
				t.Errorf("the foreign entry was changed: %v", got)
			}
			if r := records(t, in); len(r) != 0 {
				t.Errorf("a refused entry was recorded: %+v", r)
			}
		})
	}
}

// An entry left behind by a root that was deleted by hand is taken over, with a
// fresh install date.
func TestRegisterTakesOverAnAbandonedEntry(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	if err := reg.WriteKey(integrate.HiveUser, key, map[string]integrate.Value{
		integrate.OwnerValue: integrate.String(`\apps\acme-old`),
		"InstallDate":        integrate.String("20200101"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	in, ev := newIntegrator(t, m, reg)
	if err := in.RegisterUninstallEntry(context.Background(), entry()); err != nil {
		t.Fatal(err)
	}
	got := readKey(t, reg, integrate.HiveUser, key)
	if got[integrate.OwnerValue] != integrate.String(winRoot) || got["InstallDate"] != integrate.String("20260915") {
		t.Errorf("entry = %v", got)
	}
	if len(*ev) != 1 {
		t.Errorf("the takeover was not reported: %v", *ev)
	}
}

// Ownership is judged as Windows judges paths: case and a trailing separator do
// not make another root.
func TestOwnershipIgnoresCaseAndTrailingSeparator(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	if err := reg.WriteKey(integrate.HiveUser, key, map[string]integrate.Value{
		integrate.OwnerValue: integrate.String(`\APPS\Acme\`),
	}, nil); err != nil {
		t.Fatal(err)
	}
	in, _ := newIntegrator(t, m, reg)
	if err := in.RegisterUninstallEntry(context.Background(), entry()); err != nil {
		t.Fatal(err)
	}
}

// The record is written before the key. A registration that dies between them
// leaves a record Unregister passes over.
func TestRegisterRecordsBeforeItWrites(t *testing.T) {
	m := installed(t)
	boom := errors.New("disk full")
	reg := &integrate.MemRegistry{Fail: func(op string, _ integrate.Hive, _ string) error {
		if op == "write" {
			return boom
		}
		return nil
	}}
	in, _ := newIntegrator(t, m, reg)
	ctx := context.Background()
	if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if r := records(t, in); len(r) != 1 {
		t.Fatalf("the entry was not recorded before the write: %+v", r)
	}
	reg.Fail = nil
	if err := in.Unregister(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := fsx.Lstat(m, layout.Integrations(root)); !fsx.IsNotExist(err) {
		t.Errorf("the manifest survived: %v", err)
	}
}

func TestRegisterRecordFailureWritesNoKey(t *testing.T) {
	m := installed(t)
	write(t, m, layout.Integrations(root), "not json")
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	if err := in.RegisterUninstallEntry(context.Background(), entry()); !errors.Is(err, integrate.ErrManifest) {
		t.Fatalf("err = %v, want ErrManifest", err)
	}
	if reg.Keys() != 0 {
		t.Error("a key was written without a record")
	}
}

func TestRegisterSizeDoesNotFollowLinks(t *testing.T) {
	m := installed(t)
	write(t, m, "/elsewhere/huge.bin", strings.Repeat("h", 1<<20))
	dir, _ := layout.VersionDir(root, "1.2.0")
	if err := m.Symlink("/elsewhere", fsx.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	if err := in.RegisterUninstallEntry(context.Background(), entry()); err != nil {
		t.Fatal(err)
	}
	if got := readKey(t, reg, integrate.HiveUser, key)["EstimatedSize"]; got != integrate.DWord(4) {
		t.Errorf("EstimatedSize = %v, want 4: a link was followed", got)
	}
}

func TestRefreshFollowsThePointer(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	ctx := context.Background()
	e := entry()
	e.Icon = "bin/acme.exe"
	if err := in.RegisterUninstallEntry(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	if err := in.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	got := readKey(t, reg, integrate.HiveUser, key)
	if got["DisplayVersion"] != integrate.String("1.3.0") ||
		got["DisplayIcon"] != integrate.String(winRoot+`\versions\1.3.0\bin\acme.exe`) ||
		got["EstimatedSize"] != integrate.DWord(6) {
		t.Errorf("refreshed entry = %v", got)
	}
	if got["DisplayName"] != integrate.String("Acme Editor") {
		t.Error("a refresh changed what the host registered")
	}

	// Current: a refresh reads and writes nothing, so a process that may not
	// write the entry succeeds.
	reg.Fail = func(op string, _ integrate.Hive, _ string) error {
		if op != "read" {
			return errors.New("access denied")
		}
		return nil
	}
	if err := in.Refresh(ctx); err != nil {
		t.Fatalf("a refresh of a current entry wrote: %v", err)
	}
}

func TestRefreshReportsAndDoesNotGuess(t *testing.T) {
	ctx := context.Background()
	registered := func(t *testing.T) (*fsx.Mem, *integrate.MemRegistry, *integrate.Integrator) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		if err := in.RegisterUninstallEntry(ctx, entry()); err != nil {
			t.Fatal(err)
		}
		if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
			t.Fatal(err)
		}
		return m, reg, in
	}

	t.Run("missing entry", func(t *testing.T) {
		_, reg, in := registered(t)
		_ = reg.DeleteKey(integrate.HiveUser, key)
		if err := in.Refresh(ctx); !errors.Is(err, integrate.ErrMissing) {
			t.Fatalf("err = %v, want ErrMissing", err)
		}
		if reg.Keys() != 0 {
			t.Error("a refresh recreated a removed entry")
		}
	})
	t.Run("entry of another root", func(t *testing.T) {
		_, reg, in := registered(t)
		_ = reg.WriteKey(integrate.HiveUser, key, map[string]integrate.Value{integrate.OwnerValue: integrate.String(`\apps\second`)}, nil)
		if err := in.Refresh(ctx); !errors.Is(err, integrate.ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict", err)
		}
		if got := readKey(t, reg, integrate.HiveUser, key)["DisplayVersion"]; got != integrate.String("1.2.0") {
			t.Errorf("another root's entry was written: %v", got)
		}
	})
	t.Run("write fails", func(t *testing.T) {
		_, reg, in := registered(t)
		boom := errors.New("access denied")
		reg.Fail = func(op string, _ integrate.Hive, _ string) error {
			if op == "write" {
				return boom
			}
			return nil
		}
		if err := in.Refresh(ctx); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
	})
	t.Run("read fails", func(t *testing.T) {
		_, reg, in := registered(t)
		boom := errors.New("access denied")
		reg.Fail = func(string, integrate.Hive, string) error { return boom }
		if err := in.Refresh(ctx); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
	})
	t.Run("no registry", func(t *testing.T) {
		m, _, _ := registered(t)
		in, _ := newIntegrator(t, m, nil)
		if err := in.Refresh(ctx); !errors.Is(err, integrate.ErrNotSupported) {
			t.Fatalf("err = %v, want ErrNotSupported", err)
		}
	})
	t.Run("no live version", func(t *testing.T) {
		m, reg, in := registered(t)
		if err := layout.RemovePointer(m, root); err != nil {
			t.Fatal(err)
		}
		reg.Fail = func(string, integrate.Hive, string) error { return errors.New("touched") }
		if err := in.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		_, _, in := registered(t)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := in.Refresh(cctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

func TestNothingRecordedNeedsNoRegistry(t *testing.T) {
	m := installed(t)
	in, _ := newIntegrator(t, m, nil)
	ctx := context.Background()
	if err := in.Refresh(ctx); err != nil {
		t.Errorf("Refresh: %v", err)
	}
	if err := in.Unregister(ctx); err != nil {
		t.Errorf("Unregister: %v", err)
	}
	if ok, err := integrate.Recorded(m, root); ok || err != nil {
		t.Errorf("Recorded = %v, %v", ok, err)
	}
}

func TestUnregisterRemovesOnlyWhatIsOurs(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, ev := newIntegrator(t, m, reg)
	ctx := context.Background()

	mine, foreign, gone := entry(), entry(), entry()
	mine.Scope = integrate.ScopeMachine
	foreign.ID = "acme-foreign"
	gone.ID = "acme-gone"
	for _, e := range []integrate.UninstallEntry{entry(), mine, foreign, gone} {
		if err := in.RegisterUninstallEntry(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := integrate.Recorded(m, root); !ok || err != nil {
		t.Fatalf("Recorded = %v, %v", ok, err)
	}
	foreignKey := integrate.UninstallKey + `\acme-foreign`
	_ = reg.WriteKey(integrate.HiveUser, foreignKey, map[string]integrate.Value{integrate.OwnerValue: integrate.String(`\apps\second`)}, nil)
	_ = reg.DeleteKey(integrate.HiveUser, integrate.UninstallKey+`\acme-gone`)

	if err := in.Unregister(ctx); err != nil {
		t.Fatal(err)
	}
	if reg.Keys() != 1 {
		t.Errorf("%d keys remain, want only the foreign one", reg.Keys())
	}
	readKey(t, reg, integrate.HiveUser, foreignKey)
	if len(*ev) != 1 || ev.last().Phase != hook.PhaseUninstall {
		t.Errorf("leaving the foreign entry was not reported: %v", *ev)
	}
	if _, err := fsx.Lstat(m, layout.Integrations(root)); !fsx.IsNotExist(err) {
		t.Errorf("the manifest survived: %v", err)
	}
}

func (e *events) last() hook.Event { return (*e)[len(*e)-1] }

// An unregister that fails part way keeps on record exactly what is still
// registered, and a second run finishes.
func TestUnregisterResumes(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	ctx := context.Background()
	second := entry()
	second.ID = "acme-second"
	for _, e := range []integrate.UninstallEntry{entry(), second} {
		if err := in.RegisterUninstallEntry(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	boom := errors.New("access denied")
	reg.Fail = func(op string, _ integrate.Hive, path string) error {
		if op == "delete" && path == key {
			return boom
		}
		return nil
	}
	if err := in.Unregister(ctx); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if r := records(t, in); len(r) != 1 || r[0].ID != id {
		t.Fatalf("manifest after a partial unregister = %+v", r)
	}
	readKey(t, reg, integrate.HiveUser, key)

	reg.Fail = nil
	if err := in.Unregister(ctx); err != nil {
		t.Fatal(err)
	}
	if reg.Keys() != 0 {
		t.Errorf("%d keys remain", reg.Keys())
	}
}

func TestUnregisterFailures(t *testing.T) {
	ctx := context.Background()
	registered := func(t *testing.T) (*fsx.Mem, *integrate.MemRegistry, *integrate.Integrator) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		if err := in.RegisterUninstallEntry(ctx, entry()); err != nil {
			t.Fatal(err)
		}
		return m, reg, in
	}
	t.Run("no registry", func(t *testing.T) {
		m, reg, _ := registered(t)
		in, _ := newIntegrator(t, m, nil)
		if err := in.Unregister(ctx); !errors.Is(err, integrate.ErrNotSupported) {
			t.Fatalf("err = %v, want ErrNotSupported", err)
		}
		if reg.Keys() != 1 || len(records(t, in)) != 1 {
			t.Error("an unregister without a registry dropped the record")
		}
	})
	t.Run("read fails", func(t *testing.T) {
		_, reg, in := registered(t)
		boom := errors.New("access denied")
		reg.Fail = func(string, integrate.Hive, string) error { return boom }
		if err := in.Unregister(ctx); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		if len(records(t, in)) != 1 {
			t.Error("the record was dropped although the entry could not be read")
		}
	})
	t.Run("canceled", func(t *testing.T) {
		_, _, in := registered(t)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := in.Unregister(cctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

func TestManifestIsValidatedBeforeItIsActedOn(t *testing.T) {
	good := `{"schema_version":1,"entries":[{"kind":"windows-uninstall","scope":"user","id":"acme-app","launcher":"acme.exe"}]}`
	cases := map[string]string{
		"not json":       "{",
		"trailing data":  good + "{}",
		"unknown field":  `{"schema_version":1,"entries":[],"extra":true}`,
		"schema":         `{"schema_version":2,"entries":[]}`,
		"kind":           strings.Replace(good, "windows-uninstall", "systemd-unit", 1),
		"scope":          strings.Replace(good, `"user"`, `"everyone"`, 1),
		"id":             strings.Replace(good, `"acme-app"`, `"..\\\\Run"`, 1),
		"launcher":       strings.Replace(good, `"acme.exe"`, `"../acme.exe"`, 1),
		"icon":           strings.Replace(good, `"launcher"`, `"icon":"../x.ico","launcher"`, 1),
		"duplicate":      strings.Replace(good, `}]}`, `},{"kind":"windows-uninstall","scope":"user","id":"ACME-APP","launcher":"acme.exe"}]}`, 1),
		"too many":       `{"schema_version":1,"entries":[` + strings.Repeat(`{"kind":"windows-uninstall","scope":"user","id":"a","launcher":"a"},`, 64) + `{"kind":"windows-uninstall","scope":"user","id":"b","launcher":"a"}]}`,
		"oversized file": good + strings.Repeat(" ", 64<<10),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			m := installed(t)
			write(t, m, layout.Integrations(root), raw)
			reg := &integrate.MemRegistry{}
			in, _ := newIntegrator(t, m, reg)
			ctx := context.Background()
			if _, err := integrate.Recorded(m, root); !errors.Is(err, integrate.ErrManifest) {
				t.Errorf("Recorded: err = %v, want ErrManifest", err)
			}
			if err := in.Unregister(ctx); !errors.Is(err, integrate.ErrManifest) {
				t.Errorf("Unregister: err = %v, want ErrManifest", err)
			}
			if err := in.Refresh(ctx); !errors.Is(err, integrate.ErrManifest) {
				t.Errorf("Refresh: err = %v, want ErrManifest", err)
			}
			if _, err := fsx.Lstat(m, layout.Integrations(root)); err != nil {
				t.Errorf("an invalid manifest was removed: %v", err)
			}
		})
	}
}

func TestRegisterRefusesAFullManifest(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	in, _ := newIntegrator(t, m, reg)
	ctx := context.Background()
	var err error
	for n := 0; n <= 64 && err == nil; n++ {
		e := entry()
		e.ID = "acme-" + strings.Repeat("a", n+1)
		err = in.RegisterUninstallEntry(ctx, e)
	}
	if !errors.Is(err, integrate.ErrManifest) {
		t.Fatalf("err = %v, want ErrManifest at the 65th entry", err)
	}
	if reg.Keys() != 64 {
		t.Errorf("%d keys, want 64", reg.Keys())
	}
}

func TestNewValidates(t *testing.T) {
	for name, o := range map[string]integrate.Options{
		"no fs":         {Root: root},
		"relative root": {FS: fsx.NewMem(), Root: "apps/acme"},
		"no root":       {FS: fsx.NewMem()},
		"no lstat":      {FS: noLstat{fsx.NewMem()}, Root: root},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := integrate.New(o); !errors.Is(err, integrate.ErrIntegrate) {
				t.Fatalf("err = %v, want ErrIntegrate", err)
			}
		})
	}
	if _, err := integrate.New(integrate.Options{FS: fsx.NewMem(), Root: root}); err != nil {
		t.Errorf("defaults: %v", err)
	}
}

// noLstat hides Lstat.
type noLstat struct{ fsx.FS }

func TestHiveString(t *testing.T) {
	for h, want := range map[integrate.Hive]string{
		integrate.HiveUser: "HKEY_CURRENT_USER", integrate.HiveMachine: "HKEY_LOCAL_MACHINE", 7: "Hive(7)",
	} {
		if got := h.String(); got != want {
			t.Errorf("%d: %q, want %q", int(h), got, want)
		}
	}
}

func TestFilesystemFailures(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("disk full")
	failOn := func(m *fsx.Mem, op string) {
		m.Fail = func(o, name string) error {
			if o == op && strings.Contains(name, layout.IntegrationsName) {
				return boom
			}
			return nil
		}
	}

	t.Run("record", func(t *testing.T) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		failOn(m, "create")
		if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, integrate.ErrManifest) || !errors.Is(err, boom) {
			t.Fatalf("err = %v, want ErrManifest wrapping %v", err, boom)
		}
		if reg.Keys() != 0 {
			t.Error("a key was written although its record was not")
		}
	})
	t.Run("meta directory", func(t *testing.T) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		m.Fail = func(o, _ string) error {
			if o == "mkdirall" {
				return boom
			}
			return nil
		}
		if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, integrate.ErrManifest) {
			t.Fatalf("err = %v, want ErrManifest", err)
		}
	})
	t.Run("rewriting the record", func(t *testing.T) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		second := entry()
		second.ID = "acme-second"
		for _, e := range []integrate.UninstallEntry{entry(), second} {
			if err := in.RegisterUninstallEntry(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		failOn(m, "create")
		if err := in.Unregister(ctx); !errors.Is(err, integrate.ErrManifest) {
			t.Fatalf("err = %v, want ErrManifest", err)
		}
		m.Fail = nil
		// The record still names the entry that is gone; a second run passes
		// over it.
		if err := in.Unregister(ctx); err != nil {
			t.Fatal(err)
		}
		if reg.Keys() != 0 {
			t.Errorf("%d keys remain", reg.Keys())
		}
	})
	t.Run("removing the manifest", func(t *testing.T) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		if err := in.RegisterUninstallEntry(ctx, entry()); err != nil {
			t.Fatal(err)
		}
		failOn(m, "remove")
		if err := in.Unregister(ctx); !errors.Is(err, integrate.ErrManifest) {
			t.Fatalf("err = %v, want ErrManifest", err)
		}
	})
	t.Run("unreadable manifest", func(t *testing.T) {
		m := installed(t)
		in, _ := newIntegrator(t, m, &integrate.MemRegistry{})
		write(t, m, layout.Integrations(root), "[]")
		if _, err := in.Registered(); !errors.Is(err, integrate.ErrManifest) {
			t.Fatalf("Registered: err = %v, want ErrManifest", err)
		}
		failOn(m, "open")
		if _, err := integrate.Recorded(m, root); !errors.Is(err, integrate.ErrManifest) {
			t.Fatalf("Recorded: err = %v, want ErrManifest", err)
		}
	})
	t.Run("live version directory gone", func(t *testing.T) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		if err := in.RegisterUninstallEntry(ctx, entry()); err != nil {
			t.Fatal(err)
		}
		if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
			t.Fatal(err)
		}
		if err := m.RemoveAll(fsx.Join(layout.Versions(root), "1.3.0")); err != nil {
			t.Fatal(err)
		}
		if err := in.Refresh(ctx); !errors.Is(err, integrate.ErrIntegrate) {
			t.Fatalf("Refresh: err = %v, want ErrIntegrate", err)
		}
		if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, integrate.ErrIntegrate) {
			t.Fatalf("Register: err = %v, want ErrIntegrate", err)
		}
	})
	t.Run("unreadable pointer", func(t *testing.T) {
		m := installed(t)
		reg := &integrate.MemRegistry{}
		in, _ := newIntegrator(t, m, reg)
		if err := in.RegisterUninstallEntry(ctx, entry()); err != nil {
			t.Fatal(err)
		}
		if err := layout.RemovePointer(m, root); err != nil {
			t.Fatal(err)
		}
		write(t, m, layout.Current(root), "../../../etc")
		if err := in.Refresh(ctx); !errors.Is(err, integrate.ErrIntegrate) {
			t.Fatalf("Refresh: err = %v, want ErrIntegrate", err)
		}
		if err := in.RegisterUninstallEntry(ctx, entry()); !errors.Is(err, integrate.ErrIntegrate) {
			t.Fatalf("Register: err = %v, want ErrIntegrate", err)
		}
	})
}

func TestTakeoverWithoutObserver(t *testing.T) {
	m := installed(t)
	reg := &integrate.MemRegistry{}
	_ = reg.WriteKey(integrate.HiveUser, key, map[string]integrate.Value{integrate.OwnerValue: integrate.String(`\apps\gone`)}, nil)
	in, err := integrate.New(integrate.Options{FS: m, Root: root, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.RegisterUninstallEntry(context.Background(), entry()); err != nil {
		t.Fatal(err)
	}
}
