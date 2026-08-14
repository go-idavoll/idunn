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

package layout_test

import (
	"errors"
	"sort"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
)

const root = "/opt/app"

func newRoot(t *testing.T) *fsx.Mem {
	t.Helper()
	m := fsx.NewMem()
	if err := m.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return m
}

func TestPaths(t *testing.T) {
	for got, want := range map[string]string{
		layout.Current(root):  "/opt/app/current",
		layout.Versions(root): "/opt/app/versions",
		layout.Meta(root):     "/opt/app/.updater",
		layout.Journal(root):  "/opt/app/.updater/journal.json",
		layout.State(root):    "/opt/app/.updater/state.json",
		layout.Staging(root):  "/opt/app/.updater/staging",
	} {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}

	dir, err := layout.VersionDir(root, "1.3.0")
	if err != nil {
		t.Fatalf("VersionDir: %v", err)
	}
	if dir != "/opt/app/versions/1.3.0" {
		t.Fatalf("VersionDir = %q", dir)
	}
}

// A version string becomes a path element. Anything that is not a version is
// refused before it can address the filesystem, whatever produced it.
func TestVersionDirRejectsNonVersions(t *testing.T) {
	for _, v := range []string{
		"", "..", "../../etc", "1.3.0/../..", "/absolute", "latest",
		"1.3", "v1.3.0", "1.3.0 ", "C:/windows",
	} {
		t.Run(v, func(t *testing.T) {
			if _, err := layout.VersionDir(root, v); err == nil {
				t.Fatalf("%q was accepted as a version directory", v)
			} else if !errors.Is(err, layout.ErrLayout) {
				t.Fatalf("error %v is not classified as ErrLayout", err)
			}
		})
	}
}

func TestPointerRoundTrip(t *testing.T) {
	m := newRoot(t)

	// No installation yet is an empty answer, not an error: the installer has to
	// be able to ask.
	if got, err := layout.PointerTarget(m, root); err != nil || got != "" {
		t.Fatalf("PointerTarget on an empty root = %q, %v", got, err)
	}

	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	if got, err := layout.PointerTarget(m, root); err != nil || got != "1.3.0" {
		t.Fatalf("PointerTarget = %q, %v; want 1.3.0", got, err)
	}

	// Repointing replaces the link rather than failing on the existing one.
	if err := layout.SetPointer(m, root, "1.4.0"); err != nil {
		t.Fatalf("SetPointer (repoint): %v", err)
	}
	if got, _ := layout.PointerTarget(m, root); got != "1.4.0" {
		t.Fatalf("PointerTarget = %q, want 1.4.0", got)
	}

	// The stored target is relative, so the whole install tree stays movable and
	// cannot be made to point outside itself by being copied elsewhere.
	target, err := m.Readlink(layout.Current(root))
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if fsx.IsAbs(target) {
		t.Fatalf("current stores the absolute path %q", target)
	}
}

func TestSetPointerRejectsBadVersion(t *testing.T) {
	m := newRoot(t)
	if err := layout.SetPointer(m, root, "../escape"); err == nil {
		t.Fatal("SetPointer accepted a version that escapes the root")
	}
}

// Something replaced the pointer. Continuing would mean updating around whatever
// it now is, so the answer is an error rather than a guess.
func TestPointerTargetRejectsNonSymlink(t *testing.T) {
	m := newRoot(t)
	if err := fsx.WriteFileAtomic(m, layout.Current(root), []byte("versions/1.3.0"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := layout.PointerTarget(m, root); err == nil {
		t.Fatal("a regular file was accepted as the current pointer")
	}
}

func TestPointerTargetRejectsForeignTargets(t *testing.T) {
	for _, target := range []string{
		"/etc",
		"versions",
		"other/1.3.0",
		"versions/latest",
		"versions/../../etc",
		"",
	} {
		t.Run(target, func(t *testing.T) {
			m := newRoot(t)
			if target == "" {
				// An empty link target cannot be created; the equivalent state
				// is a pointer to the versions directory itself.
				target = "versions"
			}
			if err := m.Symlink(target, layout.Current(root)); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			if _, err := layout.PointerTarget(m, root); err == nil {
				t.Fatalf("current -> %q was accepted", target)
			}
		})
	}
}

func TestRemovePointerIsIdempotent(t *testing.T) {
	m := newRoot(t)
	if err := layout.SetPointer(m, root, "1.3.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := layout.RemovePointer(m, root); err != nil {
			t.Fatalf("RemovePointer #%d: %v", i+1, err)
		}
	}
	if got, _ := layout.PointerTarget(m, root); got != "" {
		t.Fatalf("PointerTarget = %q after removal", got)
	}
}

func TestInstalledVersions(t *testing.T) {
	m := newRoot(t)
	if got, err := layout.InstalledVersions(m, root); err != nil || got != nil {
		t.Fatalf("InstalledVersions on an empty root = %v, %v", got, err)
	}

	for _, v := range []string{"1.2.0", "1.3.0", "2.0.0-rc.1"} {
		dir, err := layout.VersionDir(root, v)
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := m.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	// An operator's stray file and a directory that is not a version must not
	// make the GC or the installer fail; they are ignored.
	if err := m.MkdirAll(fsx.Join(layout.Versions(root), "scratch"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsx.WriteFileAtomic(m, fsx.Join(layout.Versions(root), "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := layout.InstalledVersions(m, root)
	if err != nil {
		t.Fatalf("InstalledVersions: %v", err)
	}
	sort.Strings(got)
	want := []string{"1.2.0", "1.3.0", "2.0.0-rc.1"}
	if len(got) != len(want) {
		t.Fatalf("InstalledVersions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("InstalledVersions = %v, want %v", got, want)
		}
	}
}

func TestInstallStateRoundTrip(t *testing.T) {
	m := newRoot(t)

	// No state means no installation — an answer, not an error.
	in, err := layout.ReadInstall(m, root)
	if err != nil || in != nil {
		t.Fatalf("ReadInstall on an empty root = %+v, %v", in, err)
	}

	want := layout.Install{Name: "acme-app", Version: "1.3.0", LayoutSchema: 1}
	if err := layout.WriteInstall(m, root, want); err != nil {
		t.Fatalf("WriteInstall: %v", err)
	}
	got, err := layout.ReadInstall(m, root)
	if err != nil {
		t.Fatalf("ReadInstall: %v", err)
	}
	if got.Name != want.Name || got.Version != want.Version || got.LayoutSchema != want.LayoutSchema {
		t.Fatalf("ReadInstall = %+v, want %+v", got, want)
	}
	if got.SchemaVersion != layout.StateSchema {
		t.Fatalf("schema_version = %d, want %d", got.SchemaVersion, layout.StateSchema)
	}
}

func TestWriteInstallRejectsIncompleteState(t *testing.T) {
	m := newRoot(t)
	for _, tc := range []struct {
		name string
		in   layout.Install
	}{
		{"no name", layout.Install{Version: "1.3.0", LayoutSchema: 1}},
		{"no version", layout.Install{Name: "acme-app", LayoutSchema: 1}},
		{"bad version", layout.Install{Name: "acme-app", Version: "latest", LayoutSchema: 1}},
		{"no layout schema", layout.Install{Name: "acme-app", Version: "1.3.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := layout.WriteInstall(m, root, tc.in); err == nil {
				t.Fatalf("wrote incomplete state %+v", tc.in)
			}
		})
	}
}

// "I could not read the state" must never be reported as "nothing is installed":
// the caller acts on that answer by installing over whatever is really there.
func TestReadInstallRejectsUnreadableState(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"not json", "{"},
		{"trailing data", `{"schema_version":1,"name":"a","version":"1.3.0","layout_schema":1} {}`},
		{"unknown schema", `{"schema_version":2,"name":"a","version":"1.3.0","layout_schema":1}`},
		{"unknown field", `{"schema_version":1,"name":"a","version":"1.3.0","layout_schema":1,"extra":true}`},
		{"no name", `{"schema_version":1,"name":"","version":"1.3.0","layout_schema":1}`},
		{"bad version", `{"schema_version":1,"name":"a","version":"latest","layout_schema":1}`},
		{"no layout schema", `{"schema_version":1,"name":"a","version":"1.3.0","layout_schema":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRoot(t)
			if err := m.MkdirAll(layout.Meta(root), 0o700); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := fsx.WriteFileAtomic(m, layout.State(root), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			in, err := layout.ReadInstall(m, root)
			if err == nil {
				t.Fatalf("unreadable state was accepted as %+v", in)
			}
			if in != nil {
				t.Fatal("a rejected state was still handed to the caller")
			}
		})
	}
}
