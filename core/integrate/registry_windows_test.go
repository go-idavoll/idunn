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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/integrate"
	"github.com/go-idavoll/idunn/internal/layout"
)

// scratchKey is a key below HKEY_CURRENT_USER that only this test run uses, and
// that is removed when it ends.
func scratchKey(t *testing.T) string {
	t.Helper()
	path := fmt.Sprintf(`Software\idunn-test\%s-%d`, t.Name(), os.Getpid())
	t.Cleanup(func() {
		_ = integrate.OSRegistry().DeleteKey(integrate.HiveUser, path)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\idunn-test`)
	})
	return path
}

func TestOSRegistryReadWriteDelete(t *testing.T) {
	reg := integrate.OSRegistry()
	path := scratchKey(t)

	if _, err := reg.ReadKey(integrate.HiveUser, path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadKey of a missing key: %v, want fs.ErrNotExist", err)
	}
	if err := reg.DeleteKey(integrate.HiveUser, path); err != nil {
		t.Fatalf("DeleteKey of a missing key: %v", err)
	}

	set := map[string]integrate.Value{
		"Name":  integrate.String("Acme Editor"),
		"Flag":  integrate.DWord(1),
		"Stale": integrate.String("x"),
	}
	if err := reg.WriteKey(integrate.HiveUser, path, set, nil); err != nil {
		t.Fatal(err)
	}
	if err := reg.WriteKey(integrate.HiveUser, path, map[string]integrate.Value{"Flag": integrate.DWord(0)}, []string{"Stale", "NeverThere"}); err != nil {
		t.Fatal(err)
	}

	// Values of other types, and an expandable string, as other software leaves them.
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetExpandStringValue("Expand", `%SystemRoot%\x`); err != nil {
		t.Fatal(err)
	}
	if err := k.SetBinaryValue("Blob", []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	_ = k.Close()

	got, err := reg.ReadKey(integrate.HiveUser, path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]integrate.Value{
		"Name":   integrate.String("Acme Editor"),
		"Flag":   integrate.DWord(0),
		"Expand": integrate.String(`%SystemRoot%\x`),
	}
	if len(got) != len(want) {
		t.Errorf("ReadKey = %v, want %v", got, want)
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %+v, want %+v", name, got[name], v)
		}
	}

	if err := reg.WriteKey(integrate.HiveUser, path, map[string]integrate.Value{"Bad": {}}, nil); !errors.Is(err, integrate.ErrIntegrate) {
		t.Errorf("a value without a kind: %v", err)
	}

	if err := reg.DeleteKey(integrate.HiveUser, path); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ReadKey(integrate.HiveUser, path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the key survived DeleteKey: %v", err)
	}
}

func TestOSRegistryRefusesAnUnknownHive(t *testing.T) {
	reg := integrate.OSRegistry()
	if _, err := reg.ReadKey(0, `Software`); !errors.Is(err, integrate.ErrIntegrate) {
		t.Errorf("ReadKey: %v", err)
	}
	if err := reg.WriteKey(0, `Software`, nil, nil); !errors.Is(err, integrate.ErrIntegrate) {
		t.Errorf("WriteKey: %v", err)
	}
	if err := reg.DeleteKey(0, `Software`); !errors.Is(err, integrate.ErrIntegrate) {
		t.Errorf("DeleteKey: %v", err)
	}
}

// The whole lifecycle against the real registry and a real directory: the entry
// Settings lists appears, follows the pointer, and is gone after Unregister.
func TestUninstallEntryOnTheRealRegistry(t *testing.T) {
	dir := fsx.Slash(t.TempDir())
	f := fsx.OS()
	for _, v := range []string{"1.2.0", "1.3.0"} {
		vd, err := layout.VersionDir(dir, v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.FromSlash(vd), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.FromSlash(fsx.Join(vd, "app.exe")), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := layout.SetPointer(f, dir, "1.2.0"); err != nil {
		t.Fatal(err)
	}

	reg := integrate.OSRegistry()
	e := integrate.UninstallEntry{
		Scope:       integrate.ScopeUser,
		ID:          fmt.Sprintf("idunn-test-%d", os.Getpid()),
		DisplayName: "idunn test entry",
		Launcher:    "launcher.exe",
	}
	path := integrate.UninstallKey + `\` + e.ID
	t.Cleanup(func() { _ = reg.DeleteKey(integrate.HiveUser, path) })

	in, err := integrate.New(integrate.Options{FS: f, Root: dir, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := in.RegisterUninstallEntry(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := layout.SetPointer(f, dir, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	if err := in.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := reg.ReadKey(integrate.HiveUser, path)
	if err != nil {
		t.Fatal(err)
	}
	if got["DisplayVersion"] != integrate.String("1.3.0") || got[integrate.OwnerValue] != integrate.String(filepath.FromSlash(dir)) {
		t.Errorf("entry = %v", got)
	}

	if err := in.Unregister(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ReadKey(integrate.HiveUser, path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the entry survived Unregister: %v", err)
	}
}
