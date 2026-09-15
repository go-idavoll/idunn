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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/uninstall"
	"github.com/go-idavoll/idunn/internal/layout"
)

// osTree installs 1.0.0 on the real filesystem, with the platform's root check
// and link semantics in force.
func osTree(t *testing.T) (root, outside string) {
	t.Helper()
	if uninstall.Privileged() {
		t.Skip("running with administrator rights: the root check asks for an administrators-only root, which a temporary directory is not")
	}
	base := t.TempDir()
	root, outside = filepath.Join(base, "app"), filepath.Join(base, "precious")
	f := fsx.OS()
	dir, err := layout.VersionDir(fsx.Slash(root), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, outside} {
		if err := os.MkdirAll(filepath.FromSlash(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(filepath.FromSlash(dir), "app"), []byte("1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := layout.SetPointer(f, fsx.Slash(root), "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := layout.WriteInstall(f, fsx.Slash(root), layout.Install{Name: appName, Version: "1.0.0", LayoutSchema: release.LayoutSchema}); err != nil {
		t.Fatal(err)
	}
	j, err := txn.Open(f, fsx.Slash(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []txn.State{txn.StateBegin, txn.StateStaged, txn.StateMigrated, txn.StateSwapped, txn.StateCommitted} {
		if err := j.Append(txn.Record{State: s, Name: appName, ToVersion: "1.0.0"}); err != nil {
			t.Fatal(err)
		}
	}
	return root, outside
}

// dirLink creates a directory link at link pointing to target: a junction on
// Windows — which any user may create, and which reports as irregular rather than
// as a symlink — and a symlink elsewhere.
func dirLink(t *testing.T, target, link string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		out, err := exec.CommandContext(context.Background(), "cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
		if err != nil {
			t.Fatalf("mklink /J: %v\n%s", err, out)
		}
		return
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestOnTheRealFilesystemADirectoryLinkIsNotFollowed(t *testing.T) {
	root, outside := osTree(t)
	versionDir := filepath.Join(root, "versions", "1.0.0")
	dirLink(t, outside, filepath.Join(versionDir, "escape"))
	dirLink(t, outside, filepath.Join(root, ".updater", "staging"))

	res, err := uninstall.Run(context.Background(), uninstall.Options{FS: fsx.OS(), Root: fsx.Slash(root), Name: appName})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.RootRemoved {
		t.Fatalf("Result = %+v, want the root removed", res)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root still there: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep.txt")); err != nil || string(b) != "precious" {
		t.Fatalf("the target of a link was changed: %q, %v", b, err)
	}
}

func TestTheRootCheckAcceptsARootThisProcessMayWrite(t *testing.T) {
	root, _ := osTree(t)
	if err := uninstall.CheckRootOS(fsx.Slash(root)); err != nil {
		t.Fatalf("CheckRootOS: %v", err)
	}
}
