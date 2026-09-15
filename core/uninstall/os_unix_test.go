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

//go:build !windows

package uninstall_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/uninstall"
)

// A root this process cannot write is refused before anything is changed, with
// the error that says administrator rights are needed.
func TestARootThisProcessCannotWriteIsRefused(t *testing.T) {
	root, _ := osTree(t)
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	_, err := uninstall.Run(context.Background(), uninstall.Options{FS: fsx.OS(), Root: fsx.Slash(root), Name: appName})
	if !errors.Is(err, uninstall.ErrNotWritable) {
		t.Fatalf("Run = %v, want ErrNotWritable", err)
	}
	if _, err := os.Stat(filepath.Join(root, "versions", "1.0.0", "app")); err != nil {
		t.Fatalf("a refused uninstall removed files: %v", err)
	}
}

func TestFinishIsWindowsOnly(t *testing.T) {
	if err := uninstall.Finish(nil); !errors.Is(err, uninstall.ErrUninstall) {
		t.Fatalf("Finish = %v, want a refusal", err)
	}
}
