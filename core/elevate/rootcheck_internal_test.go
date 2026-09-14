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

package elevate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestAncestorsRunFromTheVolumeRootDown(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "a", "b")
	got := ancestors(dir)
	if len(got) < 3 {
		t.Fatalf("ancestors(%q) = %q", dir, got)
	}
	if filepath.Dir(got[0]) != got[0] {
		t.Fatalf("ancestors(%q) starts at %q, want the volume root", dir, got[0])
	}
	if got[len(got)-1] != filepath.Dir(dir) {
		t.Fatalf("ancestors(%q) ends at %q, want the parent", dir, got[len(got)-1])
	}
	for i := 1; i < len(got); i++ {
		if filepath.Dir(got[i]) != got[i-1] {
			t.Fatalf("ancestors(%q) = %q is not a chain", dir, got)
		}
	}
	vol := got[0]
	if a := ancestors(vol); len(a) != 0 {
		t.Fatalf("ancestors(%q) = %q, want none", vol, a)
	}
}

// The write set is what a helper touches in an existing install. Missing it would
// leave a user-writable journal or cache in front of a privileged process; over-
// reaching into the payload is harmless but slow, and every reused payload byte
// is hash-checked anyway.
func TestWriteSetCoversWhatTheHelperTouches(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, d := range []string{
		".updater/tuf/metadata", ".updater/staging/1.1.0/bin", "versions/1.0.0/bin",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		"current", "launcher", ".updater/journal.json", ".updater/tuf/metadata/timestamp.json", "versions/1.0.0/bin/app",
	} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(f)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := writeSet(root)
	if err != nil {
		t.Fatalf("writeSet = %v", err)
	}
	rel := make([]string, 0, len(got))
	for _, p := range got {
		r, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		rel = append(rel, filepath.ToSlash(r))
	}
	for _, want := range []string{
		".", "current", "launcher", ".updater", "versions", "versions/1.0.0",
		".updater/journal.json", ".updater/tuf", ".updater/tuf/metadata",
		".updater/tuf/metadata/timestamp.json", ".updater/staging/1.1.0/bin",
	} {
		if !slices.Contains(rel, want) {
			t.Errorf("writeSet lacks %q: %q", want, rel)
		}
	}
	for _, not := range []string{"versions/1.0.0/bin", "versions/1.0.0/bin/app"} {
		if slices.Contains(rel, not) {
			t.Errorf("writeSet reaches into the payload: %q", not)
		}
	}

	// A fresh root without metadata or versions is not an error.
	fresh := t.TempDir()
	if got, err := writeSet(fresh); err != nil || len(got) != 1 {
		t.Fatalf("writeSet(empty root) = %q, %v", got, err)
	}
}

// The helper accepts a request only for a root it may write safely. A malformed
// request is still a malformed request, whatever the root is.
func TestAcceptRequestRefusesAnUnsafeRoot(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("as root, a temporary directory is root-owned")
	}
	root := filepath.Join(t.TempDir(), "app")
	if _, err := AcceptRequest(root, "stable", "1.0.0"); !errors.Is(err, ErrUnsafeRoot) {
		t.Fatalf("AcceptRequest(user-owned root) = %v, want ErrUnsafeRoot", err)
	}
	if _, err := AcceptRequest(root, "stable&calc", "1.0.0"); !errors.Is(err, ErrRequest) {
		t.Fatalf("AcceptRequest(bad channel) = %v, want ErrRequest", err)
	}
}
