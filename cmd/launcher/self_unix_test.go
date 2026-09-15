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

//go:build unix

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Negative: a root this user cannot write — a system-wide install — is a soft
// skip. The application starts, the condition is reported with the backlog item
// that would lift it, and the launcher is untouched.
func TestAnUnwritableRootStillLaunches(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through any mode")
	}
	root, shim := selfInstall(t, "launcher v2")
	if err := os.Chmod(root, 0o555); err != nil { //nolint:gosec // G302: read-only on purpose.
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) }) //nolint:gosec // G302: restored for cleanup.

	var out bytes.Buffer
	s := &started{}
	if code := run([]string{"--root", root, "--quiet"}, &out, &out, s.exec); code != 0 {
		t.Fatalf("run = %d\n%s", code, &out)
	}
	if s.path == "" {
		t.Fatal("the application was not started")
	}
	if !strings.Contains(out.String(), "IDN-23") {
		t.Errorf("the skip was not reported: %q", out.String())
	}
	if got, _ := os.ReadFile(shim); string(got) != "launcher v1" { //nolint:gosec // G304: test fixture.
		t.Errorf("the launcher reads %q", got)
	}
}
