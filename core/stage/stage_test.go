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

package stage_test

import (
	"path"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/stage"
)

func TestSanitizeDstAccepts(t *testing.T) {
	for _, dst := range []string{
		"app",
		"bin/app",
		"lib/sub/lib.so",
		"assets/icon.png",
		"a b/c d.txt",
	} {
		t.Run(dst, func(t *testing.T) {
			got, err := stage.SanitizeDst(dst)
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if got != dst {
				t.Fatalf("cleaned %q to %q, expected it unchanged", dst, got)
			}
		})
	}
}

// Redundant separators and "." elements are normalised, not rejected: they are
// unambiguous and safe. The descriptor ingest in core/release is stricter and
// refuses them outright, so a published descriptor still has exactly one spelling
// per destination.
func TestSanitizeDstNormalises(t *testing.T) {
	for dst, want := range map[string]string{
		"bin//app":  "bin/app",
		"bin/./app": "bin/app",
		"bin/app/":  "bin/app",
		"./bin/app": "bin/app",
	} {
		t.Run(dst, func(t *testing.T) {
			got, err := stage.SanitizeDst(dst)
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if got != want {
				t.Fatalf("cleaned %q to %q, want %q", dst, got, want)
			}
		})
	}
}

// Every entry here is a way out of the install root that has bitten real
// installers. A regression that accepts one of them is a vulnerability.
func TestSanitizeDstRejects(t *testing.T) {
	for _, dst := range []string{
		"",
		".",
		"..",
		"../evil",
		"../../evil",
		"bin/../../evil",
		"./../evil",
		"/etc/passwd",
		"//server/share/evil",
		`C:\Windows\System32\evil.dll`,
		"C:evil",
		`bin\evil`,
		"bin/NUL",
		"NUL",
		"nul.txt",
		"COM1",
		"lpt9.log",
		"bin/evil ",
		"bin/evil.",
		"a\x00b",
		strings.Repeat("a/", 1024) + "b",
	} {
		t.Run(dst, func(t *testing.T) {
			if got, err := stage.SanitizeDst(dst); err == nil {
				t.Fatalf("accepted %q as %q", dst, got)
			}
		})
	}
}

// FuzzDstSanitize asserts the one property the rest of the apply path relies on:
// whatever comes back is a clean relative path that cannot leave the install root.
func FuzzDstSanitize(f *testing.F) {
	for _, seed := range []string{
		"bin/app", "../evil", "/abs", `C:\x`, "a\x00b", "NUL", "", "a/./b", "a//b", "a/../../b",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, dst string) {
		got, err := stage.SanitizeDst(dst)
		if err != nil {
			return
		}
		if got == "" {
			t.Fatal("accepted an empty destination")
		}
		if got != path.Clean(got) {
			t.Fatalf("accepted %q which is not in clean form", got)
		}
		if path.IsAbs(got) || strings.HasPrefix(got, "/") {
			t.Fatalf("accepted absolute path %q", got)
		}
		if strings.ContainsRune(got, '\\') || strings.ContainsRune(got, 0) {
			t.Fatalf("accepted %q containing a backslash or NUL", got)
		}
		for _, elem := range strings.Split(got, "/") {
			if elem == "" || elem == "." || elem == ".." {
				t.Fatalf("accepted %q with element %q", got, elem)
			}
		}
	})
}
