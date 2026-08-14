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
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

// The request is the only thing that crosses the privilege boundary, so these
// tests are the boundary's input validation. They run on every OS on purpose:
// the rules judge the text of a value, not the host that happens to run them, so
// a descriptor rejected on Linux is rejected identically on Windows.

func descriptor(channel, version string) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		Name:          "demo",
		Version:       version,
		Channel:       channel,
		OS:            "windows",
		Arch:          "amd64",
		LayoutSchema:  release.LayoutSchema,
	}
}

func TestNewRequestAcceptsAWellFormedApply(t *testing.T) {
	t.Parallel()

	for _, root := range []string{
		`C:\Program Files\demo`,
		`C:/Program Files/demo`,
		`C:\`,
		`\\fileserver\apps\demo`,
		"/opt/demo",
		"/",
	} {
		req, err := newRequest(root, descriptor("stable", "1.4.2-rc.1+build.7"))
		if err != nil {
			t.Fatalf("newRequest(%q) = %v, want a request", root, err)
		}
		if req.Root != root || req.Channel != "stable" || req.Version != "1.4.2-rc.1+build.7" {
			t.Fatalf("newRequest(%q) = %+v, want the inputs carried through", root, req)
		}
	}
}

// A request that is not exactly "this channel, this version, this root" is a
// request the privileged side would have to interpret. Everything below is a
// value that would have been interpreted rather than installed — several of them
// are attempts to smuggle a second argument, a redirected root, or a path the
// elevated process would resolve against a working directory we do not control.
func TestNewRequestRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		root    string
		channel string
		version string
	}{
		{"a relative root", `demo`, "stable", "1.0.0"},
		{"a drive-relative root", `C:demo`, "stable", "1.0.0"},
		{"an empty root", ``, "stable", "1.0.0"},
		{"a root that climbs out", `C:\apps\..\..\Windows\System32`, "stable", "1.0.0"},
		{"a root with a dot element", `C:\apps\.\demo`, "stable", "1.0.0"},
		{"a root with a doubled separator", `C:\apps\\demo`, "stable", "1.0.0"},
		{"a root with mixed doubled separators", `C:\apps\/demo`, "stable", "1.0.0"},
		{"a root ending in a separator", `C:\apps\demo\`, "stable", "1.0.0"},
		{"a root with a quote", `C:\apps\demo" --root C:\Windows`, "stable", "1.0.0"},
		{"a root with a redirection character", `C:\apps\demo|calc`, "stable", "1.0.0"},
		{"a root with a wildcard", `C:\apps\dem*`, "stable", "1.0.0"},
		{"a root with a newline", "C:\\apps\\demo\nrunas", "stable", "1.0.0"},
		{"a root with a NUL byte", "C:\\apps\\demo\x00", "stable", "1.0.0"},
		{"an overlong root", `C:\` + strings.Repeat("a", maxPathLen), "stable", "1.0.0"},
		{"an empty channel", `C:\apps\demo`, "", "1.0.0"},
		{"a channel with a space", `C:\apps\demo`, "stable beta", "1.0.0"},
		{"a channel that is a flag", `C:\apps\demo`, "--root", "1.0.0"},
		{"a channel with a shell separator", `C:\apps\demo`, "stable&calc", "1.0.0"},
		{"a channel with a path separator", `C:\apps\demo`, `..\stable`, "1.0.0"},
		{"an overlong channel", `C:\apps\demo`, strings.Repeat("s", maxFieldLen+1), "1.0.0"},
		{"an empty version", `C:\apps\demo`, "stable", ""},
		{"a version that is not SemVer", `C:\apps\demo`, "stable", "1.0"},
		{"a version with a quote", `C:\apps\demo`, "stable", `1.0.0" --root C:\Windows`},
		{"a version with a space", `C:\apps\demo`, "stable", "1.0.0 --root"},
		{"an overlong version", `C:\apps\demo`, "stable", "1.0.0-" + strings.Repeat("a", maxFieldLen)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := newRequest(tc.root, descriptor(tc.channel, tc.version)); !errors.Is(err, ErrRequest) {
				t.Fatalf("newRequest(%q, %q, %q) = %v, want ErrRequest", tc.root, tc.channel, tc.version, err)
			}
		})
	}
}

func TestNewRequestRejectsANilDescriptor(t *testing.T) {
	t.Parallel()

	if _, err := newRequest(`C:\apps\demo`, nil); !errors.Is(err, ErrRequest) {
		t.Fatalf("newRequest(nil descriptor) = %v, want ErrRequest", err)
	}
}

func TestRequestArgsCarryOnlyTheThreeScalars(t *testing.T) {
	t.Parallel()

	req := Request{Root: `C:\apps\demo`, Channel: "stable", Version: "2.0.0"}
	got := req.args()
	want := []string{"apply", "--root", `C:\apps\demo`, "--channel", "stable", "--version", "2.0.0"}
	if len(got) != len(want) {
		t.Fatalf("args() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args() = %q, want %q", got, want)
		}
	}
}

func TestCheckHelperPathAcceptsAnExistingLocalFile(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), "helper.exe")
	if err := os.WriteFile(p, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkHelperPath(p); err != nil {
		t.Fatalf("checkHelperPath(%q) = %v, want nil", p, err)
	}
}

// The helper path is the binary that will run with administrator rights. A path
// that is relative, remote, missing, or not a file is not a helper — accepting
// any of them is the elevation-of-privilege bug this package exists to avoid.
func TestCheckHelperPathRejects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tests := []struct {
		name string
		path string
	}{
		{"an empty path", ""},
		{"a relative path", `helper.exe`},
		{"a drive-relative path", `C:helper.exe`},
		{"a UNC path", `\\fileserver\tools\helper.exe`},
		// Deliberately not filepath.Join: joining would clean the ".." away, and
		// what has to be rejected is the uncleaned text a caller can hand us.
		{"a traversal", dir + `/../helper.exe`},
		{"a quote", filepath.Join(dir, `helper".exe`)},
		{"an overlong path", `C:\` + strings.Repeat("a", maxPathLen)},
		{"a missing file", filepath.Join(dir, "absent.exe")},
		{"a directory", dir},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := checkHelperPath(tc.path); !errors.Is(err, ErrRequest) {
				t.Fatalf("checkHelperPath(%q) = %v, want ErrRequest", tc.path, err)
			}
		})
	}
}
