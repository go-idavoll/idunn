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
	"runtime"
	"strings"
	"testing"
)

func TestCheckHelperLabel(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"com.acme.app.helper", "io.idunn-ci.h1", "a.b"} {
		if err := CheckHelperLabel(ok); err != nil {
			t.Errorf("CheckHelperLabel(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "helper", "com..acme", ".com.acme", "com.acme.", "com.-acme", "com.acme-",
		"com/acme", `com\acme`, "com.acme helper", "com.acme\x00", "com.acme_helper",
		"../../etc.passwd", strings.Repeat("a", 31) + "." + strings.Repeat("b", 31),
	} {
		if err := CheckHelperLabel(bad); !errors.Is(err, ErrRequest) {
			t.Errorf("CheckHelperLabel(%q) = %v, want ErrRequest", bad, err)
		}
	}
}

func TestHelperPathsPerPlatform(t *testing.T) {
	t.Parallel()

	const label = "com.acme.app.helper"
	mac, err := helperPaths("darwin", label)
	if err != nil || mac.StateDir != "/Library/Application Support/"+label ||
		mac.Endpoint != "/Library/Application Support/"+label+"/helper.sock" {
		t.Fatalf("darwin = %+v, %v", mac, err)
	}
	if len(mac.Endpoint) > 103 {
		t.Fatalf("the macOS endpoint for a %d-byte label exceeds the socket path limit", len(label))
	}
	linux, err := helperPaths("linux", label)
	if err != nil || linux.StateDir != "/etc/"+label || linux.Endpoint != "/run/"+label+"/helper.sock" {
		t.Fatalf("linux = %+v, %v", linux, err)
	}
	if _, err := helperPaths("plan9", label); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("plan9 = %v, want ErrNotImplemented", err)
	}
	if runtime.GOOS == "windows" {
		win, err := helperPaths("windows", label)
		if err != nil || !strings.HasSuffix(win.StateDir, `\`+label) || win.Endpoint != `\\.\pipe\`+label {
			t.Fatalf("windows = %+v, %v", win, err)
		}
	}
	if _, err := DefaultHelperPaths("not a label"); !errors.Is(err, ErrRequest) {
		t.Fatalf("DefaultHelperPaths(bad label) = %v, want ErrRequest", err)
	}
}

// The longest label must still give a macOS socket path the kernel accepts.
func TestTheLongestLabelFitsTheMacOSSocketLimit(t *testing.T) {
	t.Parallel()

	label := strings.Repeat("a", 30) + "." + strings.Repeat("b", 31)
	if err := CheckHelperLabel(label); err != nil {
		t.Fatal(err)
	}
	p, _ := helperPaths("darwin", label)
	if len(p.Endpoint) > 103 {
		t.Fatalf("endpoint %q is %d bytes, over 103", p.Endpoint, len(p.Endpoint))
	}
}
