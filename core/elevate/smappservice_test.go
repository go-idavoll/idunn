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
	"testing"
)

func TestDaemonStateFromStatus(t *testing.T) {
	cases := []struct {
		raw  int64
		want DaemonState
		name string
	}{
		{0, DaemonNotRegistered, "not registered"},
		{1, DaemonEnabled, "enabled"},
		{2, DaemonRequiresApproval, "requires approval"},
		{3, DaemonNotFound, "not found"},
	}
	for _, c := range cases {
		got, err := daemonStateFromStatus(c.raw)
		if err != nil || got != c.want {
			t.Errorf("daemonStateFromStatus(%d) = %v, %v; want %v", c.raw, got, err, c.want)
		}
		if got.String() != c.name {
			t.Errorf("String() = %q, want %q", got.String(), c.name)
		}
	}
}

// A status macOS adds in some later release is not guessed at. In particular it
// must never come out as DaemonEnabled, which a host would read as "the helper
// is running, send it requests".
func TestAnUnknownStatusFailsClosed(t *testing.T) {
	for _, raw := range []int64{-1, 4, 99, 1 << 40} {
		got, err := daemonStateFromStatus(raw)
		if !errors.Is(err, ErrHelper) || got != DaemonStateUnknown {
			t.Errorf("daemonStateFromStatus(%d) = %v, %v; want DaemonStateUnknown, ErrHelper", raw, got, err)
		}
	}
	var zero DaemonState
	if zero != DaemonStateUnknown || zero.String() != "unknown" {
		t.Fatalf("the zero DaemonState is %v", zero)
	}
}

// A bad plist name never reaches the framework, on any platform: it is refused
// as a malformed request before the build's own answer (ErrNotImplemented, or a
// call into ServiceManagement) has a say.
func TestDaemonFunctionsRefuseABadPlistNameEverywhere(t *testing.T) {
	for _, name := range []string{"", "../x.plist", "com.acme/helper.plist", "com.acme.helper"} {
		if _, err := DaemonStatus(name); !errors.Is(err, ErrRequest) {
			t.Errorf("DaemonStatus(%q) = %v, want ErrRequest", name, err)
		}
		if err := RegisterDaemon(name); !errors.Is(err, ErrRequest) {
			t.Errorf("RegisterDaemon(%q) = %v, want ErrRequest", name, err)
		}
		if err := UnregisterDaemon(name); !errors.Is(err, ErrRequest) {
			t.Errorf("UnregisterDaemon(%q) = %v, want ErrRequest", name, err)
		}
	}
}
