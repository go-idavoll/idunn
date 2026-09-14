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

//go:build darwin && cgo

package elevate

import (
	"errors"
	"runtime"
	"testing"
)

// These run only on macOS with cgo (the macos-latest CI job). They prove the
// bridge compiles, links and behaves on the paths a test can reach without a
// signed, notarized bundle and a user at the keyboard. Registration and
// approval cannot be among them: SMAppService registers the daemon of the
// calling *bundle*, and a go test binary is not one.

func TestAPeerRequirementThatDoesNotCompileStopsTheHelper(t *testing.T) {
	for _, req := range []string{"this is not a requirement (", `identifier "unterminated`} {
		_, err := newHelper(HelperOptions{
			Endpoint:        "/nonexistent/helper.sock",
			Applier:         nopApplier{},
			AllowedRoots:    []string{"/usr/idunn-test-acme"},
			PeerRequirement: req,
		}, func(string) error { return nil })
		if !errors.Is(err, ErrRequest) {
			t.Errorf("newHelper(%q) = %v, want ErrRequest", req, err)
		}
	}
	if err := checkPeerRequirement(someRequirement); err != nil {
		t.Fatalf("a well-formed requirement did not compile: %v", err)
	}
}

// The real check on a real connection: this test process is an allowed uid, and
// its code is not the application the requirement names, so it is denied.
func TestARealPeerFailingTheRequirementIsDenied(t *testing.T) {
	const req = `identifier "com.example.idunn.never-this-binary"`
	if err := checkPeerRequirement(req); err != nil {
		t.Fatal(err)
	}
	a := &countingApplier{}
	endpoint := startHelper(t, a, func(string) error { return nil }, func(h *Helper) {
		h.peerRequirement = req
	})
	el, err := NewService(ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	err = el.Apply(t.Context(), "/usr/idunn-test-acme", stableDescriptor("1.3.0"))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if n := a.calls.Load(); n != 0 {
		t.Fatalf("VULNERABILITY: the applier ran %d times", n)
	}
}

// The control for the test above, so that a check which denied everything
// would not pass for a working one. The Go linker ad-hoc signs binaries on
// darwin/arm64, which is what gives this process code that can be valid at
// all; on amd64 the test binary is unsigned and this cannot be asserted.
func TestARealPeerMeetingTheRequirementIsServed(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("the test binary is only linker-signed on darwin/arm64")
	}
	const req = `! identifier "com.example.idunn.never-this-binary"`
	if err := checkPeerRequirement(req); err != nil {
		t.Fatal(err)
	}
	a := &countingApplier{}
	endpoint := startHelper(t, a, func(string) error { return nil }, func(h *Helper) {
		h.peerRequirement = req
	})
	el, err := NewService(ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := el.Apply(t.Context(), "/usr/idunn-test-acme", stableDescriptor("1.3.0")); err != nil {
		t.Fatalf("err = %v", err)
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("the applier ran %d times, want 1", n)
	}
}

// Outside a bundle there is nothing registered and nothing to register, so all
// this can show is that the ServiceManagement bridge links and answers without
// claiming a daemon is enabled.
func TestDaemonStatusOutsideABundle(t *testing.T) {
	state, err := DaemonStatus("com.example.idunn.absent.plist")
	if errors.Is(err, ErrNotImplemented) {
		t.Skipf("SMAppService unavailable: %v", err)
	}
	if err != nil {
		t.Fatalf("DaemonStatus: %v", err)
	}
	if state == DaemonEnabled {
		t.Fatal("a daemon no bundle carries is reported enabled")
	}
	t.Logf("status of an absent daemon from a bare test binary: %v", state)
}
