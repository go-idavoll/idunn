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

package elevate

import (
	"errors"
	"net"
	"testing"
)

// The requirement seam, wired through a real socket: the helper consults its
// code check on the live connection after the kernel's uid, and a "no" from it
// denies a caller whose uid is allowed — before the applier is reached.
//
// The check itself is faked here, which is what lets this run on Linux; the
// real one (Security.framework) is exercised by the darwin cgo tests.
func TestAPeerFailingTheRequirementIsDeniedOverTheSocket(t *testing.T) {
	var sawConn bool
	var sawReq string
	a := &countingApplier{}
	endpoint := startHelper(t, a, func(string) error { return nil }, func(h *Helper) {
		h.peerRequirement = someRequirement
		h.checkPeerCode = func(conn net.Conn, req string) error {
			_, sawConn = conn.(*net.UnixConn)
			sawReq = req
			return errors.New("not our application")
		}
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
	if !sawConn || sawReq != someRequirement {
		t.Fatalf("the check saw conn=%v req=%q", sawConn, sawReq)
	}
}

func TestAPeerMeetingTheRequirementIsServed(t *testing.T) {
	a := &countingApplier{}
	endpoint := startHelper(t, a, func(string) error { return nil }, func(h *Helper) {
		h.peerRequirement = someRequirement
		h.checkPeerCode = func(net.Conn, string) error { return nil }
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
