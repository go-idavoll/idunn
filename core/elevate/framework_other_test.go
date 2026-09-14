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

//go:build !darwin || !cgo

package elevate

import (
	"errors"
	"testing"
)

func TestSMAppServiceIsNotImplementedHere(t *testing.T) {
	const name = "com.acme.app.helper.plist"
	if s, err := DaemonStatus(name); !errors.Is(err, ErrNotImplemented) || s != DaemonStateUnknown {
		t.Errorf("DaemonStatus = %v, %v; want DaemonStateUnknown, ErrNotImplemented", s, err)
	}
	if err := RegisterDaemon(name); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("RegisterDaemon = %v, want ErrNotImplemented", err)
	}
	if err := UnregisterDaemon(name); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("UnregisterDaemon = %v, want ErrNotImplemented", err)
	}
	if err := OpenLoginItemsSettings(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("OpenLoginItemsSettings = %v, want ErrNotImplemented", err)
	}
}

// A helper configured to check its callers' code signatures, on a build that
// cannot, must not start — least of all as a helper that checks uids only and
// looks, from its configuration, like one that checks more.
func TestAPeerRequirementIsRefusedWhereItCannotBeChecked(t *testing.T) {
	rootChecked := false
	_, err := newHelper(HelperOptions{
		Endpoint:        "/nonexistent/helper.sock",
		Applier:         nopApplier{},
		AllowedRoots:    []string{"/usr/idunn-test-acme"},
		PeerRequirement: `anchor apple generic and identifier "com.acme.app"`,
	}, func(string) error { rootChecked = true; return nil })
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("VULNERABILITY: newHelper = %v, want ErrNotImplemented", err)
	}
	if rootChecked {
		t.Fatal("the roots were judged before the unsupported requirement was refused")
	}

	if err := checkPeerRequirement("anchor apple"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("checkPeerRequirement = %v, want ErrNotImplemented", err)
	}
	if err := peerCodeCheck(nil, "anchor apple"); !errors.Is(err, ErrDenied) {
		t.Fatalf("peerCodeCheck = %v, want ErrDenied", err)
	}
}
